// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package xlate translates packets between this host's unified (virtual)
// address space and each tailnet's real address space, and decides where
// each packet goes.
//
// Translation is stateless and one-to-one: every decision is made from the
// packet's own addresses, the remap table ([Mapper]), and per-tailnet
// [Stack] information. Packets are rewritten in place.
package xlate

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
)

// Mapper translates addresses. [*remap.Table] implements it.
type Mapper interface {
	RealToVirtual(owner remap.Owner, a netip.Addr) (netip.Addr, bool)
	VirtualToReal(a netip.Addr) (remap.Owner, netip.Addr, bool)
}

// Stack describes one tailnet's stack as the translator needs it.
type Stack struct {
	Owner remap.Owner
	// Self is this node's real addresses in the tailnet.
	Self []netip.Addr
	// Advertised is the subnets this node routes for the tailnet.
	Advertised []netip.Prefix
	// OffersExit reports whether this node is an exit node for the tailnet.
	OffersExit bool
	// UsesExit reports whether this node uses an exit node of the tailnet.
	UsesExit bool
}

// Verdict says what to do with a translated packet.
type Verdict uint8

const (
	Drop    Verdict = iota // discard the packet
	ToStack                // write it to the stack named by Result.Owner
	ToHost                 // write it to the host's real TUN
)

func (v Verdict) String() string {
	switch v {
	case Drop:
		return "drop"
	case ToStack:
		return "to-stack"
	case ToHost:
		return "to-host"
	}
	return fmt.Sprintf("Verdict(%d)", uint8(v))
}

// Result is the outcome of translating one packet.
type Result struct {
	Verdict Verdict
	Owner   remap.Owner // set for ToStack and ToHost
	Reason  string      // set for Drop
}

func drop(reason string) Result { return Result{Verdict: Drop, Reason: reason} }

type stackSet struct {
	byOwner map[remap.Owner]Stack
	exit    remap.Owner // stack using an exit node, or ""
}

// Translator translates packets. It is safe for concurrent use.
type Translator struct {
	m        Mapper
	reserved []netip.Prefix
	stacks   atomic.Pointer[stackSet]
}

// New returns a translator using m. Destinations and sources inside
// reserved (the Tailscale ranges and the remap pools) are never treated as
// internet traffic for exit nodes.
func New(m Mapper, reserved []netip.Prefix) *Translator {
	t := &Translator{m: m, reserved: slices.Clone(reserved)}
	t.stacks.Store(&stackSet{byOwner: map[remap.Owner]Stack{}})
	return t
}

// SetStacks replaces the set of stacks. At most one stack may use an exit
// node, and owners must be unique and non-empty.
func (t *Translator) SetStacks(stacks []Stack) error {
	ss := &stackSet{byOwner: make(map[remap.Owner]Stack, len(stacks))}
	for _, st := range stacks {
		if st.Owner == "" {
			return errors.New("xlate: stack with empty owner")
		}
		if _, dup := ss.byOwner[st.Owner]; dup {
			return fmt.Errorf("xlate: duplicate stack %q", st.Owner)
		}
		if st.UsesExit {
			if ss.exit != "" {
				return fmt.Errorf("xlate: tailnets %q and %q both use an exit node", ss.exit, st.Owner)
			}
			ss.exit = st.Owner
		}
		st.Self = slices.Clone(st.Self)
		st.Advertised = slices.Clone(st.Advertised)
		ss.byOwner[st.Owner] = st
	}
	t.stacks.Store(ss)
	return nil
}

// Outbound translates a packet the host sent into the unified space and
// picks the stack to deliver it to.
func (t *Translator) Outbound(q *packet.Parsed) Result {
	if !wellFormed(q) {
		return drop("malformed packet")
	}
	ss := t.stacks.Load()
	src, dst := q.Src.Addr(), q.Dst.Addr()
	owner, realDst, ok := t.m.VirtualToReal(dst)
	if !ok {
		if ss.exit == "" || t.isReserved(dst) {
			return drop("no route")
		}
		owner, realDst = ss.exit, dst
	}
	st, ok := ss.byOwner[owner]
	if !ok {
		return drop("unknown tailnet")
	}
	newSrc, ok := t.outboundSrc(st, src)
	if !ok {
		return drop("source not allowed for tailnet")
	}
	if !rewrite(q, src, newSrc, dst, realDst) {
		return drop("address family mismatch")
	}
	return Result{Verdict: ToStack, Owner: owner}
}

// outboundSrc returns the real source for a packet from the host to st.
func (t *Translator) outboundSrc(st Stack, src netip.Addr) (netip.Addr, bool) {
	for _, self := range st.Self {
		if v, ok := t.m.RealToVirtual(st.Owner, self); ok && v == src {
			return self, true
		}
	}
	if _, _, ok := t.m.VirtualToReal(src); ok {
		// A virtual address other than this stack's own self address: a
		// peer's or another tailnet's. Never pass it into a stack.
		return netip.Addr{}, false
	}
	if containsAddr(st.Advertised, src) || (st.OffersExit && !t.isReserved(src)) {
		// A reply to traffic forwarded for the tailnet's peers.
		return src, true
	}
	return netip.Addr{}, false
}

// Inbound translates a packet that stack owner delivered into the unified
// space for the host.
func (t *Translator) Inbound(owner remap.Owner, q *packet.Parsed) Result {
	if !wellFormed(q) {
		return drop("malformed packet")
	}
	st, ok := t.stacks.Load().byOwner[owner]
	if !ok {
		return drop("unknown tailnet")
	}
	src, dst := q.Src.Addr(), q.Dst.Addr()
	vsrc, ok := t.m.RealToVirtual(owner, src)
	if !ok {
		return drop("unmapped source")
	}
	vdst, ok := t.inboundDst(st, dst)
	if !ok {
		return drop("destination not reachable from tailnet")
	}
	if !rewrite(q, src, vsrc, dst, vdst) {
		return drop("address family mismatch")
	}
	return Result{Verdict: ToHost, Owner: owner}
}

// inboundDst returns the host-side destination for a packet from st.
func (t *Translator) inboundDst(st Stack, dst netip.Addr) (netip.Addr, bool) {
	if slices.Contains(st.Self, dst) {
		return t.m.RealToVirtual(st.Owner, dst)
	}
	if _, _, ok := t.m.VirtualToReal(dst); ok {
		// Unified-space address: reaching it would cross tailnets.
		return netip.Addr{}, false
	}
	if containsAddr(st.Advertised, dst) || (st.OffersExit && !t.isReserved(dst)) {
		return dst, true
	}
	return netip.Addr{}, false
}

// wellFormed reports whether q is an IPv4 or IPv6 packet whose addresses
// can be rewritten safely. packet.Decode accepts IPv4 header lengths below
// 20 bytes, which would point the transport checksum offsets used by
// net/packet/checksum into the IP header itself.
func wellFormed(q *packet.Parsed) bool {
	switch q.IPVersion {
	case 4:
		return q.Buffer()[0]&0x0f >= 5
	case 6:
		return true
	}
	return false
}

func (t *Translator) isReserved(a netip.Addr) bool { return containsAddr(t.reserved, a) }

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// rewrite replaces q's addresses and fixes checksums, including the
// embedded packet of ICMP errors. It reports false, leaving q unchanged, if
// a new address is from a different family than the packet.
func rewrite(q *packet.Parsed, oldSrc, newSrc, oldDst, newDst netip.Addr) bool {
	is4 := q.IPVersion == 4
	if newSrc.Is4() != is4 || newDst.Is4() != is4 {
		return false
	}
	if newSrc != oldSrc {
		checksum.UpdateSrcAddr(q, newSrc)
	}
	if newDst != oldDst {
		checksum.UpdateDstAddr(q, newDst)
	}
	if q.IsError() && (newSrc != oldSrc || newDst != oldDst) {
		rewriteICMPError(q, oldSrc, newSrc, oldDst, newDst)
	}
	return true
}
