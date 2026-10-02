// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package xlate translates packets between this host's unified (virtual)
// address space and each tailnet's real address space, and decides where
// each packet goes.
//
// Translation is stateless and one-to-one: every decision is made from the
// packet's own addresses, the remap table ([Mapper]), and per-tailnet
// [Stack] information. Packets are rewritten in place. Dropped packets are
// left unmodified, with a [DropReason]. ICMP redirects and source quench
// are always dropped: neither side may steer the other's routing.
package xlate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/ipproto"
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
	// Quad100 reports whether the stack serves Tailscale's service address
	// (100.100.100.100, fd7a:115c:a1e0::53) to the host. Unify gives it to
	// the primary tailnet.
	Quad100 bool
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

// DropReason says why a packet was dropped. The zero DropReason is for
// packets that were not dropped.
type DropReason uint8

const (
	_                           DropReason = iota
	DropMalformedPacket                    // not a well-formed IPv4 or IPv6 packet
	DropNoRoute                            // destination in no tailnet, and no exit node for it
	DropUnknownTailnet                     // the tailnet has no stack
	DropSourceNotAllowed                   // outbound source that may not enter the tailnet
	DropFamilyMismatch                     // an address would translate to the other family
	DropUnmappedSource                     // inbound source with no unified-space address
	DropDestinationNotReachable            // inbound destination the tailnet may not reach
	DropMalformedICMPError                 // ICMP error whose quoted packet cannot be parsed
	DropICMPErrorOutsideTailnet            // ICMP error quoting addresses that do not translate within the tailnet
	DropICMPRedirect                       // ICMP redirect or source quench
)

var dropReasonStrings = [...]string{
	DropMalformedPacket:         "malformed packet",
	DropNoRoute:                 "no route",
	DropUnknownTailnet:          "unknown tailnet",
	DropSourceNotAllowed:        "source not allowed for tailnet",
	DropFamilyMismatch:          "address family mismatch",
	DropUnmappedSource:          "unmapped source",
	DropDestinationNotReachable: "destination not reachable from tailnet",
	DropMalformedICMPError:      "malformed ICMP error",
	DropICMPErrorOutsideTailnet: "ICMP error quotes a flow outside the tailnet",
	DropICMPRedirect:            "ICMP redirect or source quench",
}

func (r DropReason) String() string {
	if int(r) < len(dropReasonStrings) {
		return dropReasonStrings[r]
	}
	return fmt.Sprintf("DropReason(%d)", uint8(r))
}

// Result is the outcome of translating one packet.
type Result struct {
	Verdict Verdict
	Owner   remap.Owner // set for ToStack and ToHost
	Reason  DropReason  // set for Drop
}

func drop(r DropReason) Result { return Result{Verdict: Drop, Reason: r} }

type stackSet struct {
	byOwner map[remap.Owner]Stack
	exit    remap.Owner // stack using an exit node, or ""
	quad100 remap.Owner // stack serving quad-100, or ""
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
// node, at most one may serve quad-100, and owners must be unique and
// non-empty.
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
		if st.Quad100 {
			if ss.quad100 != "" {
				return fmt.Errorf("xlate: tailnets %q and %q both serve quad-100", ss.quad100, st.Owner)
			}
			ss.quad100 = st.Owner
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
		return drop(DropMalformedPacket)
	}
	if isRedirect(q) {
		return drop(DropICMPRedirect)
	}
	ss := t.stacks.Load()
	src, dst := q.Src.Addr(), q.Dst.Addr()
	owner, realDst, ok := t.outboundDst(ss, dst)
	if !ok {
		return drop(DropNoRoute)
	}
	st, ok := ss.byOwner[owner]
	if !ok {
		return drop(DropUnknownTailnet)
	}
	var newSrc netip.Addr
	if isQuad100(dst) {
		// The service answers this node only.
		newSrc, ok = t.realSelf(st, src)
	} else {
		newSrc, ok = t.outboundSrc(st, src)
	}
	if !ok {
		return drop(DropSourceNotAllowed)
	}
	p := plan{src: newSrc, dst: realDst}
	if q.IsError() {
		var reason DropReason
		if p.quote, reason = t.outboundQuote(ss, st, q); reason != 0 {
			return drop(reason)
		}
	}
	if !p.apply(q) {
		return drop(DropFamilyMismatch)
	}
	return Result{Verdict: ToStack, Owner: owner}
}

// outboundDst returns the stack a packet from the host to dst goes to, and
// dst in that stack's real space: the owner of dst's mapping, or the stack
// using an exit node for any other address that is not reserved. Quad-100
// is never a peer's address: it goes to the stack serving it, if any,
// whatever mapping covers it.
func (t *Translator) outboundDst(ss *stackSet, dst netip.Addr) (remap.Owner, netip.Addr, bool) {
	if isQuad100(dst) {
		return ss.quad100, dst, ss.quad100 != ""
	}
	if owner, realDst, ok := t.m.VirtualToReal(dst); ok {
		return owner, realDst, true
	}
	if ss.exit == "" || t.isReserved(dst) {
		return "", netip.Addr{}, false
	}
	return ss.exit, dst, true
}

// realSelf returns st's real self address whose unified-space address is
// v.
func (t *Translator) realSelf(st Stack, v netip.Addr) (netip.Addr, bool) {
	for _, self := range st.Self {
		if sv, ok := t.m.RealToVirtual(st.Owner, self); ok && sv == v {
			return self, true
		}
	}
	return netip.Addr{}, false
}

// outboundSrc returns the real source for a packet from the host to st.
func (t *Translator) outboundSrc(st Stack, src netip.Addr) (netip.Addr, bool) {
	if self, ok := t.realSelf(st, src); ok {
		return self, true
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
		return drop(DropMalformedPacket)
	}
	if isRedirect(q) {
		return drop(DropICMPRedirect)
	}
	ss := t.stacks.Load()
	st, ok := ss.byOwner[owner]
	if !ok {
		return drop(DropUnknownTailnet)
	}
	src, dst := q.Src.Addr(), q.Dst.Addr()
	vsrc, ok := t.inboundAddr(ss, owner, src)
	if !ok {
		return drop(DropUnmappedSource)
	}
	vdst, ok := t.inboundDst(st, dst)
	if !ok || (isQuad100(src) && !slices.Contains(st.Self, dst)) {
		// Quad-100 answers this node only.
		return drop(DropDestinationNotReachable)
	}
	p := plan{src: vsrc, dst: vdst}
	if q.IsError() {
		var reason DropReason
		if p.quote, reason = t.inboundQuote(ss, owner, q, dst, vdst); reason != 0 {
			return drop(reason)
		}
	}
	if !p.apply(q) {
		return drop(DropFamilyMismatch)
	}
	return Result{Verdict: ToHost, Owner: owner}
}

// inboundAddr translates a, a remote address in owner's real space, into
// the unified space. Mapped addresses are translated. The stack using an
// exit node may also carry internet addresses (replies from the exit), which
// are kept unchanged; reserved, unified-space and non-internet addresses
// never are, so the exit cannot impersonate a peer of any tailnet or a host
// on this host's networks. Quad-100 is kept, from the stack serving it
// only: no other stack may pose as it, whatever its mappings.
func (t *Translator) inboundAddr(ss *stackSet, owner remap.Owner, a netip.Addr) (netip.Addr, bool) {
	if isQuad100(a) {
		return a, owner == ss.quad100
	}
	if v, ok := t.m.RealToVirtual(owner, a); ok {
		return v, true
	}
	if owner != ss.exit || !t.isInternet(a) {
		return netip.Addr{}, false
	}
	if _, _, ok := t.m.VirtualToReal(a); ok {
		return netip.Addr{}, false
	}
	return a, true
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
// can be rewritten safely. It checks the IP header itself instead of
// trusting q: packet.Decode accepts IPv4 header lengths below 20 bytes
// (which would point the transport checksum offsets used by
// net/packet/checksum into the IP header), and returns before setting the
// addresses of a packet shorter than its IP length, leaving a reused Parsed
// with the previous packet's addresses.
func wellFormed(q *packet.Parsed) bool {
	b := q.Buffer()
	switch q.IPVersion {
	case 4:
		if len(b) < 20 {
			return false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		return ihl >= 20 && ihl <= total && total <= len(b) &&
			q.Src.Addr() == netip.AddrFrom4([4]byte(b[12:16])) &&
			q.Dst.Addr() == netip.AddrFrom4([4]byte(b[16:20]))
	case 6:
		return len(b) >= 40 && 40+int(binary.BigEndian.Uint16(b[4:6])) <= len(b) &&
			q.Src.Addr() == netip.AddrFrom16([16]byte(b[8:24])) &&
			q.Dst.Addr() == netip.AddrFrom16([16]byte(b[24:40]))
	}
	return false
}

func (t *Translator) isReserved(a netip.Addr) bool { return containsAddr(t.reserved, a) }

var (
	quad100v4 = tsaddr.TailscaleServiceIP()
	quad100v6 = tsaddr.TailscaleServiceIPv6()
)

// isQuad100 reports whether a is Tailscale's service address.
func isQuad100(a netip.Addr) bool { return a == quad100v4 || a == quad100v6 }

// isInternet reports whether a may be carried unchanged through an exit
// node this host uses: a global unicast address that is neither private
// (RFC 1918, ULA) nor reserved. IPv4-mapped IPv6 addresses are refused,
// as they would escape the IPv4 reserved ranges.
func (t *Translator) isInternet(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.Is4In6() && !t.isReserved(a)
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// plan is every address change for one packet. It is decided in full
// before anything is written, so a dropped packet is never modified.
type plan struct {
	src, dst netip.Addr // new outer addresses
	quote    quoteEdit  // for ICMP errors: the quoted packet's new addresses
}

// apply writes p into q and fixes checksums. It reports false, leaving q
// unchanged, if a new address is from a different family than the packet.
func (p plan) apply(q *packet.Parsed) bool {
	is4 := q.IPVersion == 4
	ok := p.src.Is4() == is4 && p.dst.Is4() == is4
	if p.quote.valid() {
		ok = ok && p.quote.src.Is4() == is4 && p.quote.dst.Is4() == is4
	}
	if !ok {
		return false
	}
	noSum := udpNoChecksum(q)
	if p.src != q.Src.Addr() {
		checksum.UpdateSrcAddr(q, p.src)
	}
	if p.dst != q.Dst.Addr() {
		checksum.UpdateDstAddr(q, p.dst)
	}
	if noSum != nil {
		// net/packet/checksum updates a zero checksum like any other.
		noSum[0], noSum[1] = 0, 0
	}
	if p.quote.valid() {
		p.quote.apply(q) // after the outer addresses: ICMPv6 checksums cover them
	}
	return true
}

// udpNoChecksum returns the checksum field of q's UDP header if q is an
// IPv4 UDP packet or first fragment sent without a checksum (a checksum of
// 0, RFC 768), or nil. An IPv6 UDP checksum of 0 is invalid (RFC 8200) and
// is not special.
func udpNoChecksum(q *packet.Parsed) []byte {
	if q.IPVersion != 4 || q.IPProto != ipproto.UDP {
		return nil
	}
	t := q.Transport()
	if len(t) < 8 || t[6] != 0 || t[7] != 0 {
		return nil
	}
	return t[6:8]
}
