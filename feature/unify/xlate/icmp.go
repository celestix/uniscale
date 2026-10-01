// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"encoding/binary"
	"net/netip"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/packet"
)

// errQuote is the drop reason for an ICMP error whose quoted packet does
// not belong to the tailnet the error travels through.
const errQuote = "ICMP error quotes a flow outside the tailnet"

// quote is the start of the packet quoted in an ICMP error. That packet
// travelled in the opposite direction to the error.
type quote struct {
	msg      []byte // the ICMP message, bounded by the IP length
	hdr      []byte // the quoted IP header, inside msg
	src, dst netip.Addr
}

// parseQuote returns the packet quoted in the ICMP error q, an IPv4 or
// IPv6 packet. It reports false if the ICMP message or the quoted IP header
// is truncated, or the quoted packet is not of q's family.
func parseQuote(q *packet.Parsed) (quote, bool) {
	msg := transport(q)
	if len(msg) < 8 {
		return quote{}, false
	}
	inner := msg[8:]
	if q.IPVersion == 4 {
		if len(inner) < 20 || inner[0]>>4 != 4 {
			return quote{}, false
		}
		ihl := int(inner[0]&0x0f) * 4
		if ihl < 20 || len(inner) < ihl {
			return quote{}, false
		}
		return quote{
			msg: msg, hdr: inner[:ihl],
			src: netip.AddrFrom4([4]byte(inner[12:16])),
			dst: netip.AddrFrom4([4]byte(inner[16:20])),
		}, true
	}
	if len(inner) < 40 || inner[0]>>4 != 6 {
		return quote{}, false
	}
	return quote{
		msg: msg, hdr: inner[:40],
		src: netip.AddrFrom16([16]byte(inner[8:24])),
		dst: netip.AddrFrom16([16]byte(inner[24:40])),
	}, true
}

// quoteEdit is the new addresses of a quoted packet.
type quoteEdit struct {
	q        quote
	src, dst netip.Addr
}

func (e quoteEdit) valid() bool { return e.q.msg != nil }

// apply writes e's addresses into the quoted header and recomputes the
// quoted IPv4 header checksum and the ICMP checksum. The outer addresses
// must already be final, as the ICMPv6 checksum covers them. The quoted
// transport checksum is not updated: receivers match errors on addresses
// and ports only.
func (e quoteEdit) apply(q *packet.Parsed) {
	if e.src == e.q.src && e.dst == e.q.dst {
		return
	}
	msg, hdr := e.q.msg, e.q.hdr
	msg[2], msg[3] = 0, 0
	switch q.IPVersion {
	case 4:
		copy(hdr[12:16], e.src.AsSlice())
		copy(hdr[16:20], e.dst.AsSlice())
		hdr[10], hdr[11] = 0, 0
		binary.BigEndian.PutUint16(hdr[10:12], fold(sum16(0, hdr)))
		binary.BigEndian.PutUint16(msg[2:4], fold(sum16(0, msg)))
	case 6:
		copy(hdr[8:24], e.src.AsSlice())
		copy(hdr[24:40], e.dst.AsSlice())
		s := sum16(0, q.Buffer()[8:40]) // outer source and destination
		s += uint32(len(msg)) + 58
		binary.BigEndian.PutUint16(msg[2:4], fold(sum16(s, msg)))
	}
}

// inboundQuote decides the quoted addresses of an ICMP error that stack
// owner delivered, with outer destination dst (vdst once translated). The
// quoted packet is one sent into owner, so it is in owner's real space,
// and the error returns to its sender. Each quoted address is translated
// on its own, so errors from any hop on the path work (PMTUD, traceroute).
// It returns a drop reason if a quoted address cannot be translated within
// owner's tailnet.
func (t *Translator) inboundQuote(ss *stackSet, owner remap.Owner, q *packet.Parsed, dst, vdst netip.Addr) (quoteEdit, string) {
	qt, ok := parseQuote(q)
	if !ok {
		return quoteEdit{}, "malformed ICMP error"
	}
	if qt.src != dst {
		return quoteEdit{}, errQuote
	}
	qdst, ok := t.inboundAddr(ss, owner, qt.dst)
	if !ok {
		return quoteEdit{}, errQuote
	}
	return quoteEdit{q: qt, src: vdst, dst: qdst}, ""
}

// outboundQuote decides the quoted addresses of an ICMP error the host
// sends to stack st, with outer source src (newSrc once translated). The
// quoted packet came from st's tailnet, so its source must translate
// within that tailnet. Its destination becomes newSrc when it is src and
// is otherwise kept, as for errors from routers on paths this node
// forwards. It returns a drop reason if the error must be dropped.
func (t *Translator) outboundQuote(ss *stackSet, st Stack, q *packet.Parsed, src, newSrc netip.Addr) (quoteEdit, string) {
	qt, ok := parseQuote(q)
	if !ok {
		return quoteEdit{}, "malformed ICMP error"
	}
	qsrc, ok := t.outboundQuotedSrc(ss, st, qt.src)
	if !ok {
		return quoteEdit{}, errQuote
	}
	qdst := qt.dst
	if qdst == src {
		qdst = newSrc
	}
	return quoteEdit{q: qt, src: qsrc, dst: qdst}, ""
}

// outboundQuotedSrc translates s, the source of the packet quoted in an
// outbound ICMP error to st, into st's real space. A unified-space address
// must belong to st's tailnet. An unmapped address is kept if st is the
// stack using an exit node, or under the source rules for traffic this node
// forwards for st (advertised subnets, exit node offered), and is never a
// reserved address.
func (t *Translator) outboundQuotedSrc(ss *stackSet, st Stack, s netip.Addr) (netip.Addr, bool) {
	if owner, r, ok := t.m.VirtualToReal(s); ok {
		if owner != st.Owner {
			return netip.Addr{}, false
		}
		return r, true
	}
	if t.isReserved(s) {
		return netip.Addr{}, false
	}
	if st.Owner == ss.exit || st.OffersExit || containsAddr(st.Advertised, s) {
		return s, true
	}
	return netip.Addr{}, false
}

// transport returns q's transport header and payload, bounded by the
// packet length in the IP header, or nil if the header is inconsistent.
func transport(q *packet.Parsed) []byte {
	b := q.Buffer()
	t := q.Transport()
	start := len(b) - len(t)
	var end int
	switch q.IPVersion {
	case 4:
		end = int(binary.BigEndian.Uint16(b[2:4]))
	case 6:
		end = 40 + int(binary.BigEndian.Uint16(b[4:6]))
	}
	if end > len(b) || end < start {
		return nil
	}
	return b[start:end]
}

// sum16 adds b, as big-endian 16-bit words, to the running one's
// complement sum s.
func sum16(s uint32, b []byte) uint32 {
	for len(b) >= 2 {
		s += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}

// fold finishes a one's complement checksum.
func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
