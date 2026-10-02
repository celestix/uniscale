// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"encoding/binary"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// The host's packets that have no route (xlate.DropNoRoute) are answered
// with an ICMP destination unreachable, so applications fail fast instead
// of timing out. The replies are rate-limited.
const (
	unreachableRate  = 10 // replies per second
	unreachableBurst = 10
)

const (
	ipv6MinMTU         = 1280 // RFC 8200, section 5
	ipv6FragmentHeader = 44   // IPv6 Next Header value of the Fragment header

	// ICMPv4 error types (RFC 792) without a correct constant in
	// net/packet, whose ICMP4ParamProblem is 0x12 (18), not 12.
	icmp4SourceQuench = 4
	icmp4Redirect     = 5
	icmp4ParamProblem = 12

	// ICMPv6 types below this are errors (RFC 4443, section 2.1).
	icmp6FirstInfo = 128
	icmp6Redirect  = 137 // RFC 4861
)

// ipHeader is what unify reads from the IP header of a packet it answers.
type ipHeader struct {
	src, dst netip.Addr
	hdrLen   int  // the IP header, with an IPv6 fragment header
	total    int  // the packet, from the IP header
	later    bool // a fragment other than the first
	proto    ipproto.Proto
}

// parseIPHeader parses the IP header of b, an IPv4 or IPv6 packet, and an
// IPv6 fragment header right after it. It reports false if b is not a
// consistent IP packet.
func parseIPHeader(b []byte) (h ipHeader, ok bool) {
	if len(b) == 0 {
		return h, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return h, false
		}
		h.hdrLen = int(b[0]&0x0f) * 4
		h.total = int(binary.BigEndian.Uint16(b[2:4]))
		h.later = binary.BigEndian.Uint16(b[6:8])&0x1fff != 0
		h.proto = ipproto.Proto(b[9])
		h.src = netip.AddrFrom4([4]byte(b[12:16]))
		h.dst = netip.AddrFrom4([4]byte(b[16:20]))
		return h, h.hdrLen >= 20 && h.hdrLen <= h.total && h.total <= len(b)
	case 6:
		if len(b) < 40 {
			return h, false
		}
		h.hdrLen = 40
		h.total = 40 + int(binary.BigEndian.Uint16(b[4:6]))
		h.proto = ipproto.Proto(b[6])
		h.src = netip.AddrFrom16([16]byte(b[8:24]))
		h.dst = netip.AddrFrom16([16]byte(b[24:40]))
		if h.proto == ipv6FragmentHeader && h.total >= 48 && len(b) >= 48 {
			h.hdrLen = 48
			h.proto = ipproto.Proto(b[40])
			h.later = binary.BigEndian.Uint16(b[42:44])>>3 != 0
		}
		return h, h.proto != ipv6FragmentHeader && h.total <= len(b)
	}
	return h, false
}

// isICMPError reports whether h, the header of b, is that of an ICMP error
// message, or of an ICMP redirect or source quench.
func isICMPError(h ipHeader, b []byte) bool {
	if h.total <= h.hdrLen {
		return false
	}
	t := b[h.hdrLen]
	switch h.proto {
	case ipproto.ICMPv4:
		switch packet.ICMP4Type(t) {
		case packet.ICMP4Unreachable, packet.ICMP4TimeExceeded, icmp4ParamProblem, icmp4SourceQuench, icmp4Redirect:
			return true
		}
	case ipproto.ICMPv6:
		return t < icmp6FirstInfo || t == icmp6Redirect
	}
	return false
}

// isHost reports whether a can be the address of one host: not
// unspecified, multicast, loopback, or (IPv4) broadcast or class E.
func isHost(a netip.Addr) bool {
	return !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !(a.Is4() && a.As4()[0] >= 240)
}

// wantsUnreachable reports whether b, a packet from the host with no
// route, may be answered with an ICMP error. Following RFC 1122 (3.2.2),
// RFC 1812 (4.3.2.7) and RFC 4443 (2.4), it must be a consistent IP packet
// between two hosts, not an ICMP error (nor a redirect), and not a
// fragment other than the first.
func wantsUnreachable(b []byte) bool {
	h, ok := parseIPHeader(b)
	return ok && !h.later && !isICMPError(h, b) && isHost(h.src) && isHost(h.dst)
}

// unreachable returns an ICMP destination unreachable message for b, a
// packet for which [wantsUnreachable] is true, as if its destination sent
// it back: ICMPv4 type 3 code 1 (host unreachable) or ICMPv6 type 1 code 3
// (address unreachable). It quotes b as far as RFC 792 and RFC 4443 say:
// the IPv4 header and 8 bytes of payload, or as much of the IPv6 packet as
// keeps the message within the IPv6 minimum MTU. The message starts after
// headroom zero bytes, the room the host device's Write needs.
func unreachable(b []byte, headroom int) []byte {
	h, _ := parseIPHeader(b)
	if h.src.Is4() {
		quote := b[:min(h.total, h.hdrLen+8)]
		out := make([]byte, headroom+20+8+len(quote))
		p := out[headroom:]
		p[0] = 0x45 // version 4, header length 20
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		p[8] = 64 // TTL
		p[9] = byte(ipproto.ICMPv4)
		copy(p[12:16], h.dst.AsSlice())
		copy(p[16:20], h.src.AsSlice())
		checksum.Put(p[10:12], ^checksum.Checksum(p[:20], 0))
		m := p[20:]
		m[0], m[1] = byte(packet.ICMP4Unreachable), byte(packet.ICMP4HostUnreachable)
		copy(m[8:], quote)
		checksum.Put(m[2:4], ^checksum.Checksum(m, 0))
		return out
	}
	quote := b[:min(h.total, ipv6MinMTU-40-8)]
	out := make([]byte, headroom+40+8+len(quote))
	p := out[headroom:]
	p[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(p[4:6], uint16(8+len(quote)))
	p[6] = byte(ipproto.ICMPv6)
	p[7] = 64 // hop limit
	copy(p[8:24], h.dst.AsSlice())
	copy(p[24:40], h.src.AsSlice())
	m := p[40:]
	m[0], m[1] = byte(packet.ICMP6Unreachable), byte(packet.ICMP6AddressUnreachable)
	copy(m[8:], quote)
	// The pseudo-header: addresses, upper-layer length, next header.
	sum := checksum.Combine(checksum.Checksum(p[8:40], 0), uint16(len(m)))
	sum = checksum.Combine(sum, uint16(ipproto.ICMPv6))
	checksum.Put(m[2:4], ^checksum.Checksum(m, sum))
	return out
}
