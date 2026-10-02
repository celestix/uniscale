// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// Test packet builders and an independent checksum verifier.

// udpPkt returns a UDP packet from src to dst ("ip:port") with valid
// checksums.
func udpPkt(src, dst string, payload []byte) []byte {
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	if s.Addr().Is4() {
		return packet.Generate(packet.UDP4Header{
			IP4Header: packet.IP4Header{Src: s.Addr(), Dst: d.Addr()},
			SrcPort:   s.Port(), DstPort: d.Port(),
		}, payload)
	}
	return packet.Generate(packet.UDP6Header{
		IP6Header: packet.IP6Header{Src: s.Addr(), Dst: d.Addr()},
		SrcPort:   s.Port(), DstPort: d.Port(),
	}, payload)
}

// icmpPkt returns an ICMP message of type typ and code from src to dst,
// with rest as everything after the ICMP checksum, and valid checksums.
func icmpPkt(src, dst string, typ, code uint8, rest []byte) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	if s.Is4() {
		return packet.Generate(packet.ICMP4Header{
			IP4Header: packet.IP4Header{Src: s, Dst: d},
			Type:      packet.ICMP4Type(typ), Code: packet.ICMP4Code(code),
		}, rest)
	}
	return packet.Generate(packet.ICMP6Header{
		IP6Header: packet.IP6Header{Src: s, Dst: d},
		Type:      packet.ICMP6Type(typ), Code: packet.ICMP6Code(code),
	}, rest)
}

// onesSum is the one's complement sum of the concatenated parts, with
// 64-bit accumulation (deliberately different code from gVisor's).
func onesSum(parts ...[]byte) uint16 {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	var s uint64
	for i := 0; i < len(b); i += 2 {
		s += uint64(binary.BigEndian.Uint16(b[i:]))
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return uint16(s)
}

// checksumsOK reports whether the IPv4 header checksum and the TCP, UDP or
// ICMP checksum of b are valid. b must not be fragmented.
func checksumsOK(t *testing.T, b []byte) bool {
	t.Helper()
	var q packet.Parsed
	q.Decode(b)
	var hdr, pseudo []byte
	switch q.IPVersion {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if onesSum(b[:ihl]) != 0xffff {
			return false
		}
		hdr, b = b[:ihl], b[ihl:total]
		pseudo = append(append(append([]byte{}, hdr[12:20]...), 0, hdr[9]), byte(len(b)>>8), byte(len(b)))
	case 6:
		total := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		hdr, b = b[:40], b[40:total]
		pseudo = append(append([]byte{}, hdr[8:40]...), byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b)), 0, 0, 0, hdr[6])
	default:
		t.Fatalf("not an IP packet: % x", b)
	}
	switch q.IPProto {
	case ipproto.ICMPv4:
		return onesSum(b) == 0xffff
	case ipproto.ICMPv6, ipproto.TCP, ipproto.UDP:
		return onesSum(pseudo, b) == 0xffff
	}
	t.Fatalf("unexpected protocol %v", q.IPProto)
	return false
}

// withIPv4Options returns b, an IPv4 packet, with n bytes of NOP options.
func withIPv4Options(b []byte, n int) []byte {
	out := append(append(bytes.Clone(b[:20]), bytes.Repeat([]byte{1}, n)...), b[20:]...)
	out[0] = 0x40 | byte((20+n)/4)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	fixIPv4Checksum(out)
	return out
}

func fixIPv4Checksum(b []byte) {
	ihl := int(b[0]&0x0f) * 4
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], ^onesSum(b[:ihl]))
}

// asFragment marks b, an IPv4 packet, as a fragment at offset (in 8-byte
// units), with more fragments to follow.
func asFragment(b []byte, offset uint16) []byte {
	b = bytes.Clone(b)
	binary.BigEndian.PutUint16(b[6:8], 0x2000|offset)
	fixIPv4Checksum(b)
	return b
}

// asFragment6 inserts an IPv6 fragment header at offset (in 8-byte units)
// into b, an IPv6 packet.
func asFragment6(b []byte, offset uint16) []byte {
	frag := make([]byte, 8)
	frag[0] = b[6] // next header
	binary.BigEndian.PutUint16(frag[2:4], offset<<3|1)
	binary.BigEndian.PutUint32(frag[4:8], 0xdecaf)
	out := append(append(bytes.Clone(b[:40]), frag...), b[40:]...)
	out[6] = 44
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	return out
}

func TestUnreachable(t *testing.T) {
	const headroom = 64
	big6 := udpPkt("[fd7a:115c:a1e0::2]:5000", "[fd7a:115c:a1e0::99]:53", bytes.Repeat([]byte{0xab}, 1400))
	small4 := udpPkt("100.64.0.2:5000", "100.64.9.9:53", []byte("hello"))
	for _, c := range []struct {
		name      string
		pkt       []byte
		wantQuote []byte // the part of pkt the error must quote
	}{
		{"ipv4 udp", small4, small4[:28]}, // RFC 792: header and 8 bytes
		{"ipv4 tcp-sized payload", udpPkt("100.64.0.2:5000", "100.64.9.9:443", bytes.Repeat([]byte{7}, 1000)),
			udpPkt("100.64.0.2:5000", "100.64.9.9:443", bytes.Repeat([]byte{7}, 1000))[:28]},
		{"ipv4 with options", withIPv4Options(small4, 8), withIPv4Options(small4, 8)[:36]},
		{"ipv4 shorter than header and 8 bytes", icmpPkt("100.64.0.2", "100.64.9.9", 8, 0, nil),
			icmpPkt("100.64.0.2", "100.64.9.9", 8, 0, nil)},
		{"ipv4 trailing bytes", append(bytes.Clone(small4[:24]), 0xee, 0xee), nil}, // fixed up below
		{"ipv6 small", udpPkt("[fd7a:115c:a1e0::2]:5000", "[fd7a:115c:a1e0::99]:53", []byte("hi")),
			udpPkt("[fd7a:115c:a1e0::2]:5000", "[fd7a:115c:a1e0::99]:53", []byte("hi"))},
		{"ipv6 large", big6, big6[:1280-48]}, // RFC 4443: at most the minimum MTU
		{"ipv6 trailing bytes", append(udpPkt("[fd7a:115c:a1e0::2]:5000", "[fd7a:115c:a1e0::99]:53", []byte("hi")), 0xee),
			udpPkt("[fd7a:115c:a1e0::2]:5000", "[fd7a:115c:a1e0::99]:53", []byte("hi"))},
		{"ipv6 first fragment", asFragment6(big6, 0), asFragment6(big6, 0)[:1280-48]},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkt := c.pkt
			if c.wantQuote == nil {
				// An IPv4 packet whose IP length (24) ends before the buffer.
				binary.BigEndian.PutUint16(pkt[2:4], 24)
				fixIPv4Checksum(pkt)
				c.wantQuote = pkt[:24]
			}
			orig := bytes.Clone(pkt)
			if !wantsUnreachable(pkt) {
				t.Fatal("wantsUnreachable = false")
			}
			out := unreachable(pkt, headroom)
			if !bytes.Equal(pkt, orig) {
				t.Fatal("unreachable modified the original packet")
			}
			if !bytes.Equal(out[:headroom], make([]byte, headroom)) {
				t.Fatal("headroom is not zero")
			}
			b := out[headroom:]
			var q, oq packet.Parsed
			q.Decode(b)
			oq.Decode(orig)
			if q.Src.Addr() != oq.Dst.Addr() || q.Dst.Addr() != oq.Src.Addr() {
				t.Fatalf("addresses %v -> %v, want %v -> %v", q.Src.Addr(), q.Dst.Addr(), oq.Dst.Addr(), oq.Src.Addr())
			}
			if !q.IsError() {
				t.Fatalf("not an ICMP error: % x", b)
			}
			var hl int
			if q.IPVersion == 4 {
				hl = 20
				if q.IPProto != ipproto.ICMPv4 || b[hl] != 3 || b[hl+1] != 1 {
					t.Fatalf("ICMPv4 type/code = %d/%d, want 3/1 (host unreachable)", b[hl], b[hl+1])
				}
				if got := int(binary.BigEndian.Uint16(b[2:4])); got != len(b) {
					t.Fatalf("IPv4 total length %d, buffer %d", got, len(b))
				}
				if b[8] == 0 {
					t.Fatal("TTL 0")
				}
			} else {
				hl = 40
				if q.IPProto != ipproto.ICMPv6 || b[hl] != 1 || b[hl+1] != 3 {
					t.Fatalf("ICMPv6 type/code = %d/%d, want 1/3 (address unreachable)", b[hl], b[hl+1])
				}
				if got := 40 + int(binary.BigEndian.Uint16(b[4:6])); got != len(b) {
					t.Fatalf("IPv6 length %d, buffer %d", got, len(b))
				}
				if len(b) > 1280 {
					t.Fatalf("ICMPv6 error of %d bytes, more than the minimum MTU", len(b))
				}
				if b[7] == 0 {
					t.Fatal("hop limit 0")
				}
			}
			if !bytes.Equal(b[hl+4:hl+8], []byte{0, 0, 0, 0}) {
				t.Fatalf("unused field = % x", b[hl+4:hl+8])
			}
			if !bytes.Equal(b[hl+8:], c.wantQuote) {
				t.Fatalf("quote (%d bytes) = % x\nwant (%d bytes) % x", len(b[hl+8:]), b[hl+8:], len(c.wantQuote), c.wantQuote)
			}
			if !checksumsOK(t, b) {
				t.Fatalf("bad checksums: % x", b)
			}
		})
	}
}

func TestWantsUnreachable(t *testing.T) {
	udp4 := udpPkt("100.64.0.2:5000", "100.64.9.9:53", []byte("hello"))
	udp6 := udpPkt("[fd7a:115c:a1e0::2]:5000", "[fd7a:115c:a1e0::99]:53", []byte("hello"))
	quoted4 := udpPkt("100.64.9.9:53", "100.64.0.2:5000", nil)
	quoted6 := udpPkt("[fd7a:115c:a1e0::99]:53", "[fd7a:115c:a1e0::2]:5000", nil)
	icmp4 := func(typ, code uint8) []byte {
		return icmpPkt("100.64.0.2", "100.64.9.9", typ, code, append(make([]byte, 4), quoted4...))
	}
	icmp6 := func(typ, code uint8) []byte {
		return icmpPkt("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::99", typ, code, append(make([]byte, 4), quoted6...))
	}
	trunc := func(b []byte, n int) []byte { return bytes.Clone(b[:n]) }
	set := func(b []byte, f func(b []byte)) []byte {
		b = bytes.Clone(b)
		f(b)
		if b[0]>>4 == 4 && len(b) >= 20 && b[0]&0x0f >= 5 && int(b[0]&0x0f)*4 <= len(b) {
			fixIPv4Checksum(b)
		}
		return b
	}
	for _, c := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"ipv4 udp", udp4, true},
		{"ipv6 udp", udp6, true},
		{"ipv4 echo request", icmp4(8, 0), true},
		{"ipv4 echo reply", icmp4(0, 0), true},
		{"ipv6 echo request", icmp6(128, 0), true},
		{"ipv6 neighbor solicitation to unicast", icmp6(135, 0), true},
		// Never answer an ICMP error (RFC 1122 3.2.2, RFC 4443 2.4(e)).
		{"ipv4 destination unreachable", icmp4(3, 1), false},
		{"ipv4 source quench", icmp4(4, 0), false},
		{"ipv4 redirect", icmp4(5, 1), false},
		{"ipv4 time exceeded", icmp4(11, 0), false},
		{"ipv4 parameter problem", icmp4(12, 0), false},
		{"ipv6 destination unreachable", icmp6(1, 3), false},
		{"ipv6 packet too big", icmp6(2, 0), false},
		{"ipv6 time exceeded", icmp6(3, 0), false},
		{"ipv6 parameter problem", icmp6(4, 0), false},
		{"ipv6 unassigned error type", icmp6(127, 0), false},
		{"ipv6 redirect", icmp6(137, 0), false},
		{"ipv4 icmp without a type", set(udp4, func(b []byte) { b[9] = 1; binary.BigEndian.PutUint16(b[2:4], 20) }), true},
		// Only packets between two hosts.
		{"ipv4 multicast destination", udpPkt("100.64.0.2:5000", "224.0.0.251:5353", nil), false},
		{"ipv4 broadcast destination", udpPkt("100.64.0.2:5000", "255.255.255.255:67", nil), false},
		{"ipv4 unspecified destination", udpPkt("100.64.0.2:5000", "0.0.0.0:67", nil), false},
		{"ipv4 loopback destination", udpPkt("100.64.0.2:5000", "127.0.0.1:53", nil), false},
		{"ipv4 class E destination", udpPkt("100.64.0.2:5000", "240.0.0.1:53", nil), false},
		{"ipv6 multicast destination", udpPkt("[fd7a:115c:a1e0::2]:5000", "[ff02::fb]:5353", nil), false},
		{"ipv6 unspecified destination", udpPkt("[fd7a:115c:a1e0::2]:5000", "[::]:53", nil), false},
		{"ipv6 loopback destination", udpPkt("[fd7a:115c:a1e0::2]:5000", "[::1]:53", nil), false},
		{"ipv4 unspecified source", udpPkt("0.0.0.0:68", "100.64.9.9:67", nil), false},
		{"ipv4 multicast source", udpPkt("224.1.1.1:5000", "100.64.9.9:53", nil), false},
		{"ipv4 broadcast source", udpPkt("255.255.255.255:5000", "100.64.9.9:53", nil), false},
		{"ipv4 loopback source", udpPkt("127.0.0.1:5000", "100.64.9.9:53", nil), false},
		{"ipv6 unspecified source", udpPkt("[::]:5000", "[fd7a:115c:a1e0::99]:53", nil), false},
		{"ipv6 multicast source", udpPkt("[ff02::1]:5000", "[fd7a:115c:a1e0::99]:53", nil), false},
		{"ipv6 loopback source", udpPkt("[::1]:5000", "[fd7a:115c:a1e0::99]:53", nil), false},
		{"ipv4 link-local source", udpPkt("169.254.1.1:5000", "100.64.9.9:53", nil), true},
		// Only the first fragment (RFC 1812 4.3.2.7).
		{"ipv4 first fragment", asFragment(udp4, 0), true},
		{"ipv4 later fragment", asFragment(udp4, 185), false},
		{"ipv4 later fragment at a small offset", asFragment(udp4, 1), false},
		{"ipv6 first fragment", asFragment6(udp6, 0), true},
		{"ipv6 later fragment", asFragment6(udp6, 185), false},
		{"ipv6 fragment header cut off", trunc(asFragment6(udp6, 0), 44), false},
		{"ipv6 fragment header past the IP length", set(asFragment6(udp6, 0), func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 4) }), false},
		// Malformed.
		{"empty", nil, false},
		{"not ip", []byte{0x10, 0, 0, 0}, false},
		{"ipv4 short", trunc(udp4, 19), false},
		{"ipv4 header length below 20", set(udp4, func(b []byte) { b[0] = 0x44 }), false},
		{"ipv4 header longer than the packet", set(udp4, func(b []byte) { b[0] = 0x4f; binary.BigEndian.PutUint16(b[2:4], 40) }), false},
		{"ipv4 length beyond the buffer", set(udp4, func(b []byte) { binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+1)) }), false},
		{"ipv4 truncated", trunc(udp4, 30), false},
		{"ipv6 short", trunc(udp6, 39), false},
		{"ipv6 length beyond the buffer", set(udp6, func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 1000) }), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			orig := bytes.Clone(c.pkt)
			if got := wantsUnreachable(c.pkt); got != c.want {
				t.Fatalf("wantsUnreachable = %v, want %v", got, c.want)
			}
			if !bytes.Equal(c.pkt, orig) {
				t.Fatal("packet modified")
			}
		})
	}
}
