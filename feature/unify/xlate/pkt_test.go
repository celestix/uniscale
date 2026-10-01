// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// Test packet builders and an independent checksum verifier.

// csum computes a one's complement checksum over the concatenation of
// parts, using 64-bit accumulation (deliberately different code from the
// package's sum16/fold).
func csum(parts ...[]byte) uint16 {
	var buf []byte
	for _, p := range parts {
		buf = append(buf, p...)
	}
	if len(buf)%2 == 1 {
		buf = append(buf, 0)
	}
	var s uint64
	for i := 0; i < len(buf); i += 2 {
		s += uint64(binary.BigEndian.Uint16(buf[i:]))
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

func pseudo(src, dst netip.Addr, proto ipproto.Proto, length int) []byte {
	var b []byte
	b = append(b, src.AsSlice()...)
	b = append(b, dst.AsSlice()...)
	if src.Is4() {
		return append(b, 0, byte(proto), byte(length>>8), byte(length))
	}
	return append(b, byte(length>>24), byte(length>>16), byte(length>>8), byte(length), 0, 0, 0, byte(proto))
}

// l4 builds a transport header plus payload with a zero checksum and
// returns it with the offset of its checksum field.
func l4(proto ipproto.Proto, src, dst netip.AddrPort, payload []byte) ([]byte, int) {
	switch proto {
	case ipproto.TCP:
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:], src.Port())
		binary.BigEndian.PutUint16(h[2:], dst.Port())
		binary.BigEndian.PutUint32(h[4:], 1)
		h[12] = 5 << 4
		h[13] = 0x02 // SYN
		binary.BigEndian.PutUint16(h[14:], 65535)
		return append(h, payload...), 16
	case ipproto.UDP:
		h := make([]byte, 8)
		binary.BigEndian.PutUint16(h[0:], src.Port())
		binary.BigEndian.PutUint16(h[2:], dst.Port())
		binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
		return append(h, payload...), 6
	case ipproto.ICMPv4:
		h := []byte{8, 0, 0, 0, 0, 1, 0, 1} // echo request
		return append(h, payload...), 2
	case ipproto.ICMPv6:
		h := []byte{128, 0, 0, 0, 0, 1, 0, 1} // echo request
		return append(h, payload...), 2
	}
	panic("unsupported proto")
}

// ipWrap prepends an IP header to body and fills in all checksums.
func ipWrap(proto ipproto.Proto, src, dst netip.Addr, body []byte, csumOff int) []byte {
	if csumOff >= 0 {
		binary.BigEndian.PutUint16(body[csumOff:], 0)
		var c uint16
		if proto == ipproto.ICMPv4 {
			c = csum(body)
		} else {
			c = csum(pseudo(src, dst, proto, len(body)), body)
		}
		binary.BigEndian.PutUint16(body[csumOff:], c)
	}
	if src.Is4() {
		h := make([]byte, 20)
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(20+len(body)))
		binary.BigEndian.PutUint16(h[4:], 1)
		h[8] = 64
		h[9] = byte(proto)
		copy(h[12:], src.AsSlice())
		copy(h[16:], dst.AsSlice())
		binary.BigEndian.PutUint16(h[10:], csum(h))
		return append(h, body...)
	}
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(body)))
	h[6] = byte(proto)
	h[7] = 64
	copy(h[8:], src.AsSlice())
	copy(h[24:], dst.AsSlice())
	return append(h, body...)
}

// pkt builds a complete packet with valid checksums.
func pkt(proto ipproto.Proto, src, dst string) []byte {
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	if proto == ipproto.ICMPv4 && !s.Addr().Is4() {
		proto = ipproto.ICMPv6
	}
	body, off := l4(proto, s, d, []byte("hello"))
	return ipWrap(proto, s.Addr(), d.Addr(), body, off)
}

// icmpErr builds an ICMP destination-unreachable error from src to dst
// quoting the start of orig.
func icmpErr(src, dst string, orig []byte) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	if s.Is4() {
		body := append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, orig[:min(len(orig), 28)]...)
		return ipWrap(ipproto.ICMPv4, s, d, body, 2)
	}
	body := append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, orig[:min(len(orig), 48)]...)
	return ipWrap(ipproto.ICMPv6, s, d, body, 2)
}

func parse(b []byte) *packet.Parsed {
	q := new(packet.Parsed)
	q.Decode(b)
	return q
}

// checksumsOK reports whether every checksum in b is valid: the IPv4
// header, the transport (TCP, UDP, ICMP, ICMPv6) of unfragmented packets,
// and the IPv4 header of a packet quoted in an ICMP error.
func checksumsOK(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	var src, dst netip.Addr
	var proto ipproto.Proto
	var body []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl || csum(b[:ihl]) != 0 {
			return false
		}
		total := int(binary.BigEndian.Uint16(b[2:]))
		if total < ihl || total > len(b) {
			return false
		}
		if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
			// A fragment (more-fragments set or nonzero offset): the
			// transport checksum covers the whole datagram, so only the
			// IP header can be checked here.
			return true
		}
		src, _ = netip.AddrFromSlice(b[12:16])
		dst, _ = netip.AddrFromSlice(b[16:20])
		proto, body = ipproto.Proto(b[9]), b[ihl:total]
	case 6:
		if len(b) < 40 {
			return false
		}
		end := 40 + int(binary.BigEndian.Uint16(b[4:]))
		if end > len(b) {
			return false
		}
		src, _ = netip.AddrFromSlice(b[8:24])
		dst, _ = netip.AddrFromSlice(b[24:40])
		proto, body = ipproto.Proto(b[6]), b[40:end]
		if proto == 44 { // fragment header
			if len(body) < 8 || binary.BigEndian.Uint16(body[2:])&0xfff9 != 0 {
				return true // a real fragment: transport checksum not checkable
			}
			proto, body = ipproto.Proto(body[0]), body[8:]
		}
	default:
		return false
	}
	switch proto {
	case ipproto.ICMPv4:
		if csum(body) != 0 {
			return false
		}
		if len(body) >= 28 && body[0] == 3 {
			qihl := int(body[8]&0x0f) * 4
			if qihl >= 20 && len(body) >= 8+qihl && csum(body[8:8+qihl]) != 0 {
				return false // quoted IPv4 header
			}
		}
		return true
	case ipproto.TCP, ipproto.UDP, ipproto.ICMPv6:
		return csum(pseudo(src, dst, proto, len(body)), body) == 0
	}
	return true
}

func addrs(b []byte) (src, dst netip.Addr) {
	q := parse(b)
	return q.Src.Addr(), q.Dst.Addr()
}

// quoted returns the source and destination of the packet quoted in the
// ICMP error b.
func quoted(t *testing.T, b []byte) (src, dst netip.Addr) {
	t.Helper()
	if b[0]>>4 == 4 {
		inner := b[28:]
		src, _ = netip.AddrFromSlice(inner[12:16])
		dst, _ = netip.AddrFromSlice(inner[16:20])
		return src, dst
	}
	inner := b[48:]
	src, _ = netip.AddrFromSlice(inner[8:24])
	dst, _ = netip.AddrFromSlice(inner[24:40])
	return src, dst
}

func TestBuildersProduceValidChecksums(t *testing.T) {
	for _, b := range [][]byte{
		pkt(ipproto.TCP, "1.2.3.4:1", "5.6.7.8:2"),
		pkt(ipproto.UDP, "[fd00::1]:1", "[fd00::2]:2"),
		pkt(ipproto.ICMPv4, "1.2.3.4:0", "5.6.7.8:0"),
		pkt(ipproto.ICMPv4, "[fd00::1]:0", "[fd00::2]:0"),
		icmpErr("5.6.7.8", "1.2.3.4", pkt(ipproto.UDP, "1.2.3.4:1", "5.6.7.8:2")),
		icmpErr("fd00::2", "fd00::1", pkt(ipproto.UDP, "[fd00::1]:1", "[fd00::2]:2")),
	} {
		if !checksumsOK(b) {
			t.Errorf("builder produced bad checksums: % x", b)
		}
	}
}

// withIPv4Options returns b with 4 bytes of NOP options added to its IPv4
// header, keeping every checksum valid.
func withIPv4Options(b []byte) []byte {
	out := append(append(append([]byte{}, b[:20]...), 1, 1, 1, 1), b[20:]...)
	out[0] = 0x46
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], csum(out[:24]))
	return out
}

// withIPv6FragHeader returns b with an atomic IPv6 fragment header (offset
// 0, no more fragments) inserted after the fixed header.
func withIPv6FragHeader(b []byte) []byte {
	frag := []byte{b[6], 0, 0, 0, 0, 0, 0, 7}
	out := append(append(append([]byte{}, b[:40]...), frag...), b[40:]...)
	out[6] = 44
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return out
}
