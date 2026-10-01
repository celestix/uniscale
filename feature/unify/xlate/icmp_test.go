// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/types/ipproto"
)

func TestICMPErrors(t *testing.T) {
	tr := scenario(t)
	t.Run("outbound ipv4: host reports port unreachable to friends peer", func(t *testing.T) {
		orig := pkt(ipproto.UDP, "198.18.0.1:5000", "100.99.0.1:53") // what the host received
		b := icmpErr("100.99.0.1", "198.18.0.1", orig)
		r := tr.Outbound(parse(b))
		if r.Verdict != ToStack || r.Owner != "friends" {
			t.Fatalf("Outbound = %+v", r)
		}
		if s, d := quoted(t, b); s != mpa("100.88.1.4") || d != mpa("100.99.0.1") {
			t.Fatalf("quoted = %v -> %v, want 100.88.1.4 -> 100.99.0.1", s, d)
		}
		if !checksumsOK(b) {
			t.Fatal("bad checksums")
		}
	})
	t.Run("inbound ipv4: friends peer reports unreachable", func(t *testing.T) {
		orig := pkt(ipproto.UDP, "100.99.0.1:5000", "100.88.1.4:53") // what the peer received
		b := icmpErr("100.88.1.4", "100.99.0.1", orig)
		r := tr.Inbound("friends", parse(b))
		if r.Verdict != ToHost {
			t.Fatalf("Inbound = %+v", r)
		}
		if s, d := quoted(t, b); s != mpa("100.99.0.1") || d != mpa("198.18.0.1") {
			t.Fatalf("quoted = %v -> %v, want 100.99.0.1 -> 198.18.0.1", s, d)
		}
		if !checksumsOK(b) {
			t.Fatal("bad checksums")
		}
	})
	t.Run("inbound ipv6: personal peer to remapped self", func(t *testing.T) {
		// Use a v6 scenario: work's v6 peer and self are identity, so build
		// one with friends' remapped v6 peer using a dedicated translator.
		tb, _ := remap.New(remap.Config{Pool6: mpp("fd00:1::/48")}, nil)
		now := time.Now()
		tb.Sync("a", []netip.Prefix{mpp("fd7a:115c:a1e0::1/128"), mpp("fd7a:115c:a1e0::2/128")}, now)
		tb.Sync("b", []netip.Prefix{mpp("fd7a:115c:a1e0::3/128"), mpp("fd7a:115c:a1e0::2/128")}, now)
		tr := New(tb, reserved)
		tr.SetStacks([]Stack{{Owner: "a", Self: []netip.Addr{mpa("fd7a:115c:a1e0::1")}},
			{Owner: "b", Self: []netip.Addr{mpa("fd7a:115c:a1e0::3")}}})
		orig := pkt(ipproto.UDP, "[fd7a:115c:a1e0::3]:5000", "[fd7a:115c:a1e0::2]:53")
		b := icmpErr("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::3", orig)
		r := tr.Inbound("b", parse(b))
		if r.Verdict != ToHost {
			t.Fatalf("Inbound = %+v", r)
		}
		if s, _ := addrs(b); s != mpa("fd00:1::") {
			t.Fatalf("outer src = %v, want fd00:1::", s)
		}
		if s, d := quoted(t, b); s != mpa("fd7a:115c:a1e0::3") || d != mpa("fd00:1::") {
			t.Fatalf("quoted = %v -> %v", s, d)
		}
		if !checksumsOK(b) {
			t.Fatal("bad checksums")
		}
	})
}

func TestMalformedICMPErrors(t *testing.T) {
	tr := scenario(t)
	orig := pkt(ipproto.UDP, "198.18.0.1:5000", "100.99.0.1:53")
	cases := map[string]func([]byte) []byte{
		"quote too short": func(b []byte) []byte { return icmpErr("100.99.0.1", "198.18.0.1", orig[:10]) },
		"quote not ipv4":  func(b []byte) []byte { b[28] = 0x65; return b },
		"quote bad ihl":   func(b []byte) []byte { b[28] = 0x41; return b },
		"quote ihl past end": func(b []byte) []byte {
			b[28] = 0x4f
			return b
		},
		"ip length past buffer": func(b []byte) []byte { b[3] = 0xff; return b },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			b := mangle(icmpErr("100.99.0.1", "198.18.0.1", orig))
			r := tr.Outbound(parse(b)) // must not panic
			_ = r
		})
	}
	t.Run("ipv6 quote not ipv6", func(t *testing.T) {
		tb, _ := remap.New(remap.Config{Pool6: mpp("fd00:1::/48")}, nil)
		tb.Sync("a", []netip.Prefix{mpp("fd7a:115c:a1e0::1/128"), mpp("fd7a:115c:a1e0::2/128")}, time.Now())
		tr := New(tb, reserved)
		tr.SetStacks([]Stack{{Owner: "a", Self: []netip.Addr{mpa("fd7a:115c:a1e0::1")}}})
		orig := pkt(ipproto.UDP, "[fd7a:115c:a1e0::1]:5000", "[fd7a:115c:a1e0::2]:53")
		b := icmpErr("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::1", orig)
		b[48] = 0x40
		tr.Inbound("a", parse(b)) // must not panic
	})
}

// Review focus: the packet quoted in an ICMP error may itself carry IPv4
// options.
func TestICMPErrorQuotingOptions(t *testing.T) {
	tr := scenario(t)
	b := icmpErr("100.99.0.1", "198.18.0.1", withIPv4Options(pkt(ipproto.UDP, "198.18.0.1:5000", "100.99.0.1:53")))
	if r := tr.Outbound(parse(b)); r.Verdict != ToStack || r.Owner != "friends" {
		t.Fatalf("Outbound = %+v", r)
	}
	if s, d := quoted(t, b); s != mpa("100.88.1.4") || d != mpa("100.99.0.1") {
		t.Fatalf("quoted = %v -> %v, want 100.88.1.4 -> 100.99.0.1", s, d)
	}
	if !checksumsOK(b) {
		t.Fatal("bad checksums")
	}
}

func TestSum16OddLength(t *testing.T) {
	if got := fold(sum16(0, []byte{0x01, 0x02, 0x03})); got != ^uint16(0x0102+0x0300) {
		t.Fatalf("checksum of odd-length input = %#x", got)
	}
}
