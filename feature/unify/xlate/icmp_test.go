// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"encoding/binary"
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

// An ICMP error whose quoted packet cannot be parsed cannot be checked
// against the tailnet, so it is dropped unmodified.
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
		"icmp header past ip length": func(b []byte) []byte {
			// The buffer holds the full error, but the IP length ends
			// 4 bytes into the ICMP header.
			binary.BigEndian.PutUint16(b[2:], 24)
			b[10], b[11] = 0, 0
			binary.BigEndian.PutUint16(b[10:], csum(b[:20]))
			return b
		},
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			b := mangle(icmpErr("100.99.0.1", "198.18.0.1", orig))
			before := string(b)
			if r := tr.Outbound(parse(b)); r.Verdict != Drop || r.Reason != DropMalformedICMPError {
				t.Fatalf("Outbound = %+v, want drop: malformed ICMP error", r)
			}
			if string(b) != before {
				t.Fatal("dropped packet was modified")
			}
		})
	}
	t.Run("ip length past buffer", func(t *testing.T) {
		b := icmpErr("100.99.0.1", "198.18.0.1", orig)
		b[3] = 0xff
		before := string(b)
		if r := tr.Outbound(parse(b)); r.Verdict != Drop || r.Reason != DropMalformedPacket {
			t.Fatalf("Outbound = %+v, want drop: malformed packet", r)
		}
		if string(b) != before {
			t.Fatal("dropped packet was modified")
		}
	})
	t.Run("ipv6 fragment header past ip length", func(t *testing.T) {
		// An atomic fragment header whose IP payload length ends inside
		// it, with the rest of the error still in the buffer.
		b := withIPv6FragHeader(icmpErr("fd7a:115c:a1e0::77", "fd00:1::", pkt(ipproto.UDP, "[fd00:1::]:5000", "[fd7a:115c:a1e0::77]:53")))
		binary.BigEndian.PutUint16(b[4:], 4)
		before := string(b)
		if r := tr.Outbound(parse(b)); r.Verdict != Drop || r.Reason != DropMalformedICMPError {
			t.Fatalf("Outbound = %+v, want drop: malformed ICMP error", r)
		}
		if string(b) != before {
			t.Fatal("dropped packet was modified")
		}
	})
	t.Run("ipv6 quote not ipv6", func(t *testing.T) {
		tb, _ := remap.New(remap.Config{Pool6: mpp("fd00:1::/48")}, nil)
		tb.Sync("a", []netip.Prefix{mpp("fd7a:115c:a1e0::1/128"), mpp("fd7a:115c:a1e0::2/128")}, time.Now())
		tr := New(tb, reserved)
		tr.SetStacks([]Stack{{Owner: "a", Self: []netip.Addr{mpa("fd7a:115c:a1e0::1")}}})
		orig := pkt(ipproto.UDP, "[fd7a:115c:a1e0::1]:5000", "[fd7a:115c:a1e0::2]:53")
		b := icmpErr("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::1", orig)
		b[48] = 0x40
		before := string(b)
		if r := tr.Inbound("a", parse(b)); r.Verdict != Drop || r.Reason != DropMalformedICMPError {
			t.Fatalf("Inbound = %+v, want drop: malformed ICMP error", r)
		}
		if string(b) != before {
			t.Fatal("dropped packet was modified")
		}
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

// v6scenario is a translator for IPv6 ICMP error tests. Sync order is a,
// then b.
//
//	a: self fd7a:115c:a1e0::1, peers fd7a:115c:a1e0::2, fd7a:115c:a1e0::3,
//	   routed subnet fd10::/64 (all identity)
//	b: self fd7a:115c:a1e0::3 -> fd00:1::
//	   peer fd7a:115c:a1e0::2 -> fd00:1::1
//	   routed subnet fd10::/64 -> fd00:1:0:1::/64
func v6scenario(t *testing.T) *Translator {
	t.Helper()
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tb, err := remap.New(remap.Config{Pool6: mpp("fd00:1::/48"), Now: func() time.Time { return now }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		owner               remap.Owner
		self, peers, subnet []netip.Prefix
	}{
		{"a", []netip.Prefix{mpp("fd7a:115c:a1e0::1/128")}, []netip.Prefix{mpp("fd7a:115c:a1e0::2/128"), mpp("fd7a:115c:a1e0::3/128")}, []netip.Prefix{mpp("fd10::/64")}},
		{"b", []netip.Prefix{mpp("fd7a:115c:a1e0::3/128")}, []netip.Prefix{mpp("fd7a:115c:a1e0::2/128")}, []netip.Prefix{mpp("fd10::/64")}},
	} {
		if _, err := tb.Sync(s.owner, remap.Order(s.self, s.peers, s.subnet), now); err != nil {
			t.Fatal(err)
		}
	}
	tr := New(tb, reserved)
	if err := tr.SetStacks([]Stack{
		{Owner: "a", Self: []netip.Addr{mpa("fd7a:115c:a1e0::1")}},
		{Owner: "b", Self: []netip.Addr{mpa("fd7a:115c:a1e0::3")}},
	}); err != nil {
		t.Fatal(err)
	}
	return tr
}

// icmpErrCase is one ICMP error through the translator. owner is the stack
// an inbound error came from; empty means outbound.
type icmpErrCase struct {
	name               string
	owner              remap.Owner
	b                  []byte
	verdict            Verdict
	wantOwner          remap.Owner
	wantSrc, wantDst   string // outer addresses after translation
	wantQSrc, wantQDst string // quoted addresses after translation
}

func runICMPErrors(t *testing.T, tr *Translator, cases []icmpErrCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !checksumsOK(c.b) {
				t.Fatal("test packet has bad checksums before translation")
			}
			orig := string(c.b)
			var r Result
			if c.owner != "" {
				r = tr.Inbound(c.owner, parse(c.b))
			} else {
				r = tr.Outbound(parse(c.b))
			}
			if r.Verdict != c.verdict {
				t.Fatalf("verdict = %v (%s), want %v", r.Verdict, r.Reason, c.verdict)
			}
			if c.verdict == Drop {
				// Every drop in these tables is about the quoted packet; the
				// outer addresses would be accepted.
				if r.Reason != DropICMPErrorOutsideTailnet {
					t.Fatalf("reason = %q", r.Reason)
				}
				if string(c.b) != orig {
					t.Fatal("dropped packet was modified")
				}
				return
			}
			if r.Owner != c.wantOwner {
				t.Fatalf("owner = %q, want %q", r.Owner, c.wantOwner)
			}
			if s, d := addrs(c.b); s != mpa(c.wantSrc) || d != mpa(c.wantDst) {
				t.Fatalf("outer = %v -> %v, want %s -> %s", s, d, c.wantSrc, c.wantDst)
			}
			if s, d := quoted(t, c.b); s != mpa(c.wantQSrc) || d != mpa(c.wantQDst) {
				t.Fatalf("quoted = %v -> %v, want %s -> %s", s, d, c.wantQSrc, c.wantQDst)
			}
			if !checksumsOK(c.b) {
				t.Fatal("bad checksums after translation")
			}
		})
	}
}

// Review focus: each quoted address is translated on its own, so an error
// from any hop on the path (not only from the flow's peer) reaches the host
// with the addresses its socket used. PMTUD and traceroute depend on it.
func TestInboundICMPErrorQuoteTranslated(t *testing.T) {
	runICMPErrors(t, scenario(t), []icmpErrCase{
		{name: "ipv4 intermediate hop in remapped subnet", owner: "personal",
			b:       tooBig("10.10.0.1", "100.70.2.9", pkt(ipproto.TCP, "100.70.2.9:4000", "10.10.3.4:443"), 1200),
			verdict: ToHost, wantOwner: "personal",
			wantSrc: "198.19.0.1", wantDst: "198.18.0.0", wantQSrc: "198.18.0.0", wantQDst: "198.19.3.4"},
		{name: "ipv4 subnet router's own frag-needed for remapped flow", owner: "personal",
			b:       tooBig("100.70.2.10", "100.70.2.9", pkt(ipproto.TCP, "100.70.2.9:4000", "10.10.3.4:443"), 1200),
			verdict: ToHost, wantOwner: "personal",
			wantSrc: "100.70.2.10", wantDst: "198.18.0.0", wantQSrc: "198.18.0.0", wantQDst: "198.19.3.4"},
		{name: "ipv4 error about an exit reply we forwarded", owner: "friends",
			b:       icmpErr("100.88.1.4", "1.1.1.1", pkt(ipproto.UDP, "1.1.1.1:53", "100.88.1.4:4000")),
			verdict: ToHost, wantOwner: "friends",
			wantSrc: "198.18.0.1", wantDst: "1.1.1.1", wantQSrc: "1.1.1.1", wantQDst: "198.18.0.1"},
		{name: "ipv4 error about a LAN reply we forwarded", owner: "work",
			b:       icmpErr("100.88.1.4", "192.168.50.7", pkt(ipproto.TCP, "192.168.50.7:22", "100.88.1.4:4000")),
			verdict: ToHost, wantOwner: "work",
			wantSrc: "100.88.1.4", wantDst: "192.168.50.7", wantQSrc: "192.168.50.7", wantQDst: "100.88.1.4"},
	})
	runICMPErrors(t, v6scenario(t), []icmpErrCase{
		{name: "ipv6 intermediate hop in remapped subnet", owner: "b",
			b:       tooBig("fd10::1", "fd7a:115c:a1e0::3", pkt(ipproto.TCP, "[fd7a:115c:a1e0::3]:4000", "[fd10::5]:443"), 1280),
			verdict: ToHost, wantOwner: "b",
			wantSrc: "fd00:1:0:1::1", wantDst: "fd00:1::", wantQSrc: "fd00:1::", wantQDst: "fd00:1:0:1::5"},
		{name: "ipv6 peer's own packet too big", owner: "b",
			b:       tooBig("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::3", pkt(ipproto.UDP, "[fd7a:115c:a1e0::3]:4000", "[fd7a:115c:a1e0::2]:53"), 1280),
			verdict: ToHost, wantOwner: "b",
			wantSrc: "fd00:1::1", wantDst: "fd00:1::", wantQSrc: "fd00:1::", wantQDst: "fd00:1::1"},
	})
}

// Review focus: a stack must not deliver an ICMP error about a flow of
// another tailnet (or a quote it cannot translate within its own), which
// would let one tailnet reset or PMTU-shrink another tailnet's flows.
func TestInboundICMPErrorCrossTailnetDropped(t *testing.T) {
	runICMPErrors(t, scenario(t), []icmpErrCase{
		{name: "ipv4 friends peer quoting a work flow", owner: "friends",
			b: icmpErr("100.88.1.4", "100.99.0.1", pkt(ipproto.UDP, "100.101.5.2:4000", "100.70.2.9:53")), verdict: Drop},
		{name: "ipv4 friends peer quoting a work peer as destination", owner: "friends",
			b: icmpErr("100.88.1.4", "100.99.0.1", pkt(ipproto.UDP, "100.99.0.1:4000", "100.70.2.9:53")), verdict: Drop},
		{name: "ipv4 internet quoted destination from stack without our exit", owner: "friends",
			b: icmpErr("100.88.1.4", "100.99.0.1", pkt(ipproto.UDP, "100.99.0.1:4000", "8.8.8.8:53")), verdict: Drop},
		{name: "ipv4 exit stack quoting work subnet host", owner: "personal",
			b: icmpErr("203.0.113.1", "100.70.2.9", pkt(ipproto.TCP, "100.70.2.9:4000", "172.20.1.1:443")), verdict: Drop},
		{name: "ipv4 exit stack quoting reserved address", owner: "personal",
			b: icmpErr("203.0.113.1", "100.70.2.9", pkt(ipproto.TCP, "100.70.2.9:4000", "100.88.1.4:443")), verdict: Drop},
		{name: "ipv6 friends peer quoting a work flow", owner: "friends",
			b: icmpErr("fd7a:115c:a1e0::99", "fd7a:115c:a1e0::77", pkt(ipproto.UDP, "[fd7a:115c:a1e0::52]:4000", "[fd7a:115c:a1e0::99]:53")), verdict: Drop},
		{name: "ipv6 friends peer quoting work self as destination", owner: "friends",
			b: icmpErr("fd7a:115c:a1e0::99", "fd7a:115c:a1e0::77", pkt(ipproto.UDP, "[fd7a:115c:a1e0::77]:4000", "[fd7a:115c:a1e0::52]:53")), verdict: Drop},
	})
}

// The packet quoted in an outbound ICMP error came from the tailnet the
// error goes to: its source must translate within that tailnet.
func TestOutboundICMPErrorQuote(t *testing.T) {
	runICMPErrors(t, scenario(t), []icmpErrCase{
		{name: "host error back through the exit node",
			b:       icmpErr("198.18.0.0", "1.1.1.1", pkt(ipproto.UDP, "1.1.1.1:53", "198.18.0.0:4000")),
			verdict: ToStack, wantOwner: "personal",
			wantSrc: "100.70.2.9", wantDst: "1.1.1.1", wantQSrc: "1.1.1.1", wantQDst: "100.70.2.9"},
		{name: "LAN host error to a work peer",
			b:       icmpErr("192.168.50.7", "100.88.1.4", pkt(ipproto.TCP, "100.88.1.4:4000", "192.168.50.7:22")),
			verdict: ToStack, wantOwner: "work",
			wantSrc: "192.168.50.7", wantDst: "100.88.1.4", wantQSrc: "100.88.1.4", wantQDst: "192.168.50.7"},
		{name: "internet router error about exit traffic we forward",
			b:       tooBig("203.0.113.1", "198.18.0.1", pkt(ipproto.TCP, "198.18.0.1:4000", "8.8.8.8:443"), 1200),
			verdict: ToStack, wantOwner: "friends",
			wantSrc: "203.0.113.1", wantDst: "100.88.1.4", wantQSrc: "100.88.1.4", wantQDst: "8.8.8.8"},
		{name: "quoted internet source for the tailnet we offer an exit to",
			b:       icmpErr("100.99.0.1", "198.18.0.1", pkt(ipproto.UDP, "8.8.8.8:5000", "100.99.0.1:53")),
			verdict: ToStack, wantOwner: "friends",
			wantSrc: "100.99.0.1", wantDst: "100.88.1.4", wantQSrc: "8.8.8.8", wantQDst: "100.99.0.1"},
		{name: "quoted source inside a subnet we advertise",
			b:       icmpErr("100.101.5.2", "100.88.1.4", pkt(ipproto.UDP, "192.168.50.9:5000", "100.101.5.2:53")),
			verdict: ToStack, wantOwner: "work",
			wantSrc: "100.101.5.2", wantDst: "100.88.1.4", wantQSrc: "192.168.50.9", wantQDst: "100.101.5.2"},
		{name: "quoted source from another tailnet",
			b: icmpErr("100.99.0.1", "198.18.0.1", pkt(ipproto.UDP, "100.88.1.4:5000", "100.99.0.1:53")), verdict: Drop},
		{name: "quoted source reserved and unmapped",
			b: icmpErr("100.99.0.1", "198.18.0.1", pkt(ipproto.UDP, "100.100.1.1:5000", "100.99.0.1:53")), verdict: Drop},
		{name: "quoted internet source for a tailnet without exit or route",
			b: icmpErr("100.101.5.2", "100.88.1.4", pkt(ipproto.UDP, "8.8.8.8:5000", "100.101.5.2:53")), verdict: Drop},
		{name: "ipv6 quoted source from another tailnet",
			b: icmpErr("fd7a:115c:a1e0::77", "fd00:1::", pkt(ipproto.UDP, "[fd7a:115c:a1e0::99]:5000", "[fd7a:115c:a1e0::77]:53")), verdict: Drop},
	})
}

// Review focus (R18): redirects and source quench tell the receiver to
// change how it routes or paces traffic. One tailnet must not steer the
// host's routing (or the host a tailnet's), so they are dropped both ways
// even when their addresses would translate.
func TestICMPRedirectAndSourceQuenchDropped(t *testing.T) {
	tr := scenario(t)
	v4out := pkt(ipproto.UDP, "198.18.0.1:5000", "100.99.0.1:53")
	v4in := pkt(ipproto.UDP, "100.99.0.1:5000", "100.88.1.4:53")
	v6out := pkt(ipproto.UDP, "[fd00:1::]:5000", "[fd7a:115c:a1e0::77]:53")
	v6in := pkt(ipproto.UDP, "[fd7a:115c:a1e0::77]:5000", "[fd7a:115c:a1e0::99]:53")
	const gw = 0x64580104 // 100.88.1.4, the redirect's gateway
	cases := []struct {
		name  string
		owner remap.Owner // "" for Outbound
		b     []byte
	}{
		{"outbound ipv4 redirect", "", icmpError(5, 1, gw, "100.99.0.1", "198.18.0.1", v4out)},
		{"outbound ipv4 source quench", "", icmpError(4, 0, 0, "100.99.0.1", "198.18.0.1", v4out)},
		{"inbound ipv4 redirect", "friends", icmpError(5, 1, gw, "100.88.1.4", "100.99.0.1", v4in)},
		{"inbound ipv4 source quench", "friends", icmpError(4, 0, 0, "100.88.1.4", "100.99.0.1", v4in)},
		{"outbound ipv6 redirect", "", icmpError(137, 0, 0, "fd7a:115c:a1e0::77", "fd00:1::", v6out)},
		{"inbound ipv6 redirect", "friends", icmpError(137, 0, 0, "fd7a:115c:a1e0::99", "fd7a:115c:a1e0::77", v6in)},
		{"inbound ipv6 redirect after fragment header", "friends",
			withIPv6FragHeader(icmpError(137, 0, 0, "fd7a:115c:a1e0::99", "fd7a:115c:a1e0::77", v6in))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !checksumsOK(c.b) {
				t.Fatal("test packet has bad checksums")
			}
			orig := string(c.b)
			var r Result
			if c.owner == "" {
				r = tr.Outbound(parse(c.b))
			} else {
				r = tr.Inbound(c.owner, parse(c.b))
			}
			if r.Verdict != Drop || r.Reason != DropICMPRedirect {
				t.Fatalf("got %+v, want drop: %v", r, DropICMPRedirect)
			}
			if string(c.b) != orig {
				t.Fatal("dropped packet was modified")
			}
		})
	}
	// Neighbouring types are not affected: ICMPv4 type 6 (alternate host
	// address, unassigned in practice) and ICMPv6 type 136 (neighbour
	// advertisement) are translated like any other ICMP message.
	for name, b := range map[string][]byte{
		"ipv4 type 6":   icmpError(6, 0, 0, "100.99.0.1", "198.18.0.1", v4out),
		"ipv6 type 136": icmpError(136, 0, 0, "fd7a:115c:a1e0::77", "fd00:1::", v6out),
	} {
		if r := tr.Outbound(parse(b)); r.Verdict != ToStack {
			t.Errorf("%s: Outbound = %+v, want to-stack", name, r)
		}
	}
	// A Parsed claiming ICMP without an ICMP header (not produced by
	// packet.Decode) is not mistaken for a redirect and does not panic.
	b := pkt(ipproto.ICMPv4, "100.99.0.1:0", "198.18.0.1:0")[:20]
	binary.BigEndian.PutUint16(b[2:], 20)
	q := parse(b)
	q.IPProto = ipproto.ICMPv4
	if r := tr.Outbound(q); r.Reason == DropICMPRedirect {
		t.Fatalf("headerless ICMP: Outbound = %+v", r)
	}
}

// Review focus (R18): an ICMP error from the exit stack quoting a flow to
// a non-internet destination is dropped, as a packet from that address
// would be; an error sent back through the exit may not quote one either.
func TestExitICMPErrorQuotesInternetOnly(t *testing.T) {
	runICMPErrors(t, exitScenario(t), []icmpErrCase{
		{name: "inbound quoting an internet destination", owner: "x",
			b:       tooBig("203.0.113.1", "100.64.0.1", pkt(ipproto.TCP, "100.64.0.1:4000", "1.1.1.1:443"), 1200),
			verdict: ToHost, wantOwner: "x",
			wantSrc: "203.0.113.1", wantDst: "100.64.0.1", wantQSrc: "100.64.0.1", wantQDst: "1.1.1.1"},
		{name: "inbound quoting a private destination", owner: "x",
			b: tooBig("203.0.113.1", "100.64.0.1", pkt(ipproto.TCP, "100.64.0.1:4000", "192.168.1.1:443"), 1200), verdict: Drop},
		{name: "inbound quoting a link-local destination", owner: "x",
			b: icmpErr("2606:4700::1", "fd7a:115c:a1e0::1", pkt(ipproto.UDP, "[fd7a:115c:a1e0::1]:4000", "[fe80::1]:53")), verdict: Drop},
		{name: "outbound quoting an internet source",
			b:       icmpErr("100.64.0.1", "1.1.1.1", pkt(ipproto.UDP, "1.1.1.1:53", "100.64.0.1:4000")),
			verdict: ToStack, wantOwner: "x",
			wantSrc: "100.64.0.1", wantDst: "1.1.1.1", wantQSrc: "1.1.1.1", wantQDst: "100.64.0.1"},
		{name: "outbound quoting a private source",
			b: icmpErr("100.64.0.1", "1.1.1.1", pkt(ipproto.UDP, "10.1.2.3:53", "100.64.0.1:4000")), verdict: Drop},
		{name: "outbound quoting a ULA source",
			b: icmpErr("fd7a:115c:a1e0::1", "2606:4700:4700::1111", pkt(ipproto.UDP, "[fd12::1]:53", "[fd7a:115c:a1e0::1]:4000")), verdict: Drop},
	})
}
