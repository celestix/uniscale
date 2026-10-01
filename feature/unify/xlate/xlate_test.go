// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

var (
	mpa = netip.MustParseAddr
	mpp = netip.MustParsePrefix
)

var reserved = []netip.Prefix{
	mpp("100.64.0.0/10"), mpp("fd7a:115c:a1e0::/48"),
	mpp("198.18.0.0/15"), mpp("fd00:1::/48"),
}

// The scenario used by most tests. Sync order is work, personal, friends.
//
//	work:     self 100.101.5.2, fd7a:115c:a1e0::52
//	          peers 100.70.2.9, 100.88.1.4, fd7a:115c:a1e0::99
//	          routed subnets 10.10.0.0/16, 172.20.0.0/16 (identity, only
//	          work routes it); advertises our LAN 192.168.50.0/24
//	personal: self 100.70.2.9        -> 198.18.0.0 (collides with work peer)
//	          peer 100.70.2.10       (identity)
//	          routed subnet 10.10.0.0/16 -> 198.19.0.0/16
//	          uses an exit node
//	friends:  self 100.99.0.1, fd7a:115c:a1e0::77 (identity)
//	          peer 100.88.1.4        -> 198.18.0.1
//	          peer fd7a:115c:a1e0::99 -> fd00:1::
//	          this node offers an exit node to friends
func scenario(t *testing.T) *Translator {
	t.Helper()
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tb, err := remap.New(remap.Config{Pool6: mpp("fd00:1::/48"), Now: func() time.Time { return now }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sync := func(owner remap.Owner, self, peers, subnets []netip.Prefix) {
		if _, err := tb.Sync(owner, remap.Order(self, peers, subnets), now); err != nil {
			t.Fatal(err)
		}
	}
	p := func(ss ...string) (out []netip.Prefix) {
		for _, s := range ss {
			out = append(out, mpp(s))
		}
		return out
	}
	sync("work", p("100.101.5.2/32", "fd7a:115c:a1e0::52/128"),
		p("100.70.2.9/32", "100.88.1.4/32", "fd7a:115c:a1e0::99/128"), p("10.10.0.0/16", "172.20.0.0/16"))
	sync("personal", p("100.70.2.9/32"), p("100.70.2.10/32"), p("10.10.0.0/16"))
	sync("friends", p("100.99.0.1/32", "fd7a:115c:a1e0::77/128"), p("100.88.1.4/32", "fd7a:115c:a1e0::99/128"), nil)

	tr := New(tb, reserved)
	if err := tr.SetStacks([]Stack{
		{Owner: "work", Self: []netip.Addr{mpa("100.101.5.2"), mpa("fd7a:115c:a1e0::52")}, Advertised: p("192.168.50.0/24")},
		{Owner: "personal", Self: []netip.Addr{mpa("100.70.2.9")}, UsesExit: true},
		{Owner: "friends", Self: []netip.Addr{mpa("100.99.0.1"), mpa("fd7a:115c:a1e0::77")}, OffersExit: true},
	}); err != nil {
		t.Fatal(err)
	}
	return tr
}

type flow struct {
	name             string
	owner            remap.Owner // Inbound only: the stack the packet came from
	proto            ipproto.Proto
	src, dst         string // ip:port
	verdict          Verdict
	wantOwner        remap.Owner
	wantSrc, wantDst string // addresses after translation
	wantReason       string // substring, for drops
}

func runFlows(t *testing.T, inbound bool, flows []flow) {
	tr := scenario(t)
	for _, f := range flows {
		t.Run(f.name, func(t *testing.T) {
			b := pkt(f.proto, f.src, f.dst)
			orig := string(b)
			q := parse(b)
			var r Result
			if inbound {
				r = tr.Inbound(f.owner, q)
			} else {
				r = tr.Outbound(q)
			}
			if r.Verdict != f.verdict {
				t.Fatalf("verdict = %v (%s), want %v", r.Verdict, r.Reason, f.verdict)
			}
			if f.verdict == Drop {
				if !strings.Contains(r.Reason, f.wantReason) {
					t.Fatalf("reason = %q, want it to contain %q", r.Reason, f.wantReason)
				}
				if string(b) != orig {
					t.Fatal("dropped packet was modified")
				}
				return
			}
			if r.Owner != f.wantOwner {
				t.Fatalf("owner = %q, want %q", r.Owner, f.wantOwner)
			}
			src, dst := addrs(b)
			if src != mpa(f.wantSrc) || dst != mpa(f.wantDst) {
				t.Fatalf("addresses = %v -> %v, want %s -> %s", src, dst, f.wantSrc, f.wantDst)
			}
			if !checksumsOK(b) {
				t.Fatal("bad checksums after translation")
			}
		})
	}
}

func TestOutbound(t *testing.T) {
	runFlows(t, false, []flow{
		{name: "work peer, identity", proto: ipproto.TCP, src: "100.101.5.2:4000", dst: "100.88.1.4:22",
			verdict: ToStack, wantOwner: "work", wantSrc: "100.101.5.2", wantDst: "100.88.1.4"},
		{name: "personal remapped subnet tcp", proto: ipproto.TCP, src: "198.18.0.0:4000", dst: "198.19.3.4:443",
			verdict: ToStack, wantOwner: "personal", wantSrc: "100.70.2.9", wantDst: "10.10.3.4"},
		{name: "personal remapped subnet udp", proto: ipproto.UDP, src: "198.18.0.0:4000", dst: "198.19.3.4:53",
			verdict: ToStack, wantOwner: "personal", wantSrc: "100.70.2.9", wantDst: "10.10.3.4"},
		{name: "personal remapped subnet icmp", proto: ipproto.ICMPv4, src: "198.18.0.0:0", dst: "198.19.3.4:0",
			verdict: ToStack, wantOwner: "personal", wantSrc: "100.70.2.9", wantDst: "10.10.3.4"},
		{name: "work subnet, identity", proto: ipproto.TCP, src: "100.101.5.2:4000", dst: "10.10.3.4:443",
			verdict: ToStack, wantOwner: "work", wantSrc: "100.101.5.2", wantDst: "10.10.3.4"},
		{name: "friends remapped peer", proto: ipproto.UDP, src: "100.99.0.1:4000", dst: "198.18.0.1:53",
			verdict: ToStack, wantOwner: "friends", wantSrc: "100.99.0.1", wantDst: "100.88.1.4"},
		{name: "friends remapped ipv6 peer", proto: ipproto.ICMPv4, src: "[fd7a:115c:a1e0::52]:0", dst: "[fd00:1::]:0",
			verdict: Drop, wantReason: "source not allowed"},
		{name: "work ipv6 peer", proto: ipproto.TCP, src: "[fd7a:115c:a1e0::52]:4000", dst: "[fd7a:115c:a1e0::99]:22",
			verdict: ToStack, wantOwner: "work", wantSrc: "fd7a:115c:a1e0::52", wantDst: "fd7a:115c:a1e0::99"},
		{name: "wrong tailnet source", proto: ipproto.TCP, src: "100.101.5.2:4000", dst: "198.18.0.1:22",
			verdict: Drop, wantReason: "source not allowed"},
		{name: "peer virtual address as source", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "198.18.0.1:22",
			verdict: Drop, wantReason: "source not allowed"},
		{name: "internet via personal exit node", proto: ipproto.TCP, src: "198.18.0.0:4000", dst: "1.1.1.1:443",
			verdict: ToStack, wantOwner: "personal", wantSrc: "100.70.2.9", wantDst: "1.1.1.1"},
		{name: "internet with another tailnet's source", proto: ipproto.TCP, src: "100.101.5.2:4000", dst: "1.1.1.1:443",
			verdict: Drop, wantReason: "source not allowed"},
		{name: "unmapped tailscale address never goes to exit", proto: ipproto.TCP, src: "198.18.0.0:4000", dst: "100.100.1.1:443",
			verdict: Drop, wantReason: "no route"},
		{name: "unmapped pool address never goes to exit", proto: ipproto.TCP, src: "198.18.0.0:4000", dst: "198.18.9.9:443",
			verdict: Drop, wantReason: "no route"},
		{name: "reply from advertised LAN keeps source", proto: ipproto.TCP, src: "192.168.50.7:22", dst: "100.88.1.4:4000",
			verdict: ToStack, wantOwner: "work", wantSrc: "192.168.50.7", wantDst: "100.88.1.4"},
		{name: "reply from internet for exit we offer", proto: ipproto.TCP, src: "8.8.8.8:443", dst: "198.18.0.1:4000",
			verdict: ToStack, wantOwner: "friends", wantSrc: "8.8.8.8", wantDst: "100.88.1.4"},
		{name: "LAN source to tailnet without that route", proto: ipproto.TCP, src: "192.168.50.7:22", dst: "100.70.2.10:4000",
			verdict: Drop, wantReason: "source not allowed"},
	})
}

func TestInbound(t *testing.T) {
	runFlows(t, true, []flow{
		{name: "work peer to self", owner: "work", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "100.101.5.2:22",
			verdict: ToHost, wantOwner: "work", wantSrc: "100.88.1.4", wantDst: "100.101.5.2"},
		{name: "personal peer to remapped self", owner: "personal", proto: ipproto.TCP, src: "100.70.2.10:4000", dst: "100.70.2.9:22",
			verdict: ToHost, wantOwner: "personal", wantSrc: "100.70.2.10", wantDst: "198.18.0.0"},
		{name: "personal subnet host", owner: "personal", proto: ipproto.UDP, src: "10.10.3.4:53", dst: "100.70.2.9:4000",
			verdict: ToHost, wantOwner: "personal", wantSrc: "198.19.3.4", wantDst: "198.18.0.0"},
		{name: "friends remapped peer", owner: "friends", proto: ipproto.ICMPv4, src: "100.88.1.4:0", dst: "100.99.0.1:0",
			verdict: ToHost, wantOwner: "friends", wantSrc: "198.18.0.1", wantDst: "100.99.0.1"},
		{name: "work peer to advertised LAN", owner: "work", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "192.168.50.7:22",
			verdict: ToHost, wantOwner: "work", wantSrc: "100.88.1.4", wantDst: "192.168.50.7"},
		{name: "friends peer to internet via our exit", owner: "friends", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "1.1.1.1:443",
			verdict: ToHost, wantOwner: "friends", wantSrc: "198.18.0.1", wantDst: "1.1.1.1"},
		{name: "isolation: friends peer to personal peer", owner: "friends", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "100.70.2.10:22",
			verdict: Drop, wantReason: "destination not reachable"},
		{name: "isolation: friends peer to personal remapped subnet", owner: "friends", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "198.19.3.4:22",
			verdict: Drop, wantReason: "destination not reachable"},
		{name: "isolation: friends peer to reserved range", owner: "friends", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "100.100.1.1:22",
			verdict: Drop, wantReason: "destination not reachable"},
		{name: "work does not get our exit", owner: "work", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "1.1.1.1:443",
			verdict: Drop, wantReason: "destination not reachable"},
		{name: "work peer to friends LAN-less self", owner: "work", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "192.168.99.1:22",
			verdict: Drop, wantReason: "destination not reachable"},
		{name: "unmapped source", owner: "work", proto: ipproto.TCP, src: "100.77.7.7:4000", dst: "100.101.5.2:22",
			verdict: Drop, wantReason: "unmapped source"},
		{name: "unknown tailnet", owner: "nobody", proto: ipproto.TCP, src: "100.88.1.4:4000", dst: "100.101.5.2:22",
			verdict: Drop, wantReason: "unknown tailnet"},
		{name: "friends ipv6 peer", owner: "friends", proto: ipproto.ICMPv4, src: "[fd7a:115c:a1e0::99]:0", dst: "[fd7a:115c:a1e0::52]:0",
			verdict: Drop, wantReason: "destination not reachable"},
		{name: "work ipv6 peer", owner: "work", proto: ipproto.UDP, src: "[fd7a:115c:a1e0::99]:4000", dst: "[fd7a:115c:a1e0::52]:53",
			verdict: ToHost, wantOwner: "work", wantSrc: "fd7a:115c:a1e0::99", wantDst: "fd7a:115c:a1e0::52"},

		// Replies from the internet through the exit node this host uses.
		{name: "tcp reply via personal exit node", owner: "personal", proto: ipproto.TCP, src: "1.1.1.1:443", dst: "100.70.2.9:4000",
			verdict: ToHost, wantOwner: "personal", wantSrc: "1.1.1.1", wantDst: "198.18.0.0"},
		{name: "udp reply via personal exit node", owner: "personal", proto: ipproto.UDP, src: "8.8.4.4:53", dst: "100.70.2.9:4000",
			verdict: ToHost, wantOwner: "personal", wantSrc: "8.8.4.4", wantDst: "198.18.0.0"},
		{name: "exit stack impersonating friends remapped peer", owner: "personal", proto: ipproto.TCP, src: "198.18.0.1:443", dst: "100.70.2.9:4000",
			verdict: Drop, wantReason: "unmapped source"},
		{name: "exit stack impersonating work peer", owner: "personal", proto: ipproto.TCP, src: "100.88.1.4:443", dst: "100.70.2.9:4000",
			verdict: Drop, wantReason: "unmapped source"},
		{name: "exit stack impersonating work subnet host", owner: "personal", proto: ipproto.TCP, src: "172.20.1.1:443", dst: "100.70.2.9:4000",
			verdict: Drop, wantReason: "unmapped source"},
		{name: "exit stack sending from unmapped tailscale address", owner: "personal", proto: ipproto.TCP, src: "100.100.1.1:443", dst: "100.70.2.9:4000",
			verdict: Drop, wantReason: "unmapped source"},
		{name: "internet source from stack offering exit", owner: "friends", proto: ipproto.TCP, src: "1.1.1.1:443", dst: "100.99.0.1:4000",
			verdict: Drop, wantReason: "unmapped source"},
		{name: "internet source from stack without exit", owner: "work", proto: ipproto.UDP, src: "8.8.4.4:53", dst: "100.101.5.2:4000",
			verdict: Drop, wantReason: "unmapped source"},
	})
}

// An ICMP error from an internet router, about a flow this host sent
// through the exit node it uses, reaches the host with the router's address
// and the quoted internet destination unchanged.
func TestICMPErrorViaExitNode(t *testing.T) {
	tr := scenario(t)
	orig := pkt(ipproto.TCP, "100.70.2.9:4000", "1.1.1.1:443") // as the exit stack sent it
	b := icmpErr("203.0.113.1", "100.70.2.9", orig)
	if r := tr.Inbound("personal", parse(b)); r.Verdict != ToHost || r.Owner != "personal" {
		t.Fatalf("Inbound = %+v", r)
	}
	if s, d := addrs(b); s != mpa("203.0.113.1") || d != mpa("198.18.0.0") {
		t.Fatalf("outer = %v -> %v, want 203.0.113.1 -> 198.18.0.0", s, d)
	}
	if s, d := quoted(t, b); s != mpa("198.18.0.0") || d != mpa("1.1.1.1") {
		t.Fatalf("quoted = %v -> %v, want 198.18.0.0 -> 1.1.1.1", s, d)
	}
	if !checksumsOK(b) {
		t.Fatal("bad checksums")
	}
}

func TestNotIP(t *testing.T) {
	tr := scenario(t)
	q := parse([]byte{0x00, 1, 2, 3})
	if r := tr.Outbound(q); r.Verdict != Drop {
		t.Errorf("Outbound(non-IP) = %v", r.Verdict)
	}
	if r := tr.Inbound("work", q); r.Verdict != Drop {
		t.Errorf("Inbound(non-IP) = %v", r.Verdict)
	}
}

func TestShortIPv4HeaderDropped(t *testing.T) {
	tr := scenario(t)
	b := pkt(ipproto.UDP, "100.88.1.4:4000", "100.99.0.1:53")
	b[0] = 0x40 // header length 0: packet.Decode accepts it
	orig := string(b)
	if r := tr.Inbound("friends", parse(b)); r.Verdict != Drop || r.Reason != "malformed packet" {
		t.Fatalf("Inbound = %+v", r)
	}
	if string(b) != orig {
		t.Fatal("malformed packet was modified")
	}
}

// Review focus: packet.Decode stops before setting the addresses of a
// packet shorter than its header says, so a reused Parsed (the packet loop
// reuses one) still holds the previous packet's addresses.
func TestStaleParsedDropped(t *testing.T) {
	tr := scenario(t)
	cases := []struct {
		name         string
		owner        remap.Owner // "" for Outbound
		valid, stale []byte
	}{
		{"ipv4 outbound", "", pkt(ipproto.TCP, "100.101.5.2:4000", "100.88.1.4:22"), pkt(ipproto.TCP, "9.9.9.9:1", "8.8.4.4:2")},
		{"ipv4 inbound", "friends", pkt(ipproto.UDP, "100.88.1.4:4000", "100.99.0.1:53"), pkt(ipproto.UDP, "9.9.9.9:1", "8.8.4.4:2")},
		{"ipv6 outbound", "", pkt(ipproto.TCP, "[fd7a:115c:a1e0::52]:4000", "[fd7a:115c:a1e0::99]:22"), pkt(ipproto.TCP, "[2001:db8::9]:1", "[2001:db8::8]:2")},
		{"ipv6 inbound", "work", pkt(ipproto.UDP, "[fd7a:115c:a1e0::99]:4000", "[fd7a:115c:a1e0::52]:53"), pkt(ipproto.UDP, "[2001:db8::9]:1", "[2001:db8::8]:2")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			translate := func(q *packet.Parsed) Result {
				if c.owner == "" {
					return tr.Outbound(q)
				}
				return tr.Inbound(c.owner, q)
			}
			var q packet.Parsed
			q.Decode(c.valid)
			if r := translate(&q); r.Verdict == Drop {
				t.Fatalf("valid packet dropped: %s", r.Reason)
			}
			b := c.stale[:len(c.stale)-3] // shorter than its IP length
			orig := string(b)
			q.Decode(b)
			if r := translate(&q); r.Verdict != Drop || r.Reason != "malformed packet" {
				t.Fatalf("truncated packet = %+v, want drop: malformed packet", r)
			}
			if string(b) != orig {
				t.Fatal("malformed packet was modified")
			}
		})
	}
}

// wellFormed checks the IP header itself rather than trusting what
// packet.Decode left in Parsed.
func TestMalformedIPHeadersDropped(t *testing.T) {
	tr := scenario(t)
	v4 := func() []byte { return pkt(ipproto.UDP, "198.18.0.0:4000", "198.19.3.4:53") }
	v6 := func() []byte { return pkt(ipproto.UDP, "[fd7a:115c:a1e0::77]:4000", "[fd00:1::]:53") }
	setLen := func(b []byte, off int, n uint16) []byte { binary.BigEndian.PutUint16(b[off:], n); return b }
	cases := map[string]func() ([]byte, *packet.Parsed){
		"ipv4 total length past buffer": func() ([]byte, *packet.Parsed) {
			b := setLen(v4(), 2, 200)
			return b, parse(b)
		},
		"ipv4 total length inside header": func() ([]byte, *packet.Parsed) {
			b := setLen(v4(), 2, 16)
			return b, parse(b)
		},
		"ipv6 payload past buffer": func() ([]byte, *packet.Parsed) {
			b := setLen(v6(), 4, 200)
			return b, parse(b)
		},
		"ipv4 header source differs from Parsed": func() ([]byte, *packet.Parsed) {
			b := v4()
			q := parse(b)
			b[12] = 10
			return b, q
		},
		"ipv4 header destination differs from Parsed": func() ([]byte, *packet.Parsed) {
			b := v4()
			q := parse(b)
			b[19] = 9
			return b, q
		},
		"ipv6 header source differs from Parsed": func() ([]byte, *packet.Parsed) {
			b := v6()
			q := parse(b)
			b[23] = 0x76
			return b, q
		},
		"ipv6 header destination differs from Parsed": func() ([]byte, *packet.Parsed) {
			b := v6()
			q := parse(b)
			b[39] = 9
			return b, q
		},
		// Not produced by Decode; wellFormed must not index past the buffer.
		"ipv4 Parsed without buffer": func() ([]byte, *packet.Parsed) { return nil, &packet.Parsed{IPVersion: 4} },
		"ipv6 Parsed without buffer": func() ([]byte, *packet.Parsed) { return nil, &packet.Parsed{IPVersion: 6} },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			b, q := mk()
			orig := string(b)
			if r := tr.Outbound(q); r.Verdict != Drop || r.Reason != "malformed packet" {
				t.Fatalf("Outbound = %+v, want drop: malformed packet", r)
			}
			if string(b) != orig {
				t.Fatal("malformed packet was modified")
			}
		})
	}
}

func TestUnknownOwnerFromMapper(t *testing.T) {
	tr := scenario(t)
	if err := tr.SetStacks([]Stack{{Owner: "work"}}); err != nil {
		t.Fatal(err)
	}
	// 198.18.0.1 belongs to friends, which is no longer a stack.
	q := parse(pkt(ipproto.TCP, "100.99.0.1:1", "198.18.0.1:2"))
	if r := tr.Outbound(q); r.Verdict != Drop || r.Reason != "unknown tailnet" {
		t.Fatalf("Outbound = %+v", r)
	}
}

// familyMapper maps addresses to addresses of the other family. Only
// virtualDst is reported as a virtual address.
type familyMapper struct{ virtualDst netip.Addr }

func (familyMapper) RealToVirtual(remap.Owner, netip.Addr) (netip.Addr, bool) {
	return mpa("fd00::1"), true
}
func (m familyMapper) VirtualToReal(a netip.Addr) (remap.Owner, netip.Addr, bool) {
	return "a", mpa("fd00::2"), a == m.virtualDst
}

func TestFamilyMismatchDropped(t *testing.T) {
	tr := New(familyMapper{virtualDst: mpa("5.6.7.8")}, nil)
	tr.SetStacks([]Stack{{Owner: "a", Self: []netip.Addr{mpa("5.6.7.8")}, Advertised: []netip.Prefix{mpp("0.0.0.0/0")}}})
	b := pkt(ipproto.TCP, "1.2.3.4:1", "5.6.7.8:2")
	orig := string(b)
	if r := tr.Inbound("a", parse(b)); r.Verdict != Drop || r.Reason != "address family mismatch" {
		t.Fatalf("Inbound = %+v", r)
	}
	if r := tr.Outbound(parse(b)); r.Verdict != Drop || r.Reason != "address family mismatch" {
		t.Fatalf("Outbound = %+v", r)
	}
	if string(b) != orig {
		t.Fatal("packet modified despite family mismatch")
	}
}

// funcMapper is a Mapper built from functions.
type funcMapper struct {
	r2v func(remap.Owner, netip.Addr) (netip.Addr, bool)
	v2r func(netip.Addr) (remap.Owner, netip.Addr, bool)
}

func (m funcMapper) RealToVirtual(o remap.Owner, a netip.Addr) (netip.Addr, bool) { return m.r2v(o, a) }
func (m funcMapper) VirtualToReal(a netip.Addr) (remap.Owner, netip.Addr, bool)   { return m.v2r(a) }

// A quoted address translated to another family is caught before the
// outer addresses are written.
func TestQuotedFamilyMismatchDropped(t *testing.T) {
	m := funcMapper{
		r2v: func(_ remap.Owner, a netip.Addr) (netip.Addr, bool) {
			if a == mpa("4.4.4.4") {
				return mpa("fd00::4"), true
			}
			return a, true
		},
		v2r: func(a netip.Addr) (remap.Owner, netip.Addr, bool) { return "", netip.Addr{}, false },
	}
	tr := New(m, nil)
	if err := tr.SetStacks([]Stack{{Owner: "a", Self: []netip.Addr{mpa("5.6.7.8")}}}); err != nil {
		t.Fatal(err)
	}
	b := icmpErr("9.9.9.9", "5.6.7.8", pkt(ipproto.UDP, "5.6.7.8:1", "4.4.4.4:2"))
	orig := string(b)
	if r := tr.Inbound("a", parse(b)); r.Verdict != Drop || r.Reason != "address family mismatch" {
		t.Fatalf("Inbound = %+v", r)
	}
	if string(b) != orig {
		t.Fatal("packet modified despite family mismatch")
	}
}

func TestSetStacksErrors(t *testing.T) {
	tr := New(familyMapper{}, nil)
	for name, stacks := range map[string][]Stack{
		"empty owner": {{}},
		"duplicate":   {{Owner: "a"}, {Owner: "a"}},
		"two exits":   {{Owner: "a", UsesExit: true}, {Owner: "b", UsesExit: true}},
	} {
		if err := tr.SetStacks(stacks); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{Drop: "drop", ToStack: "to-stack", ToHost: "to-host", 9: "Verdict(9)"} {
		if got := v.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", v, got, want)
		}
	}
}

// Review focus: real traffic carries IPv4 options and IPv6 extension
// headers. Translation must keep every checksum valid for them too.
func TestHeadersWithOptions(t *testing.T) {
	tr := scenario(t)
	cases := []struct {
		name    string
		b       []byte
		inbound remap.Owner
		wantSrc string
		wantDst string
	}{
		{"ipv4 options outbound", withIPv4Options(pkt(ipproto.TCP, "198.18.0.0:4000", "198.19.3.4:443")), "",
			"100.70.2.9", "10.10.3.4"},
		{"ipv4 options inbound", withIPv4Options(pkt(ipproto.UDP, "100.88.1.4:4000", "100.99.0.1:53")), "friends",
			"198.18.0.1", "100.99.0.1"},
		{"ipv6 fragment header inbound", withIPv6FragHeader(pkt(ipproto.UDP, "[fd7a:115c:a1e0::99]:4000", "[fd7a:115c:a1e0::77]:53")), "friends",
			"fd00:1::", "fd7a:115c:a1e0::77"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !checksumsOK(c.b) {
				t.Fatal("test packet has bad checksums before translation")
			}
			q := parse(c.b)
			var r Result
			if c.inbound != "" {
				r = tr.Inbound(c.inbound, q)
			} else {
				r = tr.Outbound(q)
			}
			if r.Verdict == Drop {
				t.Fatalf("dropped: %s", r.Reason)
			}
			if s, d := addrs(c.b); s != mpa(c.wantSrc) || d != mpa(c.wantDst) {
				t.Fatalf("addresses = %v -> %v, want %s -> %s", s, d, c.wantSrc, c.wantDst)
			}
			if !checksumsOK(c.b) {
				t.Fatal("bad checksums after translation")
			}
		})
	}
}
