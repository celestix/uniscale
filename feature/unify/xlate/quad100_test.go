// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"net/netip"
	"testing"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/types/ipproto"
)

// withQuad100 returns stacks with only owner serving quad-100.
func withQuad100(stacks []Stack, owner remap.Owner) []Stack {
	for i := range stacks {
		stacks[i].Quad100 = stacks[i].Owner == owner
	}
	return stacks
}

// Review focus (R7): quad-100 (Tailscale's service address) is served to
// the host by one stack, the primary. Only this node's own address in that
// tailnet may talk to it, and only that stack may answer from it.
func TestQuad100(t *testing.T) {
	runFlows(t, false, []flow{
		{name: "ipv4 from primary self", proto: ipproto.UDP, src: "100.101.5.2:4000", dst: "100.100.100.100:53",
			verdict: ToStack, wantOwner: "work", wantSrc: "100.101.5.2", wantDst: "100.100.100.100"},
		{name: "ipv6 from primary self", proto: ipproto.UDP, src: "[fd7a:115c:a1e0::52]:4000", dst: "[fd7a:115c:a1e0::53]:53",
			verdict: ToStack, wantOwner: "work", wantSrc: "fd7a:115c:a1e0::52", wantDst: "fd7a:115c:a1e0::53"},
		{name: "tcp to another quad-100 service", proto: ipproto.TCP, src: "100.101.5.2:4000", dst: "100.100.100.100:8080",
			verdict: ToStack, wantOwner: "work", wantSrc: "100.101.5.2", wantDst: "100.100.100.100"},
		{name: "from another tailnet's self", proto: ipproto.UDP, src: "100.99.0.1:4000", dst: "100.100.100.100:53",
			verdict: Drop, wantReason: DropSourceNotAllowed},
		{name: "from another tailnet's remapped self", proto: ipproto.UDP, src: "198.18.0.0:4000", dst: "100.100.100.100:53",
			verdict: Drop, wantReason: DropSourceNotAllowed},
		{name: "from a LAN host in a subnet the primary is advertised", proto: ipproto.UDP, src: "192.168.50.7:4000", dst: "100.100.100.100:53",
			verdict: Drop, wantReason: DropSourceNotAllowed},
		{name: "from an internet address", proto: ipproto.UDP, src: "8.8.8.8:4000", dst: "100.100.100.100:53",
			verdict: Drop, wantReason: DropSourceNotAllowed},
	})
	runFlows(t, true, []flow{
		{name: "ipv4 answer to primary self", owner: "work", proto: ipproto.UDP, src: "100.100.100.100:53", dst: "100.101.5.2:4000",
			verdict: ToHost, wantOwner: "work", wantSrc: "100.100.100.100", wantDst: "100.101.5.2"},
		{name: "ipv6 answer to primary self", owner: "work", proto: ipproto.UDP, src: "[fd7a:115c:a1e0::53]:53", dst: "[fd7a:115c:a1e0::52]:4000",
			verdict: ToHost, wantOwner: "work", wantSrc: "fd7a:115c:a1e0::53", wantDst: "fd7a:115c:a1e0::52"},
		{name: "spoofed by another stack", owner: "friends", proto: ipproto.UDP, src: "100.100.100.100:53", dst: "100.99.0.1:4000",
			verdict: Drop, wantReason: DropUnmappedSource},
		{name: "spoofed by the exit stack", owner: "personal", proto: ipproto.UDP, src: "100.100.100.100:53", dst: "100.70.2.9:4000",
			verdict: Drop, wantReason: DropUnmappedSource},
		{name: "ipv6 spoofed by another stack", owner: "friends", proto: ipproto.UDP, src: "[fd7a:115c:a1e0::53]:53", dst: "[fd7a:115c:a1e0::77]:4000",
			verdict: Drop, wantReason: DropUnmappedSource},
		{name: "to an advertised LAN host", owner: "work", proto: ipproto.UDP, src: "100.100.100.100:53", dst: "192.168.50.7:4000",
			verdict: Drop, wantReason: DropDestinationNotReachable},
	})
}

// The quad-100 owner's self may be remapped: its virtual self is rewritten
// to the real one, and back for answers.
func TestQuad100RemappedOwner(t *testing.T) {
	tr := scenario(t)
	if err := tr.SetStacks(withQuad100(scenarioStacks(), "personal")); err != nil {
		t.Fatal(err)
	}
	b := pkt(ipproto.UDP, "198.18.0.0:4000", "100.100.100.100:53")
	if r := tr.Outbound(parse(b)); r.Verdict != ToStack || r.Owner != "personal" {
		t.Fatalf("Outbound = %+v", r)
	}
	if s, d := addrs(b); s != mpa("100.70.2.9") || d != mpa("100.100.100.100") || !checksumsOK(b) {
		t.Fatalf("outbound = %v -> %v (checksums ok: %v)", s, d, checksumsOK(b))
	}
	b = pkt(ipproto.UDP, "100.100.100.100:53", "100.70.2.9:4000")
	if r := tr.Inbound("personal", parse(b)); r.Verdict != ToHost || r.Owner != "personal" {
		t.Fatalf("Inbound = %+v", r)
	}
	if s, d := addrs(b); s != mpa("100.100.100.100") || d != mpa("198.18.0.0") || !checksumsOK(b) {
		t.Fatalf("inbound = %v -> %v (checksums ok: %v)", s, d, checksumsOK(b))
	}
	// work no longer serves it.
	if r := tr.Outbound(parse(pkt(ipproto.UDP, "100.101.5.2:4000", "100.100.100.100:53"))); r.Reason != DropSourceNotAllowed {
		t.Fatalf("Outbound from work = %+v", r)
	}
	if r := tr.Inbound("work", parse(pkt(ipproto.UDP, "100.100.100.100:53", "100.101.5.2:4000"))); r.Reason != DropUnmappedSource {
		t.Fatalf("Inbound from work = %+v", r)
	}
}

// Quad-100 is never a peer's address: with no stack serving it (the
// primary is not running) it has no route, even if a tailnet's mapping
// covers it, and no stack may answer from it.
func TestQuad100WithoutOwner(t *testing.T) {
	m := funcMapper{
		// Stack a routes 100.64.0.0/10 and fd7a:115c:a1e0::/48 as identity.
		r2v: func(_ remap.Owner, a netip.Addr) (netip.Addr, bool) { return a, true },
		v2r: func(a netip.Addr) (remap.Owner, netip.Addr, bool) { return "a", a, true },
	}
	tr := New(m, reserved)
	stacks := []Stack{
		{Owner: "a", Self: []netip.Addr{mpa("100.64.0.1"), mpa("fd7a:115c:a1e0::1")}},
		{Owner: "b", Self: []netip.Addr{mpa("100.64.0.2")}},
	}
	if err := tr.SetStacks(stacks); err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{
		"100.64.0.1:4000":          "100.100.100.100:53",
		"[fd7a:115c:a1e0::1]:4000": "[fd7a:115c:a1e0::53]:53",
	} {
		if r := tr.Outbound(parse(pkt(ipproto.UDP, src, dst))); r.Verdict != Drop || r.Reason != DropNoRoute {
			t.Errorf("Outbound to %s = %+v, want drop: %v", dst, r, DropNoRoute)
		}
	}
	if r := tr.Inbound("a", parse(pkt(ipproto.UDP, "100.100.100.100:53", "100.64.0.1:4000"))); r.Reason != DropUnmappedSource {
		t.Errorf("Inbound from a = %+v, want drop: %v", r, DropUnmappedSource)
	}
	// With b serving quad-100, it goes to b although a's mapping covers it.
	if err := tr.SetStacks(withQuad100(stacks, "b")); err != nil {
		t.Fatal(err)
	}
	if r := tr.Outbound(parse(pkt(ipproto.UDP, "100.64.0.2:4000", "100.100.100.100:53"))); r.Verdict != ToStack || r.Owner != "b" {
		t.Errorf("Outbound with b serving quad-100 = %+v", r)
	}
}

// ICMP errors about quad-100 flows stay within the stack serving it.
func TestQuad100ICMPErrors(t *testing.T) {
	tr := scenario(t)
	if err := tr.SetStacks(withQuad100(scenarioStacks(), "personal")); err != nil {
		t.Fatal(err)
	}
	runICMPErrors(t, tr, []icmpErrCase{
		{name: "inbound: quad-100 port unreachable for the host", owner: "personal",
			b:       icmpErr("100.100.100.100", "100.70.2.9", pkt(ipproto.UDP, "100.70.2.9:4000", "100.100.100.100:5353")),
			verdict: ToHost, wantOwner: "personal",
			wantSrc: "100.100.100.100", wantDst: "198.18.0.0", wantQSrc: "198.18.0.0", wantQDst: "100.100.100.100"},
		{name: "outbound: host port unreachable for quad-100",
			b:       icmpErr("198.18.0.0", "100.100.100.100", pkt(ipproto.UDP, "100.100.100.100:53", "198.18.0.0:4000")),
			verdict: ToStack, wantOwner: "personal",
			wantSrc: "100.70.2.9", wantDst: "100.100.100.100", wantQSrc: "100.100.100.100", wantQDst: "100.70.2.9"},
		{name: "inbound: another stack quoting a host flow to quad-100", owner: "friends",
			b: icmpErr("100.88.1.4", "100.99.0.1", pkt(ipproto.UDP, "100.99.0.1:4000", "100.100.100.100:53")), verdict: Drop},
		{name: "outbound: quad-100 quoted to another stack",
			b: icmpErr("100.99.0.1", "198.18.0.1", pkt(ipproto.UDP, "100.100.100.100:53", "100.99.0.1:4000")), verdict: Drop},
	})
}
