// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
)

const (
	testBatch   = 8
	testTimeout = 10 * time.Second
)

// The loop tests use two tailnets whose stacks have the same real
// addresses:
//
//	a (primary, quad-100): self 100.64.0.2, fd7a:115c:a1e0::2 (identity)
//	                       peer 100.64.0.1, fd7a:115c:a1e0::1 (identity)
//	b:                     the same real addresses, remapped
//
// The test plays the host's kernel on the host device, and both stacks on
// their devices.
type loopHarness struct {
	t     *testing.T
	tb    *remap.Table
	tr    *xlate.Translator
	clock *tstest.Clock
	host  *chantun.Device // the test's side of the host TUN
	l     *loop
	a, b  *chantun.Device
	devs  map[remap.Owner]*chantun.Device // as last passed to SetStacks

	// Virtual addresses of b's self and peer.
	b4self, b4peer, b6self, b6peer netip.Addr
}

var (
	realSelf4, realPeer4 = netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1")
	realSelf6, realPeer6 = netip.MustParseAddr("fd7a:115c:a1e0::2"), netip.MustParseAddr("fd7a:115c:a1e0::1")
)

type harnessOpts struct {
	hostDepth int                              // default 64
	wrapHost  func(*chantun.Device) tun.Device // the loop's host device; default the chantun itself
	onlyA     bool                             // start with only a's device
}

func newLoopHarness(t *testing.T, opts harnessOpts) *loopHarness {
	t.Helper()
	h := &loopHarness{t: t, clock: tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_800_000_000, 0)})}
	var err error
	h.tb, err = remap.New(remap.Config{Pool6: mpp("fd00:1::/48")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	self := []netip.Prefix{netip.PrefixFrom(realSelf4, 32), netip.PrefixFrom(realSelf6, 128)}
	peers := []netip.Prefix{netip.PrefixFrom(realPeer4, 32), netip.PrefixFrom(realPeer6, 128)}
	for _, owner := range []remap.Owner{"a", "b"} {
		if _, err := h.tb.Sync(owner, remap.Order(self, peers, nil), h.clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	virt := func(a netip.Addr) netip.Addr {
		v, ok := h.tb.RealToVirtual("b", a)
		if !ok || v == a {
			t.Fatalf("b's %v is not remapped", a)
		}
		return v
	}
	h.b4self, h.b4peer, h.b6self, h.b6peer = virt(realSelf4), virt(realPeer4), virt(realSelf6), virt(realPeer6)

	h.tr = xlate.New(h.tb, append([]netip.Prefix{tsaddr.CGNATRange(), tsaddr.TailscaleULARange()}, h.tb.Pools()...))
	selfAddrs := []netip.Addr{realSelf4, realSelf6}
	if err := h.tr.SetStacks([]xlate.Stack{
		{Owner: "a", Self: selfAddrs, Quad100: true},
		{Owner: "b", Self: selfAddrs},
	}); err != nil {
		t.Fatal(err)
	}

	depth := opts.hostDepth
	if depth == 0 {
		depth = 64
	}
	h.host = newDev(t, "unify-host", depth)
	h.a, h.b = newDev(t, "a", 16), newDev(t, "b", 16)
	var host tun.Device = h.host
	if opts.wrapHost != nil {
		host = opts.wrapHost(h.host)
	}
	h.l, err = newLoop(loopConfig{host: host, tr: h.tr, logf: t.Logf, now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.l.Close() })
	if opts.onlyA {
		h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a})
	} else {
		h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": h.b})
	}
	return h
}

func newDev(t *testing.T, name string, depth int) *chantun.Device {
	t.Helper()
	d, err := chantun.New(name, 1500, testBatch, depth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func (h *loopHarness) setStacks(devs map[remap.Owner]*chantun.Device) {
	h.devs = devs
	h.l.SetStacks(devs)
}

// fromHost has the host's kernel send pkts into the TUN.
func (h *loopHarness) fromHost(pkts ...[]byte) {
	h.t.Helper()
	for _, p := range pkts {
		if err := h.host.Inject(context.Background(), bytes.Clone(p)); err != nil {
			h.t.Fatal(err)
		}
	}
}

// toHost returns the next packet the loop wrote to the host.
func (h *loopHarness) toHost() []byte {
	h.t.Helper()
	select {
	case p := <-h.host.Packets():
		return p
	case <-time.After(testTimeout):
		h.t.Fatal("no packet reached the host")
		return nil
	}
}

// noHostPacket checks that the loop has written nothing to the host.
func (h *loopHarness) noHostPacket() {
	h.t.Helper()
	if n := len(h.host.Packets()); n != 0 {
		h.t.Fatalf("%d unexpected packets reached the host; first % x", n, <-h.host.Packets())
	}
}

// fromStack has the stack on dev write pkts, in one batch.
func (h *loopHarness) fromStack(dev *chantun.Device, pkts ...[]byte) {
	h.t.Helper()
	if _, err := dev.Write(pkts, 0); err != nil {
		h.t.Fatal(err)
	}
}

// toStack returns the next packet the loop injected into dev.
func (h *loopHarness) toStack(dev *chantun.Device) []byte {
	h.t.Helper()
	type result struct {
		p   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		slab := make([]byte, 1<<17)
		pkts := make([]tun.ReadPacket, 1)
		n, err := dev.Read(slab, pkts)
		if n == 0 {
			ch <- result{err: err}
			return
		}
		ch <- result{p: bytes.Clone(slab[pkts[0].Offset : pkts[0].Offset+pkts[0].Size])}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatalf("reading the stack's device: %v", r.err)
		}
		return r.p
	case <-time.After(testTimeout):
		h.t.Fatal("no packet reached the stack") // the reader exits when dev is closed
		return nil
	}
}

// waitStats waits until cond holds for the loop's counters.
func (h *loopHarness) waitStats(what string, cond func(s loopStats) bool) {
	h.t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond(h.l.stats()) {
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s; stats %+v", what, h.l.stats())
		}
		time.Sleep(time.Millisecond)
	}
}

func ap(a netip.Addr, port uint16) string { return netip.AddrPortFrom(a, port).String() }

// wantAddrs checks b's addresses and checksums.
func wantAddrs(t *testing.T, b []byte, src, dst netip.Addr) {
	t.Helper()
	var q packet.Parsed
	q.Decode(b)
	if q.Src.Addr() != src || q.Dst.Addr() != dst {
		t.Fatalf("packet %v -> %v, want %v -> %v", q.Src.Addr(), q.Dst.Addr(), src, dst)
	}
	if !checksumsOK(t, b) {
		t.Fatalf("bad checksums: % x", b)
	}
}

func TestLoopOutbound(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})

	// Identity: a's peer at its real address.
	p := udpPkt(ap(realSelf4, 5000), ap(realPeer4, 53), []byte("to a"))
	h.fromHost(p)
	if got := h.toStack(h.a); !bytes.Equal(got, p) {
		t.Fatalf("a got % x, want the packet unchanged % x", got, p)
	}

	// Remapped: b's peer at its virtual address, from b's virtual self.
	h.fromHost(udpPkt(ap(h.b4self, 5000), ap(h.b4peer, 53), []byte("to b")))
	wantAddrs(t, h.toStack(h.b), realSelf4, realPeer4)
	h.fromHost(udpPkt(ap(h.b6self, 5000), ap(h.b6peer, 53), []byte("to b over ipv6")))
	wantAddrs(t, h.toStack(h.b), realSelf6, realPeer6)

	// Quad-100 goes to the primary.
	h.fromHost(udpPkt(ap(realSelf4, 5000), "100.100.100.100:53", []byte("dns")))
	wantAddrs(t, h.toStack(h.a), realSelf4, tsaddr.TailscaleServiceIP())

	// A burst keeps its order.
	var burst [][]byte
	for i := range 10 {
		burst = append(burst, udpPkt(ap(h.b4self, 5000+uint16(i)), ap(h.b4peer, 53), []byte{byte(i)}))
	}
	h.fromHost(burst...)
	for i := range 10 {
		got := h.toStack(h.b)
		var q packet.Parsed
		q.Decode(got)
		if q.Src.Port() != 5000+uint16(i) {
			t.Fatalf("packet %d of the burst has source port %d", i, q.Src.Port())
		}
		wantAddrs(t, got, realSelf4, realPeer4)
	}
	h.waitStats("delivery counts", func(s loopStats) bool { return s.toStack == 14 })
	h.noHostPacket()
}

func TestLoopInbound(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})

	p := udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), []byte("from a"))
	h.fromStack(h.a, p)
	if got := h.toHost(); !bytes.Equal(got, p) {
		t.Fatalf("host got % x, want the packet unchanged % x", got, p)
	}

	h.fromStack(h.b, udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), []byte("from b")))
	wantAddrs(t, h.toHost(), h.b4peer, h.b4self)
	h.fromStack(h.b, udpPkt(ap(realPeer6, 53), ap(realSelf6, 5000), []byte("from b over ipv6")))
	wantAddrs(t, h.toHost(), h.b6peer, h.b6self)

	// One batch from the stack, more packets than the host's batch size,
	// in order.
	var batch [][]byte
	for i := range 3 * testBatch {
		batch = append(batch, udpPkt(ap(realPeer4, 53), ap(realSelf4, 6000+uint16(i)), []byte{byte(i)}))
	}
	h.fromStack(h.b, batch...)
	for i := range 3 * testBatch {
		got := h.toHost()
		var q packet.Parsed
		q.Decode(got)
		if q.Dst.Port() != 6000+uint16(i) {
			t.Fatalf("packet %d of the batch has destination port %d", i, q.Dst.Port())
		}
		wantAddrs(t, got, h.b4peer, h.b4self)
	}

	// Packets of the largest sizes fill the write buffer: the loop writes
	// what it has and starts a new batch.
	var large [][]byte
	for i := range 3 {
		large = append(large, udpPkt(ap(realPeer4, 53), ap(realSelf4, 7000+uint16(i)), bytes.Repeat([]byte{byte(i)}, 65535-28)))
	}
	h.fromStack(h.b, large...)
	for i := range 3 {
		got := h.toHost()
		if len(got) != 65535 {
			t.Fatalf("large packet %d is %d bytes", i, len(got))
		}
		wantAddrs(t, got, h.b4peer, h.b4self)
	}
	h.waitStats("delivery counts", func(s loopStats) bool { return s.toHost == 3+3*testBatch+3 })

	// A packet larger than the write buffer is dropped, not split.
	marker := udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), []byte("marker"))
	h.fromStack(h.b, make([]byte, hostSlabSize-hostWriteOffset+1), marker)
	wantAddrs(t, h.toHost(), h.b4peer, h.b4self)
	if s := h.l.stats(); s.inDropped != 1 {
		t.Fatalf("inDropped = %d, want 1", s.inDropped)
	}
}

// Packets that xlate drops never reach the other side, and only a missing
// route is answered.
func TestLoopDrops(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})
	marker := udpPkt(ap(h.b4self, 5000), ap(h.b4peer, 53), []byte("marker"))

	for _, c := range []struct {
		name string
		pkt  []byte
	}{
		{"a's source to b's peer", udpPkt(ap(realSelf4, 5000), ap(h.b4peer, 53), nil)},
		{"b's real self as source", udpPkt(ap(realSelf6, 5000), ap(h.b6peer, 53), nil)},
		{"garbage", []byte{0x45, 1, 2, 3}},
		{"ipv4 length beyond the packet", []byte{0x45, 0, 0, 0xff, 0, 0, 0, 0, 64, 17, 0, 0, 100, 64, 0, 2, 100, 64, 0, 9}},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := h.l.stats()
			h.fromHost(c.pkt, marker)
			// The loop handles host packets in order: the marker comes
			// first, and nothing was written back to the host.
			wantAddrs(t, h.toStack(h.b), realSelf4, realPeer4)
			s := h.l.stats()
			if s.outDropped != before.outDropped+1 || s.icmpSent != before.icmpSent {
				t.Fatalf("stats %+v, before %+v", s, before)
			}
			h.noHostPacket()
		})
	}

	// From a stack: a source the tailnet does not map, an address of
	// another tailnet, and a stack the translator does not know.
	c := newDev(t, "c", 16)
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": h.b, "c": c})
	h.fromStack(h.a, udpPkt("100.64.0.77:53", ap(realSelf4, 5000), nil))
	h.fromStack(h.b, udpPkt(ap(realPeer4, 53), ap(h.b4self, 5000), nil))
	h.fromStack(c, udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), nil))
	h.waitStats("inbound drops", func(s loopStats) bool { return s.inDropped == 3 })
	ma := udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), []byte("marker"))
	h.fromStack(h.a, ma)
	if got := h.toHost(); !bytes.Equal(got, ma) {
		t.Fatalf("host got % x, want only the marker", got)
	}
	h.waitStats("the marker only", func(s loopStats) bool { return s.toHost == 1 })
	if s := h.l.stats(); s.inDropped != 3 {
		t.Fatalf("inDropped = %d, want 3", s.inDropped)
	}
}

// R16: a packet from the host without a route is answered with an ICMP
// destination unreachable.
func TestLoopUnreachable(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})

	check := func(t *testing.T, orig []byte, typ, code byte, quoteLen int) {
		t.Helper()
		got := h.toHost()
		var q, oq packet.Parsed
		q.Decode(got)
		oq.Decode(orig)
		wantAddrs(t, got, oq.Dst.Addr(), oq.Src.Addr())
		hl := 20
		if q.IPVersion == 6 {
			hl = 40
		}
		if got[hl] != typ || got[hl+1] != code {
			t.Fatalf("type/code %d/%d, want %d/%d", got[hl], got[hl+1], typ, code)
		}
		if !bytes.Equal(got[hl+8:], orig[:quoteLen]) {
			t.Fatalf("quote % x, want % x", got[hl+8:], orig[:quoteLen])
		}
	}
	t.Run("ipv4", func(t *testing.T) {
		p := udpPkt(ap(realSelf4, 5000), "100.64.9.9:53", []byte("nobody home"))
		h.fromHost(p)
		check(t, p, 3, 1, 28)
	})
	t.Run("private network without an exit node", func(t *testing.T) {
		p := udpPkt(ap(realSelf4, 5000), "192.168.77.1:53", nil)
		h.fromHost(p)
		check(t, p, 3, 1, 28)
	})
	t.Run("ipv6", func(t *testing.T) {
		p := udpPkt(ap(realSelf6, 5000), "[fd7a:115c:a1e0::99]:53", bytes.Repeat([]byte{1}, 1400))
		h.fromHost(p)
		check(t, p, 1, 3, 1280-48)
	})
	t.Run("not for errors, multicast or later fragments", func(t *testing.T) {
		// A reply is counted after it is written: wait for the
		// earlier ones.
		h.waitStats("the earlier replies", func(s loopStats) bool { return s.icmpSent == 3 })
		before := h.l.stats()
		quoted := udpPkt("100.64.9.9:53", ap(realSelf4, 5000), nil)
		h.fromHost(
			icmpPkt(realSelf4.String(), "100.64.9.9", 3, 1, append(make([]byte, 4), quoted...)),
			udpPkt(ap(realSelf4, 5000), "224.0.0.251:5353", nil),
			asFragment(udpPkt(ap(realSelf4, 5000), "100.64.9.9:53", bytes.Repeat([]byte{1}, 2000)), 100),
		)
		marker := udpPkt(ap(realSelf4, 5001), "100.64.9.9:53", nil)
		h.fromHost(marker)
		check(t, marker, 3, 1, 28)
		h.waitStats("one reply", func(s loopStats) bool { return s.icmpSent == before.icmpSent+1 })
		if s := h.l.stats(); s.outDropped != before.outDropped+4 {
			t.Fatalf("stats %+v, before %+v", s, before)
		}
		h.noHostPacket()
	})
}

// R16: replies are rate-limited to 10 per second with a burst of 10.
func TestLoopUnreachableRateLimit(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})
	send := func(n int) {
		for i := range n {
			h.fromHost(udpPkt(ap(realSelf4, 5000+uint16(i)), "100.64.9.9:53", nil))
		}
	}
	drain := func(n int) {
		for range n {
			h.toHost()
		}
		h.noHostPacket()
	}

	// A packet's reply is decided after its drop is counted: wait for the
	// replies.
	send(15)
	h.waitStats("15 replies or not", func(s loopStats) bool { return s.icmpSent+s.icmpLimited == 15 })
	if s := h.l.stats(); s.icmpSent != 10 || s.icmpLimited != 5 {
		t.Fatalf("after a burst of 15: sent %d, limited %d; want 10, 5", s.icmpSent, s.icmpLimited)
	}
	drain(10)

	h.clock.Advance(200 * time.Millisecond) // two tokens
	send(3)
	h.waitStats("18 replies or not", func(s loopStats) bool { return s.icmpSent+s.icmpLimited == 18 })
	if s := h.l.stats(); s.icmpSent != 12 || s.icmpLimited != 6 {
		t.Fatalf("200ms later: sent %d, limited %d; want 12, 6", s.icmpSent, s.icmpLimited)
	}
	drain(2)

	h.clock.Advance(time.Hour) // the bucket holds no more than the burst
	send(12)
	h.waitStats("30 replies or not", func(s loopStats) bool { return s.icmpSent+s.icmpLimited == 30 })
	if s := h.l.stats(); s.icmpSent != 22 || s.icmpLimited != 8 {
		t.Fatalf("an hour later: sent %d, limited %d; want 22, 8", s.icmpSent, s.icmpLimited)
	}
	drain(10)
}

func TestLoopSetStacks(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{onlyA: true})
	toB := func(tag string) []byte { return udpPkt(ap(h.b4self, 5000), ap(h.b4peer, 53), []byte(tag)) }
	fromB := udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), []byte("from b"))

	// The translator routes to b, but the loop has no device for it yet.
	h.fromHost(toB("early"))
	h.waitStats("a packet for a missing stack", func(s loopStats) bool { return s.noStack == 1 })

	// Added while running.
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": h.b})
	h.fromHost(toB("added"))
	wantAddrs(t, h.toStack(h.b), realSelf4, realPeer4)
	h.fromStack(h.b, fromB)
	wantAddrs(t, h.toHost(), h.b4peer, h.b4self)

	// The same set again changes nothing.
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": h.b})
	h.fromHost(toB("same"))
	wantAddrs(t, h.toStack(h.b), realSelf4, realPeer4)

	// Removed: once SetStacks returns, the loop neither reads b's device
	// nor writes to it.
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a})
	h.fromStack(h.b, fromB)
	h.fromHost(toB("removed"))
	h.waitStats("a packet for a removed stack", func(s loopStats) bool { return s.noStack == 2 })
	if n := len(h.b.Packets()); n != 1 {
		t.Fatalf("the loop still reads a removed stack: %d of 1 packets left", n)
	}
	h.noHostPacket()

	// Replaced by a new device.
	b2 := newDev(t, "b2", 16)
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": b2})
	h.fromHost(toB("replaced"))
	wantAddrs(t, h.toStack(b2), realSelf4, realPeer4)
	h.fromStack(b2, fromB)
	wantAddrs(t, h.toHost(), h.b4peer, h.b4self)
	b3 := newDev(t, "b3", 16)
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": b3})
	h.fromStack(b2, fromB)
	h.fromStack(b3, fromB)
	wantAddrs(t, h.toHost(), h.b4peer, h.b4self)
	if n := len(b2.Packets()); n != 1 {
		t.Fatalf("the loop still reads a replaced device: %d of 1 packets left", n)
	}
	h.noHostPacket()

	// A nil device is no device.
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": nil})
	h.fromHost(toB("nil"))
	h.waitStats("a packet for a nil device", func(s loopStats) bool { return s.noStack == 3 })

	// No stacks at all.
	h.setStacks(nil)
	h.fromHost(udpPkt(ap(realSelf4, 5000), ap(realPeer4, 53), nil))
	h.waitStats("a packet with no stacks", func(s loopStats) bool { return s.noStack == 4 })
}

// SetStacks returns only once a removed stack's reader has stopped, even
// if it is busy writing to the host.
func TestLoopSetStacksWaitsForReader(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{hostDepth: 1})
	p := func(port uint16) []byte { return udpPkt(ap(realPeer4, 53), ap(realSelf4, port), nil) }
	h.fromStack(h.b, p(1), p(2))
	// The host holds one packet; b's reader holds the other and is
	// blocked writing it.
	deadline := time.Now().Add(testTimeout)
	for len(h.host.Packets()) != 1 || len(h.b.Packets()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("b's reader did not block on the host")
		}
		time.Sleep(time.Millisecond)
	}
	set := make(chan struct{})
	go func() {
		h.l.SetStacks(map[remap.Owner]*chantun.Device{"a": h.a})
		close(set)
	}()
	select {
	case <-set:
		t.Fatal("SetStacks returned while the removed stack's reader was still writing")
	case <-time.After(100 * time.Millisecond):
	}
	h.toHost()
	h.toHost()
	<-set
	h.fromStack(h.b, p(3))
	if n := len(h.b.Packets()); n != 1 {
		t.Fatalf("the loop still reads a removed stack: %d of 1 packets left", n)
	}
	h.noHostPacket()
}

// A stack that closes its device stops being read, and packets for it are
// dropped until SetStacks removes it.
func TestLoopStackClosed(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})
	h.b.Close()
	h.fromHost(udpPkt(ap(h.b4self, 5000), ap(h.b4peer, 53), nil))
	h.waitStats("a packet for a closed stack", func(s loopStats) bool { return s.noStack == 1 })
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": h.b}) // still there: no new reader
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a})
	p := udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), nil)
	h.fromStack(h.a, p)
	if got := h.toHost(); !bytes.Equal(got, p) {
		t.Fatal("a stopped working")
	}
}

// A stack whose queue is full loses packets; the others are not held up.
func TestLoopQueueFull(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})
	slow := newDev(t, "slow", 1)
	h.setStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": slow})
	for i := range 3 {
		h.fromHost(udpPkt(ap(h.b4self, 5000+uint16(i)), ap(h.b4peer, 53), nil))
	}
	p := udpPkt(ap(realSelf4, 5000), ap(realPeer4, 53), []byte("a is not held up"))
	h.fromHost(p)
	if got := h.toStack(h.a); !bytes.Equal(got, p) {
		t.Fatal("a did not get its packet")
	}
	h.waitStats("two delivered, two lost", func(s loopStats) bool { return s.toStack == 2 && s.queueFull == 2 })
	var q packet.Parsed
	q.Decode(h.toStack(slow))
	if q.Src.Port() != 5000 {
		t.Fatalf("slow stack got source port %d, want the first packet", q.Src.Port())
	}
}

func TestLoopClose(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{hostDepth: 1})

	// Leave the stack's reader blocked writing to a full host queue.
	pkts := [][]byte{
		udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), nil),
		udpPkt(ap(realPeer4, 53), ap(realSelf4, 5001), nil),
	}
	h.fromStack(h.a, pkts...)
	h.waitStats("one packet written", func(s loopStats) bool { return s.toHost >= 1 || len(h.host.Packets()) == 1 })

	select {
	case <-h.l.Done():
		t.Fatal("Done before Close")
	default:
	}
	if err := h.l.Err(); err != nil {
		t.Fatalf("Err while running = %v", err)
	}
	if err := h.l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-h.l.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	if err := h.l.Err(); err != nil {
		t.Fatalf("Err after Close = %v", err)
	}
	select {
	case <-h.host.Done():
	default:
		t.Fatal("Close did not close the host device")
	}
	if err := h.l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// SetStacks after Close starts nothing (ResourceCheck would see it).
	h.l.SetStacks(map[remap.Owner]*chantun.Device{"a": h.a, "b": h.b})
	if h.a.Inject(context.Background(), []byte{1}) != nil {
		t.Fatal("Close closed a stack's device; stacks own theirs")
	}
}

// faultyHost is a host device with scripted reads and failing writes.
type faultyHost struct {
	*chantun.Device
	reads     chan func(slab []byte, pkts []tun.ReadPacket) (int, error)
	failWrite atomic.Bool
}

var errInjected = errors.New("injected failure")

func (f *faultyHost) Read(slab []byte, pkts []tun.ReadPacket) (int, error) {
	select {
	case r := <-f.reads:
		return r(slab, pkts)
	default:
		return f.Device.Read(slab, pkts)
	}
}

func (f *faultyHost) Write(bufs [][]byte, offset int) (int, error) {
	if f.failWrite.Load() {
		return 0, errInjected
	}
	return f.Device.Write(bufs, offset)
}

func newFaultyHarness(t *testing.T, reads ...func(slab []byte, pkts []tun.ReadPacket) (int, error)) (*loopHarness, *faultyHost) {
	var f *faultyHost
	h := newLoopHarness(t, harnessOpts{wrapHost: func(d *chantun.Device) tun.Device {
		f = &faultyHost{Device: d, reads: make(chan func([]byte, []tun.ReadPacket) (int, error), len(reads))}
		for _, r := range reads {
			f.reads <- r
		}
		return f
	}})
	return h, f
}

func TestLoopHostReadError(t *testing.T) {
	tstest.ResourceCheck(t)
	h, _ := newFaultyHarness(t, func([]byte, []tun.ReadPacket) (int, error) { return 0, errInjected })
	select {
	case <-h.l.Done():
	case <-time.After(testTimeout):
		t.Fatal("the loop did not stop on a read error")
	}
	if err := h.l.Err(); !errors.Is(err, errInjected) {
		t.Fatalf("Err = %v, want %v", err, errInjected)
	}
	// Stacks are still drained, so they do not stall, until Close.
	h.fromStack(h.a, udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), nil))
	h.toHost()
	if err := h.l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoopHostClosedUnderneath(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})
	h.host.Close()
	select {
	case <-h.l.Done():
	case <-time.After(testTimeout):
		t.Fatal("the loop did not stop when the host device closed")
	}
	if err := h.l.Err(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Err = %v, want %v", err, os.ErrClosed)
	}
}

// Read may return packets with an error. ErrTooManySegments loses part of
// a batch but is not fatal. Entries outside the slab, and counts outside
// the entries given, are ignored.
func TestLoopHostPartialRead(t *testing.T) {
	tstest.ResourceCheck(t)
	p1 := udpPkt(ap(realSelf4, 5001), ap(realPeer4, 53), []byte("with ErrTooManySegments"))
	p2 := udpPkt(ap(realSelf4, 5002), ap(realPeer4, 53), []byte("after bad entries"))
	place := func(slab []byte, off int, p []byte) tun.ReadPacket {
		copy(slab[off:], p)
		return tun.ReadPacket{Offset: off, Size: len(p)}
	}
	h, _ := newFaultyHarness(t,
		func(slab []byte, pkts []tun.ReadPacket) (int, error) {
			pkts[0] = place(slab, tun.ReadPacketSpacing, p1)
			return 1, tun.ErrTooManySegments
		},
		func(slab []byte, pkts []tun.ReadPacket) (int, error) {
			pkts[0] = tun.ReadPacket{Offset: len(slab) - 10, Size: 20} // past the slab
			pkts[1] = tun.ReadPacket{Offset: -1, Size: 20}
			pkts[2] = tun.ReadPacket{Offset: 100, Size: -5}
			pkts[3] = place(slab, 2000, p2)
			return 4, nil
		},
		func(slab []byte, pkts []tun.ReadPacket) (int, error) { return len(pkts) + 1, nil },
		func(slab []byte, pkts []tun.ReadPacket) (int, error) { return -1, nil },
	)
	for _, want := range [][]byte{p1, p2} {
		if got := h.toStack(h.a); !bytes.Equal(got, want) {
			t.Fatalf("a got % x, want % x", got, want)
		}
	}
	p3 := udpPkt(ap(realSelf4, 5003), ap(realPeer4, 53), []byte("reading goes on"))
	h.fromHost(p3)
	if got := h.toStack(h.a); !bytes.Equal(got, p3) {
		t.Fatalf("a got % x, want % x", got, p3)
	}
	h.waitStats("read errors", func(s loopStats) bool { return s.readErrors == 6 && s.toStack == 3 })
	select {
	case <-h.l.Done():
		t.Fatalf("the loop stopped: %v", h.l.Err())
	default:
	}
}

func TestLoopHostWriteError(t *testing.T) {
	tstest.ResourceCheck(t)
	h, f := newFaultyHarness(t)
	f.failWrite.Store(true)
	h.fromStack(h.a, udpPkt(ap(realPeer4, 53), ap(realSelf4, 5000), nil))
	h.fromHost(udpPkt(ap(realSelf4, 5000), "100.64.9.9:53", nil)) // its ICMP error fails too
	h.waitStats("two failed writes", func(s loopStats) bool { return s.writeErrors == 2 })
	if s := h.l.stats(); s.toHost != 0 || s.icmpSent != 0 {
		t.Fatalf("failed writes counted as sent: %+v", s)
	}
	f.failWrite.Store(false)
	p := udpPkt(ap(realPeer4, 53), ap(realSelf4, 5001), nil)
	h.fromStack(h.a, p)
	if got := h.toHost(); !bytes.Equal(got, p) {
		t.Fatal("writing did not recover")
	}
}

// The loop drains the host device's events: a Linux TUN stops watching
// its link until they are read.
func TestLoopHostEvents(t *testing.T) {
	tstest.ResourceCheck(t)
	h := newLoopHarness(t, harnessOpts{})
	h.host.SetMTU(1400)
	deadline := time.Now().Add(testTimeout)
	for len(h.host.Events()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("host events are not drained")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNewLoopErrors(t *testing.T) {
	tb, err := remap.New(remap.Config{Pool6: mpp("fd00:1::/48")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev := newDev(t, "host", 1)
	if _, err := newLoop(loopConfig{tr: xlate.New(tb, nil)}); err == nil {
		t.Error("newLoop without a host device succeeded")
	}
	if _, err := newLoop(loopConfig{host: dev}); err == nil {
		t.Error("newLoop without a translator succeeded")
	}
	// Defaults: no logf, no clock.
	l, err := newLoop(loopConfig{host: dev, tr: xlate.New(tb, nil)})
	if err != nil {
		t.Fatal(err)
	}
	l.logf("not logged anywhere")
	if l.now().IsZero() {
		t.Error("no default clock")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
