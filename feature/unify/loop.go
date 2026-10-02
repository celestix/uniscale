// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/time/rate"
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
)

// Buffers for the host device. A Linux TUN from tstun.New uses virtio-net
// headers (IFF_VNET_HDR) when the kernel supports offloads:
//
//   - Read splits one large TSO or USO segment into up to BatchSize
//     packets, so the slab must hold the worst case of tun.GSOSplit.
//     hostSlabSize is wireguard-go's batchingSlabSize, which does.
//   - Write needs offset >= 10 (virtioNetHdrLen) of headroom before each
//     packet, and coalesces TCP and UDP packets (GRO), rewriting their
//     headers in place. hostWriteOffset leaves tun.ReadPacketSpacing (64),
//     more than both that and tstun.WritePacketStartOffset (16).
//
// Without offloads the device reads and writes one packet at a time and
// ignores the headroom. Write must not be relied on for a packet count:
// the Linux TUN returns bytes.
const (
	hostSlabSize    = 2 * (1<<16 - 1)
	hostWriteOffset = tun.ReadPacketSpacing
)

// loopConfig configures a [loop].
type loopConfig struct {
	host tun.Device        // the host's real TUN; the loop closes it
	tr   *xlate.Translator // decides where packets go
	logf logger.Logf       // nil to discard
	now  func() time.Time  // for the ICMP rate limit; nil for time.Now
}

// loop moves packets between the host's TUN and the stacks' chantun
// devices, translating them with xlate.
//
// One goroutine reads the host device. Each packet goes to the stack
// xlate picks, without blocking: if the stack's queue is full the packet
// is lost, as on a congested link, so a slow tailnet cannot hold up the
// others. A packet without a route is answered with an ICMP destination
// unreachable (see [wantsUnreachable]). One goroutine per stack reads its
// device and writes what xlate lets through to the host, in batches.
type loop struct {
	host      tun.Device
	tr        *xlate.Translator
	logf      logger.Logf
	now       func() time.Time
	icmpLimit *rate.Limiter // used by the host reader only

	ctx    context.Context // canceled by Close
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{} // closed when the host reader returns
	err    error         // why the host reader returned; set before done is closed

	devs atomic.Pointer[map[remap.Owner]*chantun.Device] // for the host reader

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool // no more SetStacks
	stacks    map[remap.Owner]*stackReader

	counters loopCounters
}

// stackReader is the goroutine reading one stack's device.
type stackReader struct {
	owner  remap.Owner
	dev    *chantun.Device
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when the goroutine returns
}

// loopCounters counts packets. Each is updated once the packet's fate is
// known.
type loopCounters struct {
	toStack     atomic.Uint64 // host packets injected into a stack
	toHost      atomic.Uint64 // stack packets written to the host
	outDropped  atomic.Uint64 // host packets xlate dropped
	inDropped   atomic.Uint64 // stack packets xlate dropped, or too large
	noStack     atomic.Uint64 // host packets for a stack without a device, or a closed one
	queueFull   atomic.Uint64 // host packets lost to a full stack queue
	icmpSent    atomic.Uint64 // ICMP destination unreachable written to the host
	icmpLimited atomic.Uint64 // ICMP destination unreachable not sent, by the rate limit
	readErrors  atomic.Uint64 // host reads or read entries that lost packets
	writeErrors atomic.Uint64 // failed host writes
}

// loopStats is a snapshot of [loopCounters].
type loopStats struct {
	toStack, toHost, outDropped, inDropped, noStack, queueFull uint64
	icmpSent, icmpLimited, readErrors, writeErrors             uint64
}

// newLoop starts a loop on cfg.host. It has no stacks until SetStacks.
func newLoop(cfg loopConfig) (*loop, error) {
	if cfg.host == nil || cfg.tr == nil {
		return nil, errors.New("unify: loop needs a host device and a translator")
	}
	if cfg.logf == nil {
		cfg.logf = logger.Discard
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &loop{
		host:      cfg.host,
		tr:        cfg.tr,
		logf:      logger.RateLimitedFn(cfg.logf, 10*time.Second, 3, 64),
		now:       cfg.now,
		icmpLimit: rate.NewLimiter(unreachableRate, unreachableBurst),
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		stacks:    map[remap.Owner]*stackReader{},
	}
	l.devs.Store(&map[remap.Owner]*chantun.Device{})
	l.wg.Add(2)
	go l.readHost()
	go l.drainHostEvents()
	return l, nil
}

// SetStacks sets the stacks' devices by owner. A nil device is no device.
// Packets xlate sends to an owner without a device are dropped. The loop
// starts reading devices that are new, and stops reading the others: once
// SetStacks returns, the loop no longer reads or injects into a device
// that is not in devs. It never closes them; the stacks own them. It may
// wait for a write to the host in progress. After Close it does nothing.
func (l *loop) SetStacks(devs map[remap.Owner]*chantun.Device) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	snap := make(map[remap.Owner]*chantun.Device, len(devs))
	for owner, dev := range devs {
		if dev != nil {
			snap[owner] = dev
		}
	}
	l.devs.Store(&snap)
	for owner, r := range l.stacks {
		if snap[owner] != r.dev {
			r.cancel()
			<-r.done
			delete(l.stacks, owner)
		}
	}
	for owner, dev := range snap {
		if _, ok := l.stacks[owner]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(l.ctx)
		r := &stackReader{owner: owner, dev: dev, ctx: ctx, cancel: cancel, done: make(chan struct{})}
		l.stacks[owner] = r
		l.wg.Add(1)
		go l.readStack(r)
	}
}

// Done is closed when the loop stops reading the host device: after Close,
// or on a read error (see Err). Stacks' devices are still read until
// Close, so that they do not stall.
func (l *loop) Done() <-chan struct{} { return l.done }

// Err returns the error that stopped the loop reading the host device, or
// nil if it has not stopped or was closed.
func (l *loop) Err() error {
	select {
	case <-l.done:
		return l.err
	default:
		return nil
	}
}

// Close stops the loop, closes the host device and waits for the loop's
// goroutines. It returns the host device's Close error the first time,
// and nil after that.
func (l *loop) Close() error {
	var err error
	l.closeOnce.Do(func() {
		// Before taking mu, which SetStacks may hold while it waits
		// for a stack reader: this stops every stack reader and
		// unblocks host reads and writes.
		l.cancel()
		err = l.host.Close()
	})
	l.mu.Lock()
	l.closed = true
	for _, r := range l.stacks {
		r.cancel()
	}
	l.stacks = nil
	l.mu.Unlock()
	l.wg.Wait()
	return err
}

func (l *loop) stats() loopStats {
	c := &l.counters
	return loopStats{
		toStack:     c.toStack.Load(),
		toHost:      c.toHost.Load(),
		outDropped:  c.outDropped.Load(),
		inDropped:   c.inDropped.Load(),
		noStack:     c.noStack.Load(),
		queueFull:   c.queueFull.Load(),
		icmpSent:    c.icmpSent.Load(),
		icmpLimited: c.icmpLimited.Load(),
		readErrors:  c.readErrors.Load(),
		writeErrors: c.writeErrors.Load(),
	}
}

// drainHostEvents reads the host device's events until it is closed. A
// Linux TUN stops watching its link until they are read. Unify follows
// link changes through netmon instead.
func (l *loop) drainHostEvents() {
	defer l.wg.Done()
	for range l.host.Events() {
	}
}

// readHost reads the host device until it fails or is closed.
func (l *loop) readHost() {
	defer l.wg.Done()
	defer close(l.done)
	slab := make([]byte, hostSlabSize)
	pkts := make([]tun.ReadPacket, max(l.host.BatchSize(), 1))
	var q packet.Parsed
	for {
		n, err := l.host.Read(slab, pkts)
		if n < 0 || n > len(pkts) {
			l.counters.readErrors.Add(1)
			l.logf("unify: host read returned %d of %d packets", n, len(pkts))
			n = 0
		}
		for _, p := range pkts[:n] {
			if p.Offset < 0 || p.Size < 0 || p.Offset+p.Size > len(slab) {
				l.counters.readErrors.Add(1)
				continue
			}
			l.outbound(&q, slab[p.Offset:p.Offset+p.Size])
		}
		switch {
		case err == nil:
		case errors.Is(err, tun.ErrTooManySegments):
			// Some packets of a large segment are lost; TCP resends.
			l.counters.readErrors.Add(1)
			l.logf("unify: reading from the host: %v", err)
		default:
			if l.ctx.Err() == nil {
				l.err = err
				l.logf("unify: reading from the host stopped: %v", err)
			}
			return
		}
	}
}

// outbound handles b, a packet the host sent, decoded into q.
func (l *loop) outbound(q *packet.Parsed, b []byte) {
	q.Decode(b)
	r := l.tr.Outbound(q)
	if r.Verdict != xlate.ToStack {
		l.counters.outDropped.Add(1)
		if r.Reason == xlate.DropNoRoute {
			l.replyUnreachable(b) // xlate leaves dropped packets unchanged
		}
		return
	}
	dev := (*l.devs.Load())[r.Owner]
	if dev == nil {
		l.counters.noStack.Add(1)
		return
	}
	switch err := dev.TryInject(bytes.Clone(b)); {
	case err == nil:
		l.counters.toStack.Add(1)
	case errors.Is(err, chantun.ErrFull):
		l.counters.queueFull.Add(1)
		l.logf("unify: tailnet %q is not keeping up; dropping packets", r.Owner)
	default:
		l.counters.noStack.Add(1)
	}
}

// replyUnreachable answers b, a packet from the host with no route, with
// an ICMP destination unreachable, if it may be answered and the rate
// limit allows.
func (l *loop) replyUnreachable(b []byte) {
	if !wantsUnreachable(b) {
		return
	}
	if !l.icmpLimit.AllowN(l.now(), 1) {
		l.counters.icmpLimited.Add(1)
		return
	}
	if l.writeHost([][]byte{unreachable(b, hostWriteOffset)}) {
		l.counters.icmpSent.Add(1)
	}
}

// writeHost writes bufs, each with its packet at hostWriteOffset, to the
// host device. It reports whether that succeeded.
func (l *loop) writeHost(bufs [][]byte) bool {
	if _, err := l.host.Write(bufs, hostWriteOffset); err != nil {
		l.counters.writeErrors.Add(1)
		if !errors.Is(err, os.ErrClosed) {
			l.logf("unify: writing %d packets to the host: %v", len(bufs), err)
		}
		return false
	}
	return true
}

// readStack reads r's device until r is stopped or the device closed.
func (l *loop) readStack(r *stackReader) {
	defer l.wg.Done()
	defer close(r.done)
	w := &hostBatch{
		slab: make([]byte, hostSlabSize),
		bufs: make([][]byte, 0, max(l.host.BatchSize(), 1)),
	}
	var q packet.Parsed
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.dev.Done():
			return
		case pkt := <-r.dev.Packets():
			l.inbound(r.owner, &q, pkt, w)
		}
	more:
		for len(w.bufs) < cap(w.bufs) {
			select {
			case pkt := <-r.dev.Packets():
				l.inbound(r.owner, &q, pkt, w)
			default:
				break more
			}
		}
		l.flush(w)
	}
}

// hostBatch is packets waiting to be written to the host, each with
// hostWriteOffset bytes of headroom, packed into slab.
type hostBatch struct {
	slab []byte
	used int
	bufs [][]byte
}

// inbound translates pkt, a packet stack owner sent, decoded into q, and
// adds it to w if xlate lets it through.
func (l *loop) inbound(owner remap.Owner, q *packet.Parsed, pkt []byte, w *hostBatch) {
	need := hostWriteOffset + len(pkt)
	if need > len(w.slab) {
		l.counters.inDropped.Add(1)
		return
	}
	if w.used+need > len(w.slab) {
		l.flush(w)
	}
	buf := w.slab[w.used : w.used+need]
	copy(buf[hostWriteOffset:], pkt)
	q.Decode(buf[hostWriteOffset:])
	if r := l.tr.Inbound(owner, q); r.Verdict != xlate.ToHost {
		l.counters.inDropped.Add(1)
		return
	}
	w.bufs = append(w.bufs, buf)
	w.used += need
}

// flush writes w's packets to the host and empties w.
func (l *loop) flush(w *hostBatch) {
	if len(w.bufs) == 0 {
		return
	}
	if l.writeHost(w.bufs) {
		l.counters.toHost.Add(uint64(len(w.bufs)))
	}
	w.bufs, w.used = w.bufs[:0], 0
}
