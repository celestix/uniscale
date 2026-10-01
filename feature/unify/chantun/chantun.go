// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package chantun provides an in-memory tun.Device that connects one
// tailnet stack to the unify packet loop.
//
// The stack uses a [Device] like any TUN device: it reads the packets the
// loop injects with [Device.Inject] and writes packets that the loop
// receives from [Device.Packets].
package chantun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"
)

// Device is an in-memory tun.Device. It is safe for concurrent use.
type Device struct {
	name      string
	batch     int
	mtu       atomic.Int32
	toStack   chan []byte
	fromStack chan []byte
	done      chan struct{}

	readMu  sync.Mutex
	pending []byte // packet taken from toStack that did not fit the last Read

	mu     sync.Mutex // guards events and closed
	events chan tun.Event
	closed bool
}

var _ tun.Device = (*Device)(nil)

// New returns a device. mtu and batch must be positive; depth is the number
// of packets buffered in each direction.
func New(name string, mtu, batch, depth int) (*Device, error) {
	if mtu <= 0 || batch <= 0 || depth < 0 {
		return nil, errors.New("chantun: mtu and batch must be positive and depth not negative")
	}
	d := &Device{
		name:      name,
		batch:     batch,
		toStack:   make(chan []byte, depth),
		fromStack: make(chan []byte, depth),
		done:      make(chan struct{}),
		events:    make(chan tun.Event, 4),
	}
	d.mtu.Store(int32(mtu))
	d.events <- tun.EventUp
	return d, nil
}

// Inject queues pkt for the stack to read. It takes ownership of pkt and
// blocks until there is room, ctx is done, or the device is closed.
func (d *Device) Inject(ctx context.Context, pkt []byte) error {
	select {
	case <-d.done:
		return os.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case d.toStack <- pkt:
		return nil
	}
}

// Packets returns the packets the stack writes. The channel is never
// closed; select on [Device.Done] as well.
func (d *Device) Packets() <-chan []byte { return d.fromStack }

// Done is closed when the device is closed.
func (d *Device) Done() <-chan struct{} { return d.done }

// SetMTU changes the MTU and notifies the stack.
func (d *Device) SetMTU(mtu int) {
	d.mtu.Store(int32(mtu))
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.events <- tun.EventMTUUpdate:
	default: // event buffer full; update is dropped but MTU() still returns the latest value
	}
}

// File implements tun.Device. There is no file descriptor.
func (d *Device) File() *os.File { return nil }

// Read implements tun.Device. It blocks for the first packet, then adds
// any further queued packets that fit in slab and packets.
func (d *Device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, tun.ErrTooManySegments
	}
	first := d.pending
	d.pending = nil
	if first == nil {
		select {
		case <-d.done:
			return 0, os.ErrClosed
		case first = <-d.toStack:
		}
	}
	n, off := 0, tun.ReadPacketSpacing
	place := func(p []byte) bool {
		if off+len(p)+tun.ReadPacketSpacing > len(slab) {
			return false
		}
		copy(slab[off:], p)
		packets[n] = tun.ReadPacket{Offset: off, Size: len(p)}
		n++
		off += len(p) + tun.ReadPacketSpacing
		return true
	}
	if !place(first) {
		return 0, tun.ErrTooManySegments // larger than the whole slab: dropped
	}
	for n < len(packets) {
		select {
		case p := <-d.toStack:
			if !place(p) {
				d.pending = p
				return n, nil
			}
		default:
			return n, nil
		}
	}
	return n, nil
}

// Write implements tun.Device. It copies each packet (from offset) and
// blocks until the loop has room or the device is closed.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset > len(b) {
			return i, errors.New("chantun: offset out of range")
		}
		p := bytes.Clone(b[offset:])
		select {
		case <-d.done:
			return i, os.ErrClosed
		case d.fromStack <- p:
		}
	}
	return len(bufs), nil
}

// MTU implements tun.Device.
func (d *Device) MTU() (int, error) { return int(d.mtu.Load()), nil }

// Name implements tun.Device.
func (d *Device) Name() (string, error) { return d.name, nil }

// Events implements tun.Device.
func (d *Device) Events() <-chan tun.Event { return d.events }

// BatchSize implements tun.Device.
func (d *Device) BatchSize() int { return d.batch }

// Close implements tun.Device. It is safe to call more than once.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.done)
		close(d.events)
	}
	return nil
}
