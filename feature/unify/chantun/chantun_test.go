// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package chantun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

func newDev(t *testing.T, batch, depth int) *Device {
	t.Helper()
	d, err := New("ts-work", 1280, batch, depth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestNewValidates(t *testing.T) {
	for _, c := range [][3]int{{0, 1, 1}, {1280, 0, 1}, {1280, 1, -1}} {
		if _, err := New("x", c[0], c[1], c[2]); err == nil {
			t.Errorf("New(mtu=%d, batch=%d, depth=%d): want error", c[0], c[1], c[2])
		}
	}
}

func TestMetadata(t *testing.T) {
	d := newDev(t, 8, 1)
	if n, _ := d.Name(); n != "ts-work" {
		t.Errorf("Name = %q", n)
	}
	if m, _ := d.MTU(); m != 1280 {
		t.Errorf("MTU = %d", m)
	}
	if d.BatchSize() != 8 || d.File() != nil {
		t.Error("BatchSize or File wrong")
	}
	if e := <-d.Events(); e != tun.EventUp {
		t.Errorf("first event = %v, want EventUp", e)
	}
	d.SetMTU(1200)
	d.SetMTU(1100) // a second update before the stack reads events
	if e := <-d.Events(); e != tun.EventMTUUpdate {
		t.Errorf("event = %v, want EventMTUUpdate", e)
	}
	if m, _ := d.MTU(); m != 1100 {
		t.Errorf("MTU after SetMTU = %d", m)
	}
}

func readSlab(t *testing.T, d *Device, slabSize, nPackets int) [][]byte {
	t.Helper()
	slab := make([]byte, slabSize)
	pkts := make([]tun.ReadPacket, nPackets)
	n, err := d.Read(slab, pkts)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var out [][]byte
	for _, p := range pkts[:n] {
		if p.Offset < tun.ReadPacketSpacing {
			t.Fatalf("packet offset %d leaves no leading spacing", p.Offset)
		}
		out = append(out, slab[p.Offset:p.Offset+p.Size])
	}
	return out
}

func TestInjectAndBatchedRead(t *testing.T) {
	d := newDev(t, 4, 8)
	ctx := context.Background()
	for _, s := range []string{"one", "two", "three"} {
		if err := d.Inject(ctx, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	got := readSlab(t, d, 1024, 4)
	if len(got) != 3 || string(got[0]) != "one" || string(got[2]) != "three" {
		t.Fatalf("Read = %q", got)
	}
}

func TestReadKeepsPacketThatDoesNotFit(t *testing.T) {
	d := newDev(t, 4, 8)
	ctx := context.Background()
	d.Inject(ctx, bytes.Repeat([]byte("a"), 40))
	d.Inject(ctx, bytes.Repeat([]byte("b"), 40))
	// Room for one 40-byte packet plus spacing on both sides only.
	got := readSlab(t, d, 40+3*tun.ReadPacketSpacing, 4)
	if len(got) != 1 || got[0][0] != 'a' {
		t.Fatalf("first Read = %q", got)
	}
	got = readSlab(t, d, 1024, 4)
	if len(got) != 1 || got[0][0] != 'b' {
		t.Fatalf("second Read = %q, want the pending packet", got)
	}
}

func TestReadStopsAtPacketsLen(t *testing.T) {
	d := newDev(t, 1, 8)
	ctx := context.Background()
	d.Inject(ctx, []byte("x"))
	d.Inject(ctx, []byte("y"))
	if got := readSlab(t, d, 1024, 1); len(got) != 1 || string(got[0]) != "x" {
		t.Fatalf("Read = %q", got)
	}
	if got := readSlab(t, d, 1024, 1); len(got) != 1 || string(got[0]) != "y" {
		t.Fatalf("Read = %q", got)
	}
}

func TestReadErrors(t *testing.T) {
	d := newDev(t, 1, 1)
	if _, err := d.Read(make([]byte, 1024), nil); !errors.Is(err, tun.ErrTooManySegments) {
		t.Errorf("Read with no packet slots: err = %v", err)
	}
	if _, err := d.Read(make([]byte, tun.ReadPacketSpacing), make([]tun.ReadPacket, 1)); !errors.Is(err, tun.ErrTooManySegments) {
		t.Errorf("Read with tiny slab: err = %v", err)
	}
	d.Inject(context.Background(), make([]byte, 500))
	if _, err := d.Read(make([]byte, 200), make([]tun.ReadPacket, 1)); !errors.Is(err, tun.ErrTooManySegments) {
		t.Errorf("Read of oversized packet: err = %v", err)
	}
}

func TestWrite(t *testing.T) {
	d := newDev(t, 1, 4)
	buf := []byte("hdrPAYLOAD")
	n, err := d.Write([][]byte{buf, []byte("hdrSECOND")}, 3)
	if err != nil || n != 2 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	buf[3] = 'X' // Write must have copied
	if p := <-d.Packets(); string(p) != "PAYLOAD" {
		t.Fatalf("packet = %q", p)
	}
	if p := <-d.Packets(); string(p) != "SECOND" {
		t.Fatalf("packet = %q", p)
	}
	if _, err := d.Write([][]byte{[]byte("ab")}, 3); err == nil {
		t.Fatal("Write with offset past buffer: want error")
	}
	if _, err := d.Write([][]byte{[]byte("ab")}, -1); err == nil {
		t.Fatal("Write with negative offset: want error")
	}
}

func TestClose(t *testing.T) {
	// Unbuffered devices, so each call blocks until Close. Inject and Write
	// block on one device and Read on another; on a single device, Inject
	// and Read would hand the packet to each other.
	senders, reader := newDev(t, 1, 0), newDev(t, 1, 0)
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	wg.Add(3)
	go func() { defer wg.Done(); errs <- senders.Inject(context.Background(), []byte("x")) }()
	go func() { defer wg.Done(); _, err := senders.Write([][]byte{[]byte("x")}, 0); errs <- err }()
	go func() {
		defer wg.Done()
		_, err := reader.Read(make([]byte, 1024), make([]tun.ReadPacket, 1))
		errs <- err
	}()
	time.Sleep(10 * time.Millisecond)
	for _, d := range []*Device{senders, reader} {
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal("second Close:", err)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("blocked call returned %v, want os.ErrClosed", err)
		}
	}
	select {
	case <-senders.Done():
	default:
		t.Fatal("Done not closed")
	}
	senders.SetMTU(1000) // must not panic after Close
	for range senders.Events() {
		// drain until closed
	}
}

func TestInjectContextCanceled(t *testing.T) {
	d := newDev(t, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Inject(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Inject = %v, want context.Canceled", err)
	}
}

func TestSetMTUNeverBlocks(t *testing.T) {
	d := newDev(t, 1, 1)
	// Call SetMTU many times without reading Events(); SetMTU must not block.
	// With a buffer of 4, some updates will be dropped, but all calls return.
	for i := 0; i < 10; i++ {
		d.SetMTU(1000 + i) // calls with values 1000..1009
	}
	// The latest MTU value is always accessible.
	if m, _ := d.MTU(); m != 1009 {
		t.Fatalf("MTU = %d, want 1009", m)
	}
	// Drain events non-blockingly and verify overflow behavior.
	var events []tun.Event
	for {
		select {
		case e := <-d.Events():
			events = append(events, e)
		default:
			goto done
		}
	}
done:
	// Should have EventUp plus some (but not all) EventMTUUpdate calls.
	if len(events) < 1 || len(events) > 4 {
		t.Fatalf("drained %d events, want 1..4", len(events))
	}
	if events[0] != tun.EventUp {
		t.Errorf("first event = %v, want EventUp", events[0])
	}
	for _, e := range events[1:] {
		if e != tun.EventMTUUpdate {
			t.Errorf("event = %v, want EventMTUUpdate", e)
		}
	}
}

// Review focus: on a closed device with room in its buffers, select would
// pick at random between done and the send, so Inject and Write sometimes
// succeeded after Close.
func TestInjectWriteAfterCloseOnBufferedDevice(t *testing.T) {
	const n = 64
	d := newDev(t, 1, 2*n)
	d.Close()
	for i := range n {
		if err := d.Inject(context.Background(), []byte("x")); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Inject #%d after Close = %v, want os.ErrClosed", i, err)
		}
		if got, err := d.Write([][]byte{[]byte("x")}, 0); got != 0 || !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Write #%d after Close = %d, %v; want 0, os.ErrClosed", i, got, err)
		}
	}
}
