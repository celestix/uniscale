// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// peers returns n distinct /32 prefixes in 100.64.0.0/10.
func peers(n int) []netip.Prefix {
	out := make([]netip.Prefix, n)
	for i := range out {
		out[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64 + byte(i>>16), byte(i >> 8), byte(i)}), 32)
	}
	return out
}

// Review focus: a large tailnet whose every peer collides must still map
// quickly, both on first sight and on the frequent re-Syncs that follow.
func TestLargeTailnetCollisions(t *testing.T) {
	const n = 5000
	tb := newTable(t, testConfig(), nil)
	ps := peers(n)
	if _, err := tb.Sync("work", ps, t0); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ch, err := tb.Sync("personal", ps, t0)
	if err != nil {
		t.Fatal(err)
	}
	firstSight := time.Since(start)
	if len(ch.Added) != n || len(ch.Unmapped) != 0 {
		t.Fatalf("Added %d, Unmapped %d; want %d, 0", len(ch.Added), len(ch.Unmapped), n)
	}
	start = time.Now()
	if _, err := tb.Sync("personal", ps, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reSync := time.Since(start)
	t.Logf("first sight %v, re-sync %v", firstSight, reSync)
	if firstSight > 5*time.Second || reSync > time.Second {
		t.Fatalf("too slow: first sight %v, re-sync %v", firstSight, reSync)
	}
	wantVirtual(t, tb, "personal", "100.64.19.135", "198.18.19.135")
}

// Review focus: the packet path reads the table while netmap updates
// write it. Run with -race.
func TestConcurrentLookupsDuringSync(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if v, ok := tb.RealToVirtual("work", mpa("100.70.2.9")); !ok || v != mpa("100.70.2.9") {
					t.Errorf("RealToVirtual = %v, %v", v, ok)
					return
				}
				tb.VirtualToReal(mpa("198.18.0.5"))
			}
		}()
	}
	for i := range 200 {
		if _, err := tb.Sync("personal", peers(i+1), t0); err != nil {
			t.Fatal(err)
		}
		tb.Expire(t0)
	}
	close(stop)
	wg.Wait()
}
