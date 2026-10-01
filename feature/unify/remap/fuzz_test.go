// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"net/netip"
	"testing"
	"time"
)

// FuzzSyncInvariants applies random Sync sequences and checks the table's
// invariants after each one:
//   - virtual prefixes never overlap, except same-owner identity mappings;
//   - existing mappings never change (stickiness);
//   - RealToVirtual and VirtualToReal are inverses for every mapping.
func FuzzSyncInvariants(f *testing.F) {
	f.Add([]byte{0, 24, 1, 0, 1, 24, 1, 0, 2, 32, 1, 5})
	f.Add([]byte{0x80, 16, 0, 0, 1, 24, 0, 0, 2, 24, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := testConfig()
		cfg.Pool4 = mpp("198.18.0.0/20") // small, so exhaustion happens too
		tb, err := New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		owners := []Owner{"a", "b", "c"}
		seen := map[key]Mapping{}
		for len(data) >= 4 {
			b0, b1, b2, b3 := data[0], data[1], data[2], data[3]
			data = data[4:]
			owner := owners[int(b0&0x7f)%len(owners)]
			bits := 16 + int(b1)%17
			addr := netip.AddrFrom4([4]byte{10, 0, b2, b3})
			if b0&0x80 != 0 {
				addr = netip.AddrFrom4([4]byte{198, 18, b2 & 0x1f, b3}) // inside the pool
			}
			p := netip.PrefixFrom(addr, bits).Masked()
			if _, err := tb.Sync(owner, []netip.Prefix{p}, t0.Add(time.Duration(len(data)))); err != nil {
				t.Fatal(err)
			}
			ms := tb.Mappings()
			if err := checkDisjoint(ms); err != nil {
				t.Fatalf("after Sync(%s, %v): %v", owner, p, err)
			}
			for _, m := range ms {
				k := key{m.Owner, m.Real}
				if old, ok := seen[k]; ok && old.Virtual != m.Virtual {
					t.Fatalf("mapping changed: %v -> %v", old, m)
				}
				seen[k] = m
				a := m.Real.Addr()
				v, ok := tb.RealToVirtual(m.Owner, a)
				if !ok {
					t.Fatalf("RealToVirtual(%s, %v) failed", m.Owner, a)
				}
				o, r, ok := tb.VirtualToReal(v)
				if !ok || o != m.Owner || r != a {
					t.Fatalf("VirtualToReal(%v) = %s, %v, %v; want %s, %v", v, o, r, ok, m.Owner, a)
				}
			}
		}
	})
}
