// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
)

func TestNewPool6(t *testing.T) {
	p, err := NewPool6(bytes.NewReader([]byte{1, 2, 3, 4, 5}))
	if err != nil {
		t.Fatal(err)
	}
	if want := mpp("fd01:203:405::/48"); p != want {
		t.Errorf("NewPool6 = %v, want %v", p, want)
	}
	if _, err := NewPool6(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Error("NewPool6 with short reader: want error")
	}
}

func occupied(prefixes ...string) *bart.Table[struct{}] {
	t := new(bart.Table[struct{}])
	for _, p := range prefixes {
		t.Insert(mpp(p), struct{}{})
	}
	return t
}

func TestAllocate(t *testing.T) {
	tests := []struct {
		name string
		pool string
		bits int
		occ  []string
		want string // "" means no block
	}{
		{"empty pool", "198.18.0.0/15", 32, nil, "198.18.0.0/32"},
		{"first taken", "198.18.0.0/15", 32, []string{"198.18.0.0/32"}, "198.18.0.1/32"},
		{"skip large supernet", "198.18.0.0/15", 32, []string{"198.18.0.0/16"}, "198.19.0.0/32"},
		{"small subnet inside candidate", "198.18.0.0/15", 24, []string{"198.18.0.9/32"}, "198.18.1.0/24"},
		{"block same size", "198.18.0.0/15", 16, []string{"198.18.0.0/24"}, "198.19.0.0/16"},
		{"too big for pool", "198.18.0.0/15", 8, nil, ""},
		{"longer than address", "198.18.0.0/15", 33, nil, ""},
		{"exhausted", "198.18.0.0/31", 32, []string{"198.18.0.0/32", "198.18.0.1/32"}, ""},
		{"top of space", "255.255.255.254/31", 32, []string{"255.255.255.254/31"}, ""},
		{"ipv6", "fd00:1::/48", 128, []string{"fd00:1::/128"}, "fd00:1::1/128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := allocate(mpp(tt.pool), tt.bits, occupied(tt.occ...), netip.Addr{})
			if tt.want == "" {
				if ok {
					t.Fatalf("allocate = %v, want none", got)
				}
				return
			}
			if !ok || got != mpp(tt.want) {
				t.Fatalf("allocate = %v, %v; want %s", got, ok, tt.want)
			}
		})
	}
}

func TestAllocateFromStart(t *testing.T) {
	pool := mpp("198.18.0.0/15")
	got, ok := allocate(pool, 32, occupied(), mpa("198.18.4.7"))
	if !ok || got != mpp("198.18.4.7/32") {
		t.Fatalf("allocate from 198.18.4.7 = %v, %v", got, ok)
	}
	got, ok = allocate(pool, 24, occupied(), mpa("198.18.4.7")) // unaligned start rounds down
	if !ok || got != mpp("198.18.4.0/24") {
		t.Fatalf("allocate /24 from 198.18.4.7 = %v, %v", got, ok)
	}
	got, ok = allocate(pool, 32, occupied(), mpa("10.0.0.1")) // outside pool: from pool start
	if !ok || got != mpp("198.18.0.0/32") {
		t.Fatalf("allocate from outside pool = %v, %v", got, ok)
	}
}

func TestAllocateInvalidPool(t *testing.T) {
	var zero netip.Prefix
	if _, ok := allocate(zero, 32, occupied(), netip.Addr{}); ok {
		t.Fatal("invalid pool: want no block")
	}
}
