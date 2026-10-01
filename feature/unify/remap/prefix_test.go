// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"net/netip"
	"slices"
	"testing"
)

var (
	mpp = netip.MustParsePrefix
	mpa = netip.MustParseAddr
)

func TestTranslate(t *testing.T) {
	tests := []struct {
		a        string
		from, to string
		want     string
	}{
		{"100.70.2.9", "100.70.2.9/32", "198.18.0.7/32", "198.18.0.7"},
		{"192.168.1.77", "192.168.1.0/24", "198.18.4.0/24", "198.18.4.77"},
		{"10.1.15.3", "10.1.0.0/20", "198.18.16.0/20", "198.18.31.3"},
		{"10.1.2.3", "10.0.0.0/8", "10.0.0.0/8", "10.1.2.3"},
		{"fd7a:115c:a1e0::1:2", "fd7a:115c:a1e0::/64", "fd00:1:2:3::/64", "fd00:1:2:3::1:2"},
		{"fd7a:115c:a1e0:ab12::5", "fd7a:115c:a1e0:a000::/52", "fd00:1::/52", "fd00:1:0:b12::5"},
	}
	for _, tt := range tests {
		got := translate(mpa(tt.a), mpp(tt.from), mpp(tt.to))
		if got != mpa(tt.want) {
			t.Errorf("translate(%s, %s, %s) = %v, want %s", tt.a, tt.from, tt.to, got, tt.want)
		}
		if back := translate(got, mpp(tt.to), mpp(tt.from)); back != mpa(tt.a) {
			t.Errorf("translate back of %v = %v, want %s", got, back, tt.a)
		}
	}
}

func TestLastAddr(t *testing.T) {
	tests := map[string]string{
		"10.0.0.0/8":      "10.255.255.255",
		"198.18.0.0/15":   "198.19.255.255",
		"10.1.2.3/32":     "10.1.2.3",
		"10.1.2.3/22":     "10.1.3.255",
		"0.0.0.0/0":       "255.255.255.255",
		"fd00::/48":       "fd00:0:0:ffff:ffff:ffff:ffff:ffff",
		"fd00:1:2:3::/64": "fd00:1:2:3:ffff:ffff:ffff:ffff",
	}
	for in, want := range tests {
		if got := lastAddr(mpp(in)); got != mpa(want) {
			t.Errorf("lastAddr(%s) = %v, want %s", in, got, want)
		}
	}
}

func TestAfter(t *testing.T) {
	tests := []struct {
		p    string
		bits int
		want string
		ok   bool
	}{
		{"10.0.0.0/24", 24, "10.0.1.0/24", true},
		{"198.18.0.0/16", 32, "198.19.0.0/32", true},
		{"198.18.0.0/31", 32, "198.18.0.2/32", true},
		{"255.255.255.0/24", 24, "", false},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120", 128, "", false},
	}
	for _, tt := range tests {
		got, ok := after(mpp(tt.p), tt.bits)
		if ok != tt.ok || (ok && got != mpp(tt.want)) {
			t.Errorf("after(%s, %d) = %v, %v; want %s, %v", tt.p, tt.bits, got, ok, tt.want, tt.ok)
		}
	}
}

func TestOrder(t *testing.T) {
	got := Order(
		[]netip.Prefix{mpp("100.64.0.9/32"), mpp("100.64.0.1/32")},
		[]netip.Prefix{mpp("100.70.0.2/32"), mpp("100.65.0.1/32")},
		[]netip.Prefix{mpp("10.0.0.0/16"), mpp("10.0.0.0/8"), mpp("10.0.0.0/24")},
	)
	want := []netip.Prefix{
		mpp("100.64.0.1/32"), mpp("100.64.0.9/32"),
		mpp("100.65.0.1/32"), mpp("100.70.0.2/32"),
		mpp("10.0.0.0/8"), mpp("10.0.0.0/16"), mpp("10.0.0.0/24"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("Order = %v, want %v", got, want)
	}
}
