// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"cmp"
	"net/netip"
	"slices"
)

// translate returns a with its network part (the first from.Bits() bits)
// replaced by the network part of to, keeping the host part. from and to
// must be the same length and family, and from must contain a.
func translate(a netip.Addr, from, to netip.Prefix) netip.Addr {
	if from == to {
		return a
	}
	src := a.As16()
	dst := to.Addr().As16()
	setBits(&dst, &src, bitOffset(a)+from.Bits())
	return fromBytes(dst, a.Is4())
}

// lastAddr returns the last address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.As16()
	ones := [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	setBits(&b, &ones, bitOffset(a)+p.Bits())
	return fromBytes(b, a.Is4())
}

// after returns the first prefix of length bits that starts right after
// the last address of p. It reports false if p ends at the top of the
// address space. bits must be >= p.Bits().
func after(p netip.Prefix, bits int) (netip.Prefix, bool) {
	next := lastAddr(p).Next()
	if !next.IsValid() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(next, bits), true
}

// setBits keeps the first n bits of dst and copies the remaining bits
// from src.
func setBits(dst, src *[16]byte, n int) {
	for i := range dst {
		lo := i * 8
		switch {
		case lo+8 <= n:
			// Whole byte is network part: keep dst.
		case lo >= n:
			dst[i] = src[i]
		default:
			mask := byte(0xff) << (8 - (n - lo))
			dst[i] = dst[i]&mask | src[i]&^mask
		}
	}
}

// bitOffset is the number of leading bits of the 16-byte form of a that
// are not part of its own address (96 for IPv4, 0 for IPv6).
func bitOffset(a netip.Addr) int {
	if a.Is4() {
		return 96
	}
	return 0
}

func fromBytes(b [16]byte, is4 bool) netip.Addr {
	a := netip.AddrFrom16(b)
	if is4 {
		return a.Unmap()
	}
	return a
}

// comparePrefix orders prefixes by address, then by length.
func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits(), b.Bits())
}

// Order returns one tailnet's prefixes in the order [Table.Sync] should
// see them: this node's own addresses first, then peer addresses, then
// routed subnets. Each group is sorted, so first-sight decisions do not
// depend on map iteration or netmap order.
func Order(self, peers, subnets []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(self)+len(peers)+len(subnets))
	for _, group := range [][]netip.Prefix{self, peers, subnets} {
		g := slices.Clone(group)
		slices.SortFunc(g, comparePrefix)
		out = append(out, g...)
	}
	return out
}
