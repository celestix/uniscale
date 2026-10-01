// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"io"
	"net/netip"

	"github.com/gaissmai/bart"
)

// DefaultPool4 is the default IPv4 pool for remapped prefixes: the RFC 2544
// benchmarking range, which is rarely used on real networks.
var DefaultPool4 = netip.MustParsePrefix("198.18.0.0/15")

// NewPool6 returns a random RFC 4193 unique local /48 (fdXX:XXXX:XXXX::/48)
// using r as the source of randomness.
func NewPool6(r io.Reader) (netip.Prefix, error) {
	var b [16]byte
	b[0] = 0xfd
	if _, err := io.ReadFull(r, b[1:6]); err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), 48), nil
}

// allocate returns the first block of length bits inside pool, at or after
// start, that does not overlap any prefix in occupied. An invalid start, or
// one outside pool, means the start of pool. It reports false if no such
// block exists.
func allocate(pool netip.Prefix, bits int, occupied *bart.Table[struct{}], start netip.Addr) (netip.Prefix, bool) {
	if !pool.IsValid() || bits < pool.Bits() || bits > pool.Addr().BitLen() {
		return netip.Prefix{}, false
	}
	if !pool.Contains(start) {
		start = pool.Masked().Addr()
	}
	cand := netip.PrefixFrom(start, bits).Masked()
	for pool.Contains(cand.Addr()) {
		if !occupied.OverlapsPrefix(cand) {
			return cand, true
		}
		// Skip past the largest occupied prefix covering cand. If only
		// smaller prefixes inside cand are occupied, move to the next block.
		skip := cand
		for p := range occupied.Supernets(cand) {
			if p.Bits() < skip.Bits() {
				skip = p
			}
		}
		next, ok := after(skip, bits)
		if !ok {
			break
		}
		cand = next
	}
	return netip.Prefix{}, false
}
