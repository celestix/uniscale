// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package remap implements the sticky collision-remapping table used by
// tailnet unification.
//
// Each tailnet (an [Owner]) contributes real prefixes: this node's own
// address in it, its peers' addresses, and the subnets it routes. A prefix
// keeps its real value (an identity mapping) unless, when first seen, it
// overlaps something already in use: another tailnet's mapping, a network
// this host is directly connected to, or a recently released block. Then it
// is assigned a same-sized block from a pool. Mappings never change once
// made; they are only removed when they expire or their tailnet is removed.
package remap
