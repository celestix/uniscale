// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"net/netip"
	"slices"

	"tailscale.com/feature/unify/osglue"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
)

// tailnetState is one tailnet's routing snapshot, as its stack's
// LocalBackend reported it.
type tailnetState struct {
	owner   remap.Owner
	primary bool // the primary tailnet, PrimaryName
	snap    ipnlocal.RoutingSnapshot
}

// tailnetRouting is what one tailnet contributes to the host's routing.
// Everything but owner is zero unless running.
type tailnetRouting struct {
	owner remap.Owner

	// running reports whether the tailnet is Running. Only running
	// tailnets carry traffic and get host routes. The others keep their
	// mappings until they expire (remap.Table.Expire), so their virtual
	// addresses stay the same when they come back.
	running bool

	// sync is the tailnet's prefixes for remap.Table.Sync, in priority
	// order: this node's addresses, its peers' addresses, then the subnet
	// routes it accepts.
	sync []netip.Prefix

	// xlate is the tailnet's stack for xlate.Translator.SetStacks.
	xlate xlate.Stack

	// merge is the tailnet's stack for osglue.MergeRouter. The caller
	// sets Captured.
	merge osglue.Stack
}

// planRouting returns what each tailnet in ts, in configured order,
// contributes to the host's routing, and the tailnets whose exit node is
// not used because an earlier tailnet's is.
//
// A subnet route that overlaps one this node advertises to the same
// tailnet is left out: the host reaches that network directly, and
// replies from it must not be taken for the tailnet's (as with high
// availability subnet routers advertising the same LAN). Only the first
// running tailnet using an exit node keeps it. The primary tailnet serves
// quad-100 while it is running.
func planRouting(ts []tailnetState) (plans []tailnetRouting, exitIgnored []remap.Owner) {
	exitTaken, quad100Taken := false, false
	for _, t := range ts {
		r := tailnetRouting{owner: t.owner}
		s := t.snap
		if s.State != ipn.Running {
			plans = append(plans, r)
			continue
		}
		subnets := withoutOverlaps(s.Subnets, s.Advertised)
		usesExit := s.UsesExit && !exitTaken
		if s.UsesExit && exitTaken {
			exitIgnored = append(exitIgnored, t.owner)
		}
		exitTaken = exitTaken || usesExit
		quad100 := t.primary && !quad100Taken
		quad100Taken = quad100Taken || quad100

		r.running = true
		r.sync = remap.Order(s.Self, s.Peers, subnets)
		r.xlate = xlate.Stack{
			Owner:      t.owner,
			Self:       prefixAddrs(s.Self),
			Advertised: slices.Clone(s.Advertised),
			OffersExit: s.OffersExit,
			UsesExit:   usesExit,
			Quad100:    quad100,
		}
		r.merge = osglue.Stack{
			Owner:    t.owner,
			Primary:  t.primary,
			Self:     slices.Clone(s.Self),
			Peers:    slices.Clone(s.Peers),
			Subnets:  subnets,
			UsesExit: usesExit,
		}
		plans = append(plans, r)
	}
	return plans, exitIgnored
}

// withoutOverlaps returns the prefixes of ps that overlap none of drop,
// in a new slice, or nil.
func withoutOverlaps(ps, drop []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		if !slices.ContainsFunc(drop, p.Overlaps) {
			out = append(out, p)
		}
	}
	return out
}

// prefixAddrs returns the addresses of ps.
func prefixAddrs(ps []netip.Prefix) []netip.Addr {
	out := make([]netip.Addr, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Addr())
	}
	return out
}
