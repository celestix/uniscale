// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"net/netip"
	"slices"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/tsaddr"
	"tailscale.com/wgengine/router"
)

// Stack is what [MergeRouter] needs to know about one running stack.
type Stack struct {
	// Owner is the stack's tailnet in the remap table.
	Owner remap.Owner

	// Primary marks the primary tailnet, whose netfilter settings win.
	Primary bool

	// Self, Peers and Subnets are the stack's real prefixes: this
	// node's addresses, its peers' addresses and the subnet routes it
	// accepts.
	Self, Peers, Subnets []netip.Prefix

	// UsesExit marks the stack whose exit node carries the host's
	// internet traffic. At most one stack should set it.
	UsesExit bool

	// Captured is the stack's last router configuration (see
	// [Router.Config]), or nil.
	Captured *router.Config
}

// MergeRouter returns the configuration for the host's real router, given
// the running stacks in configured order and all mappings of the remap
// table:
//
//   - LocalAddrs: the virtual prefixes of every stack's Self.
//   - Routes: the virtual prefixes of every stack's Peers and Subnets,
//     the Tailscale service addresses (100.100.100.100/32 and
//     fd7a:115c:a1e0::53/128) and, if a stack uses an exit node, the exit
//     routes. Captured Routes are not used; they may be coarsened to
//     100.64.0.0/10.
//   - LocalRoutes: the exit stack's captured LocalRoutes, the host's
//     networks that bypass the exit node.
//   - SubnetRoutes: the union of the captured ones.
//   - SNATSubnetRoutes, StatefulFiltering: set if any captured one is.
//   - NetfilterMode, NetfilterKind, RemoveCGNATDropRule: from the primary's
//     captured configuration or, if it has none, from the first stack's
//     that has one.
//   - NewMTU: the smallest non-zero captured value.
//
// A real prefix without a mapping for its stack's owner is left out. With
// no stacks, the result is the empty configuration, which removes
// everything. Prefix lists are sorted and deduplicated, so equal inputs
// give equal results.
func MergeRouter(stacks []Stack, mappings []remap.Mapping) *router.Config {
	cfg := &router.Config{}
	if len(stacks) == 0 {
		return cfg
	}

	type ownerReal struct {
		owner remap.Owner
		real  netip.Prefix
	}
	virtual := make(map[ownerReal]netip.Prefix, len(mappings))
	for _, m := range mappings {
		virtual[ownerReal{m.Owner, m.Real}] = m.Virtual
	}
	translate := func(dst []netip.Prefix, owner remap.Owner, real []netip.Prefix) []netip.Prefix {
		for _, p := range real {
			if v, ok := virtual[ownerReal{owner, p}]; ok {
				dst = append(dst, v)
			}
		}
		return dst
	}

	cfg.Routes = []netip.Prefix{
		netip.PrefixFrom(tsaddr.TailscaleServiceIP(), 32),
		netip.PrefixFrom(tsaddr.TailscaleServiceIPv6(), 128),
	}
	for _, s := range stacks {
		cfg.LocalAddrs = translate(cfg.LocalAddrs, s.Owner, s.Self)
		cfg.Routes = translate(cfg.Routes, s.Owner, s.Peers)
		cfg.Routes = translate(cfg.Routes, s.Owner, s.Subnets)
		if s.UsesExit {
			cfg.Routes = append(cfg.Routes, tsaddr.ExitRoutes()...)
		}
		c := s.Captured
		if c == nil {
			continue
		}
		if s.UsesExit {
			cfg.LocalRoutes = append(cfg.LocalRoutes, c.LocalRoutes...)
		}
		cfg.SubnetRoutes = append(cfg.SubnetRoutes, c.SubnetRoutes...)
		cfg.SNATSubnetRoutes = cfg.SNATSubnetRoutes || c.SNATSubnetRoutes
		cfg.StatefulFiltering = cfg.StatefulFiltering || c.StatefulFiltering
		if c.NewMTU > 0 && (cfg.NewMTU == 0 || c.NewMTU < cfg.NewMTU) {
			cfg.NewMTU = c.NewMTU
		}
	}
	if nf := netfilterSource(stacks); nf != nil {
		cfg.NetfilterMode = nf.NetfilterMode
		cfg.NetfilterKind = nf.NetfilterKind
		cfg.RemoveCGNATDropRule = nf.RemoveCGNATDropRule
	}

	cfg.LocalAddrs = sortedUnique(cfg.LocalAddrs)
	cfg.Routes = sortedUnique(cfg.Routes)
	cfg.LocalRoutes = sortedUnique(cfg.LocalRoutes)
	cfg.SubnetRoutes = sortedUnique(cfg.SubnetRoutes)
	return cfg
}

// netfilterSource returns the captured configuration whose netfilter
// settings apply: the primary's, else the first one present.
func netfilterSource(stacks []Stack) *router.Config {
	for _, s := range stacks {
		if s.Primary && s.Captured != nil {
			return s.Captured
		}
	}
	for _, s := range stacks {
		if s.Captured != nil {
			return s.Captured
		}
	}
	return nil
}

// sortedUnique sorts p and removes duplicates, in place.
func sortedUnique(p []netip.Prefix) []netip.Prefix {
	tsaddr.SortPrefixes(p)
	return slices.Clip(slices.Compact(p))
}
