// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"net/netip"
	"slices"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine/router"
)

// Stack is what [MergeRouter] needs to know about one running stack.
type Stack struct {
	// Owner is the stack's tailnet in the remap table.
	Owner remap.Owner

	// Primary marks the primary tailnet, which serves the Tailscale
	// service addresses and whose netfilter settings win.
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
//   - RouteSources: the preferred source of each route, so that host
//     traffic leaves from the right tailnet's address without binding one:
//     the primary's virtual self of the route's family for the service
//     addresses (the primary serves them), and each stack's for its peers,
//     subnets and, for the exit stack, exit routes. With several selves of
//     a family, the smallest is used; a route without a self of its
//     family has no source. A route listed more than once keeps the first
//     source, the primary's service addresses first, then the stacks' in
//     order.
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

	selves := make([][]netip.Prefix, len(stacks))
	for i, s := range stacks {
		selves[i] = translate(nil, s.Owner, s.Self)
	}
	cfg.Routes = []netip.Prefix{
		netip.PrefixFrom(tsaddr.TailscaleServiceIP(), 32),
		netip.PrefixFrom(tsaddr.TailscaleServiceIPv6(), 128),
	}
	// The service addresses go to the primary, so they leave from its
	// address.
	if i := slices.IndexFunc(stacks, func(s Stack) bool { return s.Primary }); i >= 0 {
		sourcesOf(selves[i]).add(&cfg.RouteSources, cfg.Routes)
	}
	for i, s := range stacks {
		cfg.LocalAddrs = append(cfg.LocalAddrs, selves[i]...)
		routes := translate(nil, s.Owner, s.Peers)
		routes = translate(routes, s.Owner, s.Subnets)
		if s.UsesExit {
			routes = append(routes, tsaddr.ExitRoutes()...)
		}
		cfg.Routes = append(cfg.Routes, routes...)
		sourcesOf(selves[i]).add(&cfg.RouteSources, routes)
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

// sources is a stack's preferred route source for each address family.
type sources struct {
	v4, v6 netip.Addr
}

// sourcesOf returns the smallest address of each family in self.
func sourcesOf(self []netip.Prefix) sources {
	var s sources
	for _, p := range self {
		a := p.Addr()
		cur := &s.v6
		if a.Is4() {
			cur = &s.v4
		}
		if !cur.IsValid() || a.Less(*cur) {
			*cur = a
		}
	}
	return s
}

// add sets the source of each of routes that has none yet in *m, if s has
// an address of the route's family.
func (s sources) add(m *map[netip.Prefix]netip.Addr, routes []netip.Prefix) {
	for _, r := range routes {
		src := s.v6
		if r.Addr().Is4() {
			src = s.v4
		}
		if _, ok := (*m)[r]; !ok && src.IsValid() {
			mak.Set(m, r, src)
		}
	}
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
