// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"slices"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
)

// RoutingSnapshot is a point-in-time view of what a LocalBackend
// routes, for a layer that runs several backends side by side (tailnet
// unification). Every prefix list is sorted and owned by the caller.
type RoutingSnapshot struct {
	// State is the backend state.
	State ipn.State

	// Self is this node's addresses.
	Self []netip.Prefix

	// Peers is the peers' addresses that this node routes to them.
	// They are single-IP prefixes in practice.
	Peers []netip.Prefix

	// Subnets is the accepted subnet routes: routed prefixes that are
	// neither peer addresses, exit routes, nor extra WireGuard allowed
	// IPs (such as the conn25 extension's transit IPs).
	Subnets []netip.Prefix

	// Advertised is the subnet routes this node advertises, without
	// exit routes.
	Advertised []netip.Prefix

	// OffersExit is whether this node advertises itself as an exit
	// node (both the IPv4 and IPv6 exit routes).
	OffersExit bool

	// UsesExit is whether an exit node is selected and its exit routes
	// are routed. A selected exit node that does not resolve to a
	// current peer routes nothing, so UsesExit is false then.
	UsesExit bool

	// MagicDNSSuffix is the tailnet's MagicDNS suffix, without a
	// trailing dot, or empty without a netmap.
	MagicDNSSuffix string
}

// RoutingSnapshot returns what b currently routes. It takes b.mu, so it
// must not be called from the routing observer (see
// [LocalBackend.SetRoutingObserver]).
func (b *LocalBackend) RoutingSnapshot() RoutingSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()

	prefs := b.pm.CurrentPrefs()
	advertised := prefs.AdvertiseRoutes()
	snap := RoutingSnapshot{
		State:      b.state,
		Advertised: sortedPrefixes(tsaddr.WithoutExitRoute(advertised).AsSlice()),
		OffersExit: tsaddr.ContainsExitRoutes(advertised),
	}

	cn := b.currentNode()
	if nm := cn.NetMap(); nm != nil {
		snap.Self = sortedPrefixes(nm.GetAddresses().AsSlice())
		snap.MagicDNSSuffix = nm.MagicDNSSuffix()
	}

	peers, routes := cn.routeMgr.OutboundPrefixes()
	snap.Peers = peers
	var exitRouted bool
	for _, p := range routes {
		if tsaddr.IsExitRoute(p) {
			exitRouted = true
		} else {
			snap.Subnets = append(snap.Subnets, p)
		}
	}
	exitSelected := prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid()
	snap.UsesExit = exitSelected && exitRouted
	return snap
}

// sortedPrefixes sorts and returns s, which must not be shared.
func sortedPrefixes(s []netip.Prefix) []netip.Prefix {
	tsaddr.SortPrefixes(s)
	return slices.Clip(s)
}

// SetRoutingObserver sets f to be called whenever what b routes may
// have changed: on every engine reconfiguration attempt and on every
// state transition. A nil f removes the observer.
//
// f is called with b.mu held. It must not block and must not call into
// b; it should only signal another goroutine (for example with a
// non-blocking send on a channel of capacity one), which then calls
// [LocalBackend.RoutingSnapshot]. f may be called when nothing changed.
func (b *LocalBackend) SetRoutingObserver(f func()) {
	b.routingObserver.Store(f)
}

// notifyRoutingObserverLocked calls the routing observer, if any.
//
// b.mu must be held.
func (b *LocalBackend) notifyRoutingObserverLocked() {
	if f := b.routingObserver.Load(); f != nil {
		f()
	}
}
