// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"iter"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
)

// routingTestNetmap returns a netmap with this node at 100.64.0.10 and
// three peers: an exit node, a subnet router and a plain peer.
func routingTestNetmap() *netmap.NetworkMap {
	p := netip.MustParsePrefix
	self := makePeer(10, withName("self"),
		withAddresses(p("100.64.0.10/32"), p("fd7a:115c:a1e0::a/128")))
	exit := makePeer(1, withName("exit"),
		withAddresses(p("100.64.0.1/32"), p("fd7a:115c:a1e0::1/128")),
		withAllowedIPs(p("100.64.0.1/32"), p("fd7a:115c:a1e0::1/128")),
		withExitRoutes())
	subnet := makePeer(2, withName("subnet"),
		withAddresses(p("100.64.0.2/32")),
		withAllowedIPs(p("100.64.0.2/32"), p("10.0.0.0/24"), p("192.168.7.0/24")))
	plain := makePeer(3, withName("plain"),
		withAddresses(p("100.64.0.3/32"), p("fd7a:115c:a1e0::3/128")),
		withAllowedIPs(p("100.64.0.3/32"), p("fd7a:115c:a1e0::3/128")))
	nm := buildNetmapWithPeers(self, exit, subnet, plain)
	for i, n := range nm.Peers {
		mut := n.AsStruct()
		mut.Hostinfo = (&tailcfg.Hostinfo{}).View()
		nm.Peers[i] = mut.View()
	}
	return nm
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

var (
	routingTestSelf  = prefixes("100.64.0.10/32", "fd7a:115c:a1e0::a/128")
	routingTestPeers = prefixes("100.64.0.1/32", "100.64.0.2/32", "100.64.0.3/32",
		"fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::3/128")
	routingTestSubnets = prefixes("10.0.0.0/24", "192.168.7.0/24")
)

func diffSnapshot(got, want RoutingSnapshot) string {
	return cmp.Diff(want, got, cmpopts.EquateEmpty(), cmpopts.EquateComparable(netip.Prefix{}))
}

func TestRoutingSnapshot(t *testing.T) {
	tests := []struct {
		name  string
		prefs ipn.MaskedPrefs
		want  RoutingSnapshot
	}{
		{
			name: "defaults",
			want: RoutingSnapshot{
				Peers: routingTestPeers,
			},
		},
		{
			name: "route all",
			prefs: ipn.MaskedPrefs{
				Prefs:       ipn.Prefs{RouteAll: true},
				RouteAllSet: true,
			},
			want: RoutingSnapshot{
				Peers:   routingTestPeers,
				Subnets: routingTestSubnets,
			},
		},
		{
			name: "exit node by ID",
			prefs: ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{RouteAll: true, ExitNodeID: "stable1"},
				RouteAllSet:   true,
				ExitNodeIDSet: true,
			},
			want: RoutingSnapshot{
				Peers:    routingTestPeers,
				Subnets:  routingTestSubnets,
				UsesExit: true,
			},
		},
		{
			name: "exit node by IP",
			prefs: ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{ExitNodeIP: netip.MustParseAddr("100.64.0.1")},
				ExitNodeIPSet: true,
			},
			want: RoutingSnapshot{
				Peers:    routingTestPeers,
				UsesExit: true,
			},
		},
		{
			name: "unresolved exit node",
			prefs: ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{ExitNodeID: "no-such-node"},
				ExitNodeIDSet: true,
			},
			want: RoutingSnapshot{
				Peers:    routingTestPeers,
				UsesExit: true,
			},
		},
		{
			name: "exit node without exit routes",
			prefs: ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{ExitNodeID: "stable3"},
				ExitNodeIDSet: true,
			},
			want: RoutingSnapshot{
				Peers:    routingTestPeers,
				UsesExit: true,
			},
		},
		{
			name: "advertise routes and exit",
			prefs: ipn.MaskedPrefs{
				Prefs: ipn.Prefs{AdvertiseRoutes: prefixes(
					"192.168.1.0/24", "0.0.0.0/0", "::/0", "10.9.0.0/16")},
				AdvertiseRoutesSet: true,
			},
			want: RoutingSnapshot{
				Peers:      routingTestPeers,
				Advertised: prefixes("10.9.0.0/16", "192.168.1.0/24"),
				OffersExit: true,
			},
		},
		{
			name: "advertise half an exit",
			prefs: ipn.MaskedPrefs{
				Prefs:              ipn.Prefs{AdvertiseRoutes: prefixes("0.0.0.0/0", "10.9.0.0/16")},
				AdvertiseRoutesSet: true,
			},
			want: RoutingSnapshot{
				Peers:      routingTestPeers,
				Advertised: prefixes("10.9.0.0/16"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lb, _, cc := newLocalBackendWithMockEngineAndControl(t, false)
			mustDo(t)(lb.Start(ipn.Options{}))
			mp := tt.prefs
			mp.WantRunning, mp.WantRunningSet = true, true
			mustDo2(t)(lb.EditPrefs(&mp))
			cc().authenticated(routingTestNetmap())

			want := tt.want
			want.State = ipn.Starting
			want.Self = routingTestSelf
			want.MagicDNSSuffix = "test.ts.net"
			if d := diffSnapshot(lb.RoutingSnapshot(), want); d != "" {
				t.Errorf("RoutingSnapshot (-want +got):\n%s", d)
			}
		})
	}
}

func TestRoutingSnapshotNoNetmap(t *testing.T) {
	lb := newTestLocalBackend(t)
	want := RoutingSnapshot{State: ipn.NoState}
	if d := diffSnapshot(lb.RoutingSnapshot(), want); d != "" {
		t.Errorf("RoutingSnapshot (-want +got):\n%s", d)
	}
}

// TestRoutingSnapshotExcludesExtras checks that the conn25 extension's
// extra WireGuard allowed IPs, which are in the outbound table but are
// not routes, are neither peer addresses nor subnets, even when they
// look like a peer address.
func TestRoutingSnapshotExcludesExtras(t *testing.T) {
	lb, _, cc := newLocalBackendWithMockEngineAndControl(t, false)
	mustDo(t)(lb.Start(ipn.Options{}))
	mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs:          ipn.Prefs{WantRunning: true, RouteAll: true},
		WantRunningSet: true,
		RouteAllSet:    true,
	}))
	cc().authenticated(routingTestNetmap())

	extras := prefixes("fd7a:115c:a1e0:a99c:200::5/128", "169.254.0.5/32")
	cn := lb.currentNode()
	cn.updateRouteManagerExtras(func(peers iter.Seq2[tailcfg.NodeID, key.NodePublic]) map[tailcfg.NodeID][]netip.Prefix {
		return map[tailcfg.NodeID][]netip.Prefix{2: extras}
	})
	for _, p := range extras {
		if _, ok := cn.routeMgr.Outbound().Get(p); !ok {
			t.Fatalf("test setup: extra %v not in Outbound", p)
		}
	}

	snap := lb.RoutingSnapshot()
	if !slices.Equal(snap.Peers, routingTestPeers) {
		t.Errorf("Peers = %v; want %v", snap.Peers, routingTestPeers)
	}
	if !slices.Equal(snap.Subnets, routingTestSubnets) {
		t.Errorf("Subnets = %v; want %v", snap.Subnets, routingTestSubnets)
	}
}

// routingSignal returns an observer that records its calls and does a
// non-blocking send on a capacity-1 channel, the way the unify layer
// uses it. The observer also checks that it runs with b.mu held.
func routingSignal(t *testing.T, lb *LocalBackend) (f func(), ch chan struct{}, calls *atomic.Int64) {
	ch = make(chan struct{}, 1)
	calls = new(atomic.Int64)
	f = func() {
		if lb.mu.TryLock() {
			lb.mu.Unlock()
			t.Error("routing observer called without b.mu held")
		}
		calls.Add(1)
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return f, ch, calls
}

func TestRoutingObserver(t *testing.T) {
	lb, _, cc := newLocalBackendWithMockEngineAndControl(t, false)
	f, ch, _ := routingSignal(t, lb)
	lb.SetRoutingObserver(f)

	drain := func() {
		select {
		case <-ch:
		default:
		}
	}
	// step runs do and checks that the observer fired and that the
	// snapshot taken afterwards satisfies check.
	step := func(name string, do func(), check func(RoutingSnapshot) bool) {
		t.Helper()
		drain()
		do()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: routing observer did not fire", name)
		}
		if snap := lb.RoutingSnapshot(); !check(snap) {
			t.Fatalf("%s: unexpected snapshot %+v", name, snap)
		}
	}
	state := func(s ipn.State) func(RoutingSnapshot) bool {
		return func(snap RoutingSnapshot) bool { return snap.State == s }
	}

	step("start", func() { mustDo(t)(lb.Start(ipn.Options{})) }, state(ipn.NeedsLogin))
	mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs:          ipn.Prefs{WantRunning: true, RouteAll: true},
		WantRunningSet: true,
		RouteAllSet:    true,
	}))
	step("login", func() { cc().authenticated(routingTestNetmap()) }, func(snap RoutingSnapshot) bool {
		return snap.State == ipn.Starting && slices.Equal(snap.Subnets, routingTestSubnets)
	})
	// The Starting to Running transition comes from an engine status
	// update and does not reconfigure, but it changes whether unify
	// routes to this backend.
	step("running", func() {
		lb.setWgengineStatus(&wgengine.Status{AsOf: time.Now(), DERPs: 1}, nil)
	}, state(ipn.Running))
	step("prefs", func() {
		mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{RouteAllSet: true}))
	}, func(snap RoutingSnapshot) bool {
		return snap.State == ipn.Running && len(snap.Subnets) == 0
	})
	newPeer := makePeer(4, withName("new"),
		withAddresses(netip.MustParsePrefix("100.64.0.4/32")),
		withAllowedIPs(netip.MustParsePrefix("100.64.0.4/32")))
	step("peer added", func() {
		if !lb.UpdateNetmapDelta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: newPeer}}) {
			t.Fatal("UpdateNetmapDelta = false")
		}
	}, func(snap RoutingSnapshot) bool {
		return slices.Contains(snap.Peers, netip.MustParsePrefix("100.64.0.4/32"))
	})
	step("stop", func() {
		mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{WantRunningSet: true}))
	}, state(ipn.Stopped))
	step("new profile", func() { mustDo(t)(lb.NewProfile()) }, func(snap RoutingSnapshot) bool {
		return snap.State != ipn.Stopped && len(snap.Self) == 0 && len(snap.Peers) == 0
	})
}

func TestRoutingObserverNil(t *testing.T) {
	lb, _, cc := newLocalBackendWithMockEngineAndControl(t, false)
	f, _, calls := routingSignal(t, lb)
	lb.SetRoutingObserver(f)
	mustDo(t)(lb.Start(ipn.Options{}))
	if calls.Load() == 0 {
		t.Fatal("observer did not fire on Start")
	}

	// Removing the observer stops the calls, and a backend without
	// an observer reconfigures normally.
	lb.SetRoutingObserver(nil)
	before := calls.Load()
	mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true}))
	cc().authenticated(routingTestNetmap())
	if got := calls.Load(); got != before {
		t.Errorf("observer called %d times after removal", got-before)
	}
	if snap := lb.RoutingSnapshot(); snap.State != ipn.Starting || !slices.Equal(snap.Peers, routingTestPeers) {
		t.Errorf("RoutingSnapshot = %+v", snap)
	}
}

// TestRoutingObserverSlowConsumer checks that a consumer that does not
// drain its signal channel never holds up the backend, and that a
// consumer goroutine snapshotting concurrently with reconfigurations
// sees the final state once it catches up.
func TestRoutingObserverSlowConsumer(t *testing.T) {
	lb, _, cc := newLocalBackendWithMockEngineAndControl(t, false)
	f, ch, calls := routingSignal(t, lb)
	lb.SetRoutingObserver(f)
	mustDo(t)(lb.Start(ipn.Options{}))
	mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true}))
	cc().authenticated(routingTestNetmap())

	// Nobody drains ch: every reconfiguration still completes.
	const toggles = 20
	before := calls.Load()
	for i := range toggles {
		mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{
			Prefs:       ipn.Prefs{RouteAll: i%2 == 0},
			RouteAllSet: true,
		}))
	}
	if got := calls.Load() - before; got < toggles {
		t.Errorf("observer called %d times for %d reconfigurations", got, toggles)
	}
	if len(ch) != 1 {
		t.Errorf("signal channel holds %d signals; want 1", len(ch))
	}

	// A consumer goroutine snapshots on every signal while prefs keep
	// changing (exercised under the race detector).
	stop := make(chan struct{})
	var last atomic.Pointer[RoutingSnapshot]
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-ch:
				snap := lb.RoutingSnapshot()
				last.Store(&snap)
			}
		}
	})
	for i := range toggles {
		mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{
			Prefs:       ipn.Prefs{RouteAll: i%2 == 1},
			RouteAllSet: true,
		}))
	}
	close(stop)
	wg.Wait()
	if last.Load() == nil {
		t.Fatal("consumer never took a snapshot")
	}
	if got := lb.RoutingSnapshot().Subnets; !slices.Equal(got, routingTestSubnets) {
		t.Errorf("final Subnets = %v; want %v", got, routingTestSubnets)
	}

	// Snapshots are copies: changing one does not affect the next.
	snap := lb.RoutingSnapshot()
	snap.Peers[0] = netip.MustParsePrefix("1.2.3.4/32")
	snap.Self[0] = netip.MustParsePrefix("1.2.3.4/32")
	if again := lb.RoutingSnapshot(); !slices.Equal(again.Peers, routingTestPeers) || !slices.Equal(again.Self, routingTestSelf) {
		t.Errorf("snapshot shares memory with the backend: %+v", again)
	}
}

// TestRoutingSnapshotSorted checks that the snapshot's prefix lists are
// sorted, whatever order the netmap and prefs use.
func TestRoutingSnapshotSorted(t *testing.T) {
	lb, _, cc := newLocalBackendWithMockEngineAndControl(t, false)
	mustDo(t)(lb.Start(ipn.Options{}))
	mustDo2(t)(lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			WantRunning:     true,
			RouteAll:        true,
			AdvertiseRoutes: prefixes("192.168.1.0/24", "fd00::/64", "10.0.0.0/8"),
		},
		WantRunningSet:     true,
		RouteAllSet:        true,
		AdvertiseRoutesSet: true,
	}))
	nm := routingTestNetmap()
	self := nm.SelfNode.AsStruct()
	slices.Reverse(self.Addresses)
	nm.SelfNode = self.View()
	cc().authenticated(nm)

	snap := lb.RoutingSnapshot()
	for name, s := range map[string][]netip.Prefix{
		"Self": snap.Self, "Peers": snap.Peers, "Subnets": snap.Subnets, "Advertised": snap.Advertised,
	} {
		sorted := slices.Clone(s)
		tsaddr.SortPrefixes(sorted)
		if len(s) == 0 || !slices.Equal(s, sorted) {
			t.Errorf("%s = %v; want sorted and non-empty", name, s)
		}
	}
}
