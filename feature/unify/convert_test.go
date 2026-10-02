// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/feature/unify/osglue"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
)

var (
	mpa = netip.MustParseAddr
	mpp = netip.MustParsePrefix
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, mpp(s))
	}
	return out
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, mpa(s))
	}
	return out
}

// running returns a Running snapshot with the given prefixes.
func running(self, peers, subnets []netip.Prefix) ipnlocal.RoutingSnapshot {
	return ipnlocal.RoutingSnapshot{State: ipn.Running, Self: self, Peers: peers, Subnets: subnets}
}

func TestPlanRouting(t *testing.T) {
	workSelf := prefixes("100.101.5.2/32", "fd7a:115c:a1e0::52/128")
	workPeers := prefixes("100.70.2.9/32", "fd7a:115c:a1e0::99/128")
	homeSelf := prefixes("100.70.2.9/32")
	homePeers := prefixes("100.70.2.10/32")

	withExit := func(s ipnlocal.RoutingSnapshot) ipnlocal.RoutingSnapshot { s.UsesExit = true; return s }
	withState := func(s ipnlocal.RoutingSnapshot, st ipn.State) ipnlocal.RoutingSnapshot { s.State = st; return s }

	withOffer := func(s ipnlocal.RoutingSnapshot) ipnlocal.RoutingSnapshot { s.OffersExit = true; return s }

	type want struct {
		plans        []tailnetRouting
		exitIgnored  []remap.Owner
		offerIgnored []remap.Owner
	}
	for _, c := range []struct {
		name string
		in   []tailnetState
		want want
	}{
		{name: "nothing"},
		{
			name: "primary running",
			in: []tailnetState{{owner: "default", primary: true, snap: ipnlocal.RoutingSnapshot{
				State: ipn.Running, Self: workSelf, Peers: workPeers, Subnets: prefixes("10.10.0.0/16"),
				Advertised: prefixes("192.168.50.0/24"), OffersExit: true, MagicDNSSuffix: "tail1234.ts.net",
			}}},
			want: want{plans: []tailnetRouting{{
				owner:   "default",
				running: true,
				sync: prefixes(
					"100.101.5.2/32", "fd7a:115c:a1e0::52/128", // self first
					"100.70.2.9/32", "fd7a:115c:a1e0::99/128", // then peers
					"10.10.0.0/16"), // then subnets
				xlate: xlate.Stack{Owner: "default", Self: addrs("100.101.5.2", "fd7a:115c:a1e0::52"),
					Advertised: prefixes("192.168.50.0/24"), OffersExit: true, Quad100: true},
				merge: osglue.Stack{Owner: "default", Primary: true, Self: workSelf, Peers: workPeers,
					Subnets: prefixes("10.10.0.0/16")},
			}}},
		},
		{
			name: "not running",
			in: []tailnetState{
				{owner: "default", primary: true, snap: withState(withExit(running(workSelf, workPeers, nil)), ipn.Stopped)},
				{owner: "home", snap: withState(running(homeSelf, homePeers, nil), ipn.NeedsLogin)},
				{owner: "b", snap: ipnlocal.RoutingSnapshot{}}, // NoState
				{owner: "c", snap: withState(running(homeSelf, nil, nil), ipn.Starting)},
			},
			want: want{plans: []tailnetRouting{{owner: "default"}, {owner: "home"}, {owner: "b"}, {owner: "c"}}},
		},
		{
			name: "own advertised routes are not peer subnets",
			in: []tailnetState{{owner: "home", snap: ipnlocal.RoutingSnapshot{
				State: ipn.Running, Self: homeSelf,
				Subnets: prefixes(
					"10.0.0.0/24",    // kept
					"192.168.0.0/16", // contains an advertised route
					"192.168.1.0/24", // equals one (HA subnet router)
					"172.16.5.0/24",  // inside one
					"172.32.0.0/16",  // next to one: kept
					"fd00:aa::/64",   // kept
					"fd00:bb::/32",   // contains an advertised route
				),
				Advertised: prefixes("192.168.1.0/24", "172.16.0.0/12", "fd00:bb:1::/64"),
			}}},
			want: want{plans: []tailnetRouting{{
				owner:   "home",
				running: true,
				sync:    prefixes("100.70.2.9/32", "10.0.0.0/24", "172.32.0.0/16", "fd00:aa::/64"),
				xlate: xlate.Stack{Owner: "home", Self: addrs("100.70.2.9"),
					Advertised: prefixes("192.168.1.0/24", "172.16.0.0/12", "fd00:bb:1::/64")},
				merge: osglue.Stack{Owner: "home", Self: homeSelf, Subnets: prefixes("10.0.0.0/24", "172.32.0.0/16", "fd00:aa::/64")},
			}}},
		},
		{
			name: "first exit in configured order wins",
			in: []tailnetState{
				{owner: "default", primary: true, snap: running(workSelf, nil, nil)},
				{owner: "home", snap: withExit(running(homeSelf, nil, nil))},
				{owner: "c", snap: withExit(running(prefixes("100.64.0.3/32"), nil, nil))},
				{owner: "d", snap: withExit(running(prefixes("100.64.0.4/32"), nil, nil))},
			},
			want: want{
				plans: []tailnetRouting{
					{owner: "default", running: true, sync: workSelf,
						xlate: xlate.Stack{Owner: "default", Self: addrs("100.101.5.2", "fd7a:115c:a1e0::52"), Quad100: true},
						merge: osglue.Stack{Owner: "default", Primary: true, Self: workSelf}},
					{owner: "home", running: true, sync: homeSelf,
						xlate: xlate.Stack{Owner: "home", Self: addrs("100.70.2.9"), UsesExit: true},
						merge: osglue.Stack{Owner: "home", Self: homeSelf, UsesExit: true}},
					{owner: "c", running: true, sync: prefixes("100.64.0.3/32"),
						xlate: xlate.Stack{Owner: "c", Self: addrs("100.64.0.3")},
						merge: osglue.Stack{Owner: "c", Self: prefixes("100.64.0.3/32")}},
					{owner: "d", running: true, sync: prefixes("100.64.0.4/32"),
						xlate: xlate.Stack{Owner: "d", Self: addrs("100.64.0.4")},
						merge: osglue.Stack{Owner: "d", Self: prefixes("100.64.0.4/32")}},
				},
				exitIgnored: []remap.Owner{"c", "d"},
			},
		},
		{
			// C1: like stock tailscaled, this node does not offer to be an
			// exit node while it uses one: the exit clients' internet
			// traffic would leave through the used exit node, as this node
			// of another tailnet.
			name: "an exit in use clears the other tailnets' exit offers",
			in: []tailnetState{
				{owner: "default", primary: true, snap: withOffer(running(workSelf, nil, nil))}, // before the user
				{owner: "home", snap: withExit(running(homeSelf, nil, nil))},
				{owner: "c", snap: withOffer(running(prefixes("100.64.0.3/32"), nil, nil))},
				{owner: "d", snap: withExit(running(prefixes("100.64.0.4/32"), nil, nil))}, // ignored exit, no offer
				{owner: "e", snap: withState(withOffer(running(prefixes("100.64.0.5/32"), nil, nil)), ipn.Stopped)},
			},
			want: want{
				plans: []tailnetRouting{
					{owner: "default", running: true, sync: workSelf,
						xlate: xlate.Stack{Owner: "default", Self: addrs("100.101.5.2", "fd7a:115c:a1e0::52"), Quad100: true},
						merge: osglue.Stack{Owner: "default", Primary: true, Self: workSelf}},
					{owner: "home", running: true, sync: homeSelf,
						xlate: xlate.Stack{Owner: "home", Self: addrs("100.70.2.9"), UsesExit: true},
						merge: osglue.Stack{Owner: "home", Self: homeSelf, UsesExit: true}},
					{owner: "c", running: true, sync: prefixes("100.64.0.3/32"),
						xlate: xlate.Stack{Owner: "c", Self: addrs("100.64.0.3")},
						merge: osglue.Stack{Owner: "c", Self: prefixes("100.64.0.3/32")}},
					{owner: "d", running: true, sync: prefixes("100.64.0.4/32"),
						xlate: xlate.Stack{Owner: "d", Self: addrs("100.64.0.4")},
						merge: osglue.Stack{Owner: "d", Self: prefixes("100.64.0.4/32")}},
					{owner: "e"},
				},
				exitIgnored:  []remap.Owner{"d"},
				offerIgnored: []remap.Owner{"default", "c"},
			},
		},
		{
			// Stock tailscaled refuses this combination in one backend; if
			// a snapshot has it anyway, the exit node's own tailnet keeps
			// both: nothing crosses tailnets.
			name: "the exit user keeps its own offer",
			in: []tailnetState{
				{owner: "home", snap: withOffer(withExit(running(homeSelf, nil, nil)))},
			},
			want: want{plans: []tailnetRouting{
				{owner: "home", running: true, sync: homeSelf,
					xlate: xlate.Stack{Owner: "home", Self: addrs("100.70.2.9"), OffersExit: true, UsesExit: true},
					merge: osglue.Stack{Owner: "home", Self: homeSelf, UsesExit: true}},
			}},
		},
		{
			name: "offers stay without an exit in use",
			in: []tailnetState{
				{owner: "home", snap: withState(withExit(running(homeSelf, nil, nil)), ipn.Stopped)},
				{owner: "c", snap: withOffer(running(prefixes("100.64.0.3/32"), nil, nil))},
			},
			want: want{plans: []tailnetRouting{
				{owner: "home"},
				{owner: "c", running: true, sync: prefixes("100.64.0.3/32"),
					xlate: xlate.Stack{Owner: "c", Self: addrs("100.64.0.3"), OffersExit: true},
					merge: osglue.Stack{Owner: "c", Self: prefixes("100.64.0.3/32")}},
			}},
		},
		{
			name: "exit of a stopped tailnet does not count",
			in: []tailnetState{
				{owner: "home", snap: withState(withExit(running(homeSelf, nil, nil)), ipn.Stopped)},
				{owner: "c", snap: withExit(running(prefixes("100.64.0.3/32"), nil, nil))},
			},
			want: want{plans: []tailnetRouting{
				{owner: "home"},
				{owner: "c", running: true, sync: prefixes("100.64.0.3/32"),
					xlate: xlate.Stack{Owner: "c", Self: addrs("100.64.0.3"), UsesExit: true},
					merge: osglue.Stack{Owner: "c", Self: prefixes("100.64.0.3/32"), UsesExit: true}},
			}},
		},
		{
			name: "quad-100 follows the primary, wherever it is",
			in: []tailnetState{
				{owner: "home", snap: running(homeSelf, nil, nil)},
				{owner: "default", primary: true, snap: running(workSelf, nil, nil)},
			},
			want: want{plans: []tailnetRouting{
				{owner: "home", running: true, sync: homeSelf,
					xlate: xlate.Stack{Owner: "home", Self: addrs("100.70.2.9")},
					merge: osglue.Stack{Owner: "home", Self: homeSelf}},
				{owner: "default", running: true, sync: workSelf,
					xlate: xlate.Stack{Owner: "default", Self: addrs("100.101.5.2", "fd7a:115c:a1e0::52"), Quad100: true},
					merge: osglue.Stack{Owner: "default", Primary: true, Self: workSelf}},
			}},
		},
		{
			name: "no quad-100 while the primary is down",
			in: []tailnetState{
				{owner: "default", primary: true, snap: withState(running(workSelf, nil, nil), ipn.NeedsLogin)},
				{owner: "home", snap: running(homeSelf, nil, nil)},
			},
			want: want{plans: []tailnetRouting{
				{owner: "default"},
				{owner: "home", running: true, sync: homeSelf,
					xlate: xlate.Stack{Owner: "home", Self: addrs("100.70.2.9")},
					merge: osglue.Stack{Owner: "home", Self: homeSelf}},
			}},
		},
		{
			name: "only one primary serves quad-100",
			in: []tailnetState{
				{owner: "a", primary: true, snap: running(prefixes("100.64.0.1/32"), nil, nil)},
				{owner: "b", primary: true, snap: running(prefixes("100.64.0.2/32"), nil, nil)},
			},
			want: want{plans: []tailnetRouting{
				{owner: "a", running: true, sync: prefixes("100.64.0.1/32"),
					xlate: xlate.Stack{Owner: "a", Self: addrs("100.64.0.1"), Quad100: true},
					merge: osglue.Stack{Owner: "a", Primary: true, Self: prefixes("100.64.0.1/32")}},
				{owner: "b", running: true, sync: prefixes("100.64.0.2/32"),
					xlate: xlate.Stack{Owner: "b", Self: addrs("100.64.0.2")},
					merge: osglue.Stack{Owner: "b", Primary: true, Self: prefixes("100.64.0.2/32")}},
			}},
		},
		{
			name: "unsorted snapshot",
			in: []tailnetState{{owner: "home", snap: running(
				prefixes("fd7a:115c:a1e0::9/128", "100.64.0.9/32"),
				prefixes("100.64.0.20/32", "100.64.0.10/32"),
				prefixes("10.2.0.0/16", "10.1.0.0/16"),
			)}},
			want: want{plans: []tailnetRouting{{
				owner:   "home",
				running: true,
				sync:    prefixes("100.64.0.9/32", "fd7a:115c:a1e0::9/128", "100.64.0.10/32", "100.64.0.20/32", "10.1.0.0/16", "10.2.0.0/16"),
				xlate:   xlate.Stack{Owner: "home", Self: addrs("fd7a:115c:a1e0::9", "100.64.0.9")},
				merge: osglue.Stack{Owner: "home",
					Self:    prefixes("fd7a:115c:a1e0::9/128", "100.64.0.9/32"),
					Peers:   prefixes("100.64.0.20/32", "100.64.0.10/32"),
					Subnets: prefixes("10.2.0.0/16", "10.1.0.0/16")},
			}}},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			plans, ignored, offerIgnored := planRouting(c.in)
			if !reflect.DeepEqual(plans, c.want.plans) {
				t.Errorf("plans:\n got %s\nwant %s", fmtPlans(plans), fmtPlans(c.want.plans))
			}
			if !reflect.DeepEqual(ignored, c.want.exitIgnored) {
				t.Errorf("exitIgnored = %v, want %v", ignored, c.want.exitIgnored)
			}
			if !reflect.DeepEqual(offerIgnored, c.want.offerIgnored) {
				t.Errorf("offerIgnored = %v, want %v", offerIgnored, c.want.offerIgnored)
			}
			// The xlate stacks of the running tailnets must be accepted
			// as a set: one exit, one quad-100, unique owners.
			var stacks []xlate.Stack
			for _, p := range plans {
				if p.running {
					stacks = append(stacks, p.xlate)
				}
			}
			tb, err := remap.New(remap.Config{Pool6: mpp("fd00:1::/48")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := xlate.New(tb, nil).SetStacks(stacks); err != nil {
				t.Errorf("SetStacks: %v", err)
			}
		})
	}
}

// planRouting must not alias its input: the snapshot is the caller's.
func TestPlanRoutingDoesNotAlias(t *testing.T) {
	snap := ipnlocal.RoutingSnapshot{
		State:      ipn.Running,
		Self:       prefixes("100.64.0.1/32"),
		Peers:      prefixes("100.64.0.2/32"),
		Subnets:    prefixes("10.0.0.0/8"),
		Advertised: prefixes("192.168.1.0/24"),
	}
	plans, _, _ := planRouting([]tailnetState{{owner: "a", primary: true, snap: snap}})
	want, _, _ := planRouting([]tailnetState{{owner: "a", primary: true, snap: ipnlocal.RoutingSnapshot{
		State:      ipn.Running,
		Self:       prefixes("100.64.0.1/32"),
		Peers:      prefixes("100.64.0.2/32"),
		Subnets:    prefixes("10.0.0.0/8"),
		Advertised: prefixes("192.168.1.0/24"),
	}}})
	bad := mpp("1.2.3.0/24")
	snap.Self[0], snap.Peers[0], snap.Subnets[0], snap.Advertised[0] = bad, bad, bad, bad
	if !reflect.DeepEqual(plans, want) {
		t.Fatalf("plan changed with its input:\n got %s\nwant %s", fmtPlans(plans), fmtPlans(want))
	}
}

// fmtPlans formats plans for test failures. %v cannot show unexported
// fields' addresses readably.
func fmtPlans(ps []tailnetRouting) string {
	var s string
	for _, p := range ps {
		s += fmt.Sprintf("\n\t{owner=%s running=%v sync=%v xlate=%+v merge=%+v}", p.owner, p.running, p.sync, p.xlate, p.merge)
	}
	return s
}
