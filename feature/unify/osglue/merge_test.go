// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/preftype"
	"tailscale.com/wgengine/router"
)

func mapping(owner remap.Owner, real, virtual string) remap.Mapping {
	return remap.Mapping{Owner: owner, Real: pfx(real), Virtual: pfx(virtual)}
}

// quad100 is the service routes MergeRouter adds once whenever a stack
// runs.
var quad100 = []string{"100.100.100.100/32", "fd7a:115c:a1e0::53/128"}

func withQuad100(ss ...string) []netip.Prefix {
	return pfxs(append(ss, quad100...)...)
}

// srcs builds RouteSources from lists of route, source pairs, or returns
// nil if there are none.
func srcs(lists ...[]string) map[netip.Prefix]netip.Addr {
	var m map[netip.Prefix]netip.Addr
	for _, kv := range lists {
		for i := 0; i < len(kv); i += 2 {
			if m == nil {
				m = make(map[netip.Prefix]netip.Addr)
			}
			m[pfx(kv[i])] = netip.MustParseAddr(kv[i+1])
		}
	}
	return m
}

func TestMergeRouter(t *testing.T) {
	// Tailnets a (the primary) and b collide: both have a peer at
	// 100.64.0.1 and this node at 100.64.0.2. b's are remapped.
	mappings := []remap.Mapping{
		mapping("a", "100.64.0.2/32", "100.64.0.2/32"),
		mapping("a", "fd7a:115c:a1e0::2/128", "fd7a:115c:a1e0::2/128"),
		mapping("a", "100.64.0.1/32", "100.64.0.1/32"),
		mapping("a", "10.0.0.0/24", "10.0.0.0/24"),
		mapping("a", "100.64.0.9/32", "100.64.0.9/32"), // sticky, no longer a peer
		mapping("b", "100.64.0.2/32", "198.18.0.2/32"),
		mapping("b", "100.64.0.1/32", "198.18.0.1/32"),
		mapping("b", "10.0.0.0/24", "198.18.1.0/24"),
		mapping("b", "100.64.0.5/32", "198.18.0.5/32"),
		// e and f route the same virtual prefix (remap never does that).
		mapping("e", "100.64.0.7/32", "100.64.0.7/32"),
		mapping("e", "10.9.0.0/24", "10.9.0.0/24"),
		mapping("e", "100.100.100.100/32", "100.100.100.100/32"),
		mapping("f", "100.64.0.8/32", "100.64.0.8/32"),
		mapping("f", "10.8.0.0/24", "10.9.0.0/24"),
	}
	a := func() Stack {
		return Stack{
			Owner:   "a",
			Primary: true,
			Self:    pfxs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
			Peers:   pfxs("100.64.0.1/32"),
			Subnets: pfxs("10.0.0.0/24"),
		}
	}
	b := func() Stack {
		return Stack{
			Owner:   "b",
			Self:    pfxs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"), // v6 self unmapped
			Peers:   pfxs("100.64.0.1/32"),
			Subnets: pfxs("10.0.0.0/24", "172.16.0.0/12"), // 172.16/12 unmapped
		}
	}
	both := []string{"10.0.0.0/24", "100.64.0.1/32", "198.18.0.1/32", "198.18.1.0/24"}
	bothAddrs := pfxs("100.64.0.2/32", "198.18.0.2/32", "fd7a:115c:a1e0::2/128")

	// Each stack's routes prefer its virtual self of their family; b
	// has no IPv6 one. Quad-100 prefers the primary's.
	srcA := []string{"10.0.0.0/24", "100.64.0.2", "100.64.0.1/32", "100.64.0.2"}
	srcB := []string{"198.18.0.1/32", "198.18.0.2", "198.18.1.0/24", "198.18.0.2"}
	srcQuad := []string{"100.100.100.100/32", "100.64.0.2", "fd7a:115c:a1e0::53/128", "fd7a:115c:a1e0::2"}
	srcBoth := srcs(srcA, srcB, srcQuad)

	tests := []struct {
		name   string
		stacks func() []Stack
		want   *router.Config
	}{
		{
			name:   "no stacks",
			stacks: func() []Stack { return nil },
			want:   &router.Config{},
		},
		{
			name:   "one stack",
			stacks: func() []Stack { return []Stack{a()} },
			want: &router.Config{
				LocalAddrs:   pfxs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
				Routes:       withQuad100("10.0.0.0/24", "100.64.0.1/32"),
				RouteSources: srcs(srcA, srcQuad),
			},
		},
		{
			// LocalAddrs are every stack's virtual selves; Routes are
			// the virtual prefixes of the current peers and subnets,
			// skipping unmapped ones, plus quad-100 once.
			name:   "two stacks",
			stacks: func() []Stack { return []Stack{a(), b()} },
			want: &router.Config{
				LocalAddrs:   bothAddrs,
				Routes:       withQuad100(both...),
				RouteSources: srcBoth,
			},
		},
		{
			// A stack only gets its own mappings: b's mapping of
			// 100.64.0.5 does not route a's peer of that address.
			name: "owner isolation",
			stacks: func() []Stack {
				s := a()
				s.Peers = pfxs("100.64.0.5/32")
				return []Stack{s}
			},
			want: &router.Config{
				LocalAddrs:   pfxs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
				Routes:       withQuad100("10.0.0.0/24"),
				RouteSources: srcs([]string{"10.0.0.0/24", "100.64.0.2"}, srcQuad),
			},
		},
		{
			name: "duplicates",
			stacks: func() []Stack {
				s := a()
				s.Peers = pfxs("100.64.0.1/32", "100.64.0.1/32")
				s.Subnets = pfxs("10.0.0.0/24", "10.0.0.0/24")
				s.Self = append(s.Self, s.Self...)
				return []Stack{s}
			},
			want: &router.Config{
				LocalAddrs:   pfxs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
				Routes:       withQuad100("10.0.0.0/24", "100.64.0.1/32"),
				RouteSources: srcs(srcA, srcQuad),
			},
		},
		{
			// Captured Routes are not copied: they may be coarsened
			// to the CGNAT /10 and carry the stack's own exit routes.
			// Neither are captured LocalAddrs.
			name: "captured routes ignored",
			stacks: func() []Stack {
				s := b()
				s.Captured = &router.Config{
					LocalAddrs: pfxs("100.64.0.2/32"),
					Routes:     pfxs("100.64.0.0/10", "0.0.0.0/0", "::/0", "100.100.100.100/32"),
				}
				return []Stack{s}
			},
			want: &router.Config{
				LocalAddrs:   pfxs("198.18.0.2/32"),
				Routes:       withQuad100("198.18.0.1/32", "198.18.1.0/24"),
				RouteSources: srcs(srcB), // no primary, no quad-100 source
			},
		},
		{
			// The exit stack adds the exit routes and its local
			// routes (LAN access while using the exit node); other
			// stacks' local routes are ignored.
			name: "exit",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sa.Captured = &router.Config{LocalRoutes: pfxs("10.1.0.0/16")}
				sb.UsesExit = true
				sb.Captured = &router.Config{
					LocalRoutes: pfxs("192.168.1.0/24", "172.17.0.0/16", "192.168.1.0/24"),
				}
				return []Stack{sa, sb}
			},
			want: &router.Config{
				LocalAddrs:  bothAddrs,
				Routes:      withQuad100(append([]string{"0.0.0.0/0", "::/0"}, both...)...),
				LocalRoutes: pfxs("172.17.0.0/16", "192.168.1.0/24"),
				// b has no IPv6 self: ::/0 gets no source.
				RouteSources: srcs(srcA, srcB, srcQuad, []string{"0.0.0.0/0", "198.18.0.2"}),
			},
		},
		{
			name: "no exit",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sb.Captured = &router.Config{LocalRoutes: pfxs("192.168.1.0/24")}
				return []Stack{sa, sb}
			},
			want: &router.Config{
				LocalAddrs:   bothAddrs,
				Routes:       withQuad100(both...),
				RouteSources: srcBoth,
			},
		},
		{
			name: "subnet routes union",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sa.Captured = &router.Config{SubnetRoutes: pfxs("192.168.1.0/24", "10.0.0.0/24")}
				sb.Captured = &router.Config{SubnetRoutes: pfxs("172.16.0.0/16", "192.168.1.0/24")}
				return []Stack{sa, sb}
			},
			want: &router.Config{
				LocalAddrs:   bothAddrs,
				Routes:       withQuad100(both...),
				RouteSources: srcBoth,
				SubnetRoutes: pfxs("10.0.0.0/24", "172.16.0.0/16", "192.168.1.0/24"),
			},
		},
		{
			name: "snat and stateful filtering or",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sa.Captured = &router.Config{SNATSubnetRoutes: true}
				sb.Captured = &router.Config{StatefulFiltering: true}
				return []Stack{sa, sb}
			},
			want: &router.Config{
				LocalAddrs:        bothAddrs,
				Routes:            withQuad100(both...),
				RouteSources:      srcBoth,
				SNATSubnetRoutes:  true,
				StatefulFiltering: true,
			},
		},
		{
			name: "snat and stateful filtering off",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sa.Captured = &router.Config{}
				sb.Captured = &router.Config{}
				return []Stack{sa, sb}
			},
			want: &router.Config{
				LocalAddrs:   bothAddrs,
				Routes:       withQuad100(both...),
				RouteSources: srcBoth,
			},
		},
		{
			// The primary's netfilter settings win wherever it is in
			// the order.
			name: "netfilter from primary",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sb.Captured = &router.Config{
					NetfilterMode:       preftype.NetfilterOn,
					NetfilterKind:       "iptables",
					RemoveCGNATDropRule: true,
				}
				sa.Captured = &router.Config{
					NetfilterMode: preftype.NetfilterNoDivert,
					NetfilterKind: "nftables",
				}
				return []Stack{sb, sa}
			},
			want: &router.Config{
				LocalAddrs:    bothAddrs,
				Routes:        withQuad100(both...),
				RouteSources:  srcBoth, // quad-100 from the primary, second here
				NetfilterMode: preftype.NetfilterNoDivert,
				NetfilterKind: "nftables",
			},
		},
		{
			// Without a running primary, the first stack with a
			// captured configuration provides them, so firewalling
			// does not switch off.
			name: "netfilter without primary",
			stacks: func() []Stack {
				sb := b()
				sc := Stack{Owner: "c", Captured: &router.Config{
					NetfilterMode:       preftype.NetfilterOn,
					NetfilterKind:       "nftables",
					RemoveCGNATDropRule: true,
				}}
				sd := Stack{Owner: "d", Captured: &router.Config{NetfilterMode: preftype.NetfilterNoDivert}}
				return []Stack{sb, sc, sd}
			},
			want: &router.Config{
				LocalAddrs:          pfxs("198.18.0.2/32"),
				Routes:              withQuad100("198.18.0.1/32", "198.18.1.0/24"),
				RouteSources:        srcs(srcB),
				NetfilterMode:       preftype.NetfilterOn,
				NetfilterKind:       "nftables",
				RemoveCGNATDropRule: true,
			},
		},
		{
			name: "netfilter primary without captured config",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sb.Captured = &router.Config{NetfilterMode: preftype.NetfilterOn}
				return []Stack{sa, sb}
			},
			want: &router.Config{
				LocalAddrs:    bothAddrs,
				Routes:        withQuad100(both...),
				RouteSources:  srcBoth,
				NetfilterMode: preftype.NetfilterOn,
			},
		},
		{
			name: "mtu minimum non-zero",
			stacks: func() []Stack {
				sa, sb := a(), b()
				sc := Stack{Owner: "c", Captured: &router.Config{NewMTU: 1280}}
				sa.Captured = &router.Config{NewMTU: 1400}
				sb.Captured = &router.Config{}
				return []Stack{sa, sb, sc}
			},
			want: &router.Config{
				LocalAddrs:   bothAddrs,
				Routes:       withQuad100(both...),
				RouteSources: srcBoth,
				NewMTU:       1280,
			},
		},
		{
			// A running stack without self addresses or routes still
			// gets quad-100 routed to the TUN.
			name:   "empty stack",
			stacks: func() []Stack { return []Stack{{Owner: "c"}} },
			want: &router.Config{
				Routes: withQuad100(),
			},
		},
		{
			// The exit stack's own selves are the exit routes' sources.
			name: "exit through primary",
			stacks: func() []Stack {
				sa := a()
				sa.UsesExit = true
				return []Stack{sa, b()}
			},
			want: &router.Config{
				LocalAddrs: bothAddrs,
				Routes:     withQuad100(append([]string{"0.0.0.0/0", "::/0"}, both...)...),
				RouteSources: srcs(srcA, srcB, srcQuad,
					[]string{"0.0.0.0/0", "100.64.0.2", "::/0", "fd7a:115c:a1e0::2"}),
			},
		},
		{
			// With several selves of a family, the smallest is the
			// source, whatever their order.
			name: "several selves",
			stacks: func() []Stack {
				s := a()
				s.Self = pfxs("100.64.0.9/32", "fd7a:115c:a1e0::2/128", "100.64.0.2/32")
				return []Stack{s}
			},
			want: &router.Config{
				LocalAddrs:   pfxs("100.64.0.2/32", "100.64.0.9/32", "fd7a:115c:a1e0::2/128"),
				Routes:       withQuad100("10.0.0.0/24", "100.64.0.1/32"),
				RouteSources: srcs(srcA, srcQuad),
			},
		},
		{
			// A prefix two stacks route keeps the first one's source.
			name: "shared route",
			stacks: func() []Stack {
				e := Stack{Owner: "e", Self: pfxs("100.64.0.7/32"), Subnets: pfxs("10.9.0.0/24")}
				f := Stack{Owner: "f", Self: pfxs("100.64.0.8/32"), Subnets: pfxs("10.8.0.0/24")}
				return []Stack{f, e}
			},
			want: &router.Config{
				LocalAddrs:   pfxs("100.64.0.7/32", "100.64.0.8/32"),
				Routes:       withQuad100("10.9.0.0/24"),
				RouteSources: srcs([]string{"10.9.0.0/24", "100.64.0.8"}),
			},
		},
		{
			// The primary's selves serve quad-100 even if an earlier
			// stack routes the address itself.
			name: "quad-100 from primary only",
			stacks: func() []Stack {
				e := Stack{Owner: "e", Self: pfxs("100.64.0.7/32"), Subnets: pfxs("10.9.0.0/24", "100.100.100.100/32")}
				return []Stack{e, a()}
			},
			want: &router.Config{
				LocalAddrs:   pfxs("100.64.0.2/32", "100.64.0.7/32", "fd7a:115c:a1e0::2/128"),
				Routes:       withQuad100("10.0.0.0/24", "10.9.0.0/24", "100.64.0.1/32"),
				RouteSources: srcs(srcA, srcQuad, []string{"10.9.0.0/24", "100.64.0.7"}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stacks := tt.stacks()
			got := MergeRouter(stacks, mappings)
			want := tt.want.Clone()
			for _, l := range []*[]netip.Prefix{&want.LocalAddrs, &want.Routes, &want.LocalRoutes, &want.SubnetRoutes} {
				tsaddr.SortPrefixes(*l)
			}
			if d := cmp.Diff(want, got, cmpopts.EquateEmpty(), cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{})); d != "" {
				t.Errorf("MergeRouter (-want +got):\n%s", d)
			}
			checkRouteSources(t, got)
			// Merging is deterministic, so the real router's Equal
			// check sees no change for the same input.
			if again := MergeRouter(stacks, mappings); !again.Equal(got) {
				t.Errorf("second merge differs: %+v vs %+v", again, got)
			}
		})
	}
}

func TestMergeRouterDoesNotAlias(t *testing.T) {
	captured := &router.Config{
		SubnetRoutes: pfxs("10.0.0.0/24"),
		LocalRoutes:  pfxs("192.168.1.0/24"),
	}
	stacks := []Stack{{Owner: "a", Primary: true, UsesExit: true, Captured: captured}}
	got := MergeRouter(stacks, nil)
	got.SubnetRoutes[0] = pfx("1.2.3.4/32")
	got.LocalRoutes[0] = pfx("1.2.3.4/32")
	if captured.SubnetRoutes[0] != pfx("10.0.0.0/24") || captured.LocalRoutes[0] != pfx("192.168.1.0/24") {
		t.Errorf("merged config aliases the captured one: %+v", captured)
	}
}

// checkRouteSources checks what the Linux router needs of RouteSources:
// every key is a route and every source an address of LocalAddrs of the
// route's family. Without sources, the map is nil, as in configurations
// that never had any.
func checkRouteSources(t *testing.T, cfg *router.Config) {
	t.Helper()
	if cfg.RouteSources != nil && len(cfg.RouteSources) == 0 {
		t.Error("empty non-nil RouteSources")
	}
	for r, src := range cfg.RouteSources {
		if !slices.Contains(cfg.Routes, r) {
			t.Errorf("source %v for %v, which is not a route", src, r)
		}
		if !slices.Contains(cfg.LocalAddrs, netip.PrefixFrom(src, src.BitLen())) || src.Is4() != r.Addr().Is4() {
			t.Errorf("route %v: source %v is not a local address of its family", r, src)
		}
	}
}
