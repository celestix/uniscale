// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/types/preftype"
	"tailscale.com/util/checkchange"
)

func TestConfigEqual(t *testing.T) {
	testedFields := []string{
		"LocalAddrs", "Routes", "RouteSources", "LocalRoutes", "NewMTU",
		"SubnetRoutes", "SNATSubnetRoutes", "StatefulFiltering",
		"NetfilterMode", "NetfilterKind", "RemoveCGNATDropRule",
	}
	configType := reflect.TypeFor[Config]()
	configFields := []string{}
	for field := range configType.Fields() {
		configFields = append(configFields, field.Name)
	}
	if !reflect.DeepEqual(configFields, testedFields) {
		t.Errorf("Config.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			configFields, testedFields)
	}

	srcs := func(kv ...string) map[netip.Prefix]netip.Addr {
		m := make(map[netip.Prefix]netip.Addr)
		for i := 0; i < len(kv); i += 2 {
			m[netip.MustParsePrefix(kv[i])] = netip.MustParseAddr(kv[i+1])
		}
		return m
	}
	nets := func(strs ...string) (ns []netip.Prefix) {
		for _, s := range strs {
			n, err := netip.ParsePrefix(s)
			if err != nil {
				panic(err)
			}
			ns = append(ns, n)
		}
		return ns
	}
	tests := []struct {
		a, b *Config
		want bool
	}{
		{
			nil,
			nil,
			true,
		},
		{
			&Config{},
			nil,
			false,
		},
		{
			nil,
			&Config{},
			false,
		},
		{
			&Config{},
			&Config{},
			true,
		},

		{
			&Config{LocalAddrs: nets("100.1.27.82/32")},
			&Config{LocalAddrs: nets("100.2.19.82/32")},
			false,
		},
		{
			&Config{LocalAddrs: nets("100.1.27.82/32")},
			&Config{LocalAddrs: nets("100.1.27.82/32")},
			true,
		},

		{
			&Config{Routes: nets("100.1.27.0/24")},
			&Config{Routes: nets("100.2.19.0/24")},
			false,
		},
		{
			&Config{Routes: nets("100.2.19.0/24")},
			&Config{Routes: nets("100.2.19.0/24")},
			true,
		},

		{
			&Config{RouteSources: srcs("100.1.27.0/24", "100.64.0.1")},
			&Config{RouteSources: srcs("100.1.27.0/24", "100.64.0.2")},
			false,
		},
		{
			&Config{RouteSources: srcs("100.1.27.0/24", "100.64.0.1")},
			&Config{RouteSources: srcs("100.1.27.0/24", "100.64.0.1")},
			true,
		},
		{
			&Config{RouteSources: srcs("100.1.27.0/24", "100.64.0.1")},
			&Config{},
			false,
		},

		{
			&Config{LocalRoutes: nets("100.1.27.0/24")},
			&Config{LocalRoutes: nets("100.2.19.0/24")},
			false,
		},
		{
			&Config{LocalRoutes: nets("100.1.27.0/24")},
			&Config{LocalRoutes: nets("100.1.27.0/24")},
			true,
		},

		{
			&Config{SubnetRoutes: nets("100.1.27.0/24")},
			&Config{SubnetRoutes: nets("100.2.19.0/24")},
			false,
		},
		{
			&Config{SubnetRoutes: nets("100.1.27.0/24")},
			&Config{SubnetRoutes: nets("100.1.27.0/24")},
			true,
		},

		{
			&Config{SNATSubnetRoutes: false},
			&Config{SNATSubnetRoutes: true},
			false,
		},
		{
			&Config{SNATSubnetRoutes: false},
			&Config{SNATSubnetRoutes: false},
			true,
		},
		{
			&Config{StatefulFiltering: false},
			&Config{StatefulFiltering: true},
			false,
		},
		{
			&Config{StatefulFiltering: false},
			&Config{StatefulFiltering: false},
			true,
		},

		{
			&Config{NetfilterMode: preftype.NetfilterOff},
			&Config{NetfilterMode: preftype.NetfilterNoDivert},
			false,
		},
		{
			&Config{NetfilterMode: preftype.NetfilterNoDivert},
			&Config{NetfilterMode: preftype.NetfilterNoDivert},
			true,
		},
		{
			&Config{NewMTU: 0},
			&Config{NewMTU: 0},
			true,
		},
		{
			&Config{NewMTU: 1280},
			&Config{NewMTU: 0},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}

func TestConfigClone(t *testing.T) {
	if (*Config)(nil).Clone() != nil {
		t.Error("nil Clone is not nil")
	}
	p := netip.MustParsePrefix
	a := netip.MustParseAddr
	orig := &Config{
		LocalAddrs:   []netip.Prefix{p("100.64.0.2/32")},
		Routes:       []netip.Prefix{p("100.64.0.1/32")},
		RouteSources: map[netip.Prefix]netip.Addr{p("100.64.0.1/32"): a("100.64.0.2")},
		LocalRoutes:  []netip.Prefix{p("192.168.0.0/24")},
		SubnetRoutes: []netip.Prefix{p("10.0.0.0/8")},
		NewMTU:       1280,
	}
	c := orig.Clone()
	if !c.Equal(orig) {
		t.Fatalf("Clone = %+v, want %+v", c, orig)
	}
	c.LocalAddrs[0] = p("1.1.1.1/32")
	c.Routes[0] = p("1.1.1.1/32")
	c.RouteSources[p("100.64.0.1/32")] = a("1.1.1.1")
	c.RouteSources[p("1.1.1.1/32")] = a("1.1.1.1")
	c.LocalRoutes[0] = p("1.1.1.1/32")
	c.SubnetRoutes[0] = p("1.1.1.1/32")
	want := &Config{
		LocalAddrs:   []netip.Prefix{p("100.64.0.2/32")},
		Routes:       []netip.Prefix{p("100.64.0.1/32")},
		RouteSources: map[netip.Prefix]netip.Addr{p("100.64.0.1/32"): a("100.64.0.2")},
		LocalRoutes:  []netip.Prefix{p("192.168.0.0/24")},
		SubnetRoutes: []netip.Prefix{p("10.0.0.0/8")},
		NewMTU:       1280,
	}
	if !orig.Equal(want) {
		t.Errorf("changing the clone changed the original: %+v", orig)
	}

	// Without sources, the clone has none either: nil stays nil.
	if c := (&Config{}).Clone(); c.RouteSources != nil {
		t.Errorf("Clone of a config without sources has RouteSources %v", c.RouteSources)
	}
}

// TestConfigSourceOnlyChange checks that a change of route sources alone
// is a change for checkchange.Update, which the engine uses to decide
// whether to call Router.Set, and that the remembered configuration does
// not share the caller's map.
func TestConfigSourceOnlyChange(t *testing.T) {
	route := netip.MustParsePrefix("100.64.0.1/32")
	self1, self2 := netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.3")
	cfg := func(src netip.Addr) *Config {
		c := &Config{
			LocalAddrs: []netip.Prefix{netip.PrefixFrom(self1, 32), netip.PrefixFrom(self2, 32)},
			Routes:     []netip.Prefix{route},
		}
		if src.IsValid() {
			c.RouteSources = map[netip.Prefix]netip.Addr{route: src}
		}
		return c
	}

	var last *Config
	if !checkchange.Update(&last, cfg(self1)) {
		t.Fatal("first config not a change")
	}
	if checkchange.Update(&last, cfg(self1)) {
		t.Error("same config is a change")
	}
	next := cfg(self2)
	if !checkchange.Update(&last, next) {
		t.Error("source change is not a change")
	}
	next.RouteSources[route] = self1 // the caller reuses its map
	if last.RouteSources[route] != self2 {
		t.Errorf("remembered config shares the caller's map: %v", last.RouteSources)
	}
	if !checkchange.Update(&last, cfg(netip.Addr{})) {
		t.Error("source removal is not a change")
	}
}
