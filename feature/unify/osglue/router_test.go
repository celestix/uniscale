// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/wgengine/router"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func pfxs(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, pfx(s))
	}
	return out
}

var _ router.Router = (*Router)(nil)

func TestRouter(t *testing.T) {
	var notified atomic.Int64
	r := NewRouter(func() { notified.Add(1) })

	if err := r.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if cfg := r.Config(); cfg != nil {
		t.Fatalf("Config before Set = %+v; want nil", cfg)
	}

	in := &router.Config{
		LocalAddrs:   pfxs("100.64.0.1/32"),
		Routes:       pfxs("100.64.0.2/32"),
		LocalRoutes:  pfxs("192.168.1.0/24"),
		SubnetRoutes: pfxs("10.0.0.0/24"),
		NewMTU:       1280,
	}
	if err := r.Set(in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if notified.Load() != 1 {
		t.Errorf("notified %d times after Set; want 1", notified.Load())
	}
	want := in.Clone()
	// The engine keeps and may reuse its pointer: the record is a copy.
	in.Routes[0] = pfx("1.2.3.4/32")
	got := r.Config()
	if !got.Equal(want) {
		t.Errorf("Config = %+v; want %+v", got, want)
	}
	// Config returns a copy too.
	got.LocalAddrs[0] = pfx("1.2.3.4/32")
	if !r.Config().Equal(want) {
		t.Errorf("Config shares memory with the record: %+v", r.Config())
	}

	// Set(nil) means "no configuration".
	if err := r.Set(nil); err != nil {
		t.Fatalf("Set(nil): %v", err)
	}
	if cfg := r.Config(); cfg != nil {
		t.Errorf("Config after Set(nil) = %+v; want nil", cfg)
	}

	if err := r.Set(want); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if cfg := r.Config(); cfg != nil {
		t.Errorf("Config after Close = %+v; want nil", cfg)
	}
	before := notified.Load()
	if err := r.Set(want); err == nil {
		t.Error("Set after Close: want error")
	}
	if r.Config() != nil {
		t.Error("Set after Close recorded a config")
	}
	if notified.Load() != before {
		t.Error("Set after Close notified")
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if got := notified.Load(); got != 4 {
		t.Errorf("notified %d times; want 4 (three Sets and the first Close)", got)
	}
}

func TestRouterNilNotify(t *testing.T) {
	r := NewRouter(nil)
	if err := r.Set(&router.Config{NewMTU: 1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRouterConcurrent(t *testing.T) {
	r := NewRouter(func() {})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 100 {
				r.Set(&router.Config{NewMTU: i*1000 + j})
				r.Config()
			}
		})
	}
	wg.Wait()
	if r.Config() == nil {
		t.Error("Config = nil after concurrent Sets")
	}
}
