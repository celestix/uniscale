// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"errors"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

var _ dns.OSConfigurator = (*DNS)(nil)

func testOSConfig() dns.OSConfig {
	return dns.OSConfig{
		Hosts: []*dns.HostEntry{{
			Addr:  netip.MustParseAddr("100.64.0.2"),
			Hosts: []string{"peer.example.ts.net."},
		}},
		Nameservers:   []netip.Addr{netip.MustParseAddr("100.100.100.100")},
		SearchDomains: []dnsname.FQDN{"example.ts.net."},
		MatchDomains:  []dnsname.FQDN{"example.ts.net.", "corp.example."},
		Resolvers:     []*dnstype.Resolver{{Addr: "10.0.0.53"}},
	}
}

// mutateOSConfig changes every reference-typed part of c in place.
func mutateOSConfig(c dns.OSConfig) {
	c.Hosts[0].Addr = netip.MustParseAddr("1.2.3.4")
	c.Hosts[0].Hosts[0] = "changed."
	c.Nameservers[0] = netip.MustParseAddr("1.2.3.4")
	c.SearchDomains[0] = "changed."
	c.MatchDomains[0] = "changed."
	c.Resolvers[0].Addr = "changed"
}

// fakeOSConfigurator is a stand-in for the host's real DNS configurator.
type fakeOSConfigurator struct {
	split   bool
	base    dns.OSConfig
	baseErr error
	setErr  error

	set    []dns.OSConfig
	closed bool
}

func (f *fakeOSConfigurator) SetDNS(cfg dns.OSConfig) error {
	f.set = append(f.set, cfg)
	return f.setErr
}
func (f *fakeOSConfigurator) SupportsSplitDNS() bool { return f.split }
func (f *fakeOSConfigurator) GetBaseConfig() (dns.OSConfig, error) {
	return f.base, f.baseErr
}
func (f *fakeOSConfigurator) Close() error {
	f.closed = true
	return nil
}

func TestRecordingDNS(t *testing.T) {
	var notified atomic.Int64
	d := NewDNS(func() { notified.Add(1) })

	if !d.SupportsSplitDNS() {
		t.Error("SupportsSplitDNS = false; want true")
	}
	if cfg, err := d.GetBaseConfig(); !errors.Is(err, dns.ErrGetBaseConfigNotSupported) || !cfg.IsZero() {
		t.Errorf("GetBaseConfig = %+v, %v; want zero, ErrGetBaseConfigNotSupported", cfg, err)
	}
	if cfg := d.Config(); !cfg.IsZero() {
		t.Errorf("Config before SetDNS = %+v; want zero", cfg)
	}

	in := testOSConfig()
	if err := d.SetDNS(in); err != nil {
		t.Fatalf("SetDNS: %v", err)
	}
	if notified.Load() != 1 {
		t.Errorf("notified %d times after SetDNS; want 1", notified.Load())
	}
	mutateOSConfig(in)
	got := d.Config()
	if !reflect.DeepEqual(got, testOSConfig()) {
		t.Errorf("Config = %+v; want %+v", got, testOSConfig())
	}
	mutateOSConfig(got)
	if !reflect.DeepEqual(d.Config(), testOSConfig()) {
		t.Errorf("Config shares memory with the record: %+v", d.Config())
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if cfg := d.Config(); !cfg.IsZero() {
		t.Errorf("Config after Close = %+v; want zero", cfg)
	}
	if err := d.SetDNS(testOSConfig()); err == nil {
		t.Error("SetDNS after Close: want error")
	}
	if cfg := d.Config(); !cfg.IsZero() {
		t.Error("SetDNS after Close recorded a config")
	}
	if err := d.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if got := notified.Load(); got != 2 {
		t.Errorf("notified %d times; want 2 (SetDNS and the first Close)", got)
	}
}

func TestRecordingDNSNilEntries(t *testing.T) {
	d := NewDNS(nil)
	in := dns.OSConfig{
		Hosts:     []*dns.HostEntry{nil},
		Resolvers: []*dnstype.Resolver{nil},
	}
	if err := d.SetDNS(in); err != nil {
		t.Fatal(err)
	}
	if got := d.Config(); !reflect.DeepEqual(got, in) {
		t.Errorf("Config = %+v; want %+v", got, in)
	}
}

func TestRecordingDNSZeroConfig(t *testing.T) {
	d := NewDNS(nil)
	if err := d.SetDNS(testOSConfig()); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDNS(dns.OSConfig{}); err != nil {
		t.Fatal(err)
	}
	if cfg := d.Config(); !reflect.DeepEqual(cfg, dns.OSConfig{}) {
		t.Errorf("Config after zero SetDNS = %+v; want zero", cfg)
	}
}

func TestPassthroughDNS(t *testing.T) {
	base := dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}
	for _, split := range []bool{false, true} {
		real := &fakeOSConfigurator{split: split, base: base}
		var notified atomic.Int64
		d := NewPassthroughDNS(real, func() { notified.Add(1) })

		if got := d.SupportsSplitDNS(); got != split {
			t.Errorf("SupportsSplitDNS = %v; want %v", got, split)
		}
		if cfg, err := d.GetBaseConfig(); err != nil || !reflect.DeepEqual(cfg, base) {
			t.Errorf("GetBaseConfig = %+v, %v; want %+v, nil", cfg, err, base)
		}

		in := testOSConfig()
		if err := d.SetDNS(in); err != nil {
			t.Fatalf("SetDNS: %v", err)
		}
		if len(real.set) != 1 || !reflect.DeepEqual(real.set[0], testOSConfig()) {
			t.Fatalf("real SetDNS calls = %+v; want one with the stack's config", real.set)
		}
		// The real configurator owns what it got; our record is separate.
		mutateOSConfig(real.set[0])
		if !reflect.DeepEqual(d.Config(), testOSConfig()) {
			t.Errorf("Config = %+v; want %+v", d.Config(), testOSConfig())
		}
		if notified.Load() != 1 {
			t.Errorf("notified %d times; want 1", notified.Load())
		}

		// Unify closes the real configurator itself.
		if err := d.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if real.closed {
			t.Error("Close was passed through to the real configurator")
		}
		if err := d.SetDNS(testOSConfig()); err == nil {
			t.Error("SetDNS after Close: want error")
		}
		if len(real.set) != 1 {
			t.Errorf("SetDNS after Close reached the real configurator")
		}
	}
}

func TestPassthroughDNSErrors(t *testing.T) {
	setErr := errors.New("set failed")
	baseErr := dns.ErrGetBaseConfigNoResolvers
	real := &fakeOSConfigurator{setErr: setErr, baseErr: baseErr}
	d := NewPassthroughDNS(real, nil)
	if err := d.SetDNS(testOSConfig()); !errors.Is(err, setErr) {
		t.Errorf("SetDNS error = %v; want %v", err, setErr)
	}
	// The stack's wish is recorded even when the OS refuses it.
	if !reflect.DeepEqual(d.Config(), testOSConfig()) {
		t.Errorf("Config = %+v; want the stack's config", d.Config())
	}
	if _, err := d.GetBaseConfig(); !errors.Is(err, baseErr) {
		t.Errorf("GetBaseConfig error = %v; want %v", err, baseErr)
	}
}

func TestPassthroughDNSNil(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewPassthroughDNS(nil): want panic")
		}
	}()
	NewPassthroughDNS(nil, nil)
}
