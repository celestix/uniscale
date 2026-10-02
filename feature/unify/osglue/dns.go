// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osglue

import (
	"errors"
	"slices"
	"sync"

	"tailscale.com/net/dns"
)

var errDNSClosed = errors.New("osglue: DNS configurator closed")

// DNS is a dns.OSConfigurator for one stack. It records the last
// configuration the stack's DNS manager sets. A passthrough DNS (see
// [NewPassthroughDNS]) also applies it to the host. It is safe for
// concurrent use.
type DNS struct {
	real   dns.OSConfigurator // nil if recording only
	notify func()

	mu     sync.Mutex
	cfg    dns.OSConfig
	closed bool
}

var _ dns.OSConfigurator = (*DNS)(nil)

// NewDNS returns a DNS that only records. It reports split DNS support,
// so the stack's DNS manager hands it its match domains instead of asking
// for the host's base configuration, which it cannot provide.
//
// If notify is not nil, it is called after every recorded change. The
// DNS manager may call into its configurator with the stack's
// LocalBackend lock held, so notify must not block or call into the
// stack.
func NewDNS(notify func()) *DNS {
	return &DNS{notify: notify}
}

// NewPassthroughDNS returns a DNS for the primary stack that records and
// also passes SetDNS, SupportsSplitDNS and GetBaseConfig to real. Close
// is not passed on: unify closes real itself. notify is as for [NewDNS].
func NewPassthroughDNS(real dns.OSConfigurator, notify func()) *DNS {
	if real == nil {
		panic("osglue: NewPassthroughDNS with nil configurator")
	}
	return &DNS{real: real, notify: notify}
}

// SetDNS implements dns.OSConfigurator. It records a copy of cfg and, for
// a passthrough DNS, then applies cfg to the host, returning its error.
// It fails after Close.
func (d *DNS) SetDNS(cfg dns.OSConfig) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return errDNSClosed
	}
	d.cfg = cloneOSConfig(cfg)
	d.mu.Unlock()
	d.changed()
	if d.real != nil {
		return d.real.SetDNS(cfg)
	}
	return nil
}

// SupportsSplitDNS implements dns.OSConfigurator.
func (d *DNS) SupportsSplitDNS() bool {
	if d.real != nil {
		return d.real.SupportsSplitDNS()
	}
	return true
}

// GetBaseConfig implements dns.OSConfigurator. A recording DNS returns
// dns.ErrGetBaseConfigNotSupported.
func (d *DNS) GetBaseConfig() (dns.OSConfig, error) {
	if d.real != nil {
		return d.real.GetBaseConfig()
	}
	return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
}

// Close implements dns.OSConfigurator. It forgets the configuration and
// does not touch the host.
func (d *DNS) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.cfg = dns.OSConfig{}
	d.mu.Unlock()
	d.changed()
	return nil
}

// Config returns a copy of the last configuration set. It is zero before
// the first SetDNS and after Close.
func (d *DNS) Config() dns.OSConfig {
	d.mu.Lock()
	defer d.mu.Unlock()
	return cloneOSConfig(d.cfg)
}

func (d *DNS) changed() {
	if d.notify != nil {
		d.notify()
	}
}

// cloneOSConfig returns a deep copy of c.
func cloneOSConfig(c dns.OSConfig) dns.OSConfig {
	out := dns.OSConfig{
		Nameservers:   slices.Clone(c.Nameservers),
		SearchDomains: slices.Clone(c.SearchDomains),
		MatchDomains:  slices.Clone(c.MatchDomains),
	}
	for _, h := range c.Hosts {
		if h != nil {
			h = &dns.HostEntry{Addr: h.Addr, Hosts: slices.Clone(h.Hosts)}
		}
		out.Hosts = append(out.Hosts, h)
	}
	for _, r := range c.Resolvers {
		out.Resolvers = append(out.Resolvers, r.Clone())
	}
	return out
}
