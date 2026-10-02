// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package stack builds one tailnet stack for tailnet unification: a
// LocalBackend with its own event bus, health tracker, network monitor,
// dialer, userspace engine and netstack, on a TUN device, router and DNS
// configurator that unify supplies.
//
// A stack never changes process-wide state: it does not toggle netns,
// set the Tailscale interface, configure DNS fallback caches, start
// logtail, or publish expvars. The daemon does those once, for the real
// TUN.
package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/client/local"
	"tailscale.com/control/controlclient"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

// Config configures a stack.
type Config struct {
	// Name names the stack in logs. Required.
	Name string

	// Dir is the stack's state directory, created if missing. It is the
	// backend's VarRoot and, if Store is nil, holds the state file
	// tailscaled.state. Dir may be empty only if Store is set.
	Dir string

	// Store is the stack's state store. If nil, a file store in Dir is
	// used.
	Store ipn.StateStore

	// Ephemeral registers the node as ephemeral, as tailscaled does with
	// an in-memory state store.
	Ephemeral bool

	// Port is the UDP port for WireGuard and peer-to-peer traffic. Zero
	// picks a free one.
	Port uint16

	// Logf is the base logger. Every line gets the prefix
	// "[unify:<Name>] ". If nil, logs are discarded.
	Logf logger.Logf

	// LogID is the backend's log ID. Stacks without logtail of their own
	// leave it zero.
	LogID logid.PublicID

	// SocketPath is the LocalAPI socket that serves the stack, if any.
	// Serve uses it to avoid proxying to itself.
	SocketPath string

	// Tun is the stack's device. The stack closes it on Close. Required.
	Tun tun.Device

	// Router receives the stack's router configuration. The stack's
	// engine brings it up and closes it. Required.
	Router router.Router

	// DNS receives the stack's OS DNS configuration. The stack's DNS
	// manager closes it. Required.
	DNS dns.OSConfigurator

	// OnPortUpdate, if not nil, is called with each router.PortUpdate
	// the stack's magicsock publishes when it binds its UDP sockets,
	// including the first binds during New. It runs on an event bus
	// goroutine and must not block for long.
	OnPortUpdate func(router.PortUpdate)
}

func (c *Config) validate() error {
	switch {
	case c.Name == "":
		return errors.New("stack: Config.Name is required")
	case c.Tun == nil:
		return errors.New("stack: Config.Tun is required")
	case c.Router == nil:
		return errors.New("stack: Config.Router is required")
	case c.DNS == nil:
		return errors.New("stack: Config.DNS is required")
	case c.Dir == "" && c.Store == nil:
		return errors.New("stack: Config.Dir is required without Config.Store")
	}
	return nil
}

// Stack is one running tailnet stack.
type Stack struct {
	name   string
	logf   logger.Logf
	sys    *tsd.System
	ec     *eventbus.Client // nil without Config.OnPortUpdate
	netMon *netmon.Monitor
	dialer *tsdial.Dialer
	eng    wgengine.Engine
	ns     *netstack.Impl
	lb     *ipnlocal.LocalBackend

	closeOnce sync.Once
	closeErr  error
}

// New builds a stack. Its backend is not started: call
// LocalBackend().Start as tailscaled does.
func New(cfg Config) (_ *Stack, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	logf := cfg.Logf
	if logf == nil {
		logf = logger.Discard
	}
	s := &Stack{
		name: cfg.Name,
		logf: logger.WithPrefix(logf, "[unify:"+cfg.Name+"] "),
		sys:  tsd.NewSystem(),
	}
	defer func() {
		if err != nil {
			s.Close()
			err = fmt.Errorf("stack %s: %w", cfg.Name, err)
		}
	}()
	s.sys.SocketPath = cfg.SocketPath
	bus := s.sys.Bus.Get()
	if cfg.OnPortUpdate != nil {
		// Subscribe before the engine exists: magicsock publishes port
		// updates only while someone subscribes.
		s.ec = bus.Client("unify.stack")
		eventbus.SubscribeFunc(s.ec, cfg.OnPortUpdate)
	}
	if cfg.Dir != "" {
		if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
			return nil, err
		}
	}

	if s.netMon, err = netmon.New(bus, s.logf); err != nil {
		return nil, err
	}
	s.sys.Set(s.netMon)
	s.dialer = &tsdial.Dialer{Logf: s.logf}
	s.dialer.SetBus(bus)
	s.eng, err = wgengine.NewUserspaceEngine(s.logf, wgengine.Config{
		Tun:           cfg.Tun,
		Router:        cfg.Router,
		DNS:           cfg.DNS,
		ListenPort:    cfg.Port,
		EventBus:      bus,
		NetMon:        s.netMon,
		Dialer:        s.dialer,
		SetSubsystem:  s.sys.Set,
		ControlKnobs:  s.sys.ControlKnobs(),
		HealthTracker: s.sys.HealthTracker.Get(),
		Metrics:       s.sys.UserMetricsRegistry(),
	})
	if err != nil {
		return nil, err
	}
	s.sys.Set(s.eng)
	s.sys.HealthTracker.Get().SetMetricsRegistry(s.sys.UserMetricsRegistry())

	s.ns, err = netstack.Create(s.logf, s.sys.Tun.Get(), s.eng, s.sys.MagicSock.Get(), s.dialer, s.sys.DNSManager.Get(), s.sys.ProxyMapper())
	if err != nil {
		return nil, err
	}
	// Netstack only takes what tailscaled itself serves on this node's
	// addresses (peerapi, SSH, serve) and replies to the stack's own
	// connections; everything else goes out of the TUN to the host.
	s.ns.ProcessLocalIPs = false
	s.ns.ProcessSubnets = false
	s.ns.CheckLocalTransportEndpoints = true
	s.sys.Tun.Get().Start()
	s.sys.Set(s.ns)

	st := cfg.Store
	if st == nil {
		if st, err = store.New(s.logf, filepath.Join(cfg.Dir, "tailscaled.state")); err != nil {
			return nil, err
		}
	}
	s.sys.Set(st)

	flags := controlclient.LoginDefault
	if cfg.Ephemeral {
		flags = controlclient.LoginEphemeral
	}
	if s.lb, err = ipnlocal.NewLocalBackend(s.logf, cfg.LogID, s.sys, flags); err != nil {
		return nil, err
	}
	// Peerapi, serve and the web client are served by netstack only. The
	// stack's real addresses may be another tailnet's addresses on the
	// host, so a kernel listener on them would answer that tailnet's
	// peers.
	s.lb.SetNoKernelListeners(true)
	if cfg.Dir != "" {
		s.lb.SetVarRoot(cfg.Dir)
	}
	// Configure the web client to connect to this stack's socket, not the
	// primary daemon's default socket.
	if buildfeatures.HasWebClient && cfg.SocketPath != "" {
		s.lb.ConfigureWebClient(&local.Client{
			Socket:        cfg.SocketPath,
			UseSocketOnly: true,
		})
	}

	// The stack reaches its tailnet through netstack, never through the
	// host: the host routes by unified addresses and could pick another
	// tailnet.
	lb := s.lb
	s.dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		// Use netstack for known peers/routes or any Tailscale-range address.
		_, ok := lb.PeerForIP(ip)
		return ok || tsaddr.IsTailscaleIP(ip)
	}
	s.dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return netConn(s.ns.DialContextTCPWithBind(ctx, s.selfAddr(dst.Addr()), dst))
	}
	s.dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return netConn(s.ns.DialContextUDPWithBind(ctx, s.selfAddr(dst.Addr()), dst))
	}
	if err := s.ns.Start(lb); err != nil {
		return nil, err
	}
	return s, nil
}

// netConn returns c, or a nil net.Conn if err is set: a nil pointer in a
// non-nil interface trips up callers.
func netConn[T net.Conn](c T, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	return c, nil
}

// selfAddr returns this node's address of dst's family, or the zero
// address if it has none.
func (s *Stack) selfAddr(dst netip.Addr) netip.Addr {
	if nm := s.lb.NetMapNoPeers(); nm != nil {
		for _, p := range nm.GetAddresses().All() {
			if p.Addr().Is4() == dst.Is4() {
				return p.Addr()
			}
		}
	}
	return netip.Addr{}
}

// Name returns the stack's name.
func (s *Stack) Name() string { return s.name }

// Logf returns the stack's logger, which prefixes every line with the
// stack's name.
func (s *Stack) Logf() logger.Logf { return s.logf }

// Sys returns the stack's system: its own event bus, health tracker,
// network monitor, dialer, engine, netstack and state store.
func (s *Stack) Sys() *tsd.System { return s.sys }

// LocalBackend returns the stack's backend.
//
// To serve it over LocalAPI, use an ipnserver.Server on the stack's own
// bus, so a shutdown request stops only this stack's server:
//
//	lb := s.LocalBackend()
//	srv := ipnserver.New(s.Logf(), logID, lb.EventBus(), lb.NetMon())
//	srv.SetLocalBackend(lb)
//	go srv.Run(ctx, ln) // shuts lb down when it returns
func (s *Stack) LocalBackend() *ipnlocal.LocalBackend { return s.lb }

// Close shuts the stack down: its netstack, backend, engine (and with it
// the TUN, router and DNS configurator from the Config), network
// monitor, dialer and event bus. It is safe to call more than once and
// after the backend was shut down elsewhere.
func (s *Stack) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		// Close the TUN device first so any blocked writes return, allowing
		// netstack and the engine to shut down without hanging.
		if s.sys != nil {
			if tun, ok := s.sys.Tun.GetOK(); ok {
				if tunDev := tun.Unwrap(); tunDev != nil {
					tunDev.Close()
				}
			}
		}
		if s.ns != nil {
			errs = append(errs, s.ns.Close())
		}
		if s.lb != nil {
			s.lb.Shutdown() // also closes the engine
		} else if s.eng != nil {
			s.eng.Close()
			<-s.eng.Done()
		}
		if s.netMon != nil {
			errs = append(errs, s.netMon.Close())
		}
		if s.dialer != nil {
			errs = append(errs, s.dialer.Close())
		}
		if s.ec != nil {
			s.ec.Close()
		}
		if s.sys != nil {
			s.sys.Bus.Get().Close()
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}
