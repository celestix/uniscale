// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package unify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine/router"
)

// hostDeps creates what the tailnets share on the host: the real TUN
// device, its router and OS DNS configurator, and the LocalAPI listeners.
// osHost has the real ones; tests use fakes.
type hostDeps struct {
	// newTUN creates the TUN device name and returns it with the name the
	// OS gave it.
	newTUN func(logf logger.Logf, name string) (tun.Device, string, error)

	// newRouter creates the router of dev.
	newRouter func(logf logger.Logf, dev tun.Device, sys *tsd.System) (router.Router, error)

	// newDNS creates the OS DNS configurator for the interface devName.
	newDNS func(logf logger.Logf, sys *tsd.System, devName string) (dns.OSConfigurator, error)

	// linkUp configures link features of dev (the GRO knobs and probe),
	// once its router is up. It may be nil.
	linkUp func(dev tun.Device, logf logger.Logf)

	// listen listens on a LocalAPI socket.
	listen func(path string) (net.Listener, error)
}

// runDaemon runs tailscaled in tailnet unification mode, as the
// [tailscaledhooks.Unify] hook: the primary tailnet and those in the
// configuration file ([ConfigPath]), each on its own stack and serving
// LocalAPI on its own socket ([TailnetSocket]), all on one host TUN
// device. It returns when ctx is done, the host TUN device fails or a
// LocalAPI server stops (as on a shutdown request), after shutting
// everything down.
func runDaemon(ctx context.Context, a tailscaledhooks.UnifyArgs, host hostDeps) (err error) {
	if err := checkDaemonArgs(a); err != nil {
		return err
	}
	logf := a.Logf
	if logf == nil {
		logf = logger.Discard
	}
	cfg, err := LoadConfig(ConfigPath(a.StateDir))
	if err != nil {
		return err
	}
	var st ipn.StateStore
	if a.StatePath != "" {
		if st, err = store.New(logf, a.StatePath); err != nil {
			return fmt.Errorf("unify: primary state: %w", err)
		}
	}

	// Listen first, as tailscaled does, so clients can connect while the
	// stacks come up.
	names := []string{PrimaryName}
	for _, t := range cfg.Tailnets {
		names = append(names, t.Name)
	}
	lns := make(map[string]net.Listener, len(names))
	defer func() {
		if err != nil {
			for _, ln := range lns {
				ln.Close()
			}
		}
	}()
	for _, name := range names {
		ln, err := host.listen(socketPath(a.SocketPath, name))
		if err != nil {
			return fmt.Errorf("unify: LocalAPI socket for tailnet %q: %w", name, err)
		}
		lns[name] = ln
	}

	dev, devName, err := host.newTUN(logf, a.TunName)
	if err != nil {
		return fmt.Errorf("unify: creating TUN %q: %w", a.TunName, err)
	}
	// Every stack treats the host TUN as the Tailscale interface. It is
	// process-wide state, set once, as tailscaled does for its own TUN.
	netmon.SetTailscaleInterfaceProps(devName, 0)
	r, err := host.newRouter(logf, dev, a.Sys)
	if err != nil {
		dev.Close()
		return fmt.Errorf("unify: creating the router: %w", err)
	}
	d, err := host.newDNS(logf, a.Sys, devName)
	if err != nil {
		for _, ln := range lns {
			ln.Close()
		}
		clear(lns)
		// The router before the TUN, as Unify.Close does.
		return errors.Join(fmt.Errorf("unify: creating the OS DNS configurator: %w", err), r.Close(), dev.Close())
	}
	opts := daemonOptions(a, cfg.Tailnets, st, dev, r, d)
	if host.linkUp != nil {
		opts.HostLinkUp = func(dev tun.Device) { host.linkUp(dev, logf) }
	}
	u, err := New(opts) // closes dev, r and d on error
	if err != nil {
		return err
	}
	if err := u.Start(); err != nil {
		for _, ln := range lns {
			ln.Close()
		}
		clear(lns)
		return errors.Join(err, u.Close())
	}
	served := lns
	lns = nil // the servers close them
	return serve(ctx, logf, a.LogID, u, served)
}

// checkDaemonArgs reports whether a has what runDaemon needs.
func checkDaemonArgs(a tailscaledhooks.UnifyArgs) error {
	switch {
	case a.Sys == nil:
		return errors.New("unify: no tailscaled system")
	case a.StateDir == "":
		return errors.New("unify: --unify needs a state directory; set --statedir")
	case a.SocketPath == "":
		return errors.New("unify: --unify needs a LocalAPI socket; set --socket")
	case a.TunName == "", a.TunName == "userspace-networking", strings.HasPrefix(a.TunName, "tap:"), strings.Contains(a.TunName, ","):
		return fmt.Errorf("unify: --tun=%q: --unify needs the name of one TUN device, not userspace-networking, a TAP device or a list", a.TunName)
	}
	return nil
}

// daemonOptions returns the unify options for tailscaled's arguments a,
// the other tailnets and the primary's state store st (nil for a file in
// the state directory), on the host's TUN device, router and OS DNS
// configurator.
func daemonOptions(a tailscaledhooks.UnifyArgs, tailnets []TailnetConfig, st ipn.StateStore, dev tun.Device, r router.Router, d dns.OSConfigurator) Options {
	nm, _ := a.Sys.NetMon.GetOK()
	return Options{
		Logf:     a.Logf,
		StateDir: a.StateDir,
		Primary: PrimaryOptions{
			Dir:        a.StateDir,
			Store:      st,
			Ephemeral:  a.Ephemeral,
			Port:       a.Port,
			LogID:      a.LogID,
			SocketPath: a.SocketPath,
		},
		Tailnets:   tailnets,
		HostTUN:    dev,
		HostRouter: r,
		HostBus:    a.Sys.Bus.Get(),
		HostDNS:    d,
		NetMon:     nm,
	}
}

// socketPath returns the LocalAPI socket of tailnet name, given
// tailscaled's --socket.
func socketPath(mainSocket, name string) string {
	if name == PrimaryName {
		return mainSocket
	}
	return TailnetSocket(mainSocket, name)
}

// serve serves each stack's LocalAPI on its listener in lns until ctx is
// done, the host TUN device fails or a server stops. Then it stops the
// servers, which shut their backends down, and closes u.
func serve(ctx context.Context, logf logger.Logf, logID logid.PublicID, u *Unify, lns map[string]net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type stopped struct {
		name string
		err  error
	}
	done := make(chan stopped, len(lns))
	for _, st := range u.Stacks() {
		id := logid.PublicID{} // the other tailnets have no logtail
		if st.Name() == PrimaryName {
			id = logID
		}
		lb := st.LocalBackend()
		srv := ipnserver.New(st.Logf(), id, lb.EventBus(), lb.NetMon())
		srv.SetLocalBackend(lb)
		ln := lns[st.Name()]
		go func() { done <- stopped{st.Name(), srv.Run(ctx, ln)} }()
	}

	var errs []error
	record := func(s stopped) {
		if s.err != nil && !errors.Is(s.err, context.Canceled) {
			errs = append(errs, fmt.Errorf("unify: LocalAPI server of tailnet %q: %w", s.name, s.err))
		}
	}
	running := len(lns)
	select {
	case <-ctx.Done():
		logf("unify: shutting down")
	case <-u.Done():
		errs = append(errs, fmt.Errorf("unify: host TUN device stopped: %w", u.Err()))
	case s := <-done:
		running--
		logf("unify: LocalAPI server of tailnet %q stopped; shutting down", s.name)
		record(s)
	}
	cancel()
	for ; running > 0; running-- {
		record(<-done)
	}
	errs = append(errs, u.Close())
	return errors.Join(errs...)
}
