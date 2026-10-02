// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_unify

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/control/controlclient"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
)

func init() {
	// feature/unify, which tailscaled links through feature/condregister,
	// has already set its hook in its own init, unless TS_DISABLE_FEATURE
	// disabled it.
	if tailscaledhooks.Unify.IsSet() {
		hookRunUnify.Set(runUnify)
	}
}

// unifyUnsupportedFlags are the tailscaled flags that --unify does not
// support yet.
var unifyUnsupportedFlags = []string{
	"bird-socket",
	"config",
	"hardware-attestation",
	"outbound-http-proxy-listen",
	"socks5-server",
}

// runUnify runs tailscaled in tailnet unification mode until SIGINT or
// SIGTERM: the primary tailnet on tailscaled's usual state and socket,
// and the tailnets in <statedir>/unify/config.json.
func runUnify(logf logger.Logf, logID logid.PublicID, sys *tsd.System) error {
	if err := checkUnifyFlags(flag.CommandLine); err != nil {
		return err
	}
	opts := ipnServerOpts()
	if opts.VarRoot == "" {
		return errors.New("--unify needs a state directory; set --statedir")
	}
	if logPol != nil {
		logPol.Logtail.SetNetMon(sys.NetMon.Get())
	}
	// Process-wide caches, kept for the primary tailnet as without --unify.
	dnsfallback.SetCachePath(filepath.Join(opts.VarRoot, "derpmap.cached.json"), logf)
	if f, ok := dnscache.HookSetCacheDir.GetOk(); ok {
		f(filepath.Join(opts.VarRoot, "dns-cache"), logf)
	}
	if buildfeatures.HasDebug && debugMux != nil {
		go runDebugServer(logf, debugMux, args.debug)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	if sigPipe != nil {
		signal.Ignore(sigPipe)
	}
	go func() {
		select {
		case s := <-interrupt:
			logf("tailscaled got signal %v; shutting down", s)
			cancel()
		case <-ctx.Done():
		}
	}()

	return tailscaledhooks.Unify.Get()(ctx, tailscaledhooks.UnifyArgs{
		Logf:       logf,
		LogID:      logID,
		Sys:        sys,
		StateDir:   opts.VarRoot,
		StatePath:  statePathOrDefault(),
		Ephemeral:  opts.LoginFlags&controlclient.LoginEphemeral != 0,
		SocketPath: args.socketpath,
		Port:       args.port,
		TunName:    args.tunname,
	})
}

// checkUnifyFlags reports an error if fs has a flag set that --unify does
// not support yet.
func checkUnifyFlags(fs *flag.FlagSet) error {
	var set []string
	fs.Visit(func(f *flag.Flag) {
		if slices.Contains(unifyUnsupportedFlags, f.Name) {
			set = append(set, "--"+f.Name)
		}
	})
	if len(set) > 0 {
		return fmt.Errorf("--unify does not support %s yet", strings.Join(set, ", "))
	}
	return nil
}
