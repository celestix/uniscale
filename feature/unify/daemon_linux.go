// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"context"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/feature"
	"tailscale.com/net/dns"
	"tailscale.com/net/tstun"
	"tailscale.com/safesocket"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"
)

func init() {
	if !feature.Register("unify") {
		return
	}
	tailscaledhooks.Unify.Set(func(ctx context.Context, a tailscaledhooks.UnifyArgs) error {
		return runDaemon(ctx, a, osHost)
	})
}

// osHost creates the host's real TUN device, router and OS DNS
// configurator as tailscaled does for its single tailnet, and the LocalAPI
// sockets.
var osHost = hostDeps{
	newTUN: func(logf logger.Logf, name string) (tun.Device, string, error) {
		dev, devName, err := tstun.New(logf, name)
		if err != nil {
			tstun.Diagnose(logf, name, err)
		}
		return dev, devName, err
	},
	newRouter: func(logf logger.Logf, dev tun.Device, sys *tsd.System) (router.Router, error) {
		return router.New(logf, dev, sys.NetMon.Get(), sys.HealthTracker.Get(), sys.Bus.Get())
	},
	newDNS: func(logf logger.Logf, sys *tsd.System, devName string) (dns.OSConfigurator, error) {
		return dns.NewOSConfigurator(logf, sys.HealthTracker.Get(), sys.Bus.Get(), sys.PolicyClientOrDefault(), sys.ControlKnobs(), devName)
	},
	// The host TUN gets tailscaled's GRO environment knobs and probe, as
	// tstun.Wrapper does. The control-plane knobs are per tailnet, so
	// none are applied.
	linkUp: func(dev tun.Device, logf logger.Logf) {
		tstun.SetDeviceLinkFeaturesPostUp(dev, nil, logf)
	},
	listen: safesocket.Listen,
}
