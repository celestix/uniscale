// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_gro

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/control/controlknobs"
	"tailscale.com/types/logger"
)

func (t *Wrapper) SetLinkFeaturesPostUp(_ *controlknobs.Knobs) {}

// SetDeviceLinkFeaturesPostUp does nothing on this platform or build.
func SetDeviceLinkFeaturesPostUp(_ tun.Device, _ *controlknobs.Knobs, _ logger.Logf) {}

func (t *Wrapper) ApplyGROKnobs(_ *controlknobs.Knobs) {}
