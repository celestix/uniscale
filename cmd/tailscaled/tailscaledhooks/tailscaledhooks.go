// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailscaledhooks provides hooks for optional features
// to add to during init that tailscaled calls at runtime.
package tailscaledhooks

import (
	"context"

	"tailscale.com/feature"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
)

// UninstallSystemDaemonWindows is called when the Windows
// system daemon is uninstalled.
var UninstallSystemDaemonWindows feature.Hooks[func()]

// Unify, if set, runs tailscaled in tailnet unification mode (its --unify
// flag) in place of its usual single tailnet, until ctx is done or it
// fails. It is set by feature/unify on Linux.
var Unify feature.Hook[func(ctx context.Context, args UnifyArgs) error]

// UnifyArgs is what tailscaled passes to [Unify]: its flags and the parts
// of its system that tailnet unification uses.
type UnifyArgs struct {
	// Logf is tailscaled's logger.
	Logf logger.Logf

	// LogID is tailscaled's log ID, or zero if logging is not in use. It
	// goes to the primary tailnet only.
	LogID logid.PublicID

	// Sys is tailscaled's system. Its event bus, health tracker, network
	// monitor, policy client and control knobs serve the host's TUN
	// device, router and DNS configurator, which unification shares
	// between the tailnets.
	Sys *tsd.System

	// StateDir is tailscaled's state directory (its VarRoot: --statedir,
	// or derived from --state). It holds the unification configuration
	// file, unify/config.json.
	StateDir string

	// StatePath is the primary tailnet's state, as tailscaled passes it to
	// store.New: --state, or its default in StateDir. If empty, the state
	// file is tailscaled.state in StateDir.
	StatePath string

	// Ephemeral registers the primary tailnet's node as ephemeral, as
	// tailscaled does with in-memory state.
	Ephemeral bool

	// SocketPath is the LocalAPI socket (--socket). It serves the primary
	// tailnet; the other tailnets get sockets next to it.
	SocketPath string

	// Port is the primary tailnet's UDP port (--port).
	Port uint16

	// TunName is the name of the TUN device to create (--tun).
	TunName string
}
