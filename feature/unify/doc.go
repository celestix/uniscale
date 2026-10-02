// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package unify connects one tailscaled to several tailnets at once
// (tailnet unification).
//
// Each tailnet runs in its own stack (package stack) on an in-memory TUN
// (package chantun). Unify owns the host's single real TUN, router and DNS
// configurator. Its packet loop moves packets between the real TUN and the
// stacks, translating addresses between each tailnet's real address space
// and the host's unified one (packages remap and xlate). It keeps the
// translation and the host's routes in step with what each stack routes.
//
// The primary tailnet, [PrimaryName], uses tailscaled's usual state and
// socket. The others are listed in the file at [ConfigPath].
//
// [New] builds it all and [Unify.Start] starts it; [Unify.Stack] gives
// each tailnet's stack, to serve its LocalAPI.
package unify
