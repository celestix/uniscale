// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package osglue connects the tailnet stacks of tailnet unification to the
// host's single real router and DNS configurator.
//
// Each stack's engine gets a [Router] and a [DNS] instead of the real ones.
// They record what the stack asks for, and the primary stack's [DNS] also
// passes calls to the real DNS configurator. [MergeRouter] combines the
// running stacks into the one configuration unify applies to the real
// router.
package osglue
