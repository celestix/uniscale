// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_unify

package main

import (
	"context"
	"errors"
	"flag"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/tsd"
	"tailscale.com/types/logid"
)

func TestUnifyHookLinked(t *testing.T) {
	if !hookRunUnify.IsSet() {
		t.Fatal("--unify is not available on Linux")
	}
}

func TestCheckUnifyFlags(t *testing.T) {
	fs := flag.NewFlagSet("tailscaled", flag.ContinueOnError)
	for _, name := range []string{"config", "port", "bird-socket", "socks5-server"} {
		fs.String(name, "", "")
	}
	if err := checkUnifyFlags(fs); err != nil {
		t.Fatalf("no flags set: %v", err)
	}
	if err := fs.Parse([]string{"--port=41641", "--config=/etc/tailscale.conf", "--socks5-server=:1080"}); err != nil {
		t.Fatal(err)
	}
	err := checkUnifyFlags(fs)
	if err == nil || !strings.Contains(err.Error(), "--config, --socks5-server") || strings.Contains(err.Error(), "--port") {
		t.Fatalf("checkUnifyFlags = %v, want --config and --socks5-server rejected", err)
	}
}

func TestRunUnify(t *testing.T) {
	saved := args
	t.Cleanup(func() { args = saved })
	var got tailscaledhooks.UnifyArgs
	var gotCtx context.Context
	errBoom := errors.New("boom")
	t.Cleanup(tailscaledhooks.Unify.SetForTest(func(ctx context.Context, a tailscaledhooks.UnifyArgs) error {
		gotCtx, got = ctx, a
		return errBoom
	}))
	sys := tsd.NewSystem()
	defer sys.Bus.Get().Close()
	logID := logid.PublicID{3}

	// Without a state directory (as with --state=mem: alone).
	args.statedir, args.statepath = "", "mem:"
	if err := runUnify(t.Logf, logID, sys); err == nil || !strings.Contains(err.Error(), "--statedir") {
		t.Fatalf("runUnify without a state directory = %v", err)
	}
	if got.Sys != nil {
		t.Fatal("hook called without a state directory")
	}

	dir := t.TempDir()
	args.statedir, args.statepath = dir, "mem:"
	args.socketpath = filepath.Join(dir, "tailscaled.sock")
	args.port = 41641
	args.tunname = "tailscale0"
	if err := runUnify(t.Logf, logID, sys); err != errBoom {
		t.Fatalf("runUnify = %v, want the hook's error", err)
	}
	want := tailscaledhooks.UnifyArgs{
		LogID:      logID,
		Sys:        sys,
		StateDir:   dir,
		StatePath:  "mem:",
		Ephemeral:  true,
		SocketPath: args.socketpath,
		Port:       41641,
		TunName:    "tailscale0",
	}
	if got.Logf == nil {
		t.Error("no Logf")
	}
	got.Logf = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hook args = %+v, want %+v", got, want)
	}
	if err := gotCtx.Err(); err == nil {
		t.Error("hook's context still live after runUnify returned")
	}

	// A state file at its default place in --statedir.
	args.statepath = ""
	runUnify(t.Logf, logID, sys)
	if got.StatePath != filepath.Join(dir, "tailscaled.state") || got.Ephemeral {
		t.Errorf("StatePath, Ephemeral = %q, %v", got.StatePath, got.Ephemeral)
	}
}

// TestRunUnifyRejectsTPM checks that runUnify fails closed on the effective
// --encrypt-state and --hardware-attestation values, which handleTPMFlags has
// resolved from the flags and policy, as the secondary tailnets' state would
// otherwise be written in plaintext and attestation silently dropped.
func TestRunUnifyRejectsTPM(t *testing.T) {
	saved := args
	t.Cleanup(func() { args = saved })
	var hookCalled bool
	t.Cleanup(tailscaledhooks.Unify.SetForTest(func(context.Context, tailscaledhooks.UnifyArgs) error {
		hookCalled = true
		return errors.New("boom")
	}))
	sys := tsd.NewSystem()
	defer sys.Bus.Get().Close()

	for _, c := range []struct {
		name    string
		mod     func()
		wantErr string // empty if runUnify should reach the hook
	}{
		{"encrypt-state", func() { args.encryptState = boolFlag{set: true, v: true} }, "state encryption"},
		{"encrypt-state by policy", func() { args.encryptState = boolFlag{v: true} }, "state encryption"},
		{"hardware-attestation", func() { args.hardwareAttestation = boolFlag{set: true, v: true} }, "hardware attestation"},
		{"hardware-attestation by policy", func() { args.hardwareAttestation = boolFlag{v: true} }, "hardware attestation"},
		{"encrypt-state=false", func() { args.encryptState = boolFlag{set: true} }, ""},
		{"neither", func() {}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			args = saved
			dir := t.TempDir()
			args.statedir, args.statepath = dir, "mem:"
			c.mod()
			hookCalled = false
			err := runUnify(t.Logf, logid.PublicID{3}, sys)
			if c.wantErr == "" {
				if !hookCalled || err == nil || !strings.Contains(err.Error(), "boom") {
					t.Fatalf("runUnify = %v, hook called %v; want the hook's error", err, hookCalled)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "--unify does not support "+c.wantErr) {
				t.Fatalf("runUnify = %v, want an error about %s", err, c.wantErr)
			}
			if hookCalled {
				t.Error("hook called")
			}
		})
	}
}
