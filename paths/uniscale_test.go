// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package paths

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/version/distro"
)

// TestUniscaleDefaultsLinux checks that on a generic Linux host Uniscale keeps
// its state and socket apart from a stock Tailscale install's.
func TestUniscaleDefaultsLinux(t *testing.T) {
	switch d := distro.Get(); d {
	case distro.JetKVM, distro.Gokrazy, distro.Synology, distro.QNAP:
		t.Skipf("distro %v keeps its packaging paths", d)
	}
	if got, want := statePath(), "/var/lib/uniscale/uniscaled.state"; got != want {
		t.Errorf("statePath() = %q, want %q", got, want)
	}
	if fi, err := os.Stat("/var/run"); err == nil && fi.IsDir() {
		if got, want := DefaultTailscaledSocket(), "/var/run/uniscale/uniscaled.sock"; got != want {
			t.Errorf("DefaultTailscaledSocket() = %q, want %q", got, want)
		}
	}
}

// TestUniscaleXDGStateFallback checks the state file a non-root user gets
// when the system state directory is not writable.
func TestUniscaleXDGStateFallback(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root uses the system state directory")
	}
	switch d := distro.Get(); d {
	case distro.JetKVM, distro.Gokrazy:
		t.Skipf("distro %v keeps its packaging paths", d)
	}
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	if got, want := stateFileUnix(), filepath.Join(xdg, "uniscale", "uniscaled.state"); got != want {
		t.Errorf("stateFileUnix() = %q, want %q", got, want)
	}
}

// TestEnsureStateDirPermsUniscale checks that a state directory named
// uniscale is made private like a tailscale one, and others are left alone.
func TestEnsureStateDirPermsUniscale(t *testing.T) {
	for name, want := range map[string]os.FileMode{"uniscale": 0700, "tailscale": 0700, "other": 0755} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0755); err != nil { // undo the umask
			t.Fatal(err)
		}
		if err := ensureStateDirPermsUnix(dir); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %v, want %v", name, got, want)
		}
	}
}
