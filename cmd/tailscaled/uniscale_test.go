// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

func TestUniscaleTunName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TUN name only defaults to uniscale0 on Linux")
	}
	switch d := distro.Get(); d {
	case distro.Synology, distro.Crostini:
		t.Skipf("distro %v has its own default", d)
	}
	if got, want := defaultTunName(), "uniscale0"; got != want {
		t.Errorf("defaultTunName() = %q, want %q", got, want)
	}
}

// TestShouldRunCLIByName checks that the multicall binary turns into the CLI
// when run as uniscale, and still as tailscale.
func TestShouldRunCLIByName(t *testing.T) {
	tstest.Replace(t, &beCLI, func() {})
	tstest.Replace(t, &os.Args, nil)
	for name, want := range map[string]bool{
		"/usr/bin/uniscale":   true,
		"/usr/bin/tailscale":  true,
		"/usr/sbin/uniscaled": false,
	} {
		os.Args = []string{name, "status"}
		if got := shouldRunCLI(); got != want {
			t.Errorf("shouldRunCLI() as %s = %v, want %v", name, got, want)
		}
	}
}

// TestIPNServerOptsUniscaleStateDir checks that the state directory is
// derived from a --state file in a directory named uniscale.
func TestIPNServerOptsUniscaleStateDir(t *testing.T) {
	saved := args
	t.Cleanup(func() { args = saved })
	for statepath, want := range map[string]string{
		"/var/lib/uniscale/uniscaled.state":   "/var/lib/uniscale",
		"/var/lib/tailscale/tailscaled.state": "/var/lib/tailscale",
		"/var/lib/other/tailscaled.state":     "",
	} {
		args.statedir, args.statepath = "", statepath
		if got := ipnServerOpts().VarRoot; got != want {
			t.Errorf("--state=%s: VarRoot = %q, want %q", statepath, got, want)
		}
	}
}

func TestDaemonVersion(t *testing.T) {
	if got, want := daemonVersion(), "uniscaled "+version.String(); got != want {
		t.Errorf("daemonVersion() = %q, want %q", got, want)
	}
}

// TestUniscaledUnit checks that the systemd unit uses Uniscale's own paths,
// so it never touches a stock Tailscale install's state.
func TestUniscaledUnit(t *testing.T) {
	unit, err := os.ReadFile("uniscaled.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"EnvironmentFile=-/etc/default/uniscaled",
		"ExecStart=/usr/sbin/uniscaled --state=/var/lib/uniscale/uniscaled.state --socket=/run/uniscale/uniscaled.sock --port=${PORT} $FLAGS",
		"ExecStopPost=/usr/sbin/uniscaled --cleanup",
		"RuntimeDirectory=uniscale",
		"StateDirectory=uniscale",
		"CacheDirectory=uniscale",
	} {
		if !strings.Contains(string(unit), want+"\n") {
			t.Errorf("uniscaled.service lacks line %q", want)
		}
	}
	for _, path := range []string{"/var/lib/tailscale", "/run/tailscale", "/etc/default/tailscaled", "/usr/sbin/tailscaled"} {
		if strings.Contains(string(unit), path) {
			t.Errorf("uniscaled.service refers to %s", path)
		}
	}
	defaults, err := os.ReadFile("uniscaled.defaults")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`PORT="41641"`, `FLAGS=""`} {
		if !strings.Contains(string(defaults), want) {
			t.Errorf("uniscaled.defaults lacks %q", want)
		}
	}
}
