// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/version"
)

func TestRootCmdUniscale(t *testing.T) {
	root := newRootCmd(t)
	if root.Name != "uniscale" {
		t.Errorf("root command name = %q, want uniscale", root.Name)
	}
	if !strings.HasPrefix(root.ShortUsage, "uniscale ") {
		t.Errorf("root usage = %q, want it to start with %q", root.ShortUsage, "uniscale ")
	}
	if !strings.Contains(root.ShortHelp, "tailnets") {
		t.Errorf("root help = %q, want it to say it runs several tailnets", root.ShortHelp)
	}
}

func TestVersionNamesUniscale(t *testing.T) {
	var out bytes.Buffer
	tstest.Replace[io.Writer](t, &Stdout, &out)
	tstest.Replace(t, &versionArgs, versionArgs)
	versionArgs.daemon, versionArgs.json, versionArgs.upstream = false, false, false
	if err := runVersion(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "uniscale "+version.String()+"\n"; got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestCLINameUsage(t *testing.T) {
	for in, want := range map[string]string{
		"tailscale up [flags]": "uniscale up [flags]",
		"tailscale switch <id>\ntailscale switch --list [--json]": "uniscale switch <id>\nuniscale switch --list [--json]",
		"tailscale":                         "uniscale",
		"synology-cert [--domain <domain>]": "synology-cert [--domain <domain>]",
		"tailscaled --cleanup":              "tailscaled --cleanup",
		"":                                  "",
		"see 'tailscale up' for details":    "see 'tailscale up' for details",
	} {
		if got := cliNameUsage(in); got != want {
			t.Errorf("cliNameUsage(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSubcommandUsageUniscale checks that subcommands' usage lines name the
// CLI as uniscale, as its root does.
func TestSubcommandUsageUniscale(t *testing.T) {
	var bad []string
	walkCommands(newRootCmd(t), func(w cmdWalk) bool {
		for line := range strings.SplitSeq(w.ShortUsage, "\n") {
			if strings.HasPrefix(line, "tailscale ") || line == "tailscale" {
				bad = append(bad, line)
			}
		}
		return true
	})
	if len(bad) > 0 {
		t.Errorf("usage lines still naming the CLI tailscale: %q", bad)
	}
}
