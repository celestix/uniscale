// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/tstest"
)

// TestProcNetRouteSkipsUniscale checks that a default route through
// Uniscale's TUN (an exit node) is not taken for the host's own.
func TestProcNetRouteSkipsUniscale(t *testing.T) {
	tstest.Replace(t, &procNetRoutePath, filepath.Join(t.TempDir(), "route"))
	buf := []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"uniscale0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
	if err := os.WriteFile(procNetRoutePath, buf, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := defaultRouteInterfaceProcNetInternal(128)
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth0" {
		t.Errorf("default route interface = %q, want eth0", got)
	}
}
