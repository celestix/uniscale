// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"runtime"
	"testing"
)

// TestIsTailscaleInterfaceUniscale checks that Uniscale's TUN is recognised
// as this node's own interface, not a local network, when its name is not
// set explicitly.
func TestIsTailscaleInterfaceUniscale(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin uses utun names")
	}
	oldName, oldIndex := tsIfProps.tsIfName(), tsIfProps.tsIfIndex()
	tsIfProps.set("", 0)
	t.Cleanup(func() { tsIfProps.set(oldName, oldIndex) })
	for name, want := range map[string]bool{
		"uniscale0":  true,
		"tailscale0": true,
		"eth0":       false,
	} {
		if got := isTailscaleInterface(name, nil); got != want {
			t.Errorf("isTailscaleInterface(%q) = %v, want %v", name, got, want)
		}
	}
}
