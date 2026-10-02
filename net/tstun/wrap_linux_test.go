// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_gro

package tstun

import (
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"tailscale.com/control/controlknobs"
	"tailscale.com/types/logger"
)

// fakeGRODev is a [tun.GRODevice] whose Write fails with writeErr and
// which records GRO disablement and writes.
type fakeGRODev struct {
	tun.Device
	writeErr       error
	writes         int
	udpOff, tcpOff int
}

func (d *fakeGRODev) Write(bufs [][]byte, offset int) (int, error) {
	d.writes++
	return len(bufs), d.writeErr
}
func (d *fakeGRODev) DisableUDPGRO() { d.udpOff++ }
func (d *fakeGRODev) DisableTCPGRO() { d.tcpOff++ }

// plainDev is a [tun.Device] without GRO support.
type plainDev struct {
	tun.Device
	writes int
}

func (d *plainDev) Write(bufs [][]byte, offset int) (int, error) {
	d.writes++
	return len(bufs), nil
}

func TestSetDeviceLinkFeaturesPostUp(t *testing.T) {
	tests := []struct {
		name             string
		env              map[string]string
		knobs            func() *controlknobs.Knobs
		writeErr         error
		wantUDP, wantTCP int
		wantLog          bool
	}{
		{name: "probe ok, nothing disabled"},
		{name: "udp env", env: map[string]string{"TS_TUN_DISABLE_UDP_GRO": "1"}, wantUDP: 1},
		{name: "tcp env", env: map[string]string{"TS_TUN_DISABLE_TCP_GRO": "true"}, wantTCP: 1},
		{name: "both env", env: map[string]string{"TS_TUN_DISABLE_UDP_GRO": "1", "TS_TUN_DISABLE_TCP_GRO": "1"}, wantUDP: 1, wantTCP: 1},
		{name: "env false", env: map[string]string{"TS_TUN_DISABLE_UDP_GRO": "0", "TS_TUN_DISABLE_TCP_GRO": "0"}},
		{name: "probe EINVAL", writeErr: unix.EINVAL, wantUDP: 1, wantTCP: 1, wantLog: true},
		{name: "probe other error", writeErr: unix.EPERM},
		{
			name: "knobs are applied",
			knobs: func() *controlknobs.Knobs {
				k := new(controlknobs.Knobs)
				k.DisableTUNUDPGRO.Store(true)
				k.DisableTUNTCPGRO.Store(true)
				return k
			},
			wantUDP: 1, wantTCP: 1,
		},
		{name: "nil knobs", knobs: func() *controlknobs.Knobs { return nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var knobs *controlknobs.Knobs
			if tt.knobs != nil {
				knobs = tt.knobs()
			}
			dev := &fakeGRODev{writeErr: tt.writeErr}
			var logged int
			SetDeviceLinkFeaturesPostUp(dev, knobs, func(string, ...any) { logged++ })
			if dev.udpOff != tt.wantUDP || dev.tcpOff != tt.wantTCP {
				t.Errorf("DisableUDPGRO, DisableTCPGRO called %d, %d times; want %d, %d", dev.udpOff, dev.tcpOff, tt.wantUDP, tt.wantTCP)
			}
			if dev.writes != 1 {
				t.Errorf("probe wrote %d times, want 1", dev.writes)
			}
			if (logged > 0) != tt.wantLog {
				t.Errorf("logged %d times, want log=%v", logged, tt.wantLog)
			}
		})
	}
}

func TestSetDeviceLinkFeaturesPostUpNoGRO(t *testing.T) {
	t.Setenv("TS_TUN_DISABLE_UDP_GRO", "1")
	dev := &plainDev{}
	SetDeviceLinkFeaturesPostUp(dev, nil, logger.Discard)
	if dev.writes != 0 {
		t.Errorf("probed a device without GRO: %d writes", dev.writes)
	}
}

// SetLinkFeaturesPostUp and SetDeviceLinkFeaturesPostUp behave the same,
// except that the Wrapper skips a TAP device.
func TestWrapperSetLinkFeaturesPostUp(t *testing.T) {
	t.Setenv("TS_TUN_DISABLE_TCP_GRO", "1")
	for _, tap := range []bool{false, true} {
		dev := &fakeGRODev{writeErr: unix.EINVAL}
		w := &Wrapper{tdev: dev, isTAP: tap, logf: logger.Discard}
		w.SetLinkFeaturesPostUp(nil)
		want := 2 // the env knob, then the probe's EINVAL
		if tap {
			want = 0
		}
		if dev.tcpOff != want {
			t.Errorf("tap=%v: DisableTCPGRO called %d times, want %d", tap, dev.tcpOff, want)
		}
		if tap && dev.writes != 0 {
			t.Errorf("tap: probed %d times", dev.writes)
		}
	}
}
