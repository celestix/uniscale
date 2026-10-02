// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_gro

package tstun

import (
	"errors"
	"net/netip"
	"runtime"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

// SetLinkFeaturesPostUp configures link features on t based on select TS_TUN_
// environment variables, control-plane node attributes (via knobs, which may be
// nil), and OS feature tests. Callers should ensure t is up prior to calling,
// otherwise OS feature tests may be inconclusive.
func (t *Wrapper) SetLinkFeaturesPostUp(knobs *controlknobs.Knobs) {
	if t.isTAP {
		return
	}
	setLinkFeaturesPostUp(t.tdev, knobs, t.logf)
}

// SetDeviceLinkFeaturesPostUp does for the raw TUN device dev what
// [Wrapper.SetLinkFeaturesPostUp] does for a Wrapper's: it applies the
// TS_TUN_DISABLE_UDP_GRO and TS_TUN_DISABLE_TCP_GRO environment variables and
// the control-plane GRO knobs (knobs may be nil, as it is when dev is shared
// by several tailnets, whose knobs are per tailnet), then probes for the
// kernel bug that makes GRO writes fail with EINVAL and disables GRO if it
// finds it. dev must be up, otherwise the probe may be inconclusive. It does
// nothing if dev does not support GRO, on Android, and on platforms other than Linux.
func SetDeviceLinkFeaturesPostUp(dev tun.Device, knobs *controlknobs.Knobs, logf logger.Logf) {
	setLinkFeaturesPostUp(dev, knobs, logf)
}

// setLinkFeaturesPostUp is the implementation of both.
func setLinkFeaturesPostUp(dev tun.Device, knobs *controlknobs.Knobs, logf logger.Logf) {
	if runtime.GOOS == "android" {
		return
	}
	if groDev, ok := dev.(tun.GRODevice); ok {
		if envknob.Bool("TS_TUN_DISABLE_UDP_GRO") ||
			(knobs != nil && knobs.DisableTUNUDPGRO.Load()) {
			groDev.DisableUDPGRO()
		}
		if envknob.Bool("TS_TUN_DISABLE_TCP_GRO") ||
			(knobs != nil && knobs.DisableTUNTCPGRO.Load()) {
			groDev.DisableTCPGRO()
		}
		err := probeTCPGRO(groDev)
		if errors.Is(err, unix.EINVAL) {
			groDev.DisableTCPGRO()
			groDev.DisableUDPGRO()
			logf("disabled TUN TCP & UDP GRO due to GRO probe error: %v", err)
		}
	}
}

// ApplyGROKnobs applies the [tailcfg.NodeAttrDisableTUNUDPGRO] and
// [tailcfg.NodeAttrDisableTUNTCPGRO] knob values (via knobs, which must be
// non-nil) to t's underlying device. It is intended to be called when a
// control-plane node attribute change is detected after [SetLinkFeaturesPostUp]
// has already run.
//
// Note: wireguard-go's GRO disablement is one-way (sticky); ApplyGROKnobs can
// move TUN UDP/TCP GRO from enabled to disabled, but the reverse requires a
// client restart.
func (t *Wrapper) ApplyGROKnobs(knobs *controlknobs.Knobs) {
	if t.isTAP || runtime.GOOS == "android" || knobs == nil {
		return
	}
	groDev, ok := t.tdev.(tun.GRODevice)
	if !ok {
		return
	}
	if knobs.DisableTUNUDPGRO.Load() {
		groDev.DisableUDPGRO()
	}
	if knobs.DisableTUNTCPGRO.Load() {
		groDev.DisableTCPGRO()
	}
}

func probeTCPGRO(dev tun.GRODevice) error {
	ipPort := netip.MustParseAddrPort(tsaddr.TailscaleServiceIPString + ":0")
	fingerprint := []byte("tailscale-probe-tun-gro")
	segmentSize := len(fingerprint)
	iphLen := 20
	tcphLen := 20
	totalLen := iphLen + tcphLen + segmentSize
	ipAs4 := ipPort.Addr().As4()
	bufs := make([][]byte, 2)
	for i := range bufs {
		bufs[i] = make([]byte, WritePacketStartOffset+totalLen, WritePacketStartOffset+(totalLen*2))
		ipv4H := header.IPv4(bufs[i][WritePacketStartOffset:])
		ipv4H.Encode(&header.IPv4Fields{
			SrcAddr:  tcpip.AddrFromSlice(ipAs4[:]),
			DstAddr:  tcpip.AddrFromSlice(ipAs4[:]),
			Protocol: unix.IPPROTO_TCP,
			// Use a zero value TTL as best effort means to reduce chance of
			// probe packet leaking further than it needs to.
			TTL:         0,
			TotalLength: uint16(totalLen),
		})
		tcpH := header.TCP(bufs[i][WritePacketStartOffset+iphLen:])
		tcpH.Encode(&header.TCPFields{
			SrcPort:    ipPort.Port(),
			DstPort:    ipPort.Port(),
			SeqNum:     1 + uint32(i*segmentSize),
			AckNum:     1,
			DataOffset: 20,
			Flags:      header.TCPFlagAck,
			WindowSize: 3000,
		})
		copy(bufs[i][WritePacketStartOffset+iphLen+tcphLen:], fingerprint)
		ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
		pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(tcphLen+segmentSize))
		pseudoCsum = checksum.Checksum(bufs[i][WritePacketStartOffset+iphLen+tcphLen:], pseudoCsum)
		tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	}
	_, err := dev.Write(bufs, WritePacketStartOffset)
	return err
}
