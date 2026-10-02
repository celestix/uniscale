// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"bytes"
	"testing"

	"tailscale.com/feature/unify/remap"
	"tailscale.com/types/ipproto"
)

// FuzzTranslate feeds arbitrary bytes through Outbound and through Inbound
// for every stack. Translation must never panic, dropped packets must be
// left unmodified, and a packet whose checksums were valid before
// translation must still have valid checksums after it.
func FuzzTranslate(f *testing.F) {
	f.Add(pkt(ipproto.TCP, "198.18.0.0:4000", "198.19.3.4:443"))
	f.Add(pkt(ipproto.UDP, "100.88.1.4:4000", "100.99.0.1:53"))
	f.Add(pkt(ipproto.ICMPv4, "[fd7a:115c:a1e0::99]:0", "[fd7a:115c:a1e0::52]:0"))
	f.Add(icmpErr("100.99.0.1", "198.18.0.1", pkt(ipproto.UDP, "198.18.0.1:5000", "100.99.0.1:53")))
	f.Add(icmpErr("100.88.1.4", "100.99.0.1", pkt(ipproto.UDP, "100.99.0.1:5000", "100.88.1.4:53")))
	f.Add(zeroUDPChecksum(pkt(ipproto.UDP, "198.18.0.0:4000", "198.19.3.4:53")))
	f.Add(icmpError(5, 1, 0, "100.88.1.4", "100.99.0.1", pkt(ipproto.UDP, "100.99.0.1:5000", "100.88.1.4:53")))
	f.Add(pkt(ipproto.UDP, "192.168.1.1:53", "100.70.2.9:4000")) // private source via the exit
	f.Add(pkt(ipproto.UDP, "100.101.5.2:4000", "100.100.100.100:53"))
	f.Add(icmpErr("100.100.100.100", "100.101.5.2", pkt(ipproto.UDP, "100.101.5.2:4000", "100.100.100.100:53")))
	// Regressions found by fuzzing:
	// IPv4 total length (1) shorter than the header.
	f.Add([]byte("E\x00\x00\x01\x00-\x00\x00@\x06\xeb\xa0\xc6\x12\x00\x00\xc6\x13\x03\x04"))
	// Non-first IPv4 fragment claiming TCP.
	f.Add([]byte("E\x00\x00-\x00\x00@\x01\x00\x06\xeb\xa0\xc6\x12\x00\x00\xc6\x13\x03\x04\x0f\xa0\x01\xbb\x00\x00\x00\x01\x00\x00\x00\x00P\x02\xff\xff\xcb\x85\x00\x00hello"))
	// IPv4 header length 0, which packet.Decode accepts.
	f.Add([]byte("@\x00\x00!\x00\x01\x00\x00E\x11\xb1\vdX\x01\x04dc\x00\x01\x0f\xa0\x005\x00\r\xe2lhello"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tr := scenario(t)
		check := func(r Result, before, after []byte) {
			if r.Verdict == Drop && !bytes.Equal(before, after) {
				t.Fatalf("dropped packet modified (%s)", r.Reason)
			}
			if r.Verdict != Drop && checksumsOK(before) && !checksumsOK(after) {
				t.Fatalf("translation broke checksums:\nbefore % x\nafter  % x", before, after)
			}
		}
		b := bytes.Clone(data)
		check(tr.Outbound(parse(b)), data, b)
		for _, owner := range []string{"work", "personal", "friends"} {
			b := bytes.Clone(data)
			check(tr.Inbound(remapOwner(owner), parse(b)), data, b)
		}
	})
}

func remapOwner(s string) remap.Owner { return remap.Owner(s) }
