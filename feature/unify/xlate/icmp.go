// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlate

import (
	"encoding/binary"
	"net/netip"

	"tailscale.com/net/packet"
)

// rewriteICMPError translates the packet embedded in an ICMP error. The
// embedded packet travelled in the opposite direction, so its source is
// the outer destination and its destination is the outer source. The
// embedded transport checksum is not updated: receivers match errors on
// addresses and ports only.
func rewriteICMPError(q *packet.Parsed, oldSrc, newSrc, oldDst, newDst netip.Addr) {
	msg := transport(q)
	if len(msg) < 8 {
		return
	}
	inner := msg[8:]
	swap := func(field []byte) {
		a, _ := netip.AddrFromSlice(field)
		switch a {
		case oldDst:
			copy(field, newDst.AsSlice())
		case oldSrc:
			copy(field, newSrc.AsSlice())
		}
	}
	switch q.IPVersion {
	case 4:
		if len(inner) < 20 || inner[0]>>4 != 4 {
			return
		}
		ihl := int(inner[0]&0x0f) * 4
		if ihl < 20 || len(inner) < ihl {
			return
		}
		swap(inner[12:16])
		swap(inner[16:20])
		inner[10], inner[11] = 0, 0
		binary.BigEndian.PutUint16(inner[10:12], fold(sum16(0, inner[:ihl])))
		msg[2], msg[3] = 0, 0
		binary.BigEndian.PutUint16(msg[2:4], fold(sum16(0, msg)))
	case 6:
		if len(inner) < 40 || inner[0]>>4 != 6 {
			return
		}
		swap(inner[8:24])
		swap(inner[24:40])
		msg[2], msg[3] = 0, 0
		b := q.Buffer()
		s := sum16(0, b[8:40]) // outer source and destination
		s += uint32(len(msg)) + 58
		binary.BigEndian.PutUint16(msg[2:4], fold(sum16(s, msg)))
	}
}

// transport returns q's transport header and payload, bounded by the
// packet length in the IP header, or nil if the header is inconsistent.
func transport(q *packet.Parsed) []byte {
	b := q.Buffer()
	t := q.Transport()
	start := len(b) - len(t)
	var end int
	switch q.IPVersion {
	case 4:
		end = int(binary.BigEndian.Uint16(b[2:4]))
	case 6:
		end = 40 + int(binary.BigEndian.Uint16(b[4:6]))
	}
	if end > len(b) || end < start {
		return nil
	}
	return b[start:end]
}

// sum16 adds b, as big-endian 16-bit words, to the running one's
// complement sum s.
func sum16(s uint32, b []byte) uint32 {
	for len(b) >= 2 {
		s += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}

// fold finishes a one's complement checksum.
func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
