// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"net/netip"
	"testing"
	"time"
)

// FuzzSyncInvariants applies random sequences of Sync, Expire and
// RemoveOwner, with a clock that never goes backwards, and checks the
// table's invariants after each step:
//   - virtual prefixes never overlap, except same-owner identity mappings;
//   - live mappings never change (stickiness);
//   - RealToVirtual and VirtualToReal are inverses for every mapping;
//   - a block quarantined for one (owner, real) is never assigned to
//     another while its quarantine is active;
//   - an (owner, real) that returns while its last block is quarantined
//     gets that block back if it is otherwise free.
//
// Each step is 5 bytes: op and owner, prefix length, two address bytes, and
// how far the clock moves forward.
func FuzzSyncInvariants(f *testing.F) {
	f.Add([]byte{0, 8, 1, 0, 0, 1, 8, 1, 0, 0, 2, 16, 1, 5, 0})
	f.Add([]byte{0x80, 0, 0, 0, 0, 1, 8, 0, 0, 0, 2, 8, 0, 0, 0})
	// Collide, expire both, return during quarantine, a third owner
	// is kept out, then the quarantine ends.
	f.Add([]byte{
		0x00, 8, 1, 0, 0, // a syncs 10.0.1.0/24 (identity)
		0x01, 8, 1, 0, 0, // b syncs 10.0.1.0/24 (remapped)
		0x60, 0, 0, 0, 36, // +3h, Expire: both released
		0x00, 8, 1, 0, 1, // a returns: identity again
		0x01, 8, 1, 0, 0, // b returns: its pool block again
		0x02, 8, 1, 0, 0, // c collides: a fresh block
		0x72, 0, 0, 0, 60, // +5h, RemoveOwner(c)
		0x60, 0, 0, 0, 0, // Expire: ended quarantines forgotten
		0x02, 8, 1, 0, 0, // c returns after its quarantine ended
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := testConfig()
		cfg.Pool4 = mpp("198.18.0.0/20") // small, so exhaustion happens too
		cfg.GCAfter = 2 * time.Hour
		cfg.Quarantine = 4 * time.Hour
		tb, err := New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		owners := []Owner{"a", "b", "c"}
		seen := map[key]Mapping{}
		quar := map[netip.Prefix]released{} // model of the quarantine
		release := func(ch Changes, now time.Time) {
			for _, m := range ch.Removed {
				k := key{m.Owner, m.Real}
				delete(seen, k)
				quar[m.Virtual] = released{k, now.Add(cfg.Quarantine)}
			}
		}
		now := t0
		for len(data) >= 5 {
			b0, b1, b2, b3, b4 := data[0], data[1], data[2], data[3], data[4]
			data = data[5:]
			now = now.Add(time.Duration(b4) * 5 * time.Minute)
			owner := owners[int(b0&0x0f)%len(owners)]
			switch op := b0 >> 4 & 0x7; op {
			case 6:
				ch, err := tb.Expire(now)
				if err != nil {
					t.Fatal(err)
				}
				release(ch, now)
				for v, r := range quar {
					if !now.Before(r.until) {
						delete(quar, v)
					}
				}
				for _, m := range tb.Mappings() {
					if now.Sub(m.LastSeen) > cfg.GCAfter {
						t.Fatalf("Expire(%v) kept %v, last seen %v", now, m, m.LastSeen)
					}
				}
			case 7:
				ch, err := tb.RemoveOwner(owner, now)
				if err != nil {
					t.Fatal(err)
				}
				release(ch, now)
				for _, m := range tb.Mappings() {
					if m.Owner == owner {
						t.Fatalf("RemoveOwner(%s) kept %v", owner, m)
					}
				}
			default:
				bits := 16 + int(b1)%17
				addr := netip.AddrFrom4([4]byte{10, 0, b2, b3})
				if b0&0x80 != 0 {
					addr = netip.AddrFrom4([4]byte{198, 18, b2 & 0x1f, b3}) // inside the pool
				}
				p := netip.PrefixFrom(addr, bits).Masked()
				before := tb.Mappings()
				ch, err := tb.Sync(owner, []netip.Prefix{p}, now)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range ch.Added {
					checkQuarantine(t, m, before, quar, now)
				}
			}
			checkTable(t, tb, seen)
		}
	})
}

// checkQuarantine checks a mapping that Sync just added against the model
// of the quarantine, and takes a reclaimed block out of the model. before
// is the table's mappings before the Sync, which synced one prefix.
func checkQuarantine(t *testing.T, m Mapping, before []Mapping, quar map[netip.Prefix]released, now time.Time) {
	t.Helper()
	k := key{m.Owner, m.Real}
	var last netip.Prefix // k's most recently released, still quarantined block
	for v, r := range quar {
		if !now.Before(r.until) {
			continue
		}
		if r.key != k {
			if v.Overlaps(m.Virtual) {
				t.Fatalf("Sync assigned %v, overlapping %v quarantined for %v until %v", m, v, r.key, r.until)
			}
			continue
		}
		if l := quar[last]; !last.IsValid() || r.until.After(l.until) || r.until.Equal(l.until) && comparePrefix(v, last) < 0 {
			last = v
		}
	}
	if !last.IsValid() || !otherwiseFree(k, last, before, quar, now) {
		return
	}
	if m.Virtual != last {
		t.Fatalf("Sync mapped %v; want its quarantined block %v back", m, last)
	}
	delete(quar, last)
}

// otherwiseFree reports whether v is free for k apart from k's own
// quarantine: no live mapping overlaps it (k's owner's identity mappings
// may, if v is an identity block) and no block quarantined for another
// (owner, real) does.
func otherwiseFree(k key, v netip.Prefix, live []Mapping, quar map[netip.Prefix]released, now time.Time) bool {
	ident := v == k.real
	for _, m := range live {
		if m.Virtual.Overlaps(v) && !(ident && m.Owner == k.owner && !m.Remapped()) {
			return false
		}
	}
	for q, r := range quar {
		if r.key != k && now.Before(r.until) && q.Overlaps(v) {
			return false
		}
	}
	return true
}

// checkTable checks the invariants that hold after every step.
func checkTable(t *testing.T, tb *Table, seen map[key]Mapping) {
	t.Helper()
	ms := tb.Mappings()
	if err := checkDisjoint(ms); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		k := key{m.Owner, m.Real}
		if old, ok := seen[k]; ok && old.Virtual != m.Virtual {
			t.Fatalf("mapping changed: %v -> %v", old, m)
		}
		seen[k] = m
		a := m.Real.Addr()
		v, ok := tb.RealToVirtual(m.Owner, a)
		if !ok {
			t.Fatalf("RealToVirtual(%s, %v) failed", m.Owner, a)
		}
		o, r, ok := tb.VirtualToReal(v)
		if !ok || o != m.Owner || r != a {
			t.Fatalf("VirtualToReal(%v) = %s, %v, %v; want %s, %v", v, o, r, ok, m.Owner, a)
		}
	}
}
