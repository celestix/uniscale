// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"bytes"
	"errors"
	"io/fs"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// memStore is an in-memory [Store] for tests.
type memStore struct {
	data       []byte
	loadErr    error
	saveErr    error
	discardErr error
	saves      int
	discarded  bool
}

func (s *memStore) Load() ([]byte, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.data == nil {
		return nil, fs.ErrNotExist
	}
	return s.data, nil
}

func (s *memStore) Save(b []byte) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.data = bytes.Clone(b)
	s.saves++
	return nil
}

func (s *memStore) Discard(time.Time) error {
	s.discarded = true
	s.data = nil
	return s.discardErr
}

func testConfig() Config {
	return Config{
		Pool6: mpp("fd00:1::/48"),
		Now:   func() time.Time { return t0 },
	}
}

func newTable(t *testing.T, cfg Config, st Store) *Table {
	t.Helper()
	tb, err := New(cfg, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tb
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, mpp(s))
	}
	return out
}

func mustSync(t *testing.T, tb *Table, owner Owner, now time.Time, ps ...string) Changes {
	t.Helper()
	ch, err := tb.Sync(owner, prefixes(ps...), now)
	if err != nil {
		t.Fatalf("Sync(%s): %v", owner, err)
	}
	return ch
}

func wantVirtual(t *testing.T, tb *Table, owner Owner, real, virtual string) {
	t.Helper()
	got, ok := tb.RealToVirtual(owner, mpa(real))
	if !ok || got != mpa(virtual) {
		t.Fatalf("RealToVirtual(%s, %s) = %v, %v; want %s", owner, real, got, ok, virtual)
	}
	o, r, ok := tb.VirtualToReal(got)
	if !ok || o != owner || r != mpa(real) {
		t.Fatalf("VirtualToReal(%v) = %s, %v, %v; want %s, %s", got, o, r, ok, owner, real)
	}
}

func TestIdentityWhenFree(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	ch := mustSync(t, tb, "work", t0, "100.64.0.1/32", "192.168.1.0/24")
	if len(ch.Added) != 2 || ch.Added[0].Remapped() || ch.Added[1].Remapped() {
		t.Fatalf("Added = %v, want two identity mappings", ch.Added)
	}
	wantVirtual(t, tb, "work", "100.64.0.1", "100.64.0.1")
	wantVirtual(t, tb, "work", "192.168.1.200", "192.168.1.200")
}

func TestPeerCollision(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	ch := mustSync(t, tb, "personal", t0, "100.70.2.9/32")
	if len(ch.Added) != 1 || ch.Added[0].Virtual != mpp("198.18.0.0/32") {
		t.Fatalf("Added = %v, want personal remapped to 198.18.0.0/32", ch.Added)
	}
	wantVirtual(t, tb, "work", "100.70.2.9", "100.70.2.9")
	wantVirtual(t, tb, "personal", "100.70.2.9", "198.18.0.0")
}

func TestSubnetCollisionKeepsHostPart(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "work", t0, "192.168.1.0/24")
	mustSync(t, tb, "personal", t0, "192.168.1.0/24")
	wantVirtual(t, tb, "personal", "192.168.1.77", "198.18.0.77")
	wantVirtual(t, tb, "work", "192.168.1.77", "192.168.1.77")
}

func TestPartialOverlap(t *testing.T) {
	t.Run("small after big", func(t *testing.T) {
		tb := newTable(t, testConfig(), nil)
		mustSync(t, tb, "work", t0, "192.168.0.0/16")
		mustSync(t, tb, "personal", t0, "192.168.1.0/24")
		wantVirtual(t, tb, "personal", "192.168.1.5", "198.18.0.5")
	})
	t.Run("big after small", func(t *testing.T) {
		tb := newTable(t, testConfig(), nil)
		mustSync(t, tb, "personal", t0, "192.168.1.0/24")
		mustSync(t, tb, "work", t0, "192.168.0.0/16")
		wantVirtual(t, tb, "work", "192.168.7.5", "198.18.7.5")
		wantVirtual(t, tb, "personal", "192.168.1.5", "192.168.1.5")
	})
}

func TestSameOwnerOverlapStaysIdentity(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	ch := mustSync(t, tb, "work", t0, "10.0.0.0/8", "10.1.0.0/16")
	for _, m := range ch.Added {
		if m.Remapped() {
			t.Fatalf("%v remapped; same-owner overlaps must stay identity", m)
		}
	}
	if err := checkDisjoint(tb.Mappings()); err != nil {
		t.Fatal(err)
	}
}

func TestSameOwnerMayNotOverlapOwnRemappedBlock(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "work", t0, "192.168.1.0/24")
	mustSync(t, tb, "personal", t0, "192.168.1.0/24") // -> 198.18.0.0/24
	// personal also routes a real subnet that overlaps its own remapped block.
	mustSync(t, tb, "personal", t0, "192.168.1.0/24", "198.18.0.0/16")
	wantVirtual(t, tb, "personal", "198.18.3.4", "198.19.3.4")
	if err := checkDisjoint(tb.Mappings()); err != nil {
		t.Fatal(err)
	}
}

func TestLocalWinsAtFirstSight(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	if c := tb.SetLocal(prefixes("192.168.1.0/24")); len(c) != 0 {
		t.Fatalf("SetLocal conflicts = %v, want none", c)
	}
	mustSync(t, tb, "friends", t0, "192.168.1.0/24")
	wantVirtual(t, tb, "friends", "192.168.1.10", "198.18.0.10")
}

func TestLocalAppearingLaterIsAConflict(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "work", t0, "192.168.1.0/24")
	c := tb.SetLocal([]netip.Prefix{mpp("192.168.1.0/24"), {}})
	if len(c) != 1 || c[0].Local != mpp("192.168.1.0/24") || c[0].Mapping.Owner != "work" {
		t.Fatalf("SetLocal conflicts = %v, want one for work", c)
	}
	wantVirtual(t, tb, "work", "192.168.1.10", "192.168.1.10") // sticky
}

func TestSelfAddressCollision(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	for _, o := range []Owner{"work", "personal"} {
		if _, err := tb.Sync(o, Order(prefixes("100.101.5.2/32"), nil, nil), t0); err != nil {
			t.Fatal(err)
		}
	}
	wantVirtual(t, tb, "personal", "100.101.5.2", "198.18.0.0")
}

func TestStickyAcrossChanges(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "personal", t0, "100.70.2.9/32")
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	// personal's peer goes away; work's remapping must not move.
	mustSync(t, tb, "personal", t0.Add(time.Minute))
	ch := mustSync(t, tb, "work", t0.Add(time.Minute), "100.70.2.9/32")
	if !ch.Empty() {
		t.Fatalf("re-Sync changes = %+v, want none", ch)
	}
	wantVirtual(t, tb, "work", "100.70.2.9", "198.18.0.0")
	wantVirtual(t, tb, "personal", "100.70.2.9", "100.70.2.9")
}

func TestSyncInputCleanup(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	in := []netip.Prefix{
		mpp("0.0.0.0/0"), mpp("::/0"), {},
		netip.PrefixFrom(mpa("10.1.2.3"), 24), // unmasked
		mpp("10.1.2.0/24"),                    // duplicate after masking
	}
	ch, err := tb.Sync("work", in, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 1 || ch.Added[0].Real != mpp("10.1.2.0/24") {
		t.Fatalf("Added = %v, want just 10.1.2.0/24", ch.Added)
	}
	if _, err := tb.Sync("", nil, t0); err == nil {
		t.Fatal("Sync with empty owner: want error")
	}
}

func TestPoolExhaustion(t *testing.T) {
	cfg := testConfig()
	cfg.Pool4 = mpp("198.18.0.0/31")
	tb := newTable(t, cfg, nil)
	mustSync(t, tb, "a", t0, "100.64.0.1/32", "100.64.0.2/32", "100.64.0.3/32", "10.0.0.0/24")
	ch := mustSync(t, tb, "b", t0, "100.64.0.1/32", "100.64.0.2/32", "100.64.0.3/32", "10.0.0.0/24")
	want := prefixes("100.64.0.3/32", "10.0.0.0/24")
	if len(ch.Unmapped) != 2 || ch.Unmapped[0] != want[0] || ch.Unmapped[1] != want[1] {
		t.Fatalf("Unmapped = %v, want %v", ch.Unmapped, want)
	}
	if _, ok := tb.RealToVirtual("b", mpa("100.64.0.3")); ok {
		t.Fatal("unmapped prefix must not translate")
	}
}

func TestIPv6Collision(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	mustSync(t, tb, "work", t0, "fd7a:115c:a1e0::1/128")
	mustSync(t, tb, "personal", t0, "fd7a:115c:a1e0::1/128")
	wantVirtual(t, tb, "personal", "fd7a:115c:a1e0::1", "fd00:1::")
}

func TestUnknownLookups(t *testing.T) {
	tb := newTable(t, testConfig(), nil)
	if _, ok := tb.RealToVirtual("nobody", mpa("1.2.3.4")); ok {
		t.Error("RealToVirtual for unknown owner: want false")
	}
	mustSync(t, tb, "work", t0, "100.64.0.1/32")
	if _, ok := tb.RealToVirtual("work", mpa("100.64.0.2")); ok {
		t.Error("RealToVirtual for unknown address: want false")
	}
	if _, _, ok := tb.VirtualToReal(mpa("8.8.8.8")); ok {
		t.Error("VirtualToReal for unknown address: want false")
	}
}

func TestExpireAndQuarantine(t *testing.T) {
	cfg := testConfig()
	cfg.GCAfter = time.Hour
	cfg.Quarantine = 2 * time.Hour
	tb := newTable(t, cfg, &memStore{})
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	mustSync(t, tb, "personal", t0, "100.70.2.9/32") // -> 198.18.0.0
	mustSync(t, tb, "work", t0.Add(30*time.Minute), "100.70.2.9/32")

	ch, err := tb.Expire(t0.Add(90 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Removed) != 1 || ch.Removed[0].Owner != "personal" {
		t.Fatalf("Removed = %v, want personal only", ch.Removed)
	}
	if _, _, ok := tb.VirtualToReal(mpa("198.18.0.0")); ok {
		t.Fatal("expired mapping still translates")
	}
	// The released block is quarantined: a new collision gets the next one.
	mustSync(t, tb, "friends", t0.Add(90*time.Minute), "100.70.2.9/32")
	wantVirtual(t, tb, "friends", "100.70.2.9", "198.18.0.1")

	// After quarantine ends the block is forgotten, and Expire reports no
	// mapping changes.
	ch, err = tb.Expire(t0.Add(90*time.Minute + 2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Removed) != 2 { // work and friends both unseen for > 1h
		t.Fatalf("Removed = %v, want 2", ch.Removed)
	}
	if ch, _ := tb.Expire(t0.Add(10 * time.Hour)); !ch.Empty() {
		t.Fatalf("second Expire = %+v, want empty", ch)
	}
}

func TestRemoveOwner(t *testing.T) {
	tb := newTable(t, testConfig(), &memStore{})
	mustSync(t, tb, "work", t0, "100.70.2.9/32", "10.0.0.0/24")
	mustSync(t, tb, "personal", t0, "100.70.2.10/32")
	ch, err := tb.RemoveOwner("work", t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Removed) != 2 || ch.Removed[0].Real != mpp("10.0.0.0/24") {
		t.Fatalf("Removed = %v, want work's two mappings sorted", ch.Removed)
	}
	// Removed identity block is quarantined too.
	mustSync(t, tb, "friends", t0, "100.70.2.9/32")
	wantVirtual(t, tb, "friends", "100.70.2.9", "198.18.0.0")
	if ch, _ := tb.RemoveOwner("nobody", t0); !ch.Empty() {
		t.Fatalf("RemoveOwner(nobody) = %+v, want empty", ch)
	}
}

// Review focus: quarantine exists so a released block cannot point to a
// different peer. The (owner, real) that held it may take it back while it
// is quarantined; anyone else is still kept out (R4: remap only on
// collision).
func TestQuarantineReclaim(t *testing.T) {
	cfg := testConfig()
	cfg.GCAfter = time.Hour
	cfg.Quarantine = 2 * time.Hour
	expire := func(t *testing.T, tb *Table, now time.Time, want int) {
		t.Helper()
		ch, err := tb.Expire(now)
		if err != nil {
			t.Fatal(err)
		}
		if len(ch.Removed) != want {
			t.Fatalf("Expire removed %v, want %d mappings", ch.Removed, want)
		}
	}
	t.Run("identity after expiry", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "100.70.2.9/32")
		expire(t, tb, t0.Add(90*time.Minute), 1)
		mustSync(t, tb, "work", t0.Add(100*time.Minute), "100.70.2.9/32")
		wantVirtual(t, tb, "work", "100.70.2.9", "100.70.2.9")
	})
	t.Run("remapped after expiry", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "100.70.2.9/32")
		mustSync(t, tb, "personal", t0, "100.70.2.9/32") // -> 198.18.0.0
		mustSync(t, tb, "work", t0.Add(30*time.Minute), "100.70.2.9/32")
		expire(t, tb, t0.Add(90*time.Minute), 1) // personal only
		mustSync(t, tb, "personal", t0.Add(100*time.Minute), "100.70.2.9/32")
		wantVirtual(t, tb, "personal", "100.70.2.9", "198.18.0.0")
	})
	t.Run("identity after RemoveOwner", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "100.70.2.9/32", "10.0.0.0/24")
		if _, err := tb.RemoveOwner("work", t0); err != nil {
			t.Fatal(err)
		}
		mustSync(t, tb, "work", t0.Add(time.Minute), "100.70.2.9/32", "10.0.0.0/24")
		wantVirtual(t, tb, "work", "100.70.2.9", "100.70.2.9")
		wantVirtual(t, tb, "work", "10.0.0.7", "10.0.0.7")
	})
	t.Run("other owner still blocked, then owner returns", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "100.70.2.9/32")
		tb.RemoveOwner("work", t0)
		mustSync(t, tb, "personal", t0, "100.70.2.9/32")
		wantVirtual(t, tb, "personal", "100.70.2.9", "198.18.0.0")
		mustSync(t, tb, "work", t0, "100.70.2.9/32")
		wantVirtual(t, tb, "work", "100.70.2.9", "100.70.2.9")
	})
	t.Run("other owner kept out of quarantined remapped block", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "100.70.2.9/32")
		mustSync(t, tb, "personal", t0, "100.70.2.9/32") // -> 198.18.0.0
		tb.RemoveOwner("personal", t0)
		mustSync(t, tb, "friends", t0, "100.70.2.9/32")
		wantVirtual(t, tb, "friends", "100.70.2.9", "198.18.0.1")
		mustSync(t, tb, "personal", t0, "100.70.2.9/32")
		wantVirtual(t, tb, "personal", "100.70.2.9", "198.18.0.0")
	})
	t.Run("same owner, other real prefix still blocked", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "10.0.0.0/24")
		tb.RemoveOwner("work", t0)
		mustSync(t, tb, "work", t0, "10.0.0.0/25")
		wantVirtual(t, tb, "work", "10.0.0.7", "198.18.0.7")
	})
	t.Run("not reclaimed when no longer free", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "192.168.1.0/24")
		tb.RemoveOwner("work", t0)
		tb.SetLocal(prefixes("192.168.1.0/24"))
		mustSync(t, tb, "work", t0, "192.168.1.0/24")
		wantVirtual(t, tb, "work", "192.168.1.7", "198.18.0.7")
	})
	t.Run("reclaimed block leaves quarantine", func(t *testing.T) {
		// Once taken back, the block is an ordinary identity mapping: the
		// owner's nested identity prefixes may overlap it, in the same
		// Sync or later.
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "10.0.0.0/8")
		tb.RemoveOwner("work", t0)
		ch := mustSync(t, tb, "work", t0, "10.0.0.0/8", "10.1.0.0/16")
		for _, m := range ch.Added {
			if m.Remapped() {
				t.Fatalf("%v remapped; want identity", m)
			}
		}
		mustSync(t, tb, "work", t0, "10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16")
		wantVirtual(t, tb, "work", "10.2.0.1", "10.2.0.1")
		// Another owner is now blocked by the live mapping, as usual.
		mustSync(t, tb, "personal", t0, "10.3.0.0/16")
		wantVirtual(t, tb, "personal", "10.3.0.1", "198.18.0.1")
	})
	t.Run("nested identity blocks of one owner", func(t *testing.T) {
		// Review focus (C2): an owner routing 10.0.0.0/8 and 10.1.0.0/16
		// holds two overlapping identity blocks, as same-owner identity
		// mappings may. Released together, neither may keep the other out
		// when the owner returns during the quarantine.
		for _, order := range [][]string{
			{"10.0.0.0/8", "10.1.0.0/16"},
			{"10.1.0.0/16", "10.0.0.0/8"},
		} {
			tb := newTable(t, cfg, &memStore{})
			mustSync(t, tb, "work", t0, "10.0.0.0/8", "10.1.0.0/16")
			if _, err := tb.RemoveOwner("work", t0); err != nil {
				t.Fatal(err)
			}
			ch := mustSync(t, tb, "work", t0.Add(time.Minute), order...)
			if len(ch.Added) != 2 || len(ch.Unmapped) != 0 {
				t.Fatalf("%v: Sync = %+v, want both added", order, ch)
			}
			wantVirtual(t, tb, "work", "10.2.0.1", "10.2.0.1")
			wantVirtual(t, tb, "work", "10.1.0.1", "10.1.0.1")
			// Both blocks left quarantine: another owner is kept out by
			// the live mappings, as usual.
			mustSync(t, tb, "personal", t0.Add(time.Minute), "10.1.2.0/24")
			wantVirtual(t, tb, "personal", "10.1.2.3", "198.18.0.3")
		}
	})
	t.Run("nested identity blocks returning one at a time", func(t *testing.T) {
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "10.0.0.0/8", "10.1.0.0/16")
		tb.RemoveOwner("work", t0)
		mustSync(t, tb, "work", t0.Add(time.Minute), "10.1.0.0/16")
		wantVirtual(t, tb, "work", "10.1.0.1", "10.1.0.1")
		mustSync(t, tb, "work", t0.Add(2*time.Minute), "10.0.0.0/8")
		wantVirtual(t, tb, "work", "10.2.0.1", "10.2.0.1")
	})
	t.Run("most recent block is reclaimed", func(t *testing.T) {
		// work's 10.0.0.0/24 is released twice while its first block is
		// still quarantined: it takes back the block it held last.
		tb := newTable(t, cfg, &memStore{})
		mustSync(t, tb, "work", t0, "10.0.0.0/24")
		tb.RemoveOwner("work", t0)
		tb.SetLocal(prefixes("10.0.0.0/24"))
		mustSync(t, tb, "work", t0.Add(time.Minute), "10.0.0.0/24") // -> 198.18.0.0/24
		tb.RemoveOwner("work", t0.Add(time.Minute))
		tb.SetLocal(nil)
		mustSync(t, tb, "work", t0.Add(2*time.Minute), "10.0.0.0/24")
		wantVirtual(t, tb, "work", "10.0.0.7", "198.18.0.7")
	})
	t.Run("blocks released at the same time", func(t *testing.T) {
		// Both of work's blocks for 10.0.0.0/24 were released at t0; the
		// choice must not depend on map iteration order.
		for range 20 {
			tb := newTable(t, cfg, &memStore{})
			mustSync(t, tb, "work", t0, "10.0.0.0/24")
			tb.RemoveOwner("work", t0)
			tb.SetLocal(prefixes("10.0.0.0/24"))
			mustSync(t, tb, "work", t0, "10.0.0.0/24") // -> 198.18.0.0/24
			tb.RemoveOwner("work", t0)
			tb.SetLocal(nil)
			mustSync(t, tb, "work", t0, "10.0.0.0/24")
			wantVirtual(t, tb, "work", "10.0.0.7", "10.0.0.7")
		}
	})
	t.Run("never overlaps others, even from inconsistent saved state", func(t *testing.T) {
		// Saved state the table itself would not produce: blocks
		// quarantined for a overlap b's live mapping and c's quarantined
		// block. Taking them back would break the disjoint virtual space.
		until := t0.Add(time.Hour).Format(time.RFC3339)
		st := &memStore{data: []byte(`{"version":1,` +
			`"mappings":[{"owner":"b","real":"10.0.0.0/24","virtual":"10.0.0.0/24","lastSeen":"2026-10-01T12:00:00Z"}],` +
			`"quarantine":[` +
			`{"virtual":"10.0.0.0/24","owner":"a","real":"10.0.0.0/24","until":"` + until + `"},` +
			`{"virtual":"10.0.1.0/24","owner":"a","real":"10.0.1.0/24","until":"` + until + `"},` +
			`{"virtual":"10.0.1.0/25","owner":"c","real":"10.0.1.0/25","until":"` + until + `"}]}`)}
		tb := newTable(t, cfg, st)
		if err := tb.LoadErr(); err != nil {
			t.Fatal(err)
		}
		mustSync(t, tb, "a", t0, "10.0.0.0/24", "10.0.1.0/24")
		wantVirtual(t, tb, "a", "10.0.0.7", "198.18.0.7")
		wantVirtual(t, tb, "a", "10.0.1.7", "198.18.1.7")
		if err := checkDisjoint(tb.Mappings()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("identity exception is narrow", func(t *testing.T) {
		// Saved states the table would not produce, so each case isolates
		// one overlapping quarantined block. Only the same owner's
		// identity blocks may overlap a reclaimed identity block.
		until := t0.Add(time.Hour).Format(time.RFC3339)
		q := func(virtual, owner, real string) string {
			return `{"virtual":"` + virtual + `","owner":"` + owner + `","real":"` + real + `","until":"` + until + `"}`
		}
		for _, c := range []struct {
			name string
			quar []string
			sync string
			want string // virtual prefix, or "" for unmapped
		}{
			{"same owner's identity block", []string{q("10.0.0.0/8", "a", "10.0.0.0/8"), q("10.1.0.0/16", "a", "10.1.0.0/16")},
				"10.0.0.0/8", "10.0.0.0/8"},
			{"same owner's remapped block", []string{q("10.0.0.0/8", "a", "10.0.0.0/8"), q("10.1.0.0/16", "a", "172.16.0.0/16")},
				"10.0.0.0/8", ""},
			{"another owner's identity block", []string{q("10.0.0.0/8", "a", "10.0.0.0/8"), q("10.1.0.0/16", "b", "10.1.0.0/16")},
				"10.0.0.0/8", ""},
			// Not taken back: a's remapped block is not an identity block.
			// 192.168.1.0/24 itself is free, so it is mapped as identity.
			{"remapped block, same owner's identity block", []string{q("198.18.0.0/24", "a", "192.168.1.0/24"), q("198.18.0.0/16", "a", "198.18.0.0/16")},
				"192.168.1.0/24", "192.168.1.0/24"},
		} {
			t.Run(c.name, func(t *testing.T) {
				st := &memStore{data: []byte(`{"version":1,"quarantine":[` + strings.Join(c.quar, ",") + `]}`)}
				tb := newTable(t, cfg, st)
				if err := tb.LoadErr(); err != nil {
					t.Fatal(err)
				}
				ch := mustSync(t, tb, "a", t0, c.sync)
				if c.want == "" {
					if len(ch.Unmapped) != 1 {
						t.Fatalf("Sync = %+v, want %s unmapped (pool too small)", ch, c.sync)
					}
					return
				}
				if len(ch.Added) != 1 || ch.Added[0].Virtual != mpp(c.want) {
					t.Fatalf("Sync = %+v, want %s -> %s", ch, c.sync, c.want)
				}
			})
		}
	})
	t.Run("persisted with owner and real", func(t *testing.T) {
		st := &memStore{}
		tb := newTable(t, cfg, st)
		mustSync(t, tb, "work", t0, "100.70.2.9/32")
		tb.RemoveOwner("work", t0)
		tb2 := newTable(t, cfg, st)
		mustSync(t, tb2, "friends", t0, "100.70.2.9/32")
		wantVirtual(t, tb2, "friends", "100.70.2.9", "198.18.0.0")
		mustSync(t, tb2, "work", t0, "100.70.2.9/32")
		wantVirtual(t, tb2, "work", "100.70.2.9", "100.70.2.9")
	})
}

func TestPersistenceRoundTrip(t *testing.T) {
	st := &memStore{}
	cfg := testConfig()
	cfg.Pool6 = netip.Prefix{}
	cfg.Rand = bytes.NewReader([]byte{9, 9, 9, 9, 9})
	tb := newTable(t, cfg, st)
	if got := tb.Pools()[1]; got != mpp("fd09:909:909::/48") {
		t.Fatalf("generated Pool6 = %v", got)
	}
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	mustSync(t, tb, "personal", t0, "100.70.2.9/32", "fd7a:115c:a1e0::1/128")
	mustSync(t, tb, "work", t0, "fd7a:115c:a1e0::1/128")
	tb.RemoveOwner("friends", t0) // no-op
	if _, err := tb.Expire(t0); err != nil {
		t.Fatal(err)
	}

	cfg2 := testConfig()
	cfg2.Pool6 = netip.Prefix{}
	cfg2.Rand = errReader{}
	tb2 := newTable(t, cfg2, st)
	if err := tb2.LoadErr(); err != nil {
		t.Fatalf("LoadErr = %v", err)
	}
	if got := tb2.Pools()[1]; got != mpp("fd09:909:909::/48") {
		t.Fatalf("reloaded Pool6 = %v, want saved one", got)
	}
	wantVirtual(t, tb2, "personal", "100.70.2.9", "198.18.0.0")
	wantVirtual(t, tb2, "work", "fd7a:115c:a1e0::1", "fd09:909:909::")
	if len(tb2.Mappings()) != 4 {
		t.Fatalf("Mappings = %v", tb2.Mappings())
	}

	// An explicitly configured Pool6 wins over the saved one.
	cfg3 := testConfig()
	tb3 := newTable(t, cfg3, st)
	if got := tb3.Pools()[1]; got != mpp("fd00:1::/48") {
		t.Fatalf("configured Pool6 = %v", got)
	}
}

func TestQuarantinePersisted(t *testing.T) {
	st := &memStore{}
	tb := newTable(t, testConfig(), st)
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	tb.RemoveOwner("work", t0)
	tb2 := newTable(t, testConfig(), st)
	mustSync(t, tb2, "friends", t0, "100.70.2.9/32")
	wantVirtual(t, tb2, "friends", "100.70.2.9", "198.18.0.0")
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

func TestSaveThrottle(t *testing.T) {
	st := &memStore{}
	tb := newTable(t, testConfig(), st)
	mustSync(t, tb, "work", t0, "100.64.0.1/32")
	saves := st.saves
	mustSync(t, tb, "work", t0.Add(time.Minute), "100.64.0.1/32")
	if st.saves != saves {
		t.Fatal("LastSeen-only Sync saved before the save interval")
	}
	mustSync(t, tb, "work", t0.Add(2*time.Hour), "100.64.0.1/32")
	if st.saves != saves+1 {
		t.Fatal("LastSeen-only Sync did not save after the save interval")
	}
	st.saveErr = errors.New("disk full")
	ch, err := tb.Sync("work", prefixes("100.64.0.2/32"), t0.Add(3*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("Sync with failing store: err = %v", err)
	}
	if len(ch.Added) != 1 {
		t.Fatal("in-memory table must update even when saving fails")
	}
	wantVirtual(t, tb, "work", "100.64.0.2", "100.64.0.2")
}

func TestNewErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		st   Store
	}{
		{"ipv6 pool4", Config{Pool4: mpp("fd00::/48"), Pool6: mpp("fd00::/48")}, nil},
		{"unmasked pool4", Config{Pool4: netip.PrefixFrom(mpa("198.18.0.1"), 15), Pool6: mpp("fd00::/48")}, nil},
		{"ipv4 pool6", Config{Pool6: mpp("10.0.0.0/8")}, nil},
		{"4in6 pool6", Config{Pool6: mpp("::ffff:10.0.0.0/104")}, nil},
		{"negative gc", Config{Pool6: mpp("fd00::/48"), GCAfter: -1}, nil},
		{"no randomness", Config{Rand: errReader{}}, nil},
		{"cannot save generated pool6", Config{Rand: bytes.NewReader(make([]byte, 5))}, &memStore{saveErr: errors.New("ro")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg, tt.st); err == nil {
				t.Fatal("New: want error")
			}
		})
	}
}

func TestCorruptStateDiscarded(t *testing.T) {
	good := `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24","virtual":"10.0.0.0/24","lastSeen":"2026-10-01T12:00:00Z"}],` +
		`"quarantine":[{"virtual":"198.18.0.0/32","owner":"p","real":"100.70.2.9/32","until":"2026-10-02T12:00:00Z"}]}`
	bad := map[string]string{
		"not json":                   `{`,
		"wrong version":              `{"version":2,"mappings":[]}`,
		"bad pool6":                  `{"version":1,"pool6":"10.0.0.0/8","mappings":[]}`,
		"empty owner":                `{"version":1,"mappings":[{"owner":"","real":"10.0.0.0/24","virtual":"10.0.0.0/24"}]}`,
		"invalid prefix":             `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24"}]}`,
		"unmasked":                   `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.1/24","virtual":"10.0.0.0/24"}]}`,
		"length mismatch":            `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24","virtual":"10.0.0.0/25"}]}`,
		"default route":              `{"version":1,"mappings":[{"owner":"w","real":"0.0.0.0/0","virtual":"0.0.0.0/0"}]}`,
		"duplicate":                  `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24","virtual":"10.0.0.0/24"},{"owner":"w","real":"10.0.0.0/24","virtual":"198.18.0.0/24"}]}`,
		"overlap owners":             `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24","virtual":"10.0.0.0/24"},{"owner":"p","real":"10.0.0.0/16","virtual":"10.0.0.0/16"}]}`,
		"bad quarantine":             `{"version":1,"mappings":[],"quarantine":[{"virtual":"10.0.0.1/24","owner":"w","real":"10.0.0.0/24","until":"2026-10-01T12:00:00Z"}]}`,
		"quarantine no owner":        `{"version":1,"mappings":[],"quarantine":[{"virtual":"10.0.0.0/24","real":"10.0.0.0/24","until":"2026-10-01T12:00:00Z"}]}`,
		"quarantine no real":         `{"version":1,"mappings":[],"quarantine":[{"virtual":"10.0.0.0/24","owner":"w","until":"2026-10-01T12:00:00Z"}]}`,
		"quarantine unmasked real":   `{"version":1,"mappings":[],"quarantine":[{"virtual":"198.18.0.0/24","owner":"w","real":"10.0.0.1/24","until":"2026-10-01T12:00:00Z"}]}`,
		"quarantine length mismatch": `{"version":1,"mappings":[],"quarantine":[{"virtual":"198.18.0.0/24","owner":"w","real":"10.0.0.0/25","until":"2026-10-01T12:00:00Z"}]}`,
		"quarantine family mismatch": `{"version":1,"mappings":[],"quarantine":[{"virtual":"198.18.0.0/24","owner":"w","real":"fd00::/24","until":"2026-10-01T12:00:00Z"}]}`,
		"4in6 pool6":                 `{"version":1,"pool6":"::ffff:10.0.0.0/104","mappings":[]}`,
		"overlap remapped":           `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24","virtual":"198.18.0.0/24"},{"owner":"w","real":"198.18.0.0/16","virtual":"198.18.0.0/16"}]}`,
		"overlap same exact":         `{"version":1,"mappings":[{"owner":"w","real":"10.0.0.0/24","virtual":"10.0.0.0/24"},{"owner":"p","real":"10.0.0.0/24","virtual":"10.0.0.0/24"}]}`,
	}
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			st := &memStore{data: []byte(data)}
			tb := newTable(t, testConfig(), st)
			if tb.LoadErr() == nil {
				t.Fatal("LoadErr = nil, want error")
			}
			if !st.discarded {
				t.Fatal("bad state not discarded")
			}
			if len(tb.Mappings()) != 0 {
				t.Fatal("table not empty after discarding state")
			}
		})
	}
	t.Run("good", func(t *testing.T) {
		tb := newTable(t, testConfig(), &memStore{data: []byte(good)})
		if err := tb.LoadErr(); err != nil {
			t.Fatal(err)
		}
		wantVirtual(t, tb, "w", "10.0.0.5", "10.0.0.5")
		// The quarantined block keeps others out and returns to p.
		mustSync(t, tb, "x", t0, "198.18.0.0/32")
		wantVirtual(t, tb, "x", "198.18.0.0", "198.18.0.1")
		mustSync(t, tb, "w", t0, "100.70.2.9/32")
		wantVirtual(t, tb, "w", "100.70.2.9", "100.70.2.9")
		mustSync(t, tb, "p", t0, "100.70.2.9/32")
		wantVirtual(t, tb, "p", "100.70.2.9", "198.18.0.0")
	})
	t.Run("load error", func(t *testing.T) {
		// An I/O error says nothing about the saved state: keep it, and
		// fail instead of starting with an empty table.
		st := &memStore{data: []byte(good), loadErr: errors.New("io")}
		if _, err := New(testConfig(), st); err == nil || !strings.Contains(err.Error(), "io") {
			t.Fatalf("New = %v, want the load error", err)
		}
		if st.discarded {
			t.Fatal("state discarded after a load I/O error")
		}
	})
	t.Run("discard error", func(t *testing.T) {
		st := &memStore{data: []byte(`{`), discardErr: errors.New("rename")}
		tb := newTable(t, testConfig(), st)
		err := tb.LoadErr()
		if err == nil || !strings.Contains(err.Error(), "invalid saved state") || !strings.Contains(err.Error(), "rename") {
			t.Fatalf("LoadErr = %v, want both errors", err)
		}
	})
}

func TestMappingHelpers(t *testing.T) {
	m := Mapping{Owner: "w", Real: mpp("10.0.0.0/24"), Virtual: mpp("198.18.0.0/24")}
	if !m.Remapped() || m.String() != "w:10.0.0.0/24->198.18.0.0/24" {
		t.Fatalf("Remapped=%v String=%q", m.Remapped(), m.String())
	}
	if !(Changes{}).Empty() || (Changes{Unmapped: prefixes("10.0.0.0/8")}).Empty() {
		t.Fatal("Changes.Empty wrong")
	}
	if c := compareMapping(Mapping{Owner: "b"}, Mapping{Owner: "a"}); c != 1 {
		t.Fatalf("compareMapping = %d, want 1", c)
	}
}
