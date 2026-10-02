// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
)

// Owner names a tailnet.
type Owner string

// Mapping maps one of an owner's real prefixes to a virtual prefix of the
// same length and family.
type Mapping struct {
	Owner    Owner        `json:"owner"`
	Real     netip.Prefix `json:"real"`
	Virtual  netip.Prefix `json:"virtual"`
	LastSeen time.Time    `json:"lastSeen"`
}

// Remapped reports whether m changes addresses (is not an identity mapping).
func (m Mapping) Remapped() bool { return m.Real != m.Virtual }

func (m Mapping) String() string {
	return fmt.Sprintf("%s:%v->%v", m.Owner, m.Real, m.Virtual)
}

// Default durations for [Config].
const (
	DefaultGCAfter    = 30 * 24 * time.Hour
	DefaultQuarantine = 30 * 24 * time.Hour
)

// saveInterval bounds how often Sync persists LastSeen-only updates.
const saveInterval = time.Hour

// Config configures a [Table]. Zero fields take defaults.
type Config struct {
	// Pool4 is the IPv4 pool for remapped prefixes. Default [DefaultPool4].
	Pool4 netip.Prefix
	// Pool6 is the IPv6 pool. If zero, the pool saved in the store is used,
	// or a new random one is generated and saved.
	Pool6 netip.Prefix
	// GCAfter is how long a mapping may go unseen before it is released.
	GCAfter time.Duration
	// Quarantine is how long a released virtual block stays unusable.
	Quarantine time.Duration
	// Now returns the current time. Default time.Now.
	Now func() time.Time
	// Rand is the randomness source for generating Pool6. Default
	// crypto/rand.Reader.
	Rand io.Reader
}

func (c Config) withDefaults() Config {
	if !c.Pool4.IsValid() {
		c.Pool4 = DefaultPool4
	}
	if c.GCAfter == 0 {
		c.GCAfter = DefaultGCAfter
	}
	if c.Quarantine == 0 {
		c.Quarantine = DefaultQuarantine
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	return c
}

func (c Config) validate() error {
	if !c.Pool4.Addr().Is4() || c.Pool4 != c.Pool4.Masked() {
		return fmt.Errorf("remap: Pool4 %v must be a masked IPv4 prefix", c.Pool4)
	}
	if c.Pool6.IsValid() && (!c.Pool6.Addr().Is6() || c.Pool6.Addr().Is4In6() || c.Pool6 != c.Pool6.Masked()) {
		return fmt.Errorf("remap: Pool6 %v must be a masked IPv6 prefix", c.Pool6)
	}
	if c.GCAfter < 0 || c.Quarantine < 0 {
		return errors.New("remap: durations must not be negative")
	}
	return nil
}

// Changes describes what a call changed.
type Changes struct {
	Added    []Mapping
	Removed  []Mapping
	Unmapped []netip.Prefix // real prefixes that could not be mapped: pool exhausted
}

// Empty reports whether c holds no changes.
func (c Changes) Empty() bool {
	return len(c.Added) == 0 && len(c.Removed) == 0 && len(c.Unmapped) == 0
}

// Conflict is an existing mapping whose virtual prefix overlaps a network
// this host is directly connected to. The mapping is kept (mappings are
// sticky); the conflict is reported so it can be surfaced as a warning.
type Conflict struct {
	Local   netip.Prefix
	Mapping Mapping
}

type key struct {
	owner Owner
	real  netip.Prefix
}

// released is a quarantined virtual block: the (owner, real prefix) that
// held it, and when it may be reused by anyone else.
type released struct {
	key   key
	until time.Time
}

// snapshot is an immutable lookup view, published after every change so
// the packet path can read it without locks.
type snapshot struct {
	byVirtual *bart.Table[Mapping]
	byOwner   map[Owner]*bart.Table[Mapping]
}

// Table is the sticky remapping table. Lookups are safe for concurrent use
// and never block; mutating methods are serialized internally.
type Table struct {
	cfg   Config
	store Store

	mu         sync.Mutex
	mappings   map[key]Mapping
	quarantine map[netip.Prefix]released // by released virtual block
	local      []netip.Prefix
	lastSave   time.Time
	loadErr    error

	snap atomic.Pointer[snapshot]
}

// New returns a table configured by cfg and loaded from store. store may be
// nil for a table that is not persisted. Saved state that cannot be decoded
// or is invalid is moved aside with [Store.Discard] and the table starts
// empty; see [Table.LoadErr]. An error reading the store (other than
// nothing having been saved) is returned, and nothing is discarded.
func New(cfg Config, store Store) (*Table, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	t := &Table{
		cfg:        cfg,
		store:      store,
		mappings:   map[key]Mapping{},
		quarantine: map[netip.Prefix]released{},
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	saved, err := t.loadLocked()
	if err != nil {
		return nil, err
	}
	if !t.cfg.Pool6.IsValid() {
		t.cfg.Pool6 = saved
	}
	if !t.cfg.Pool6.IsValid() {
		p, err := NewPool6(t.cfg.Rand)
		if err != nil {
			return nil, fmt.Errorf("remap: generating Pool6: %w", err)
		}
		t.cfg.Pool6 = p
		if err := t.saveLocked(t.cfg.Now(), true); err != nil {
			return nil, err
		}
	}
	t.publishLocked()
	return t, nil
}

// loadLocked loads saved state and returns the saved Pool6, if any. Only
// state that cannot be decoded or is invalid is discarded; an error reading
// the store is returned.
func (t *Table) loadLocked() (netip.Prefix, error) {
	if t.store == nil {
		return netip.Prefix{}, nil
	}
	b, err := t.store.Load()
	if errors.Is(err, fs.ErrNotExist) {
		return netip.Prefix{}, nil
	}
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("remap: loading state: %w", err)
	}
	st, err := decodeState(b)
	if err != nil {
		t.loadErr = fmt.Errorf("remap: discarded saved state: %w", err)
		if derr := t.store.Discard(t.cfg.Now()); derr != nil {
			t.loadErr = errors.Join(t.loadErr, derr)
		}
		return netip.Prefix{}, nil
	}
	for _, m := range st.Mappings {
		t.mappings[key{m.Owner, m.Real}] = m
	}
	for _, q := range st.Quarantine {
		t.quarantine[q.Virtual] = released{key{q.Owner, q.Real}, q.Until}
	}
	return st.Pool6, nil
}

// LoadErr returns the error that made [New] discard saved state, or nil.
func (t *Table) LoadErr() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.loadErr
}

// Pools returns the IPv4 and IPv6 pools in use.
func (t *Table) Pools() []netip.Prefix {
	t.mu.Lock()
	defer t.mu.Unlock()
	return []netip.Prefix{t.cfg.Pool4, t.cfg.Pool6}
}

// SetLocal records the networks this host is directly connected to. They
// are never remapped and block identity mappings for prefixes first seen
// after this call. Existing mappings that overlap them are kept and
// returned as conflicts.
func (t *Table) SetLocal(prefixes []netip.Prefix) []Conflict {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.local = t.local[:0]
	for _, p := range prefixes {
		if p.IsValid() {
			t.local = append(t.local, p.Masked())
		}
	}
	var out []Conflict
	for _, l := range t.local {
		for _, m := range t.sortedLocked() {
			if m.Virtual.Overlaps(l) {
				out = append(out, Conflict{Local: l, Mapping: m})
			}
		}
	}
	return out
}

// Sync records the current real prefixes of owner, in priority order (see
// [Order]). Prefixes seen for the first time are mapped; known ones have
// LastSeen updated. Prefixes no longer present keep their mappings until
// they expire (see [Table.Expire]). Default routes are never mapped.
//
// A prefix whose previous mapping was released and whose block is still
// quarantined takes that block back if nothing else now overlaps it; an
// identity block may overlap the owner's own identity mappings and
// quarantined identity blocks. Any other new mapping gets a block that
// overlaps no quarantined one.
//
// The returned error reports a failure to persist; the in-memory table is
// updated regardless.
func (t *Table) Sync(owner Owner, real []netip.Prefix, now time.Time) (Changes, error) {
	if owner == "" {
		return Changes{}, errors.New("remap: empty owner")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var ch Changes
	occAll, occIdent := t.occupiedLocked(owner, now)
	reclaim := t.reclaimableLocked(owner, now)
	cursors := map[cursorKey]netip.Addr{}
	seen := map[netip.Prefix]bool{}
	for _, p := range real {
		if !p.IsValid() || p.Bits() == 0 {
			continue
		}
		p = p.Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		k := key{owner, p}
		if m, ok := t.mappings[k]; ok {
			m.LastSeen = now
			t.mappings[k] = m
			continue
		}
		v, ok := reclaim[p]
		if ok && t.reclaimLocked(k, v, now) {
			if v == p {
				// No longer a quarantined block but the owner's own
				// identity mapping, which its identities may overlap.
				occIdent.Delete(v)
			}
		} else if v, ok = t.chooseLocked(p, occAll, occIdent, cursors); !ok {
			ch.Unmapped = append(ch.Unmapped, p)
			continue
		}
		m := Mapping{Owner: owner, Real: p, Virtual: v, LastSeen: now}
		t.mappings[k] = m
		occAll.Insert(v, struct{}{})
		if m.Remapped() {
			occIdent.Insert(v, struct{}{})
		}
		ch.Added = append(ch.Added, m)
	}
	if len(ch.Added) > 0 {
		t.publishLocked()
	}
	return ch, t.saveLocked(now, len(ch.Added) > 0)
}

// cursorKey identifies a next-fit allocation cursor: one per address
// family and block length.
type cursorKey struct {
	is4  bool
	bits int
}

// chooseLocked picks the virtual prefix for a new real prefix p: p itself
// if it is free, otherwise the first free block in the pool.
//
// cursors holds, for the current Sync, where the next search for each block
// size starts. Nothing is freed during a Sync, so continuing from the last
// allocation gives the same result as searching from the start of the pool,
// without rescanning it for every prefix.
func (t *Table) chooseLocked(p netip.Prefix, occAll, occIdent *bart.Table[struct{}], cursors map[cursorKey]netip.Addr) (netip.Prefix, bool) {
	if !occIdent.OverlapsPrefix(p) {
		return p, true
	}
	pool := t.cfg.Pool4
	if !p.Addr().Is4() {
		pool = t.cfg.Pool6
	}
	ck := cursorKey{p.Addr().Is4(), p.Bits()}
	v, ok := allocate(pool, p.Bits(), occAll, cursors[ck])
	if !ok {
		return netip.Prefix{}, false
	}
	if next, ok := after(v, v.Bits()); ok {
		cursors[ck] = next.Addr()
	} else {
		delete(cursors, ck)
	}
	return v, true
}

// occupiedLocked returns two views of the used address space for mapping
// prefixes of owner: occAll holds everything (used for pool allocation);
// occIdent leaves out owner's own identity mappings, which a new identity
// mapping of the same owner may overlap.
func (t *Table) occupiedLocked(owner Owner, now time.Time) (occAll, occIdent *bart.Table[struct{}]) {
	occAll, occIdent = new(bart.Table[struct{}]), new(bart.Table[struct{}])
	add := func(p netip.Prefix, ident bool) {
		occAll.Insert(p, struct{}{})
		if ident {
			occIdent.Insert(p, struct{}{})
		}
	}
	for _, m := range t.mappings {
		add(m.Virtual, m.Owner != owner || m.Remapped())
	}
	for _, l := range t.local {
		add(l, true)
	}
	for p, r := range t.quarantine {
		if now.Before(r.until) {
			add(p, true)
		}
	}
	return occAll, occIdent
}

// reclaimableLocked returns, for each real prefix of owner that held a
// still-quarantined block, the block it held last. Blocks released at the
// same time are ordered by prefix, so the choice does not depend on map
// iteration order.
func (t *Table) reclaimableLocked(owner Owner, now time.Time) map[netip.Prefix]netip.Prefix {
	last := map[netip.Prefix]netip.Prefix{}
	for v, r := range t.quarantine {
		if r.key.owner != owner || !now.Before(r.until) {
			continue
		}
		prev, ok := last[r.key.real]
		pr := t.quarantine[prev]
		if !ok || r.until.After(pr.until) || r.until.Equal(pr.until) && comparePrefix(v, prev) < 0 {
			last[r.key.real] = v
		}
	}
	return last
}

// reclaimLocked reports whether k may take back v, the block it held
// before it was released, and if so takes v out of quarantine. v must be
// otherwise free: no mapping, local network, or block quarantined for
// another (owner, real) overlaps it, except, when v is an identity block,
// k's owner's own identity mappings and quarantined identity blocks (an
// owner's identity blocks may overlap, for example 10.0.0.0/8 and
// 10.1.0.0/16, and are released together by [Table.RemoveOwner]).
func (t *Table) reclaimLocked(k key, v netip.Prefix, now time.Time) bool {
	ident := v == k.real
	for _, m := range t.mappings {
		if m.Virtual.Overlaps(v) && !(ident && m.Owner == k.owner && !m.Remapped()) {
			return false
		}
	}
	for _, l := range t.local {
		if l.Overlaps(v) {
			return false
		}
	}
	for p, r := range t.quarantine {
		ownIdent := ident && r.key.owner == k.owner && p == r.key.real
		if r.key != k && now.Before(r.until) && p.Overlaps(v) && !ownIdent {
			return false
		}
	}
	delete(t.quarantine, v)
	return true
}

// Expire releases mappings not seen within the GC interval and forgets
// quarantined blocks whose quarantine has ended.
//
// Run it after the live owners have synced: a prefix that is still present
// but has not been synced for longer than the GC interval expires too. If
// it is synced again while its block is quarantined it takes the same block
// back (see [Table.Sync]); after the quarantine it is mapped as if seen for
// the first time.
func (t *Table) Expire(now time.Time) (Changes, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ch Changes
	for k, m := range t.mappings {
		if now.Sub(m.LastSeen) > t.cfg.GCAfter {
			ch.Removed = append(ch.Removed, t.releaseLocked(k, now))
		}
	}
	changed := len(ch.Removed) > 0
	for p, r := range t.quarantine {
		if !now.Before(r.until) {
			delete(t.quarantine, p)
			changed = true
		}
	}
	return t.finishLocked(ch, now, changed)
}

// RemoveOwner releases all of owner's mappings.
func (t *Table) RemoveOwner(owner Owner, now time.Time) (Changes, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ch Changes
	for k := range t.mappings {
		if k.owner == owner {
			ch.Removed = append(ch.Removed, t.releaseLocked(k, now))
		}
	}
	return t.finishLocked(ch, now, len(ch.Removed) > 0)
}

func (t *Table) releaseLocked(k key, now time.Time) Mapping {
	m := t.mappings[k]
	delete(t.mappings, k)
	t.quarantine[m.Virtual] = released{k, now.Add(t.cfg.Quarantine)}
	return m
}

func (t *Table) finishLocked(ch Changes, now time.Time, changed bool) (Changes, error) {
	slices.SortFunc(ch.Removed, compareMapping)
	if !changed {
		return ch, nil
	}
	t.publishLocked()
	return ch, t.saveLocked(now, true)
}

func compareMapping(a, b Mapping) int {
	if a.Owner != b.Owner {
		if a.Owner < b.Owner {
			return -1
		}
		return 1
	}
	return comparePrefix(a.Real, b.Real)
}

func (t *Table) sortedLocked() []Mapping {
	ms := slices.Collect(maps.Values(t.mappings))
	slices.SortFunc(ms, compareMapping)
	return ms
}

// Mappings returns all mappings, sorted by owner then real prefix.
func (t *Table) Mappings() []Mapping {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sortedLocked()
}

func (t *Table) publishLocked() {
	s := &snapshot{
		byVirtual: new(bart.Table[Mapping]),
		byOwner:   map[Owner]*bart.Table[Mapping]{},
	}
	for _, m := range t.mappings {
		s.byVirtual.Insert(m.Virtual, m)
		bt := s.byOwner[m.Owner]
		if bt == nil {
			bt = new(bart.Table[Mapping])
			s.byOwner[m.Owner] = bt
		}
		bt.Insert(m.Real, m)
	}
	t.snap.Store(s)
}

// saveLocked persists state if force is set or enough time has passed
// since the last save.
func (t *Table) saveLocked(now time.Time, force bool) error {
	if t.store == nil || (!force && now.Sub(t.lastSave) < saveInterval) {
		return nil
	}
	st := state{Version: stateVersion, Pool6: t.cfg.Pool6, Mappings: t.sortedLocked()}
	for p, r := range t.quarantine {
		st.Quarantine = append(st.Quarantine, quarantined{Virtual: p, Owner: r.key.owner, Real: r.key.real, Until: r.until})
	}
	slices.SortFunc(st.Quarantine, func(a, b quarantined) int { return comparePrefix(a.Virtual, b.Virtual) })
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := t.store.Save(b); err != nil {
		return fmt.Errorf("remap: saving state: %w", err)
	}
	t.lastSave = now
	return nil
}

// RealToVirtual translates owner's real address a into the unified space.
func (t *Table) RealToVirtual(owner Owner, a netip.Addr) (netip.Addr, bool) {
	bt := t.snap.Load().byOwner[owner]
	if bt == nil {
		return netip.Addr{}, false
	}
	m, ok := bt.Lookup(a)
	if !ok {
		return netip.Addr{}, false
	}
	return translate(a, m.Real, m.Virtual), true
}

// VirtualToReal translates a unified-space address back to its owner and
// real address.
func (t *Table) VirtualToReal(a netip.Addr) (Owner, netip.Addr, bool) {
	m, ok := t.snap.Load().byVirtual.Lookup(a)
	if !ok {
		return "", netip.Addr{}, false
	}
	return m.Owner, translate(a, m.Virtual, m.Real), true
}
