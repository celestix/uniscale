// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gaissmai/bart"
)

// Store persists the table's state.
type Store interface {
	// Load returns the saved state. It returns an error satisfying
	// errors.Is(err, fs.ErrNotExist) when nothing has been saved yet.
	Load() ([]byte, error)
	// Save atomically replaces the saved state.
	Save([]byte) error
	// Discard moves unreadable saved state aside so it can be inspected.
	Discard(now time.Time) error
}

const stateVersion = 1

// state is the persisted form of a [Table].
type state struct {
	Version    int           `json:"version"`
	Pool6      netip.Prefix  `json:"pool6,omitzero"`
	Mappings   []Mapping     `json:"mappings"`
	Quarantine []quarantined `json:"quarantine,omitempty"`
}

type quarantined struct {
	Virtual netip.Prefix `json:"virtual"`
	Until   time.Time    `json:"until"`
}

var errCorrupt = errors.New("remap: invalid saved state")

// decodeState parses and validates saved state.
func decodeState(b []byte) (state, error) {
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return state{}, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	if st.Version != stateVersion {
		return state{}, fmt.Errorf("%w: version %d, want %d", errCorrupt, st.Version, stateVersion)
	}
	if st.Pool6.IsValid() && (!st.Pool6.Addr().Is6() || st.Pool6 != st.Pool6.Masked()) {
		return state{}, fmt.Errorf("%w: bad pool6 %v", errCorrupt, st.Pool6)
	}
	for _, m := range st.Mappings {
		if err := m.check(); err != nil {
			return state{}, fmt.Errorf("%w: %v", errCorrupt, err)
		}
	}
	if err := checkDisjoint(st.Mappings); err != nil {
		return state{}, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	for _, q := range st.Quarantine {
		if !q.Virtual.IsValid() || q.Virtual != q.Virtual.Masked() {
			return state{}, fmt.Errorf("%w: bad quarantined prefix %v", errCorrupt, q.Virtual)
		}
	}
	return st, nil
}

// check reports whether m is internally consistent.
func (m Mapping) check() error {
	switch {
	case m.Owner == "":
		return errors.New("mapping with empty owner")
	case !m.Real.IsValid() || !m.Virtual.IsValid():
		return fmt.Errorf("mapping %v: invalid prefix", m)
	case m.Real != m.Real.Masked() || m.Virtual != m.Virtual.Masked():
		return fmt.Errorf("mapping %v: prefix not masked", m)
	case m.Real.Addr().Is4() != m.Virtual.Addr().Is4() || m.Real.Bits() != m.Virtual.Bits():
		return fmt.Errorf("mapping %v: real and virtual differ in family or length", m)
	case m.Real.Bits() == 0:
		return fmt.Errorf("mapping %v: default route", m)
	}
	return nil
}

// overlapAllowed reports whether two mappings may have overlapping virtual
// prefixes: only identity mappings of the same owner (for example a tailnet
// routing both 10.0.0.0/8 and 10.1.0.0/16).
func overlapAllowed(a, b Mapping) bool {
	return a.Owner == b.Owner && !a.Remapped() && !b.Remapped()
}

// checkDisjoint verifies the virtual-space invariant across ms.
func checkDisjoint(ms []Mapping) error {
	var t bart.Table[Mapping]
	type k struct {
		owner Owner
		real  netip.Prefix
	}
	seen := map[k]bool{}
	for _, m := range ms {
		if seen[k{m.Owner, m.Real}] {
			return fmt.Errorf("duplicate mapping for %s %v", m.Owner, m.Real)
		}
		seen[k{m.Owner, m.Real}] = true
		for _, o := range overlapping(&t, m.Virtual) {
			if !overlapAllowed(o, m) {
				return fmt.Errorf("mappings %v and %v overlap", o, m)
			}
		}
		t.Insert(m.Virtual, m)
	}
	return nil
}

// overlapping returns the values of all prefixes in t that overlap p.
func overlapping[V any](t *bart.Table[V], p netip.Prefix) []V {
	var out []V
	for _, v := range t.Supernets(p) {
		out = append(out, v)
	}
	for q, v := range t.Subnets(p) {
		if q != p {
			out = append(out, v)
		}
	}
	return out
}
