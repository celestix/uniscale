// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/atomicfile"
)

// FileStore is a [Store] backed by a single file, written with mode 0600.
type FileStore struct {
	Path string
}

// Load implements [Store].
func (s FileStore) Load() ([]byte, error) { return os.ReadFile(s.Path) }

// Save implements [Store].
func (s FileStore) Save(b []byte) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(s.Path, b, 0o600)
}

// Discard implements [Store] by renaming the file to <path>.bad-<unix time>.
func (s FileStore) Discard(now time.Time) error {
	return os.Rename(s.Path, fmt.Sprintf("%s.bad-%d", s.Path, now.Unix()))
}
