// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remap

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	st := FileStore{Path: filepath.Join(dir, "unify", "remap.json")}
	if _, err := st.Load(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load before Save: err = %v, want ErrNotExist", err)
	}
	if err := st.Save([]byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	b, err := st.Load()
	if err != nil || string(b) != `{"version":1}` {
		t.Fatalf("Load = %q, %v", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(st.Path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file mode = %v, want 0600", perm)
		}
	}
	if err := st.Discard(t0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fmt.Sprintf("%s.bad-%d", st.Path, t0.Unix())); err != nil {
		t.Fatalf("discarded file missing: %v", err)
	}
	if _, err := st.Load(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load after Discard: err = %v, want ErrNotExist", err)
	}
}

func TestFileStoreSaveError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent "directory" is a regular file, so MkdirAll fails.
	st := FileStore{Path: filepath.Join(blocker, "remap.json")}
	if err := st.Save([]byte("x")); err == nil {
		t.Fatal("Save under a regular file: want error")
	}
}

func TestTableWithFileStore(t *testing.T) {
	st := FileStore{Path: filepath.Join(t.TempDir(), "remap.json")}
	tb := newTable(t, testConfig(), st)
	mustSync(t, tb, "work", t0, "100.70.2.9/32")
	mustSync(t, tb, "personal", t0, "100.70.2.9/32")
	tb2 := newTable(t, testConfig(), st)
	wantVirtual(t, tb2, "personal", "100.70.2.9", "198.18.0.0")
}
