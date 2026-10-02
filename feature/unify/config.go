// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// PrimaryName is the name of the primary tailnet. It uses tailscaled's
// usual state file and LocalAPI socket, so it is not listed in [Config].
const PrimaryName = "default"

// maxNameLen is the longest tailnet name.
const maxNameLen = 32

// maxConfigSize bounds the configuration file.
const maxConfigSize = 1 << 20

// Config is the unify configuration file, at [ConfigPath].
//
//	{"tailnets": [{"name": "work", "port": 41700}, {"name": "home"}]}
type Config struct {
	// Tailnets lists the tailnets other than the primary, in order. The
	// order decides ties: which tailnet's exit node is used if several
	// select one, and the default UDP ports (see [Config.Ports]).
	Tailnets []TailnetConfig `json:"tailnets"`
}

// TailnetConfig configures one tailnet other than the primary.
type TailnetConfig struct {
	// Name names the tailnet, in logs and on disk (see [TailnetDir]). It
	// matches ^[a-z0-9-]{1,32}$ and is not [PrimaryName].
	Name string `json:"name"`

	// Port is the tailnet's WireGuard UDP port. Zero picks a default
	// (see [Config.Ports]).
	Port uint16 `json:"port,omitzero"`
}

// ConfigPath returns the path of the configuration file in tailscaled's
// state directory.
func ConfigPath(stateDir string) string {
	return filepath.Join(stateDir, "unify", "config.json")
}

// RemapPath returns the path of the saved remap table in tailscaled's
// state directory.
func RemapPath(stateDir string) string {
	return filepath.Join(stateDir, "unify", "remap.json")
}

// TailnetDir returns the directory of tailnet name, other than the
// primary: its state file (tailscaled.state) and its VarRoot.
func TailnetDir(stateDir, name string) string {
	return filepath.Join(stateDir, "unify", "tailnets", name)
}

// CheckName reports whether name is a valid name for a tailnet in
// [Config]: 1 to 32 lowercase ASCII letters, digits or hyphens, and not
// [PrimaryName].
func CheckName(name string) error {
	if name == PrimaryName {
		return fmt.Errorf("tailnet name %q is reserved for the primary tailnet", name)
	}
	if len(name) == 0 || len(name) > maxNameLen {
		return fmt.Errorf("invalid tailnet name %q: must be 1 to %d characters", name, maxNameLen)
	}
	for _, c := range []byte(name) {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return fmt.Errorf("invalid tailnet name %q: only a-z, 0-9 and - are allowed", name)
		}
	}
	return nil
}

// Validate reports whether every name in c is valid and unique.
func (c Config) Validate() error {
	seen := make(map[string]bool, len(c.Tailnets))
	for _, t := range c.Tailnets {
		if err := CheckName(t.Name); err != nil {
			return err
		}
		if seen[t.Name] {
			return fmt.Errorf("duplicate tailnet %q", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

// LoadConfig reads and validates the configuration file at path. A missing
// file is an empty configuration: the primary tailnet only. Unknown fields
// are errors, so typos do not go unnoticed.
func LoadConfig(path string) (Config, error) {
	c, err := loadConfig(path)
	if err != nil {
		return Config{}, fmt.Errorf("unify: %s: %w", path, err)
	}
	return c, nil
}

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return Config{}, err
	}
	if len(b) > maxConfigSize {
		return Config{}, fmt.Errorf("larger than %d bytes", maxConfigSize)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, errors.New("trailing data after the configuration")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Ports returns the WireGuard UDP port of each tailnet in c, in order,
// given primary, the primary tailnet's port (tailscaled's --port). A
// tailnet's own Port is used if set. Otherwise the i-th tailnet (from 1)
// gets primary+i, or 0 (any free port) if primary is 0. Two tailnets
// may not get the same non-zero port.
func (c Config) Ports(primary uint16) ([]uint16, error) {
	ports := make([]uint16, len(c.Tailnets))
	owner := map[uint16]string{}
	if primary != 0 {
		owner[primary] = PrimaryName
	}
	for i, t := range c.Tailnets {
		p := t.Port
		if p == 0 && primary != 0 {
			n := int(primary) + i + 1
			if n > 65535 {
				return nil, fmt.Errorf("tailnet %q: port %d+%d is out of range; set its port in config.json", t.Name, primary, i+1)
			}
			p = uint16(n)
		}
		if p != 0 {
			if o, dup := owner[p]; dup {
				return nil, fmt.Errorf("tailnet %q: port %d is already used by tailnet %q", t.Name, p, o)
			}
			owner[p] = t.Name
		}
		ports[i] = p
	}
	return ports, nil
}
