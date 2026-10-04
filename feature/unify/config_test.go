// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCheckName(t *testing.T) {
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"work", true},
		{"a", true},
		{"0", true},
		{"-", true},
		{"my-tailnet-2", true},
		{strings.Repeat("a", 32), true},
		{strings.Repeat("a", 33), false},
		{strings.Repeat("z", 1000), false},
		{"", false},
		{"default", false}, // the primary's name
		{"Work", false},
		{"WORK", false},
		{"my_tailnet", false},
		{"my.tailnet", false},
		{"..", false},
		{"a/b", false},
		{"../etc", false},
		{"a b", false},
		{" work", false},
		{"work\n", false},
		{"work\x00", false},
		{"wörk", false},
		{"ｗork", false}, // fullwidth
		{"defaul", true},
		{"default2", true},
		{"default-", true},
	} {
		err := CheckName(c.name)
		if (err == nil) != c.ok {
			t.Errorf("CheckName(%q) = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	for _, c := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" for no error
	}{
		{"empty", Config{}, ""},
		{"one", Config{Tailnets: []TailnetConfig{{Name: "work"}}}, ""},
		{"several", Config{Tailnets: []TailnetConfig{{Name: "work", Port: 41700}, {Name: "home"}, {Name: "friends"}}}, ""},
		{"duplicate", Config{Tailnets: []TailnetConfig{{Name: "work"}, {Name: "home"}, {Name: "work"}}}, `duplicate tailnet "work"`},
		{"reserved", Config{Tailnets: []TailnetConfig{{Name: "default"}}}, `"default" is reserved`},
		{"invalid", Config{Tailnets: []TailnetConfig{{Name: "Work"}}}, `invalid tailnet name "Work"`},
		{"empty name", Config{Tailnets: []TailnetConfig{{Name: ""}}}, `invalid tailnet name ""`},
		{"too long", Config{Tailnets: []TailnetConfig{{Name: strings.Repeat("x", 33)}}}, "invalid tailnet name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Validate = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	for _, c := range []struct {
		name    string
		data    string
		want    Config
		wantErr string // substring; "" for no error
	}{
		{name: "empty object", data: `{}`},
		{name: "no tailnets", data: `{"tailnets": []}`, want: Config{Tailnets: []TailnetConfig{}}},
		{name: "null tailnets", data: `{"tailnets": null}`},
		{name: "two", data: `{"tailnets":[{"name":"work","port":41700},{"name":"home"}]}`,
			want: Config{Tailnets: []TailnetConfig{{Name: "work", Port: 41700}, {Name: "home"}}}},
		{name: "explicit zero port", data: `{"tailnets":[{"name":"work","port":0}]}`,
			want: Config{Tailnets: []TailnetConfig{{Name: "work"}}}},
		{name: "highest port", data: `{"tailnets":[{"name":"work","port":65535}]}`,
			want: Config{Tailnets: []TailnetConfig{{Name: "work", Port: 65535}}}},
		{name: "whitespace", data: "\n {\"tailnets\" : [ {\"name\" : \"work\"} ] }\n\n",
			want: Config{Tailnets: []TailnetConfig{{Name: "work"}}}},
		{name: "empty file", data: ``, wantErr: "EOF"},
		{name: "not json", data: `tailnets = work`, wantErr: "invalid character"},
		{name: "array", data: `[{"name":"work"}]`, wantErr: "cannot unmarshal array"},
		{name: "unknown field", data: `{"tailnets":[{"name":"work","prot":1}]}`, wantErr: `unknown field "prot"`},
		{name: "unknown top-level field", data: `{"tailnet":[{"name":"work"}]}`, wantErr: `unknown field "tailnet"`},
		{name: "trailing data", data: `{"tailnets":[]} {}`, wantErr: "trailing data"},
		{name: "trailing garbage", data: `{"tailnets":[]}x`, wantErr: "trailing data"},
		{name: "port too large", data: `{"tailnets":[{"name":"work","port":65536}]}`, wantErr: "cannot unmarshal number 65536"},
		{name: "negative port", data: `{"tailnets":[{"name":"work","port":-1}]}`, wantErr: "cannot unmarshal number -1"},
		{name: "fractional port", data: `{"tailnets":[{"name":"work","port":1.5}]}`, wantErr: "cannot unmarshal number 1.5"},
		{name: "string port", data: `{"tailnets":[{"name":"work","port":"41700"}]}`, wantErr: "cannot unmarshal string"},
		{name: "number name", data: `{"tailnets":[{"name":7}]}`, wantErr: "cannot unmarshal number"},
		{name: "null entry", data: `{"tailnets":[null]}`, wantErr: `invalid tailnet name ""`},
		{name: "missing name", data: `{"tailnets":[{"port":41700}]}`, wantErr: `invalid tailnet name ""`},
		{name: "reserved", data: `{"tailnets":[{"name":"default"}]}`, wantErr: "reserved"},
		{name: "duplicate", data: `{"tailnets":[{"name":"a"},{"name":"a"}]}`, wantErr: `duplicate tailnet "a"`},
		{name: "path traversal", data: `{"tailnets":[{"name":"../x"}]}`, wantErr: "invalid tailnet name"},
		{name: "name too long", data: `{"tailnets":[{"name":"` + strings.Repeat("a", 33) + `"}]}`, wantErr: "invalid tailnet name"},
		{name: "duplicate port", data: `{"tailnets":[{"name":"a","port":5000},{"name":"b","port":5000}]}`,
			want: Config{Tailnets: []TailnetConfig{{Name: "a", Port: 5000}, {Name: "b", Port: 5000}}}}, // checked by Ports, with --port
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(c.data), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadConfig(path)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("LoadConfig = %+v, %v; want error containing %q", got, err, c.wantErr)
				}
				if !strings.Contains(err.Error(), path) {
					t.Errorf("error %q does not name the file", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("LoadConfig = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestLoadConfigMissing(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{
		filepath.Join(dir, "config.json"),
		filepath.Join(dir, "unify", "config.json"), // directory missing too
	} {
		got, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig(%q) = %v, want nil error", path, err)
		}
		if len(got.Tailnets) != 0 {
			t.Fatalf("LoadConfig(%q) = %+v, want no tailnets", path, got)
		}
	}
}

func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("directory", func(t *testing.T) {
		if _, err := LoadConfig(dir); err == nil {
			t.Fatal("LoadConfig of a directory succeeded")
		}
	})

	t.Run("too large", func(t *testing.T) {
		path := filepath.Join(dir, "large.json")
		// Valid JSON, padded with whitespace past the limit.
		data := `{"tailnets":[]}` + strings.Repeat(" ", maxConfigSize)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("LoadConfig = %v, want size error", err)
		}
	})

	t.Run("at the size limit", func(t *testing.T) {
		path := filepath.Join(dir, "limit.json")
		data := `{"tailnets":[]}`
		data += strings.Repeat(" ", maxConfigSize-len(data))
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err != nil {
			t.Fatalf("LoadConfig of a file of exactly %d bytes: %v", maxConfigSize, err)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads any file")
		}
		path := filepath.Join(dir, "secret.json")
		if err := os.WriteFile(path, []byte(`{}`), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("LoadConfig of an unreadable file succeeded")
		}
	})
}

func TestPorts(t *testing.T) {
	tn := func(name string, port uint16) TailnetConfig { return TailnetConfig{Name: name, Port: port} }
	for _, c := range []struct {
		name     string
		primary  uint16
		tailnets []TailnetConfig
		want     []uint16
		wantErr  string // substring; "" for no error
	}{
		{name: "no tailnets", primary: 41641, want: []uint16{}},
		{name: "derived", primary: 41641, tailnets: []TailnetConfig{tn("a", 0), tn("b", 0)},
			want: []uint16{41642, 41643}},
		{name: "explicit", primary: 41641, tailnets: []TailnetConfig{tn("a", 5000), tn("b", 0)},
			want: []uint16{5000, 41643}}, // the index counts configured order
		{name: "explicit below primary", primary: 41641, tailnets: []TailnetConfig{tn("a", 0), tn("b", 41640)},
			want: []uint16{41642, 41640}},
		{name: "random primary", primary: 0, tailnets: []TailnetConfig{tn("a", 0), tn("b", 0)},
			want: []uint16{0, 0}},
		{name: "random primary with explicit", primary: 0, tailnets: []TailnetConfig{tn("a", 0), tn("b", 7000)},
			want: []uint16{0, 7000}},
		{name: "last port", primary: 65534, tailnets: []TailnetConfig{tn("a", 0)},
			want: []uint16{65535}},
		{name: "overflow", primary: 65535, tailnets: []TailnetConfig{tn("a", 0)},
			wantErr: `tailnet "a": port 65535+1 is out of range`},
		{name: "overflow at the second", primary: 65534, tailnets: []TailnetConfig{tn("a", 0), tn("b", 0)},
			wantErr: `tailnet "b": port 65534+2 is out of range`},
		{name: "explicit avoids overflow", primary: 65535, tailnets: []TailnetConfig{tn("a", 1000)},
			want: []uint16{1000}},
		{name: "explicit equals primary", primary: 41641, tailnets: []TailnetConfig{tn("a", 41641)},
			wantErr: `tailnet "a": port 41641 is already used by tailnet "default"`},
		{name: "explicit duplicates", primary: 0, tailnets: []TailnetConfig{tn("a", 5000), tn("b", 5000)},
			wantErr: `tailnet "b": port 5000 is already used by tailnet "a"`},
		{name: "explicit equals derived", primary: 41641, tailnets: []TailnetConfig{tn("a", 0), tn("b", 41642)},
			wantErr: `tailnet "b": port 41642 is already used by tailnet "a"`},
		{name: "derived equals explicit", primary: 41641, tailnets: []TailnetConfig{tn("a", 41644), tn("b", 0), tn("c", 0)},
			wantErr: `tailnet "c": port 41644 is already used by tailnet "a"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Config{Tailnets: c.tailnets}.Ports(c.primary)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("Ports = %v, %v; want error containing %q", got, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ports: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Ports = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPaths(t *testing.T) {
	const sd = "/var/lib/tailscale"
	for _, c := range []struct{ got, want string }{
		{ConfigPath(sd), "/var/lib/tailscale/unify/config.json"},
		{RemapPath(sd), "/var/lib/tailscale/unify/remap.json"},
		{TailnetDir(sd, "work"), "/var/lib/tailscale/unify/tailnets/work"},
		{TailnetDir("rel", "home"), "rel/unify/tailnets/home"},
		{TailnetSocket("/var/run/tailscale/tailscaled.sock", "work"), "/var/run/tailscale/tailscaled-work.sock"},
		{TailnetSocket("tailscaled.sock", "home"), "tailscaled-home.sock"},
		{TailnetSocket("", "work"), ""},
		{TailnetSocket("/var/run/uniscale/uniscaled.sock", "work"), "/var/run/uniscale/uniscaled-work.sock"},
		{TailnetSocket("/var/run/uniscaled.socket", "work"), "/var/run/uniscaled-work.sock"},
		{TailnetSocket("/srv/ctl", "home"), "/srv/ctl-home.sock"},
	} {
		if c.got != filepath.FromSlash(c.want) {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if PrimaryName != "default" {
		t.Errorf("PrimaryName = %q", PrimaryName)
	}
}
