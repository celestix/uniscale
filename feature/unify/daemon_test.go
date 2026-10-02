// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package unify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/client/local"
	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/feature"
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/osglue"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/safesocket"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/router"
)

// daemonHarness runs runDaemon with live stacks on a chantun host TUN,
// the fake router and DNS configurator, and LocalAPI sockets in a
// temporary directory. Every host part it creates logs its Close to
// events.
type daemonHarness struct {
	t      *testing.T
	args   tailscaledhooks.UnifyArgs
	host   hostDeps
	dev    *chantun.Device
	router *fakeRouter
	dns    *fakeDNS
	events *eventLog
	logs   *logBuffer

	mu        sync.Mutex
	created   []string // what host created, in order
	linkUps   []string // each linkUp call, with the router's state
	listeners map[string]*eventListener
}

// newDaemonHarness returns a harness whose state directory holds config,
// the unify configuration file, unless it is empty.
func newDaemonHarness(t *testing.T, config string) *daemonHarness {
	t.Helper()
	h := &daemonHarness{
		t:      t,
		router: &fakeRouter{},
		events: &eventLog{},
		logs:   &logBuffer{t: t},

		listeners: map[string]*eventListener{},
	}
	h.router.events = h.events
	h.dns = &fakeDNS{DNS: osglue.NewDNS(nil), events: h.events}
	h.dev = newDev(t, "unify0", 64)
	// runDaemon names the host TUN the Tailscale interface.
	t.Cleanup(func() { netmon.SetTailscaleInterfaceProps("", 0) })
	stateDir := t.TempDir()
	if config != "" {
		h.writeConfig(stateDir, config)
	}
	sys := tsd.NewSystem()
	nm, err := netmon.New(sys.Bus.Get(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	sys.Set(nm)
	t.Cleanup(func() {
		nm.Close()
		sys.Bus.Get().Close()
	})
	h.args = tailscaledhooks.UnifyArgs{
		Logf:       h.logs.logf,
		LogID:      logid.PublicID{1},
		Sys:        sys,
		StateDir:   stateDir,
		StatePath:  filepath.Join(stateDir, "tailscaled.state"),
		SocketPath: filepath.Join(t.TempDir(), "tailscaled.sock"),
		TunName:    "unify0",
	}
	h.host = hostDeps{
		newTUN: func(logf logger.Logf, name string) (tun.Device, string, error) {
			h.record("tun " + name)
			return eventTUN{h.dev, h.events}, name, nil
		},
		newRouter: func(logf logger.Logf, dev tun.Device, sys *tsd.System) (router.Router, error) {
			if d, ok := dev.(eventTUN); !ok || d.Device != h.dev || sys != h.args.Sys {
				t.Errorf("newRouter(%v, %p), want the host TUN and tailscaled's system", dev, sys)
			}
			h.record("router")
			return h.router, nil
		},
		newDNS: func(logf logger.Logf, sys *tsd.System, devName string) (dns.OSConfigurator, error) {
			if devName != h.args.TunName || sys != h.args.Sys {
				t.Errorf("newDNS(%p, %q), want tailscaled's system and %q", sys, devName, h.args.TunName)
			}
			h.record("dns")
			return h.dns, nil
		},
		linkUp: func(dev tun.Device, logf logger.Logf) {
			h.router.mu.Lock()
			ups := h.router.ups
			h.router.mu.Unlock()
			if d, ok := dev.(eventTUN); !ok || d.Device != h.dev || logf == nil {
				t.Errorf("linkUp(%v, %v), want the host TUN and tailscaled's logf", dev, logf)
			}
			h.mu.Lock()
			h.linkUps = append(h.linkUps, fmt.Sprintf("router-ups=%d", ups))
			h.mu.Unlock()
		},
		listen: func(path string) (net.Listener, error) {
			ln, err := safesocket.Listen(path)
			if err != nil {
				return nil, err
			}
			name := filepath.Base(path)
			h.record("listen " + name)
			el := &eventListener{Listener: ln, name: name, events: h.events}
			h.mu.Lock()
			h.listeners[name] = el
			h.mu.Unlock()
			return el, nil
		},
	}
	return h
}

func (h *daemonHarness) writeConfig(stateDir, config string) {
	h.t.Helper()
	path := ConfigPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *daemonHarness) record(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.created = append(h.created, s)
}

func (h *daemonHarness) getCreated() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.created)
}

// run starts runDaemon. Its result arrives on the returned channel.
func (h *daemonHarness) run(ctx context.Context) <-chan error {
	errc := make(chan error, 1)
	go func() { errc <- runDaemon(ctx, h.args, h.host) }()
	return errc
}

// wait returns runDaemon's result.
func (h *daemonHarness) wait(errc <-chan error) error {
	h.t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(testTimeout):
		h.t.Fatal("runDaemon did not return")
		return nil
	}
}

// client returns a LocalAPI client for tailnet name's socket. It does
// not keep connections open, so none outlive the test.
func (h *daemonHarness) client(name string) *local.Client {
	path := socketPath(h.args.SocketPath, name)
	return &local.Client{
		Socket: path,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}

// status returns the status of tailnet name, retrying until its socket
// is up.
func (h *daemonHarness) status(ctx context.Context, name string) *ipnstate.Status {
	h.t.Helper()
	lc := h.client(name)
	for {
		st, err := lc.Status(ctx)
		if err == nil {
			return st
		}
		select {
		case <-ctx.Done():
			h.t.Fatalf("%s: Status: %v", name, err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// checkClosed checks that every host part the daemon created was closed
// exactly once and the sockets were removed. If ordered, the sockets must
// close first, then the router, DNS configurator and TUN, in that order.
func (h *daemonHarness) checkClosed(ordered bool) {
	h.t.Helper()
	var sockets []string
	created := set.Set[string]{}
	for _, c := range h.getCreated() {
		if name, ok := strings.CutPrefix(c, "listen "); ok {
			sockets = append(sockets, "close "+name)
		} else {
			component := strings.Fields(c)[0]
			created.Add(component)
		}
	}
	got := h.events.get()
	// Unify.Close closes in order: stacks, portClient, router, dns, loop/tun.
	// Daemon stacks run under ipnserver, which closes them as part of shutting down.
	// For host components, the order is: router, dns, tun (in that order).
	closeOrder := []string{"router", "dns", "tun"}
	var expectedHostOrder []string
	for _, component := range closeOrder {
		if created.Contains(component) {
			expectedHostOrder = append(expectedHostOrder, component)
		}
	}
	want := append(slices.Clip(sockets), expectedHostOrder...)
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		h.t.Fatalf("closed %q, want each of %q once", got, want)
	}
	if ordered {
		// Sockets should close first (any order among themselves).
		if !slices.Equal(slices.Sorted(slices.Values(got[:len(sockets)])), slices.Sorted(slices.Values(sockets))) {
			h.t.Fatalf("closed %q, want sockets first %q (any order)", got, sockets)
		}
		// Host components should close in the explicit order.
		if !slices.Equal(got[len(sockets):], expectedHostOrder) {
			h.t.Fatalf("closed %q, want sockets %q (any order) then host components %q", got, sockets, expectedHostOrder)
		}
	}
	for _, c := range sockets {
		path := filepath.Join(filepath.Dir(h.args.SocketPath), strings.TrimPrefix(c, "close "))
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			h.t.Errorf("socket %s left behind: %v", path, err)
		}
	}
}

// eventListener is a LocalAPI listener that logs its first Close.
type eventListener struct {
	net.Listener
	name   string
	events *eventLog
	once   sync.Once
}

func (l *eventListener) Close() error {
	l.once.Do(func() { l.events.add("close " + l.name) })
	return l.Listener.Close()
}

// liveDaemonTest prepares a test that brings up live stacks.
func liveDaemonTest(t *testing.T) {
	tstest.ResourceCheck(t)
	netns.SetEnabled(false) // no SO_MARK without CAP_NET_ADMIN
	t.Cleanup(func() { netns.SetEnabled(true) })
}

// waitLog waits for a log line that contains all of subs.
func (h *daemonHarness) waitLog(subs ...string) {
	h.t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		h.logs.mu.Lock()
		found := slices.ContainsFunc(h.logs.lines, func(l string) bool {
			return !slices.ContainsFunc(subs, func(s string) bool { return !strings.Contains(l, s) })
		})
		h.logs.mu.Unlock()
		if found {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("no log line with %q", subs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// freeUDPPort returns a UDP port that was free a moment ago.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func TestDaemon(t *testing.T) {
	liveDaemonTest(t)
	h := newDaemonHarness(t, `{"tailnets": [{"name": "b"}]}`)
	h.args.Port = freeUDPPort(t)
	// The primary's magicsock port (--port) must reach tailscaled's bus,
	// for the host router. Drain the bus so it never waits for the test.
	ports := eventbus.Subscribe[router.PortUpdate](h.args.Sys.Bus.Get().Client("test"))
	defer ports.Close()
	gotPort := make(chan struct{})
	go func(got chan struct{}, port uint16) {
		for {
			select {
			case pu := <-ports.Events():
				if pu.UDPPort == port && got != nil {
					close(got)
					got = nil
				}
			case <-ports.Done():
				return
			}
		}
	}(gotPort, h.args.Port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := h.run(ctx)

	reqCtx, reqCancel := context.WithTimeout(ctx, testTimeout)
	defer reqCancel()
	primary, b := h.client(PrimaryName), h.client("b")
	for _, name := range []string{PrimaryName, "b"} {
		if st := h.status(reqCtx, name); st.BackendState != ipn.NeedsLogin.String() {
			t.Errorf("%s: BackendState = %q, want %q (started, not logged in)", name, st.BackendState, ipn.NeedsLogin)
		}
	}
	select {
	case <-gotPort:
	case <-time.After(testTimeout):
		t.Fatalf("no port update for --port %d on tailscaled's bus", h.args.Port)
	}

	// Each socket serves its own tailnet.
	if _, err := b.EditPrefs(reqCtx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{Hostname: "tailnet-b"}, HostnameSet: true}); err != nil {
		t.Fatalf("b: EditPrefs: %v", err)
	}
	for lc, want := range map[*local.Client]string{primary: "", b: "tailnet-b"} {
		p, err := lc.GetPrefs(reqCtx)
		if err != nil {
			t.Fatalf("GetPrefs(%s): %v", lc.Socket, err)
		}
		if p.Hostname != want {
			t.Errorf("GetPrefs(%s).Hostname = %q, want %q", lc.Socket, p.Hostname, want)
		}
	}
	// And b's socket is b's: b's stack made the change, and only the
	// primary's has tailscaled's log ID.
	h.waitLog(`[unify:b] EditPrefs: MaskedPrefs{Hostname="tailnet-b"}`)
	if n := h.logs.count("[unify:default] EditPrefs"); n != 0 {
		t.Errorf("the primary edited its prefs %d times", n)
	}
	h.waitLog("[unify:default] ", `"BackendLogID":"`+h.args.LogID.String()+`"`)
	h.waitLog("[unify:b] ", `"BackendLogID":"`+logid.PublicID{}.String()+`"`)

	// The host side: the TUN is the Tailscale interface and the router is
	// up.
	if name, err := netmon.TailscaleInterfaceName(); name != "unify0" {
		t.Errorf("TailscaleInterfaceName = %q, %v", name, err)
	}
	h.router.mu.Lock()
	ups := h.router.ups
	h.router.mu.Unlock()
	if ups != 1 {
		t.Errorf("router brought up %d times", ups)
	}
	if want := []string{"listen tailscaled.sock", "listen tailscaled-b.sock", "tun unify0", "router", "dns"}; !slices.Equal(h.getCreated(), want) {
		t.Errorf("created %q, want %q", h.getCreated(), want)
	}
	// The host TUN's link features were set once, after the router came up.
	h.mu.Lock()
	linkUps := slices.Clone(h.linkUps)
	h.mu.Unlock()
	if want := []string{"router-ups=1"}; !slices.Equal(linkUps, want) {
		t.Errorf("linkUp calls = %q, want %q", linkUps, want)
	}
	if n := len(h.events.get()); n != 0 {
		t.Errorf("closed %q while running", h.events.get())
	}

	cancel()
	if err := h.wait(errc); err != nil {
		t.Fatalf("runDaemon = %v", err)
	}
	h.checkClosed(true)
	if h.logs.count("unify: shutting down") != 1 {
		t.Error("shutdown not logged")
	}
}

// TestDaemonHostTUNFails runs the primary tailnet alone (no
// configuration file) until the host TUN fails underneath.
func TestDaemonHostTUNFails(t *testing.T) {
	liveDaemonTest(t)
	h := newDaemonHarness(t, "")
	errc := h.run(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	h.status(ctx, PrimaryName)
	if want := []string{"listen tailscaled.sock", "tun unify0", "router", "dns"}; !slices.Equal(h.getCreated(), want) {
		t.Errorf("created %q, want %q", h.getCreated(), want)
	}
	h.dev.Close()
	err := h.wait(errc)
	if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "host TUN") {
		t.Fatalf("runDaemon = %v, want the host TUN's failure", err)
	}
	h.checkClosed(true)
}

// TestDaemonFollowsLinkChanges checks that the daemon starts tailscaled's
// network monitor. Under --unify no engine runs on it, and a monitor
// reports nothing until it is started: unify would never re-read the
// host's local networks, nor the host router see ip rule deletions.
func TestDaemonFollowsLinkChanges(t *testing.T) {
	liveDaemonTest(t)
	h := newDaemonHarness(t, "")
	var reads atomic.Int32
	h.host.localPrefixes = func() []netip.Prefix {
		reads.Add(1)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := h.run(ctx)
	reqCtx, reqCancel := context.WithTimeout(ctx, testTimeout)
	defer reqCancel()
	h.status(reqCtx, PrimaryName)
	waitReads := func(what string, n int32) {
		t.Helper()
		if err := tstest.WaitFor(testTimeout, func() error {
			if got := reads.Load(); got < n {
				return fmt.Errorf("%d reads of the local networks", got)
			}
			return nil
		}); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	waitReads("at start", 1)

	// A link change on tailscaled's monitor reaches unify, which reads the
	// local networks again.
	n := reads.Load()
	h.args.Sys.NetMon.Get().InjectEvent()
	waitReads("after a link change", n+1)

	cancel()
	if err := h.wait(errc); err != nil {
		t.Fatalf("runDaemon = %v", err)
	}
	h.checkClosed(true)
}

// TestDaemonServerStops stops everything when one tailnet's LocalAPI
// server stops by itself, as on a shutdown request, like tailscaled.
func TestDaemonServerStops(t *testing.T) {
	liveDaemonTest(t)
	h := newDaemonHarness(t, `{"tailnets": [{"name": "b"}]}`)
	errc := h.run(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	h.status(ctx, "b")
	h.mu.Lock()
	ln := h.listeners["tailscaled-b.sock"]
	h.mu.Unlock()
	ln.Listener.Close() // b's server stops accepting
	err := h.wait(errc)
	if !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), `tailnet "b"`) {
		t.Fatalf("runDaemon = %v, want b's server stopping", err)
	}
	if h.logs.count(`LocalAPI server of tailnet "b" stopped`) != 1 {
		t.Error("stop not logged")
	}
	h.checkClosed(true)
}

func TestDaemonErrors(t *testing.T) {
	errBoom := errors.New("boom")
	fileDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(fileDir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	listens := []string{"listen tailscaled.sock", "listen tailscaled-b.sock"}
	for _, c := range []struct {
		name    string
		mod     func(h *daemonHarness)
		live    bool     // builds live stacks
		want    string   // in the error
		created []string // the host parts created
		ordered bool     // closes sockets, router, DNS, TUN in that order
	}{
		{name: "no system", mod: func(h *daemonHarness) { h.args.Sys = nil }, want: "system"},
		{name: "no state directory", mod: func(h *daemonHarness) { h.args.StateDir = "" }, want: "--statedir"},
		{name: "no socket", mod: func(h *daemonHarness) { h.args.SocketPath = "" }, want: "--socket"},
		{name: "no tun", mod: func(h *daemonHarness) { h.args.TunName = "" }, want: `--tun=""`},
		{name: "userspace networking", mod: func(h *daemonHarness) { h.args.TunName = "userspace-networking" }, want: "--tun"},
		{name: "tap", mod: func(h *daemonHarness) { h.args.TunName = "tap:tap0" }, want: "--tun"},
		{name: "tun list", mod: func(h *daemonHarness) { h.args.TunName = "tailscale0,userspace-networking" }, want: "--tun"},
		{name: "bad config", mod: func(h *daemonHarness) { h.writeConfig(h.args.StateDir, "{") }, want: "config.json"},
		{name: "bad state", mod: func(h *daemonHarness) { h.args.StatePath = filepath.Join(fileDir, "tailscaled.state") }, want: "primary state"},
		{
			name: "primary socket",
			mod: func(h *daemonHarness) {
				h.host.listen = func(string) (net.Listener, error) { return nil, errBoom }
			},
			want: `socket for tailnet "default"`,
		},
		{
			name: "b socket",
			mod: func(h *daemonHarness) {
				listen := h.host.listen
				h.host.listen = func(path string) (net.Listener, error) {
					if filepath.Base(path) == "tailscaled-b.sock" {
						return nil, errBoom
					}
					return listen(path)
				}
			},
			want:    `socket for tailnet "b"`,
			created: listens[:1],
		},
		{
			name: "no logger",
			mod: func(h *daemonHarness) {
				h.args.Logf = nil
				h.host.newTUN = func(logger.Logf, string) (tun.Device, string, error) { return nil, "", errBoom }
			},
			want:    "boom",
			created: listens,
		},
		{
			name: "tun",
			mod: func(h *daemonHarness) {
				h.host.newTUN = func(logger.Logf, string) (tun.Device, string, error) { return nil, "", errBoom }
			},
			want:    `TUN "unify0"`,
			created: listens,
		},
		{
			name: "router",
			mod: func(h *daemonHarness) {
				h.host.newRouter = func(logger.Logf, tun.Device, *tsd.System) (router.Router, error) { return nil, errBoom }
			},
			want:    "router",
			created: append(slices.Clip(listens), "tun unify0"),
		},
		{
			name: "dns",
			mod: func(h *daemonHarness) {
				h.host.newDNS = func(logger.Logf, *tsd.System, string) (dns.OSConfigurator, error) { return nil, errBoom }
			},
			want:    "DNS",
			created: append(slices.Clip(listens), "tun unify0", "router"),
			ordered: true,
		},
		{
			name:    "new",
			mod:     func(h *daemonHarness) { h.args.Port = 65535 }, // b's default port is out of range
			want:    "out of range",
			created: append(slices.Clip(listens), "tun unify0", "router", "dns"),
		},
		{
			name:    "start",
			mod:     func(h *daemonHarness) { h.router.upErr = errBoom },
			live:    true,
			want:    "boom",
			created: append(slices.Clip(listens), "tun unify0", "router", "dns"),
			ordered: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.live {
				liveDaemonTest(t)
			} else {
				tstest.ResourceCheck(t)
			}
			h := newDaemonHarness(t, `{"tailnets": [{"name": "b"}]}`)
			c.mod(h)
			err := h.wait(h.run(context.Background()))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("runDaemon = %v, want an error with %q", err, c.want)
			}
			if !strings.HasPrefix(err.Error(), "unify: ") {
				t.Errorf("error %q lacks the unify: prefix", err)
			}
			if got := h.getCreated(); !slices.Equal(got, c.created) {
				t.Errorf("created %q, want %q", got, c.created)
			}
			// Only the cases that fail after the host parts exist and
			// close them in a fixed order are checked for it. The rest
			// fail before any part exists, or inside New, which closes
			// the parts itself while the deferred cleanup closes the
			// sockets, so their relative order is not fixed.
			h.checkClosed(c.ordered)
		})
	}
}

func TestDaemonOptions(t *testing.T) {
	sys := tsd.NewSystem()
	defer sys.Bus.Get().Close()
	nm := netmon.NewStatic()
	sys.Set(nm)
	logs := &logBuffer{t: t}
	a := tailscaledhooks.UnifyArgs{
		Logf:       logs.logf,
		LogID:      logid.PublicID{7},
		Sys:        sys,
		StateDir:   "/var/lib/tailscale",
		Ephemeral:  true,
		SocketPath: "/run/tailscale/tailscaled.sock",
		Port:       41641,
	}
	st := new(mem.Store)
	dev := newDev(t, "unify0", 1)
	r, d := &fakeRouter{}, osglue.NewDNS(nil)
	tailnets := []TailnetConfig{{Name: "b"}, {Name: "c", Port: 5}}
	o := daemonOptions(a, tailnets, st, dev, r, d)
	o.Logf("hello")
	if logs.count("hello") != 1 {
		t.Error("Logf is not tailscaled's")
	}
	want := PrimaryOptions{
		Dir:        "/var/lib/tailscale",
		Store:      st,
		Ephemeral:  true,
		Port:       41641,
		LogID:      logid.PublicID{7},
		SocketPath: "/run/tailscale/tailscaled.sock",
	}
	if o.Primary != want {
		t.Errorf("Primary = %+v, want %+v", o.Primary, want)
	}
	if o.StateDir != a.StateDir || !slices.Equal(o.Tailnets, tailnets) {
		t.Errorf("StateDir, Tailnets = %q, %v", o.StateDir, o.Tailnets)
	}
	if o.HostTUN != dev || o.HostRouter != r || o.HostDNS != d || o.HostBus != sys.Bus.Get() || o.NetMon != nm {
		t.Errorf("host parts = %v, %v, %v, %p, %p", o.HostTUN, o.HostRouter, o.HostDNS, o.HostBus, o.NetMon)
	}
	if o.LocalPrefixes != nil || o.Clock != nil || o.Pool4 != (netip.Prefix{}) || o.Pool6 != (netip.Prefix{}) {
		t.Error("defaults overridden")
	}

	// Without a network monitor, unify watches no local networks.
	o = daemonOptions(tailscaledhooks.UnifyArgs{Sys: tsd.NewSystem()}, nil, nil, dev, r, d)
	if o.NetMon != nil {
		t.Errorf("NetMon = %p", o.NetMon)
	}
	o.HostBus.Close()
}

func TestSocketPath(t *testing.T) {
	if got := socketPath("/run/tailscale/tailscaled.sock", PrimaryName); got != "/run/tailscale/tailscaled.sock" {
		t.Errorf("primary: %q", got)
	}
	if got := socketPath("/run/tailscale/tailscaled.sock", "b"); got != "/run/tailscale/tailscaled-b.sock" {
		t.Errorf("b: %q", got)
	}
}

// TestDaemonHook checks that unify registers itself and its tailscaled
// hook, which runs the daemon on the host's real TUN device, router and
// DNS configurator. Bad arguments fail before it touches the host.
func TestDaemonHook(t *testing.T) {
	if !feature.IsRegistered("unify") {
		t.Error("unify is not registered")
	}
	run, ok := tailscaledhooks.Unify.GetOk()
	if !ok {
		t.Fatal("tailscaledhooks.Unify is not set")
	}
	sys := tsd.NewSystem()
	defer sys.Bus.Get().Close()
	err := run(context.Background(), tailscaledhooks.UnifyArgs{
		Sys:        sys,
		StateDir:   t.TempDir(),
		SocketPath: filepath.Join(t.TempDir(), "tailscaled.sock"),
		TunName:    "userspace-networking",
	})
	if err == nil || !strings.Contains(err.Error(), "--tun") {
		t.Fatalf("Unify hook = %v, want the --tun error", err)
	}
}
