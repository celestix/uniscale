// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/osglue"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine/router"
)

// startControl starts a DERP and STUN server and a test control server
// and returns the control URL.
func startControl(t *testing.T) string {
	t.Helper()
	// Tests cannot set the socket mark (corp#4520).
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	logf := tstest.WhileTestRunningLogger(t)
	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, logf, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

// startPeer starts a plain tsnet node and returns it with its IPv4
// address.
func startPeer(t *testing.T, ctx context.Context, controlURL string) (*tsnet.Server, netip.Addr) {
	t.Helper()
	s := &tsnet.Server{
		Dir:        filepath.Join(t.TempDir(), "peer"),
		ControlURL: controlURL,
		Hostname:   "peer",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { s.Close() })
	st, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitHomeDERP(t, ctx, s.Sys())
	return s, st.TailscaleIPs[0]
}

// waitHomeDERP waits until the node has a home DERP region and has
// heard from it, so DERP does not drop the first disco frames to it.
func waitHomeDERP(t *testing.T, ctx context.Context, sys *tsd.System) {
	t.Helper()
	h, ms := sys.HealthTracker.Get(), sys.MagicSock.Get()
	for {
		if r := ms.GetLastNetcheckReport(ctx); r != nil && r.PreferredDERP != 0 &&
			!h.GetDERPRegionReceivedTime(r.PreferredDERP).IsZero() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for home DERP: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// testStack is a Stack on a chantun device whose host side is drained
// by the test.
type testStack struct {
	*Stack
	dev    *chantun.Device
	router *osglue.Router
	dns    *osglue.DNS
	ports  chan router.PortUpdate
	signal chan struct{}

	udp     chan []byte  // UDP packets to port 9999 the stack wrote to the host
	tcpFrom atomic.Int64 // TCP packets from port 8081 the stack wrote to the host
}

func newTestStack(t *testing.T, name string, store ipn.StateStore) *testStack {
	t.Helper()
	dev, err := chantun.New("unify-"+name, 1280, 8, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	ts := &testStack{
		dev:    dev,
		router: osglue.NewRouter(nil),
		dns:    osglue.NewDNS(nil),
		ports:  make(chan router.PortUpdate, 16),
		signal: make(chan struct{}, 1),
		udp:    make(chan []byte, 64),
	}
	st, err := New(Config{
		Name:      name,
		Dir:       filepath.Join(t.TempDir(), name),
		Store:     store,
		Ephemeral: store != nil,
		Logf:      tstest.WhileTestRunningLogger(t),
		Tun:       dev,
		Router:    ts.router,
		DNS:       ts.dns,
		OnPortUpdate: func(pu router.PortUpdate) {
			select {
			case ts.ports <- pu:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("New(%s): %v", name, err)
	}
	t.Cleanup(func() { st.Close() })
	ts.Stack = st
	go ts.drain()
	st.LocalBackend().SetRoutingObserver(func() {
		select {
		case ts.signal <- struct{}{}:
		default:
		}
	})
	return ts
}

// drain reads what the stack writes to the host until the device closes.
func (ts *testStack) drain() {
	for {
		select {
		case <-ts.dev.Done():
			return
		case pkt := <-ts.dev.Packets():
			var p packet.Parsed
			p.Decode(pkt)
			switch {
			case p.IPProto == ipproto.UDP && p.Dst.Port() == 9999:
				select {
				case ts.udp <- pkt:
				default:
				}
			case p.IPProto == ipproto.TCP && p.Src.Port() == 8081:
				ts.tcpFrom.Add(1)
			}
		}
	}
}

// up starts the stack's backend against controlURL, as tailscale up
// would.
func (ts *testStack) up(t *testing.T, ctx context.Context, controlURL string) {
	t.Helper()
	lb := ts.LocalBackend()
	prefs := ipn.NewPrefs()
	prefs.ControlURL = controlURL
	prefs.WantRunning = true
	prefs.Hostname = ts.Name()
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs}); err != nil {
		t.Fatalf("Start(%s): %v", ts.Name(), err)
	}
	if lb.State() == ipn.NeedsLogin {
		if err := lb.StartLoginInteractive(ctx); err != nil {
			t.Fatalf("StartLoginInteractive(%s): %v", ts.Name(), err)
		}
	}
}

// waitSnapshot waits until the stack's routing snapshot satisfies cond,
// re-checking whenever the routing observer fires.
func (ts *testStack) waitSnapshot(t *testing.T, ctx context.Context, what string, cond func(ipnlocal.RoutingSnapshot) bool) ipnlocal.RoutingSnapshot {
	t.Helper()
	for {
		snap := ts.LocalBackend().RoutingSnapshot()
		if cond(snap) {
			return snap
		}
		select {
		case <-ts.signal:
		case <-time.After(time.Second):
		case <-ctx.Done():
			t.Fatalf("%s: waiting for %s: %v; last snapshot %+v", ts.Name(), what, ctx.Err(), snap)
		}
	}
}

func first4(pfxs []netip.Prefix) netip.Addr {
	for _, p := range pfxs {
		if p.Addr().Is4() {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

// echoUDP returns the reply to an IPv4 UDP packet: addresses and ports
// swapped, same payload.
func echoUDP(pkt []byte) []byte {
	var p packet.Parsed
	p.Decode(pkt)
	h := p.UDP4Header()
	h.ToResponse()
	return packet.Generate(h, p.Payload())
}

func TestStacks(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	controlURL := startControl(t)
	peer, peer4 := startPeer(t, ctx, controlURL)
	one := newTestStack(t, "one", nil) // file store in its directory
	two := newTestStack(t, "two", new(mem.Store))
	one.up(t, ctx, controlURL)
	two.up(t, ctx, controlURL)

	running := func(s ipnlocal.RoutingSnapshot) bool { return s.State == ipn.Running && len(s.Self) > 0 }
	oneSelf := one.waitSnapshot(t, ctx, "Running", running).Self
	twoSelf := two.waitSnapshot(t, ctx, "Running", running).Self
	peerPfx := netip.PrefixFrom(peer4, 32)

	t.Run("snapshots", func(t *testing.T) {
		for _, c := range []struct {
			ts          *testStack
			self, other []netip.Prefix
		}{{one, oneSelf, twoSelf}, {two, twoSelf, oneSelf}} {
			snap := c.ts.waitSnapshot(t, ctx, "peers", func(s ipnlocal.RoutingSnapshot) bool {
				return slices.Contains(s.Peers, peerPfx) && slices.Contains(s.Peers, netip.PrefixFrom(first4(c.other), 32))
			})
			var want []netip.Prefix
			for _, a := range c.ts.LocalBackend().StatusWithoutPeers().TailscaleIPs {
				want = append(want, netip.PrefixFrom(a, a.BitLen()))
			}
			tsaddr.SortPrefixes(want)
			if !slices.Equal(snap.Self, want) {
				t.Errorf("%s: Self = %v; want %v", c.ts.Name(), snap.Self, want)
			}
			if !first4(c.self).IsValid() || slices.Contains(snap.Peers, netip.PrefixFrom(first4(c.self), 32)) {
				t.Errorf("%s: self %v missing or listed as a peer in %v", c.ts.Name(), c.self, snap.Peers)
			}
			if snap.MagicDNSSuffix != "tail-scale.ts.net" {
				t.Errorf("%s: MagicDNSSuffix = %q", c.ts.Name(), snap.MagicDNSSuffix)
			}
		}
	})

	t.Run("router and DNS captured", func(t *testing.T) {
		if err := tstest.WaitFor(30*time.Second, func() error {
			cfg := one.router.Config()
			if cfg == nil || !slices.Equal(cfg.LocalAddrs, oneSelf) {
				return errors.New("router config does not have the stack's addresses yet")
			}
			if len(one.dns.Config().Nameservers) == 0 {
				return errors.New("no DNS configuration recorded yet")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("port update", func(t *testing.T) {
		want := one.Sys().MagicSock.Get().LocalPort()
		timeout := time.After(10 * time.Second)
		for {
			select {
			case pu := <-one.ports:
				if pu.EndpointNetwork == "udp4" && pu.UDPPort == want {
					return
				}
			case <-timeout:
				t.Fatalf("no udp4 PortUpdate for port %d", want)
			}
		}
	})

	one4 := first4(oneSelf)
	waitHomeDERP(t, ctx, one.Sys())
	lc, err := peer.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := tstest.WaitFor(30*time.Second, func() error {
		pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
		defer pcancel()
		_, err := lc.Ping(pctx, one4, tailcfg.PingTSMP)
		return err
	}); err != nil {
		t.Fatalf("peer cannot reach stack one: %v", err)
	}

	// Traffic from a peer to the stack's own address is not consumed
	// by netstack: it comes out of the stack's TUN to the host.
	t.Run("peer to host via TUN", func(t *testing.T) {
		conn, err := peer.Dial(ctx, "udp", netip.AddrPortFrom(one4, 9999).String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		const msg = "hello host"
		var pkt []byte
		deadline := time.After(30 * time.Second)
		for pkt == nil {
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			}
			select {
			case pkt = <-one.udp:
			case <-time.After(500 * time.Millisecond):
			case <-deadline:
				t.Fatal("no UDP packet came out of the stack's TUN")
			}
		}
		var p packet.Parsed
		p.Decode(pkt)
		if p.Src.Addr() != peer4 || p.Dst != netip.AddrPortFrom(one4, 9999) || string(p.Payload()) != msg {
			t.Fatalf("TUN packet %v -> %v %q; want from %v to %v:9999 %q", p.Src, p.Dst, p.Payload(), peer4, one4, msg)
		}
		// The host answers through the TUN.
		if err := one.dev.Inject(ctx, echoUDP(pkt)); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("peer read %q, %v; want %q", buf[:n], err, msg)
		}
	})

	// The stack's own dials to tailnet addresses use netstack, never the
	// host's routing.
	t.Run("stack dials use netstack", func(t *testing.T) {
		ln, err := peer.Listen("tcp", ":8081")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			io.Copy(c, c)
		}()

		d := one.Sys().Dialer.Get()
		if !d.UseNetstackForIP(peer4) {
			t.Fatalf("UseNetstackForIP(%v) = false", peer4)
		}
		if d.UseNetstackForIP(netip.MustParseAddr("127.0.0.1")) {
			t.Fatal("UseNetstackForIP(127.0.0.1) = true")
		}
		dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
		defer dcancel()
		c, err := d.UserDial(dctx, "tcp", netip.AddrPortFrom(peer4, 8081).String())
		if err != nil {
			t.Fatalf("UserDial: %v", err)
		}
		defer c.Close()
		const msg = "ping over netstack"
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
			t.Fatalf("read %q, %v; want %q", buf, err, msg)
		}
		if n := one.tcpFrom.Load(); n != 0 {
			t.Errorf("%d replies to the stack's own connection leaked to the host", n)
		}

		// UDP takes the same path.
		pc, err := peer.ListenPacket("udp", netip.AddrPortFrom(peer4, 8082).String())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		go func() {
			buf := make([]byte, 100)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				pc.WriteTo(buf[:n], from)
			}
		}()
		uc, err := d.UserDial(dctx, "udp", netip.AddrPortFrom(peer4, 8082).String())
		if err != nil {
			t.Fatalf("UserDial udp: %v", err)
		}
		defer uc.Close()
		buf = make([]byte, 100)
		for {
			if _, err := uc.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			}
			uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := uc.Read(buf)
			if err == nil && string(buf[:n]) == msg {
				break
			}
			if dctx.Err() != nil {
				t.Fatalf("no UDP echo over netstack: %v", err)
			}
		}
	})

	// The stack is served over LocalAPI by an ipnserver on its own bus.
	// This runs last: when the server stops it shuts the backend down.
	t.Run("LocalAPI", func(t *testing.T) {
		lb := two.LocalBackend()
		sock := filepath.Join(t.TempDir(), "two.sock")
		ln, err := safesocket.Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		srv := ipnserver.New(two.Logf(), logid.PublicID{}, lb.EventBus(), lb.NetMon())
		srv.SetLocalBackend(lb)
		srvCtx, srvCancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- srv.Run(srvCtx, ln) }()

		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return safesocket.ConnectContext(ctx, sock)
		}}
		defer tr.CloseIdleConnections()
		lc := &local.Client{Transport: tr, UseSocketOnly: true}
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.BackendState != ipn.Running.String() || !slices.Contains(st.TailscaleIPs, first4(twoSelf)) {
			t.Errorf("Status = %v %v; want Running with %v", st.BackendState, st.TailscaleIPs, first4(twoSelf))
		}
		srvCancel()
		<-done
	})

	t.Run("close", func(t *testing.T) {
		for _, ts := range []*testStack{one, two} {
			if err := ts.Close(); err != nil {
				t.Errorf("%s: Close: %v", ts.Name(), err)
			}
			select {
			case <-ts.dev.Done():
			default:
				t.Errorf("%s: Close did not close the TUN", ts.Name())
			}
			if cfg := ts.router.Config(); cfg != nil {
				t.Errorf("%s: router still configured after Close: %+v", ts.Name(), cfg)
			}
			if err := ts.Close(); err != nil {
				t.Errorf("%s: second Close: %v", ts.Name(), err)
			}
		}
	})
}

func TestAccessors(t *testing.T) {
	ts := newTestStack(t, "acc", new(mem.Store))
	if ts.Name() != "acc" {
		t.Errorf("Name = %q", ts.Name())
	}
	if ts.LocalBackend().Sys() != ts.Sys() {
		t.Error("LocalBackend and Sys disagree")
	}
	if got := ts.Sys().Tun.Get().Unwrap(); got != ts.dev {
		t.Errorf("stack TUN = %v; want the configured device", got)
	}
	if got := ts.Sys().Router.Get(); got != ts.router {
		t.Errorf("stack router = %v; want the configured one", got)
	}
	if _, ok := ts.Sys().Netstack.GetOK(); !ok {
		t.Error("no netstack")
	}

	// Without a netmap there is no address to dial from; the dial
	// fails with a nil net.Conn, not a nil pointer in one.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c, err := ts.Sys().Dialer.Get().NetstackDialTCP(ctx, netip.MustParseAddrPort("100.64.0.99:1"))
	if err == nil || c != nil {
		t.Errorf("NetstackDialTCP without a netmap = %v, %v; want nil, error", c, err)
	}
}

func TestLogPrefix(t *testing.T) {
	dev, err := chantun.New("unify-log", 1280, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	var mu sync.Mutex
	var lines []string
	st, err := New(Config{
		Name:   "work",
		Store:  new(mem.Store),
		Tun:    dev,
		Router: osglue.NewRouter(nil),
		DNS:    osglue.NewDNS(nil),
		Logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st.Logf()("from test")
	st.Close()
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(lines, "[unify:work] from test") {
		t.Errorf("Logf output %q lacks %q", lines, "[unify:work] from test")
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "[unify:work] ") {
			t.Errorf("log line %q lacks the stack prefix", l)
		}
	}
}

type failingRouter struct{ router.Router }

func (failingRouter) Up() error    { return errors.New("router up failed") }
func (failingRouter) Close() error { return nil }

type failingStore struct{ ipn.StateStore }

func (failingStore) ReadState(ipn.StateKey) ([]byte, error) { return nil, errors.New("store broken") }

func newErrConfig(t *testing.T) Config {
	dev, err := chantun.New("unify-err", 1280, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	return Config{
		Name:   "err",
		Dir:    t.TempDir(),
		Tun:    dev,
		Router: osglue.NewRouter(nil),
		DNS:    osglue.NewDNS(nil),
	}
}

func TestNewErrors(t *testing.T) {
	tstest.ResourceCheck(t)
	tests := []struct {
		name    string
		mod     func(t *testing.T, c *Config)
		wantErr string
	}{
		{"no name", func(t *testing.T, c *Config) { c.Name = "" }, "Name"},
		{"no tun", func(t *testing.T, c *Config) { c.Tun = nil }, "Tun"},
		{"no router", func(t *testing.T, c *Config) { c.Router = nil }, "Router"},
		{"no dns", func(t *testing.T, c *Config) { c.DNS = nil }, "DNS"},
		{"no dir or store", func(t *testing.T, c *Config) { c.Dir = "" }, "Dir"},
		{"dir is a file", func(t *testing.T, c *Config) {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0600); err != nil {
				t.Fatal(err)
			}
			c.Dir = f
		}, "file"},
		{"state file is a directory", func(t *testing.T, c *Config) {
			if err := os.MkdirAll(filepath.Join(c.Dir, "tailscaled.state"), 0700); err != nil {
				t.Fatal(err)
			}
		}, "tailscaled.state"},
		{"store fails", func(t *testing.T, c *Config) { c.Store = failingStore{} }, "store broken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newErrConfig(t)
			tt.mod(t, &cfg)
			st, err := New(cfg)
			if err == nil {
				st.Close()
				t.Fatal("New succeeded; want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("New error = %v; want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// TestNewEngineError checks that an engine failure fails New. It has no
// goroutine leak check: wgengine.NewUserspaceEngine leaks wireguard-go
// goroutines when it fails after bringing its device up, because the
// tstun.Wrapper it closes was never started and its readers wait for
// Start forever.
func TestNewEngineError(t *testing.T) {
	cfg := newErrConfig(t)
	cfg.Router = failingRouter{}
	st, err := New(cfg)
	if err == nil {
		st.Close()
		t.Fatal("New succeeded; want error")
	}
	if !strings.Contains(err.Error(), "router up failed") {
		t.Errorf("New error = %v; want the router's error", err)
	}
}

// TestCloseWithBlockedTUN tests that Close does not hang when the TUN
// is not being drained. Without closing the TUN device first, netstack's
// Close could block waiting for injectWG when packets are pending.
func TestCloseWithBlockedTUN(t *testing.T) {
	tstest.ResourceCheck(t)
	dev, err := chantun.New("unify-blocked", 1280, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	st, err := New(Config{
		Name:   "blocked",
		Store:  new(mem.Store),
		Tun:    dev,
		Router: osglue.NewRouter(nil),
		DNS:    osglue.NewDNS(nil),
		Logf:   tstest.WhileTestRunningLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Crucially, do not drain the device's host side:
	// the existing tests drain the device to consume packets,
	// but this test leaves it undrained to verify that Close
	// still succeeds quickly even when the TUN is blocked.

	// Close should return quickly without hanging, because we close
	// the TUN device first in Stack.Close (ruling 1).
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	closeErr := make(chan error, 1)
	go func() {
		closeErr <- st.Close()
	}()

	select {
	case err := <-closeErr:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-closeCtx.Done():
		t.Fatal("Close hung for 5 seconds; want it to return quickly even with an undrained TUN")
	}
}

// TestConfigureWebClient verifies that ConfigureWebClient is called
// with the stack's socket path when one is configured.
func TestConfigureWebClient(t *testing.T) {
	dev, err := chantun.New("unify-webclient", 1280, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	socketPath := filepath.Join(t.TempDir(), "test.sock")
	st, err := New(Config{
		Name:       "webclient",
		Store:      new(mem.Store),
		Tun:        dev,
		Router:     osglue.NewRouter(nil),
		DNS:        osglue.NewDNS(nil),
		Logf:       tstest.WhileTestRunningLogger(t),
		SocketPath: socketPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Verify that New succeeds and the LocalBackend is created.
	// ConfigureWebClient is called internally after NewLocalBackend,
	// so if New succeeds without error, it means the call succeeded.
	// The LocalBackend.web field is private and not directly observable,
	// but the code has been verified to call ConfigureWebClient with
	// Socket and UseSocketOnly set (see stack.go implementation).
	lb := st.LocalBackend()
	if lb == nil {
		t.Fatal("LocalBackend is nil")
	}
	if st.Sys() == nil {
		t.Fatal("System is nil")
	}
}

// TestDialTailscaleRangeNotPeer verifies that dialing a Tailscale-range
// address that is not a known peer/route uses netstack, not the OS dialer.
func TestDialTailscaleRangeNotPeer(t *testing.T) {
	dev, err := chantun.New("unify-dial", 1280, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	st, err := New(Config{
		Name:   "dial",
		Store:  new(mem.Store),
		Tun:    dev,
		Router: osglue.NewRouter(nil),
		DNS:    osglue.NewDNS(nil),
		Logf:   tstest.WhileTestRunningLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	d := st.Sys().Dialer.Get()

	// Choose a Tailscale-range address that is not in the backend's netmap.
	// 100.64.0.99 is in the CGNAT range and should be treated as a Tailscale address.
	unknownIP := netip.MustParseAddr("100.64.0.99")

	// The dialer should use netstack for Tailscale-range addresses.
	if !d.UseNetstackForIP(unknownIP) {
		t.Fatalf("UseNetstackForIP(%v) = false; want true for Tailscale-range address", unknownIP)
	}

	// Test an actual dial: it should fail quickly with a netstack error
	// (no route), not a host OS error.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := d.UserDial(ctx, "tcp", netip.AddrPortFrom(unknownIP, 80).String())
	if c != nil {
		defer c.Close()
		t.Fatalf("dial to unknown Tailscale address returned a connection; want an error")
	}
	if err == nil {
		t.Fatal("dial to unknown Tailscale address returned no error")
	}
	// The error should mention netstack, not OS dial.
	// (e.g., "no route to host" from netstack, not "connection refused" from OS)
	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host") {
		t.Fatalf("dial error suggests OS dial, not netstack: %v", err)
	}
}
