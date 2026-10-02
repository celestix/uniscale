// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/osglue"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

// The integration test runs unify against two test control servers
// sharing one DERP and STUN server. In each tailnet the peer registers
// first and the unify stack second, so both tailnets have the same
// addresses: the peers are 100.64.0.1 and the stacks 100.64.0.2 (and the
// matching IPv6 addresses). The primary ("default", control A) syncs
// first and keeps them; "b" (control B) is remapped into the pools.
//
// The test plays the host's kernel on a chantun host TUN, with a fake
// router and OS DNS configurator. The peers are plain tsnet nodes, whose
// netstack answers ICMP echo for their addresses.

const integrationTimeout = 20 * time.Second

// runDERPAndSTUN starts a DERP and a STUN server on 127.0.0.1, as
// integration.RunDERPAndSTUN does. Tests here cannot import
// tstest/integration: it links feature/condregister, which links this
// package.
func runDERPAndSTUN(t *testing.T, logf logger.Logf) *tailcfg.DERPMap {
	t.Helper()
	d := derpserver.New(key.NewNode(), logf)
	srv := httptest.NewUnstartedServer(derpserver.Handler(d))
	srv.Config.ErrorLog = logger.StdLogger(logf)
	srv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	srv.StartTLS()
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		d.Close()
		stunCleanup()
	})
	return &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{{
					Name:             "t1",
					RegionID:         1,
					HostName:         "127.0.0.1",
					IPv4:             "127.0.0.1",
					IPv6:             "none",
					STUNPort:         stunAddr.Port,
					DERPPort:         srv.Listener.Addr().(*net.TCPAddr).Port,
					InsecureForTests: true,
					STUNTestIP:       "127.0.0.1",
				}},
			},
		},
	}
}

func startTestControl(t *testing.T, derpMap *tailcfg.DERPMap, logf logger.Logf) string {
	t.Helper()
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

// startTestPeer starts a plain tsnet node and waits until it is
// registered and has a home DERP.
func startTestPeer(t *testing.T, ctx context.Context, controlURL, name string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{
		Dir:        filepath.Join(t.TempDir(), name),
		ControlURL: controlURL,
		Hostname:   name,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.WithPrefix(tstest.WhileTestRunningLogger(t), name+": "),
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	waitHomeDERP(t, ctx, s.Sys())
	return s
}

// waitHomeDERP waits until the node has a home DERP region and has heard
// from it, so DERP does not drop the first disco frames to it.
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

// waitPeerReachable waits until lb's netmap has the peer with key k, with
// a home DERP and endpoints (the tsnet tests' waitForPeerReachable).
func waitPeerReachable(t *testing.T, lb *ipnlocal.LocalBackend, k key.NodePublic) {
	t.Helper()
	if err := tstest.WaitFor(integrationTimeout, func() error {
		nm := lb.NetMapWithPeers()
		if nm == nil {
			return errors.New("no netmap yet")
		}
		for _, p := range nm.Peers {
			if p.Key() != k {
				continue
			}
			if p.HomeDERP() == 0 {
				return fmt.Errorf("peer %v: no home DERP", k.ShortString())
			}
			if p.Endpoints().Len() == 0 {
				return fmt.Errorf("peer %v: no endpoints", k.ShortString())
			}
			return nil
		}
		return fmt.Errorf("peer %v not in netmap", k.ShortString())
	}); err != nil {
		t.Fatal(err)
	}
}

// testHost is a Unify on a chantun host TUN that the test drives as the
// host's kernel.
type testHost struct {
	t      *testing.T
	u      *Unify
	host   *chantun.Device
	router *fakeRouter
	dns    *fakeDNS
	bus    *eventbus.Bus
	done   chan struct{} // closed when drain returns

	closeOnce sync.Once

	replies chan []byte // echo replies the host received
	answer  atomic.Bool // whether to answer echo requests
	seq     atomic.Uint32

	mu       sync.Mutex
	requests [][2]netip.Addr     // source and destination of echo requests the host received
	ports    []router.PortUpdate // published on the host router's bus
}

// startUnify starts a Unify with state in stateDir: the primary and "b".
func startUnify(t *testing.T, stateDir string) *testHost {
	t.Helper()
	th := &testHost{
		t:       t,
		router:  &fakeRouter{events: &eventLog{}},
		dns:     &fakeDNS{DNS: osglue.NewDNS(nil), events: &eventLog{}},
		bus:     eventbus.New(),
		done:    make(chan struct{}),
		replies: make(chan []byte, 64),
	}
	ec := th.bus.Client("test.ports")
	eventbus.SubscribeFunc(ec, func(pu router.PortUpdate) {
		th.mu.Lock()
		defer th.mu.Unlock()
		th.ports = append(th.ports, pu)
	})
	var err error
	if th.host, err = chantun.New("unify0", 1280, 8, 256); err != nil {
		t.Fatal(err)
	}
	th.u, err = New(Options{
		Logf:       tstest.WhileTestRunningLogger(t),
		StateDir:   stateDir,
		Primary:    PrimaryOptions{Dir: stateDir},
		Tailnets:   []TailnetConfig{{Name: "b"}},
		HostTUN:    th.host,
		HostRouter: th.router,
		HostBus:    th.bus,
		HostDNS:    th.dns,
		LocalPrefixes: func() []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	go th.drain()
	t.Cleanup(th.close)
	if err := th.u.Start(); err != nil {
		t.Fatal(err)
	}
	return th
}

// close closes the Unify and waits for the drain goroutine. It is safe to
// call more than once.
func (th *testHost) close() {
	th.closeOnce.Do(func() {
		th.u.Close()
		<-th.done
		th.bus.Close()
	})
}

// drain plays the host's kernel: it reads everything the loop writes to
// the host, keeps echo replies and answers echo requests when asked to.
func (th *testHost) drain() {
	defer close(th.done)
	for {
		select {
		case <-th.host.Done():
			return
		case pkt := <-th.host.Packets():
			var q packet.Parsed
			q.Decode(pkt)
			switch {
			case q.IsEchoRequest():
				th.mu.Lock()
				th.requests = append(th.requests, [2]netip.Addr{q.Src.Addr(), q.Dst.Addr()})
				th.mu.Unlock()
				if th.answer.Load() {
					th.host.TryInject(echoReplyTo(&q))
				}
			case q.IsEchoResponse():
				select {
				case th.replies <- pkt:
				default:
				}
			}
		}
	}
}

// echoReplyTo returns the reply to the echo request q.
func echoReplyTo(q *packet.Parsed) []byte {
	if q.IPVersion == 4 {
		h := q.ICMP4Header()
		h.ToResponse()
		return packet.Generate(h, q.Payload())
	}
	h := q.ICMP6Header()
	h.ToResponse()
	return packet.Generate(h, q.Payload())
}

// echoRequest returns an ICMP echo request from src to dst with a unique
// identifier and sequence number. Its length is even: net/packet computes
// wrong ICMPv6 checksums for odd lengths.
func (th *testHost) echoRequest(src, dst netip.Addr) []byte {
	payload := make([]byte, 4, 16)
	binary.BigEndian.PutUint16(payload, 0x5ca1)
	binary.BigEndian.PutUint16(payload[2:], uint16(th.seq.Add(1)))
	payload = append(payload, "unify!"...)
	b := echoPkt(src, dst, payload)
	if !checksumsOK(th.t, b) {
		th.t.Fatalf("echo request %v -> %v has bad checksums", src, dst)
	}
	return b
}

// isReplyTo reports whether r is the echo reply to req.
func isReplyTo(r, req []byte) bool {
	var q, p packet.Parsed
	q.Decode(r)
	p.Decode(req)
	return q.IsEchoResponse() && q.Src.Addr() == p.Dst.Addr() && q.Dst.Addr() == p.Src.Addr() &&
		bytes.Equal(q.Payload(), p.Payload())
}

// echo sends an echo request from src to dst into the host TUN every
// 500 ms until its reply comes back, and returns the reply.
func (th *testHost) echo(ctx context.Context, src, dst netip.Addr) []byte {
	th.t.Helper()
	req := th.echoRequest(src, dst)
	deadline := time.After(integrationTimeout)
	for {
		if err := th.host.Inject(ctx, bytes.Clone(req)); err != nil {
			th.t.Fatalf("echo %v -> %v: %v", src, dst, err)
		}
		retry := time.After(500 * time.Millisecond)
	wait:
		for {
			select {
			case r := <-th.replies:
				if isReplyTo(r, req) {
					return r
				}
			case <-retry:
				break wait
			case <-deadline:
				th.t.Fatalf("no echo reply %v -> %v", dst, src)
			}
		}
	}
}

func (th *testHost) sawRequest(src, dst netip.Addr) bool {
	th.mu.Lock()
	defer th.mu.Unlock()
	return slices.Contains(th.requests, [2]netip.Addr{src, dst})
}

func (th *testHost) portUpdates() []router.PortUpdate {
	th.mu.Lock()
	defer th.mu.Unlock()
	return slices.Clone(th.ports)
}

// login starts tailnet name's backend against controlURL, as tailscale
// up would.
func (th *testHost) login(ctx context.Context, name, controlURL string) {
	th.t.Helper()
	lb := th.u.Stack(name).LocalBackend()
	prefs := ipn.NewPrefs()
	prefs.ControlURL = controlURL
	prefs.WantRunning = true
	prefs.Hostname = "unify-" + name
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs}); err != nil {
		th.t.Fatalf("Start(%s): %v", name, err)
	}
	if lb.State() == ipn.NeedsLogin {
		if err := lb.StartLoginInteractive(ctx); err != nil {
			th.t.Fatalf("StartLoginInteractive(%s): %v", name, err)
		}
	}
}

// running waits until tailnet name is Running with a peer, and returns
// its routing snapshot.
func (th *testHost) running(name string) ipnlocal.RoutingSnapshot {
	th.t.Helper()
	var snap ipnlocal.RoutingSnapshot
	if err := tstest.WaitFor(integrationTimeout, func() error {
		snap = th.u.Stack(name).LocalBackend().RoutingSnapshot()
		if snap.State != ipn.Running || len(snap.Self) == 0 || len(snap.Peers) == 0 {
			return fmt.Errorf("%s: %+v", name, snap)
		}
		return nil
	}); err != nil {
		th.t.Fatal(err)
	}
	return snap
}

// virtualOf waits until owner's real prefixes ps are mapped, and returns
// their unified-space prefixes.
func (th *testHost) virtualOf(owner remap.Owner, ps []netip.Prefix) []netip.Prefix {
	th.t.Helper()
	var out []netip.Prefix
	if err := tstest.WaitFor(integrationTimeout, func() error {
		out = out[:0]
		for _, p := range ps {
			v, ok := th.u.table.RealToVirtual(owner, p.Addr())
			if !ok {
				return fmt.Errorf("%s's %v is not mapped", owner, p)
			}
			out = append(out, netip.PrefixFrom(v, p.Bits()))
		}
		return nil
	}); err != nil {
		th.t.Fatal(err)
	}
	return out
}

// waitRouterConfig waits until the host router's last configuration has
// exactly these local addresses, routes and route sources.
func (th *testHost) waitRouterConfig(localAddrs, routes []netip.Prefix, sources map[netip.Prefix]netip.Addr) {
	th.t.Helper()
	var last *router.Config
	if err := tstest.WaitFor(integrationTimeout, func() error {
		last = th.router.last()
		if last == nil || !slices.Equal(last.LocalAddrs, localAddrs) || !slices.Equal(last.Routes, routes) ||
			!maps.Equal(last.RouteSources, sources) {
			return errors.New("not yet")
		}
		return nil
	}); err != nil {
		th.t.Fatalf("host router config %+v\nwant LocalAddrs %v\nRoutes %v\nRouteSources %v", last, localAddrs, routes, sources)
	}
}

func peerKey(t *testing.T, ctx context.Context, s *tsnet.Server) key.NodePublic {
	t.Helper()
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return st.Self.PublicKey
}

func first4(ps []netip.Prefix) netip.Addr {
	for _, p := range ps {
		if p.Addr().Is4() {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

func first6(ps []netip.Prefix) netip.Addr {
	for _, p := range ps {
		if p.Addr().Is6() {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

func TestIntegration(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	// Tests cannot set the socket mark (corp#4520).
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	logf := tstest.WhileTestRunningLogger(t)
	derpMap := runDERPAndSTUN(t, logf)
	urlA, urlB := startTestControl(t, derpMap, logf), startTestControl(t, derpMap, logf)
	peerA := startTestPeer(t, ctx, urlA, "peer-a")
	peerB := startTestPeer(t, ctx, urlB, "peer-b")

	stateDir := t.TempDir()
	th := startUnify(t, stateDir)
	// The primary first, so it keeps the colliding addresses.
	th.login(ctx, PrimaryName, urlA)
	snapA := th.running(PrimaryName)
	th.login(ctx, "b", urlB)
	snapB := th.running("b")

	if !slices.Equal(snapA.Self, snapB.Self) || !slices.Equal(snapA.Peers, snapB.Peers) {
		t.Fatalf("tailnets do not collide: A self %v peers %v, B self %v peers %v", snapA.Self, snapA.Peers, snapB.Self, snapB.Peers)
	}
	self4, peer4 := first4(snapA.Self), first4(snapA.Peers)
	if self4 != mpa("100.64.0.2") || peer4 != mpa("100.64.0.1") {
		t.Fatalf("self %v, peer %v; want 100.64.0.2 and 100.64.0.1 (registration order)", self4, peer4)
	}

	// The merged router configuration (item 4) also says the mappings
	// are in place: the primary's identity, b's remapped.
	vSelfA, vPeerA := th.virtualOf(PrimaryName, snapA.Self), th.virtualOf(PrimaryName, snapA.Peers)
	vSelfB, vPeerB := th.virtualOf("b", snapB.Self), th.virtualOf("b", snapB.Peers)
	if !slices.Equal(vSelfA, snapA.Self) || !slices.Equal(vPeerA, snapA.Peers) {
		t.Fatalf("primary remapped: self %v peers %v", vSelfA, vPeerA)
	}
	b4self, b4peer, b6self, b6peer := first4(vSelfB), first4(vPeerB), first6(vSelfB), first6(vPeerB)
	pool4 := remap.DefaultPool4
	if !pool4.Contains(b4self) || !pool4.Contains(b4peer) || !th.u.table.Pools()[1].Contains(b6self) {
		t.Fatalf("b not remapped: self %v peers %v", vSelfB, vPeerB)
	}
	wantAddrs := sortedPrefixes(vSelfA, vSelfB)
	wantRoutes := sortedPrefixes(vPeerA, vPeerB, quad100)
	// Each tailnet's peers prefer its virtual self of their family as
	// source (spec section 5, outbound step 1), quad-100 the primary's.
	wantSources := make(map[netip.Prefix]netip.Addr)
	for _, c := range []struct{ routes, self []netip.Prefix }{
		{vPeerA, vSelfA}, {vPeerB, vSelfB}, {quad100, vSelfA},
	} {
		for _, r := range c.routes {
			src := first6(c.self)
			if r.Addr().Is4() {
				src = first4(c.self)
			}
			wantSources[r] = src
		}
	}
	if wantSources[host32(b4peer)] != b4self || wantSources[host32(b6peer)] != b6self || len(wantSources) != 6 {
		t.Fatalf("expected sources %v", wantSources)
	}
	th.waitRouterConfig(wantAddrs, wantRoutes, wantSources)

	stA, stB := th.u.Stack(PrimaryName), th.u.Stack("b")
	if sts := th.u.Stacks(); len(sts) != 2 || sts[0] != stA || sts[1] != stB {
		t.Fatalf("Stacks = %v", sts)
	}
	waitHomeDERP(t, ctx, stA.Sys())
	waitHomeDERP(t, ctx, stB.Sys())
	waitPeerReachable(t, stA.LocalBackend(), peerKey(t, ctx, peerA))
	waitPeerReachable(t, stB.LocalBackend(), peerKey(t, ctx, peerB))

	t.Run("host to peers", func(t *testing.T) { // item 1
		for _, c := range []struct{ src, dst netip.Addr }{
			{self4, peer4},   // A, identity
			{b4self, b4peer}, // B, remapped
			{b6self, b6peer}, // B, remapped IPv6
		} {
			r := th.echo(ctx, c.src, c.dst)
			if !checksumsOK(t, r) {
				t.Errorf("echo reply %v -> %v: bad checksums", c.dst, c.src)
			}
		}
	})

	t.Run("isolation", func(t *testing.T) { // item 3
		// A's self may not reach B's peer, though both are virtual
		// addresses this host has.
		req := th.echoRequest(self4, b4peer)
		var q packet.Parsed
		q.Decode(bytes.Clone(req))
		if r := th.u.tr.Outbound(&q); r.Verdict != xlate.Drop || r.Reason != xlate.DropSourceNotAllowed {
			t.Fatalf("Outbound = %+v, want drop: source not allowed", r)
		}
		before := th.u.loop.stats()
		if err := th.host.Inject(ctx, bytes.Clone(req)); err != nil {
			t.Fatal(err)
		}
		if err := tstest.WaitFor(integrationTimeout, func() error {
			if th.u.loop.stats().outDropped == before.outDropped {
				return errors.New("not dropped yet")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if after := th.u.loop.stats(); after.toStack != before.toStack || after.icmpSent != before.icmpSent {
			t.Errorf("stats %+v after %+v: the packet reached a stack or was answered", after, before)
		}
		timeout := time.After(time.Second)
		for done := false; !done; {
			select {
			case r := <-th.replies:
				if isReplyTo(r, req) {
					t.Fatal("isolated echo was answered")
				}
			case <-timeout:
				done = true
			}
		}
	})

	t.Run("peers to host", func(t *testing.T) { // item 2
		th.answer.Store(true)
		defer th.answer.Store(false)
		for _, c := range []struct {
			peer       *tsnet.Server
			dst        netip.Addr // the stack's real self in the peer's tailnet
			vsrc, vdst netip.Addr // as the host sees them
		}{
			{peerA, self4, peer4, self4},
			{peerB, self4, b4peer, b4self},
		} {
			lc, err := c.peer.LocalClient()
			if err != nil {
				t.Fatal(err)
			}
			if err := tstest.WaitFor(integrationTimeout, func() error {
				pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
				defer pcancel()
				res, err := lc.Ping(pctx, c.dst, tailcfg.PingICMP)
				if err != nil {
					return err
				}
				if res.Err != "" {
					return errors.New(res.Err)
				}
				return nil
			}); err != nil {
				t.Fatalf("%s ping %v: %v", c.peer.Hostname, c.dst, err)
			}
			if !th.sawRequest(c.vsrc, c.vdst) {
				t.Errorf("host saw no echo request %v -> %v", c.vsrc, c.vdst)
			}
		}
	})

	t.Run("host configuration", func(t *testing.T) { // item 4, and R8/R10
		th.waitRouterConfig(wantAddrs, wantRoutes, wantSources)
		if err := tstest.WaitFor(integrationTimeout, func() error {
			if !slices.Contains(th.dns.Config().Nameservers, mpa("100.100.100.100")) {
				return fmt.Errorf("host DNS %+v", th.dns.Config())
			}
			return nil
		}); err != nil {
			t.Errorf("primary's DNS did not reach the host: %v", err)
		}
		portA := stA.Sys().MagicSock.Get().LocalPort()
		portB := stB.Sys().MagicSock.Get().LocalPort()
		ups := th.portUpdates()
		if !slices.Contains(ups, router.PortUpdate{UDPPort: portA, EndpointNetwork: "udp4"}) {
			t.Errorf("primary's port %d not published: %v", portA, ups)
		}
		for _, pu := range ups {
			if pu.UDPPort == portB {
				t.Errorf("b's port %d published: %v", portB, ups)
			}
		}
	})

	t.Run("restart", func(t *testing.T) { // item 5
		th.close()
		th = startUnify(t, stateDir) // the backends start from their saved state
		th.running(PrimaryName)
		th.running("b")
		th.waitRouterConfig(wantAddrs, wantRoutes, wantSources)
		for _, c := range []struct {
			name   string
			ps, vs []netip.Prefix
		}{
			{PrimaryName, snapA.Self, vSelfA}, {PrimaryName, snapA.Peers, vPeerA},
			{"b", snapB.Self, vSelfB}, {"b", snapB.Peers, vPeerB},
		} {
			if got := th.virtualOf(remap.Owner(c.name), c.ps); !slices.Equal(got, c.vs) {
				t.Errorf("%s: %v now at %v, was %v", c.name, c.ps, got, c.vs)
			}
		}
		th.echo(ctx, b4self, b4peer)
	})
}
