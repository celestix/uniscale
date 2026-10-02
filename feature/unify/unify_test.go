// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"errors"
	"fmt"
	"maps"
	"net"
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
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/osglue"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/stack"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
	"tailscale.com/types/logid"
	"tailscale.com/types/preftype"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

// eventLog records the order in which fakes are closed.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// fakeStack is a tailnetStack whose routing snapshot the test sets. Close
// closes its device, router and DNS configurator, as a stack's engine does.
type fakeStack struct {
	cfg    stack.Config
	events *eventLog

	mu       sync.Mutex
	snap     ipnlocal.RoutingSnapshot
	snaps    int // RoutingSnapshot calls
	observer func()
	starts   int
	startErr error
	closed   bool
}

func (f *fakeStack) RoutingSnapshot() ipnlocal.RoutingSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps++
	return f.snap
}

func (f *fakeStack) numSnaps() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snaps
}

func (f *fakeStack) SetRoutingObserver(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observer = fn
}

func (f *fakeStack) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	return f.startErr
}

func (f *fakeStack) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	f.cfg.Tun.Close()
	f.cfg.Router.Close()
	f.cfg.DNS.Close()
	f.events.add("stack " + f.cfg.Name)
	return nil
}

// set has the stack's engine record captured as its router configuration,
// then changes the routing snapshot and calls the observer, as
// LocalBackend does after a reconfiguration.
func (f *fakeStack) set(snap ipnlocal.RoutingSnapshot, captured *router.Config) {
	f.cfg.Router.Set(captured)
	f.mu.Lock()
	f.snap = snap
	obs := f.observer
	// Call observer while still holding lock, as LocalBackend calls it under b.mu.
	if obs != nil {
		obs()
	}
	f.mu.Unlock()
}

// notify calls the observer without changing anything.
func (f *fakeStack) notify() {
	f.mu.Lock()
	obs := f.observer
	f.mu.Unlock()
	obs()
}

func (f *fakeStack) dev() *chantun.Device { return f.cfg.Tun.(*chantun.Device) }

// fakeRouter is the host's router.
type fakeRouter struct {
	events *eventLog

	mu     sync.Mutex
	ups    int
	upErr  error
	setErr error
	sets   []*router.Config
	closes int
}

func (r *fakeRouter) Up() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ups++
	return r.upErr
}

func (r *fakeRouter) Set(cfg *router.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets = append(r.sets, cfg.Clone())
	return r.setErr
}

func (r *fakeRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes++
	r.events.add("router")
	return nil
}

func (r *fakeRouter) numSets() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sets)
}

func (r *fakeRouter) last() *router.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sets) == 0 {
		return nil
	}
	return r.sets[len(r.sets)-1].Clone()
}

func (r *fakeRouter) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setErr = err
}

// fakeDNS is the host's OS DNS configurator: a recording one that logs
// its Close.
type fakeDNS struct {
	*osglue.DNS
	events *eventLog
	closes atomic.Int32
}

func (d *fakeDNS) Close() error {
	d.closes.Add(1)
	d.events.add("dns")
	return d.DNS.Close()
}

// eventTUN is the host's TUN device, logging its Close.
type eventTUN struct {
	*chantun.Device
	events *eventLog
}

func (d eventTUN) Close() error {
	d.events.add("tun")
	return d.Device.Close()
}

// logBuffer collects log lines.
type logBuffer struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (b *logBuffer) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	b.mu.Lock()
	b.lines = append(b.lines, line)
	b.mu.Unlock()
	b.t.Log(line)
}

// count returns how many lines contain s.
func (b *logBuffer) count(s string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, l := range b.lines {
		if strings.Contains(l, s) {
			n++
		}
	}
	return n
}

// harness runs a Unify on fakes: a chantun host TUN, a fake router and
// DNS configurator, and fake stacks. The primary and "b" have the same
// real addresses:
//
//	self 100.64.0.2, fd7a:115c:a1e0::2; peer 100.64.0.1, fd7a:115c:a1e0::1
type harness struct {
	t      *testing.T
	opts   Options
	u      *Unify
	host   *chantun.Device // the test's side of the host TUN
	router *fakeRouter
	dns    *fakeDNS
	clock  *tstest.Clock
	events *eventLog
	logs   *logBuffer

	failBuild string // the stack New fails to build

	mu         sync.Mutex
	stacks     map[string]*fakeStack
	local      []netip.Prefix
	localCalls int
}

var (
	selfPfx = []netip.Prefix{mpp("100.64.0.2/32"), mpp("fd7a:115c:a1e0::2/128")}
	peerPfx = []netip.Prefix{mpp("100.64.0.1/32"), mpp("fd7a:115c:a1e0::1/128")}
	quad100 = []netip.Prefix{mpp("100.100.100.100/32"), mpp("fd7a:115c:a1e0::53/128")}
)

const testPool6 = "fd00:1::/48"

// newHarness builds a Unify with "b" as the only other tailnet. mod, if
// not nil, changes h.opts or h.failBuild first.
func newHarness(t *testing.T, mod func(h *harness)) (*harness, error) {
	t.Helper()
	h := &harness{
		t:      t,
		router: &fakeRouter{},
		clock:  tstest.NewClock(tstest.ClockOpts{Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}),
		events: &eventLog{},
		logs:   &logBuffer{t: t},
		stacks: map[string]*fakeStack{},
	}
	h.router.events = h.events
	h.dns = &fakeDNS{DNS: osglue.NewDNS(nil), events: h.events}
	h.host = newDev(t, "unify0", 64)
	stateDir := t.TempDir()
	h.opts = Options{
		Logf:     h.logs.logf,
		StateDir: stateDir,
		Primary: PrimaryOptions{
			Dir:        stateDir,
			Port:       41641,
			LogID:      logid.PublicID{1},
			SocketPath: filepath.Join(t.TempDir(), "tailscaled.sock"),
		},
		Tailnets:      []TailnetConfig{{Name: "b"}},
		HostTUN:       eventTUN{h.host, h.events},
		HostRouter:    h.router,
		HostDNS:       h.dns,
		Pool6:         mpp(testPool6),
		LocalPrefixes: h.localPrefixes,
		Clock:         h.clock,
	}
	if mod != nil {
		mod(h)
	}
	u, err := newUnify(h.opts, h.build)
	if err != nil {
		return h, err
	}
	u.settle = time.Millisecond
	h.u = u
	t.Cleanup(func() { u.Close() })
	return h, nil
}

func mustHarness(t *testing.T, mod func(h *harness)) *harness {
	t.Helper()
	h, err := newHarness(t, mod)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) build(cfg stack.Config) (tailnetStack, error) {
	if cfg.Name == h.failBuild {
		return nil, errors.New("build failed")
	}
	f := &fakeStack{cfg: cfg, events: h.events}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stacks[cfg.Name] = f
	return f, nil
}

func (h *harness) stack(name string) *fakeStack {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stacks[name]
}

func (h *harness) localPrefixes() []netip.Prefix {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.localCalls++
	return slices.Clone(h.local)
}

func (h *harness) setLocal(ps ...netip.Prefix) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.local = ps
}

func (h *harness) numLocalCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.localCalls
}

func (h *harness) start() {
	h.t.Helper()
	if err := h.u.Start(); err != nil {
		h.t.Fatal(err)
	}
}

// waitRouter waits until the host router's last configuration satisfies
// cond, and returns it.
func (h *harness) waitRouter(what string, cond func(*router.Config) bool) *router.Config {
	h.t.Helper()
	var last *router.Config
	if err := tstest.WaitFor(testTimeout, func() error {
		last = h.router.last()
		if last == nil || !cond(last) {
			return errors.New("not yet")
		}
		return nil
	}); err != nil {
		h.t.Fatalf("waiting for host router %s; last config %+v", what, last)
	}
	return last
}

// waitFor waits until cond holds.
func (h *harness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	if err := tstest.WaitFor(testTimeout, func() error {
		if !cond() {
			return errors.New("not yet")
		}
		return nil
	}); err != nil {
		h.t.Fatalf("waiting for %s", what)
	}
}

// virtual returns owner's virtual address for its real address a.
func (h *harness) virtual(owner remap.Owner, a netip.Addr) netip.Addr {
	h.t.Helper()
	v, ok := h.u.table.RealToVirtual(owner, a)
	if !ok {
		h.t.Fatalf("%s's %v is not mapped", owner, a)
	}
	return v
}

func hasAll(have []netip.Prefix, want ...netip.Prefix) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

func sortedPrefixes(ps ...[]netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		out = append(out, p...)
	}
	tsaddr.SortPrefixes(out)
	return out
}

func host32(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

// echoPkt returns an ICMP echo request from src to dst with payload (the
// identifier, sequence number and data).
func echoPkt(src, dst netip.Addr, payload []byte) []byte {
	typ := uint8(8)
	if src.Is6() {
		typ = 128
	}
	return icmpPkt(src.String(), dst.String(), typ, 0, payload)
}

// echoReq returns an echo request from src to dst. Its length is even:
// net/packet computes wrong ICMPv6 checksums for odd lengths.
func echoReq(src, dst netip.Addr) []byte {
	return echoPkt(src, dst, []byte{0, 1, 0, 2, 'h', 'i'})
}

func TestNewErrors(t *testing.T) {
	cases := []struct {
		name string
		mod  func(h *harness)
		want string
	}{
		{"no state dir", func(h *harness) { h.opts.StateDir = "" }, "StateDir"},
		{"no host TUN", func(h *harness) { h.opts.HostTUN = nil }, "HostTUN"},
		{"no host router", func(h *harness) { h.opts.HostRouter = nil }, "HostRouter"},
		{"invalid tailnet", func(h *harness) { h.opts.Tailnets = []TailnetConfig{{Name: "B"}} }, "invalid tailnet name"},
		{"reserved tailnet", func(h *harness) { h.opts.Tailnets = []TailnetConfig{{Name: PrimaryName}} }, "reserved"},
		{"duplicate tailnet", func(h *harness) { h.opts.Tailnets = []TailnetConfig{{Name: "b"}, {Name: "b"}} }, "duplicate"},
		{"port out of range", func(h *harness) { h.opts.Primary.Port = 65535 }, "out of range"},
		{"bad pool", func(h *harness) { h.opts.Pool4 = mpp("fd00::/64") }, "Pool4"},
		{"remap state unreadable", func(h *harness) {
			if err := os.MkdirAll(RemapPath(h.opts.StateDir), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "loading state"},
		{"primary stack fails", func(h *harness) { h.failBuild = PrimaryName }, `tailnet "default": build failed`},
		{"other stack fails", func(h *harness) { h.failBuild = "b" }, `tailnet "b": build failed`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tstest.ResourceCheck(t)
			h, err := newHarness(t, c.mod)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("New error = %v, want one containing %q", err, c.want)
			}
			// New owns the host's devices even when it fails.
			select {
			case <-h.host.Done():
				if h.opts.HostTUN == nil {
					t.Error("host TUN closed though not passed")
				}
			default:
				if h.opts.HostTUN != nil {
					t.Error("host TUN not closed")
				}
			}
			if want := btoi(h.opts.HostRouter != nil); h.router.closes != want {
				t.Errorf("host router closed %d times, want %d", h.router.closes, want)
			}
			if n := h.dns.closes.Load(); n != 1 {
				t.Errorf("host DNS closed %d times, want 1", n)
			}
			for name, f := range h.stacks {
				if !f.closed || !isClosed(f.dev()) {
					t.Errorf("stack %s built but not closed", name)
				}
			}
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isClosed(d *chantun.Device) bool {
	select {
	case <-d.Done():
		return true
	default:
		return false
	}
}

func TestStackConfigs(t *testing.T) {
	tstest.ResourceCheck(t)
	bus := eventbus.New()
	defer bus.Close()
	store := new(mem.Store)
	h := mustHarness(t, func(h *harness) {
		h.opts.Primary.Store = store
		h.opts.Primary.Ephemeral = true
		h.opts.HostBus = bus
		h.opts.Tailnets = []TailnetConfig{{Name: "b"}, {Name: "c", Port: 5000}}
	})
	p, b, c := h.stack(PrimaryName), h.stack("b"), h.stack("c")
	if p == nil || b == nil || c == nil {
		t.Fatalf("stacks built: %v", h.stacks)
	}
	if p.cfg.Name != PrimaryName || p.cfg.Dir != h.opts.Primary.Dir || p.cfg.Store != store || !p.cfg.Ephemeral ||
		p.cfg.Port != 41641 || p.cfg.LogID != h.opts.Primary.LogID || p.cfg.SocketPath != h.opts.Primary.SocketPath {
		t.Errorf("primary config = %+v", p.cfg)
	}
	sock := h.opts.Primary.SocketPath
	for _, x := range []struct {
		f    *fakeStack
		name string
		port uint16
	}{{b, "b", 41642}, {c, "c", 5000}} {
		cfg := x.f.cfg
		if cfg.Name != x.name || cfg.Dir != TailnetDir(h.opts.StateDir, x.name) || cfg.Store != nil || cfg.Ephemeral ||
			cfg.Port != x.port || cfg.LogID != (logid.PublicID{}) || cfg.SocketPath != TailnetSocket(sock, x.name) || cfg.OnPortUpdate != nil {
			t.Errorf("%s config = %+v", x.name, cfg)
		}
	}
	if p.cfg.OnPortUpdate == nil {
		t.Error("primary has no port update bridge")
	}
	if p.cfg.Logf == nil || b.cfg.Logf == nil {
		t.Error("stacks have no logger")
	}

	// Every stack has its own device and router stub.
	devs := map[any]bool{}
	for _, f := range []*fakeStack{p, b, c} {
		if _, ok := f.cfg.Router.(*osglue.Router); !ok {
			t.Errorf("%s router is %T", f.cfg.Name, f.cfg.Router)
		}
		if mtu, _ := f.dev().MTU(); mtu <= 0 {
			t.Errorf("%s device MTU %d", f.cfg.Name, mtu)
		}
		devs[f.cfg.Tun] = true
		devs[f.cfg.Router] = true
	}
	if len(devs) != 6 {
		t.Errorf("stacks share devices or routers")
	}

	// The primary's DNS goes through to the host's configurator; the
	// others' is only recorded.
	osCfg := dns.OSConfig{Nameservers: []netip.Addr{mpa("100.100.100.100")}}
	if err := p.cfg.DNS.SetDNS(osCfg); err != nil {
		t.Fatal(err)
	}
	if got := h.dns.Config(); !slices.Equal(got.Nameservers, osCfg.Nameservers) {
		t.Errorf("host DNS = %+v, want the primary's", got)
	}
	if err := b.cfg.DNS.SetDNS(dns.OSConfig{Nameservers: []netip.Addr{mpa("100.100.100.101")}}); err != nil {
		t.Fatal(err)
	}
	if got := h.dns.Config(); !slices.Equal(got.Nameservers, osCfg.Nameservers) {
		t.Errorf("host DNS = %+v after b's SetDNS, want the primary's", got)
	}
	if _, err := b.cfg.DNS.GetBaseConfig(); !errors.Is(err, dns.ErrGetBaseConfigNotSupported) {
		t.Errorf("b GetBaseConfig error = %v", err)
	}
}

func TestPrimaryDNSWithoutHostDNS(t *testing.T) {
	h := mustHarness(t, func(h *harness) { h.opts.HostDNS = nil })
	p := h.stack(PrimaryName)
	if err := p.cfg.DNS.SetDNS(dns.OSConfig{Nameservers: []netip.Addr{mpa("100.100.100.100")}}); err != nil {
		t.Fatal(err)
	}
	if got := p.cfg.DNS.(*osglue.DNS).Config(); len(got.Nameservers) != 1 {
		t.Errorf("primary DNS stub recorded %+v", got)
	}
	if h.dns.closes.Load() != 0 {
		t.Error("unused DNS configurator was closed")
	}
}

// R10: only the primary stack's magicsock port reaches the host router's
// bus.
func TestPortBridge(t *testing.T) {
	tstest.ResourceCheck(t)
	bus := eventbus.New()
	defer bus.Close()
	sub := eventbus.Subscribe[router.PortUpdate](bus.Client("test"))
	h := mustHarness(t, func(h *harness) { h.opts.HostBus = bus })
	want := router.PortUpdate{UDPPort: 41641, EndpointNetwork: "udp4"}
	h.stack(PrimaryName).cfg.OnPortUpdate(want)
	select {
	case got := <-sub.Events():
		if got != want {
			t.Fatalf("host bus got %+v, want %+v", got, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("port update not published on the host bus")
	}
	if h.stack("b").cfg.OnPortUpdate != nil {
		t.Error("b's port updates are bridged")
	}
	h.u.Close()
	// After Close, updates are dropped rather than published.
	h.stack(PrimaryName).cfg.OnPortUpdate(want)
	select {
	case got := <-sub.Events():
		t.Fatalf("host bus got %+v after Close", got)
	case <-time.After(50 * time.Millisecond):
	}

	h2 := mustHarness(t, nil)
	if h2.stack(PrimaryName).cfg.OnPortUpdate != nil {
		t.Error("port updates bridged without a host bus")
	}
}

func TestRouting(t *testing.T) {
	tstest.ResourceCheck(t)
	h := mustHarness(t, nil)
	p, b := h.stack(PrimaryName), h.stack("b")
	h.start()

	// Nothing running: the host router is brought up and emptied.
	h.waitRouter("emptied", func(c *router.Config) bool { return c.Equal(&router.Config{}) })
	if h.router.ups != 1 {
		t.Errorf("host router Up called %d times", h.router.ups)
	}
	if p.starts != 1 || b.starts != 1 {
		t.Errorf("backends started %d and %d times, want once each", p.starts, b.starts)
	}

	snap := running(selfPfx, peerPfx, nil)
	p.set(snap, &router.Config{LocalAddrs: selfPfx, NetfilterMode: preftype.NetfilterOn, NewMTU: 1280})
	h.waitRouter("primary routes", func(c *router.Config) bool {
		return slices.Equal(c.LocalAddrs, selfPfx) && hasAll(c.Routes, peerPfx...)
	})

	b.set(snap, &router.Config{LocalAddrs: selfPfx, NetfilterMode: preftype.NetfilterOff, SNATSubnetRoutes: true, NewMTU: 1400})
	cfg := h.waitRouter("b routes", func(c *router.Config) bool { return len(c.LocalAddrs) == 4 })
	b4self, b4peer := h.virtual("b", mpa("100.64.0.2")), h.virtual("b", mpa("100.64.0.1"))
	b6self, b6peer := h.virtual("b", mpa("fd7a:115c:a1e0::2")), h.virtual("b", mpa("fd7a:115c:a1e0::1"))
	if !mpp("198.18.0.0/15").Contains(b4self) || !mpp(testPool6).Contains(b6self) {
		t.Fatalf("b's self is not remapped: %v %v", b4self, b6self)
	}
	self4, self6 := mpa("100.64.0.2"), mpa("fd7a:115c:a1e0::2")
	want := &router.Config{
		LocalAddrs: sortedPrefixes(selfPfx, []netip.Prefix{host32(b4self), host32(b6self)}),
		Routes:     sortedPrefixes(peerPfx, quad100, []netip.Prefix{host32(b4peer), host32(b6peer)}),
		// Each tailnet's routes prefer its own address; quad-100 the
		// primary's.
		RouteSources: map[netip.Prefix]netip.Addr{
			mpp("100.64.0.1/32"):          self4,
			mpp("fd7a:115c:a1e0::1/128"):  self6,
			host32(b4peer):                b4self,
			host32(b6peer):                b6self,
			mpp("100.100.100.100/32"):     self4,
			mpp("fd7a:115c:a1e0::53/128"): self6,
		},
		NewMTU:           1280,
		SNATSubnetRoutes: true,
		NetfilterMode:    preftype.NetfilterOn,
	}
	if !cfg.Equal(want) {
		t.Fatalf("host router config\n got %+v\nwant %+v", cfg, want)
	}

	// The loop translates for both stacks: host to b and back.
	h.host.Inject(t.Context(), echoReq(b4self, b4peer))
	got := readOne(t, b.dev())
	wantAddrs(t, got, mpa("100.64.0.2"), mpa("100.64.0.1"))
	if _, err := b.dev().Write([][]byte{echoReq(mpa("fd7a:115c:a1e0::1"), mpa("fd7a:115c:a1e0::2"))}, 0); err != nil {
		t.Fatal(err)
	}
	wantAddrs(t, nextHostPacket(t, h.host), b6peer, b6self)
	// Quad-100 goes to the primary.
	h.host.Inject(t.Context(), udpPkt(ap(mpa("100.64.0.2"), 5353), "100.100.100.100:53", []byte("q")))
	wantAddrs(t, readOne(t, p.dev()), mpa("100.64.0.2"), mpa("100.100.100.100"))

	// b stops: its routes go, its mappings stay.
	b.set(ipnlocal.RoutingSnapshot{State: ipn.Stopped}, &router.Config{})
	h.waitRouter("b gone", func(c *router.Config) bool { return slices.Equal(c.LocalAddrs, selfPfx) })
	if v := h.virtual("b", mpa("100.64.0.2")); v != b4self {
		t.Errorf("b's mapping changed to %v", v)
	}
	var q packet.Parsed
	q.Decode(echoReq(b4self, b4peer))
	if r := h.u.tr.Outbound(&q); r.Verdict != xlate.Drop {
		t.Errorf("traffic to stopped b: %+v", r)
	}

	// The primary stops: no quad-100 owner, empty router.
	p.set(ipnlocal.RoutingSnapshot{State: ipn.NeedsLogin}, &router.Config{})
	h.waitRouter("emptied again", func(c *router.Config) bool { return c.Equal(&router.Config{}) })
	q.Decode(udpPkt(ap(mpa("100.64.0.2"), 5353), "100.100.100.100:53", []byte("q")))
	if r := h.u.tr.Outbound(&q); r.Verdict != xlate.Drop || r.Reason != xlate.DropNoRoute {
		t.Errorf("quad-100 without a running primary: %+v", r)
	}

	// b alone serves no quad-100, but keeps its virtual addresses.
	b.set(snap, nil)
	cfg = h.waitRouter("b alone", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })
	if !slices.Equal(cfg.LocalAddrs, sortedPrefixes([]netip.Prefix{host32(b4self), host32(b6self)})) {
		t.Errorf("b alone: LocalAddrs %v", cfg.LocalAddrs)
	}
	// Quad-100 is still routed to the TUN, without a source: no tailnet
	// serves it.
	wantSrc := map[netip.Prefix]netip.Addr{host32(b4peer): b4self, host32(b6peer): b6self}
	if !maps.Equal(cfg.RouteSources, wantSrc) {
		t.Errorf("b alone: RouteSources %v, want %v", cfg.RouteSources, wantSrc)
	}
	q.Decode(udpPkt(ap(b4self, 5353), "100.100.100.100:53", []byte("q")))
	if r := h.u.tr.Outbound(&q); r.Verdict != xlate.Drop {
		t.Errorf("quad-100 through b: %+v", r)
	}
}

// R5: a subnet this node advertises to the same tailnet is neither
// mapped nor routed to it.
func TestOwnAdvertisedSubnetSkipped(t *testing.T) {
	h := mustHarness(t, nil)
	h.start()
	snap := running(selfPfx, peerPfx, prefixes("192.168.7.0/24", "10.9.0.0/16"))
	snap.Advertised = prefixes("192.168.7.0/24")
	h.stack(PrimaryName).set(snap, nil)
	cfg := h.waitRouter("subnet", func(c *router.Config) bool { return hasAll(c.Routes, mpp("10.9.0.0/16")) })
	if slices.Contains(cfg.Routes, mpp("192.168.7.0/24")) {
		t.Errorf("own advertised subnet routed: %v", cfg.Routes)
	}
	for _, m := range h.u.table.Mappings() {
		if m.Real == mpp("192.168.7.0/24") {
			t.Errorf("own advertised subnet mapped: %v", m)
		}
	}
}

func TestReconcileCoalesces(t *testing.T) {
	h := mustHarness(t, nil)
	h.u.settle = 50 * time.Millisecond
	h.start()
	h.waitRouter("emptied", func(c *router.Config) bool { return c.Equal(&router.Config{}) })
	p := h.stack(PrimaryName)
	start := h.router.numSets()
	for i := range 50 {
		peers := append(slices.Clone(peerPfx), netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 1, byte(i)}), 32))
		p.set(running(selfPfx, peers, nil), nil)
	}
	h.waitRouter("last peer", func(c *router.Config) bool { return slices.Contains(c.Routes, mpp("100.64.1.49/32")) })
	if n := h.router.numSets() - start; n > 5 {
		t.Errorf("50 changes in a burst took %d host router updates", n)
	}

	// A signal without a change does not touch the host router.
	n, snaps := h.router.numSets(), p.numSnaps()
	p.notify()
	h.waitFor("reconcile", func() bool { return p.numSnaps() > snaps })
	h.u.Close()
	if got := h.router.numSets(); got != n {
		t.Errorf("unchanged configuration set again (%d -> %d)", n, got)
	}
}

// Close stops a worker waiting out the settle delay.
func TestCloseWhileSettling(t *testing.T) {
	tstest.ResourceCheck(t)
	h := mustHarness(t, nil)
	h.u.settle = time.Hour
	h.start()
	h.stack(PrimaryName).notify()
	time.Sleep(10 * time.Millisecond)
	done := make(chan error)
	go func() { done <- h.u.Close() }()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Close blocked on a settling worker")
	}
	if n := h.router.numSets(); n != 0 {
		t.Errorf("host router set %d times", n)
	}
}

// R6: only the first running tailnet's exit node is used.
func TestExitExclusive(t *testing.T) {
	h := mustHarness(t, nil)
	h.start()
	snap := running(selfPfx, peerPfx, nil)
	snap.UsesExit = true
	captured := &router.Config{LocalRoutes: prefixes("192.168.1.0/24")}
	h.stack("b").set(snap, captured)
	cfg := h.waitRouter("b's exit", func(c *router.Config) bool { return hasAll(c.Routes, tsaddr.AllIPv4(), tsaddr.AllIPv6()) })
	// Internet traffic leaves from b's address in its tailnet.
	b4self, b6self := h.virtual("b", mpa("100.64.0.2")), h.virtual("b", mpa("fd7a:115c:a1e0::2"))
	if got4, got6 := cfg.RouteSources[tsaddr.AllIPv4()], cfg.RouteSources[tsaddr.AllIPv6()]; got4 != b4self || got6 != b6self {
		t.Errorf("exit route sources %v, %v; want b's %v, %v", got4, got6, b4self, b6self)
	}
	h.stack(PrimaryName).set(snap, nil)
	h.waitFor("warning", func() bool { return h.logs.count(`ignoring the exit node of [b]`) == 1 })
	cfg = h.waitRouter("primary's exit", func(c *router.Config) bool { return len(c.LocalAddrs) == 4 })
	if len(cfg.LocalRoutes) != 0 {
		t.Errorf("LocalRoutes = %v, want the primary's (none)", cfg.LocalRoutes)
	}
	// b mapped first here, so the primary's self is the remapped one.
	if got, want := cfg.RouteSources[tsaddr.AllIPv4()], h.virtual(PrimaryName, mpa("100.64.0.2")); got != want {
		t.Errorf("exit route source %v, want the primary's %v", got, want)
	}
	// The warning is not repeated while nothing changes.
	h.stack(PrimaryName).set(snap, &router.Config{NewMTU: 1280})
	h.waitRouter("mtu", func(c *router.Config) bool { return c.NewMTU == 1280 })
	if n := h.logs.count("ignoring the exit node"); n != 1 {
		t.Errorf("exit warning logged %d times", n)
	}
	// b's exit is used again once the primary stops using one.
	snap.UsesExit = false
	h.stack(PrimaryName).set(snap, nil)
	h.waitRouter("b's LocalRoutes", func(c *router.Config) bool { return slices.Equal(c.LocalRoutes, captured.LocalRoutes) })
}

// C1: while one tailnet uses an exit node, this node is no other tailnet's
// exit node, as stock tailscaled refuses to both offer and use one.
// Otherwise b's exit clients' internet traffic would reach the host, be
// routed into the primary's exit node and leave as this node of the
// primary's tailnet.
func TestExitOfferExclusive(t *testing.T) {
	h := mustHarness(t, nil)
	h.start()
	p, b := h.stack(PrimaryName), h.stack("b")
	offer := running(selfPfx, peerPfx, nil)
	offer.OffersExit = true
	b.set(offer, nil)
	h.waitRouter("b's routes", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })

	// b's exit client, its peer, sends a packet to the internet.
	bPeer := mpa("100.64.0.1") // b synced first: identity mapped
	internet := mpa("8.8.8.8")
	inbound := func() xlate.Result {
		var q packet.Parsed
		q.Decode(echoReq(bPeer, internet))
		return h.u.tr.Inbound("b", &q)
	}
	if r := inbound(); r.Verdict != xlate.ToHost {
		t.Fatalf("b's exit client to the internet, no exit in use: %+v, want to-host", r)
	}

	// The primary uses an exit node: b's exit clients fail closed.
	use := running(selfPfx, peerPfx, nil)
	use.UsesExit = true
	p.set(use, nil)
	h.waitRouter("primary's exit", func(c *router.Config) bool { return hasAll(c.Routes, tsaddr.AllIPv4(), tsaddr.AllIPv6()) })
	if r := inbound(); r.Verdict != xlate.Drop || r.Reason != xlate.DropDestinationNotReachable {
		t.Fatalf("b's exit client to the internet, primary using an exit: %+v, want drop: %v", r, xlate.DropDestinationNotReachable)
	}
	// Through the loop too: the packet from b's stack never reaches the
	// host.
	before := h.u.loop.stats()
	if _, err := b.dev().Write([][]byte{echoReq(bPeer, internet)}, 0); err != nil {
		t.Fatal(err)
	}
	h.waitFor("inbound drop", func() bool { return h.u.loop.stats().inDropped > before.inDropped })
	if after := h.u.loop.stats(); after.toHost != before.toHost {
		t.Errorf("b's exit client reached the host: stats %+v after %+v", after, before)
	}
	h.waitFor("warning", func() bool { return h.logs.count(`not offering this node as an exit node in [b]`) == 1 })

	// The warning is not repeated while nothing changes.
	p.set(use, &router.Config{NewMTU: 1280})
	h.waitRouter("mtu", func(c *router.Config) bool { return c.NewMTU == 1280 })
	if n := h.logs.count("not offering this node as an exit node"); n != 1 {
		t.Errorf("offer warning logged %d times", n)
	}

	// b is an exit node again once the primary stops using one.
	use.UsesExit = false
	p.set(use, nil)
	h.waitFor("b's offer back", func() bool { return inbound().Verdict == xlate.ToHost })
}

func TestHostRouterSetError(t *testing.T) {
	h := mustHarness(t, nil)
	h.router.setError(errors.New("netlink exploded"))
	h.start()
	h.waitFor("error logged", func() bool { return h.logs.count("netlink exploded") == 1 })
	// The same configuration is tried again on the next change signal.
	h.router.setError(nil)
	h.stack(PrimaryName).notify()
	h.waitFor("retry", func() bool { return h.router.numSets() == 2 })
	p := h.stack(PrimaryName)
	snaps := p.numSnaps()
	p.notify()
	h.waitFor("reconcile", func() bool { return p.numSnaps() > snaps })
	h.u.Close()
	if n := h.router.numSets(); n != 2 {
		t.Errorf("host router set %d times, want 2", n)
	}
}

func TestStartErrors(t *testing.T) {
	t.Run("router up fails", func(t *testing.T) {
		h := mustHarness(t, nil)
		h.router.upErr = errors.New("no tun")
		if err := h.u.Start(); err == nil || !strings.Contains(err.Error(), "no tun") {
			t.Fatalf("Start = %v", err)
		}
		if h.stack(PrimaryName).starts != 0 {
			t.Error("backend started after the router failed")
		}
	})
	t.Run("link up hook skipped when the router fails", func(t *testing.T) {
		h := mustHarness(t, func(h *harness) {
			h.opts.HostLinkUp = func(tun.Device) { t.Error("HostLinkUp called") }
		})
		h.router.upErr = errors.New("no tun")
		if err := h.u.Start(); err == nil {
			t.Fatal("Start succeeded")
		}
	})
	t.Run("backend start fails", func(t *testing.T) {
		h := mustHarness(t, nil)
		h.stack("b").startErr = errors.New("bad prefs")
		if err := h.u.Start(); err == nil || !strings.Contains(err.Error(), `tailnet "b": bad prefs`) {
			t.Fatalf("Start = %v", err)
		}
	})
	t.Run("twice", func(t *testing.T) {
		h := mustHarness(t, nil)
		h.start()
		if err := h.u.Start(); err == nil {
			t.Fatal("second Start succeeded")
		}
	})
	t.Run("after close", func(t *testing.T) {
		h := mustHarness(t, nil)
		h.u.Close()
		if err := h.u.Start(); err == nil {
			t.Fatal("Start after Close succeeded")
		}
	})
}

// R14: local networks are read at start and after link changes.
func TestLocalNetworks(t *testing.T) {
	h := mustHarness(t, nil)
	h.setLocal(mpp("10.10.0.0/16"), netip.Prefix{})
	h.start()
	if n := h.numLocalCalls(); n != 1 {
		t.Fatalf("LocalPrefixes called %d times at Start", n)
	}
	// A subnet the host is on is remapped, not used as is.
	h.stack(PrimaryName).set(running(selfPfx, peerPfx, prefixes("10.10.0.0/16", "10.20.0.0/16")), nil)
	h.waitRouter("subnets", func(c *router.Config) bool { return hasAll(c.Routes, mpp("10.20.0.0/16")) })
	for _, m := range h.u.table.Mappings() {
		if m.Real == mpp("10.10.0.0/16") && !m.Remapped() {
			t.Errorf("local network mapped as is: %v", m)
		}
	}

	// A new local network that an existing identity mapping uses is
	// reported.
	h.setLocal(mpp("10.10.0.0/16"), mpp("10.20.0.0/24"))
	h.u.linkChange()
	h.waitFor("conflict", func() bool { return h.logs.count("overlaps local network 10.20.0.0/24") == 1 })

	// An unchanged set of local networks is not applied again.
	h.u.linkChange()
	h.waitFor("second read", func() bool { return h.numLocalCalls() == 3 })
	h.u.Close()
	if n := h.logs.count("overlaps local network"); n != 1 {
		t.Errorf("conflict logged %d times", n)
	}
}

func TestLocalNetworksFromNetMon(t *testing.T) {
	tstest.ResourceCheck(t)
	bus := eventbus.New()
	defer bus.Close()
	nm, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer nm.Close()
	nm.Start()

	h := mustHarness(t, func(h *harness) { h.opts.NetMon = nm })
	h.start()
	h.waitFor("initial read", func() bool { return h.numLocalCalls() == 1 })
	nm.InjectEvent()
	h.waitFor("read after a link change", func() bool { return h.numLocalCalls() >= 2 })
	h.u.Close()
	// After Close, link changes are not followed.
	n := h.numLocalCalls()
	nm.InjectEvent()
	time.Sleep(100 * time.Millisecond)
	if got := h.numLocalCalls(); got != n {
		t.Errorf("LocalPrefixes called after Close")
	}

	// Without LocalPrefixes, the monitor's interfaces are used.
	h2 := mustHarness(t, func(h *harness) { h.opts.NetMon = nm; h.opts.LocalPrefixes = nil })
	if got, want := h2.u.localPrefixes(), interfacePrefixes(nm.InterfaceState(), "unify0"); !slices.Equal(got, want) {
		t.Errorf("local prefixes = %v, want %v", got, want)
	}
	h3 := mustHarness(t, func(h *harness) { h.opts.LocalPrefixes = nil })
	if h3.u.localPrefixes != nil {
		t.Error("local prefixes without a source")
	}
	h3.start()
}

func TestInterfacePrefixes(t *testing.T) {
	iface := func(name string, flags net.Flags) netmon.Interface {
		return netmon.Interface{Interface: &net.Interface{Name: name, Flags: flags}}
	}
	st := &netmon.State{
		InterfaceIPs: map[string][]netip.Prefix{
			"eth0":    prefixes("192.168.1.10/24", "fe80::1/64", "2001:db8::5/64"),
			"lo":      prefixes("127.0.0.1/8", "::1/128"),
			"unify0":  prefixes("100.64.0.2/32", "198.18.0.0/32"),
			"docker0": prefixes("172.17.0.1/16"),
			"wlan0":   prefixes("192.168.1.11/24"),
			"gone":    prefixes("10.1.2.3/8"),
		},
		Interface: map[string]netmon.Interface{
			"eth0":    iface("eth0", net.FlagUp),
			"lo":      iface("lo", net.FlagUp|net.FlagLoopback),
			"unify0":  iface("unify0", net.FlagUp),
			"docker0": iface("docker0", 0),
			"wlan0":   iface("wlan0", net.FlagUp),
		},
	}
	want := prefixes("10.0.0.0/8", "172.17.0.0/16", "192.168.1.0/24", "2001:db8::/64", "fe80::/64")
	tsaddr.SortPrefixes(want)
	if got := interfacePrefixes(st, "unify0"); !slices.Equal(got, want) {
		t.Errorf("interfacePrefixes = %v, want %v", got, want)
	}
	if got := interfacePrefixes(nil, "unify0"); got != nil {
		t.Errorf("interfacePrefixes(nil) = %v", got)
	}
}

// R15: Expire runs hourly, right after every running stack has synced,
// so only the mappings of tailnets that stay away expire.
func TestExpire(t *testing.T) {
	h := mustHarness(t, nil)
	h.start()
	snap := running(selfPfx, peerPfx, nil)
	h.stack(PrimaryName).set(snap, nil)
	h.stack("b").set(snap, nil)
	h.waitRouter("both", func(c *router.Config) bool { return len(c.LocalAddrs) == 4 })
	h.stack("b").set(ipnlocal.RoutingSnapshot{State: ipn.Stopped}, nil)
	h.waitRouter("b stopped", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })

	owners := func() map[remap.Owner]int {
		m := map[remap.Owner]int{}
		for _, x := range h.u.table.Mappings() {
			m[x.Owner]++
		}
		return m
	}
	// An hour on, nothing is old enough.
	h.clock.Advance(expireInterval)
	h.waitFor("hourly sync", func() bool {
		for _, m := range h.u.table.Mappings() {
			if m.Owner == PrimaryName && m.LastSeen.Equal(h.clock.PeekNow()) {
				return true
			}
		}
		return false
	})
	if got := owners(); got[PrimaryName] != 4 || got["b"] != 4 {
		t.Fatalf("mappings after an hour: %v", got)
	}
	// Past the GC interval, b's go and the primary's, synced just
	// before, stay.
	h.clock.Advance(remap.DefaultGCAfter)
	h.waitFor("b expired", func() bool { return owners()["b"] == 0 })
	if got := owners(); got[PrimaryName] != 4 {
		t.Fatalf("mappings after expiry: %v", got)
	}
	h.waitFor("logged", func() bool { return h.logs.count("released unused mappings") == 1 })
	// The release is saved.
	b, err := os.ReadFile(RemapPath(h.opts.StateDir))
	if err != nil || !strings.Contains(string(b), `"quarantine"`) {
		t.Errorf("saved remap state: %s, %v", b, err)
	}
}

// Mappings survive a restart: whichever tailnet syncs first afterwards,
// both keep their virtual addresses.
func TestRemapPersisted(t *testing.T) {
	h := mustHarness(t, nil)
	h.start()
	snap := running(selfPfx, peerPfx, nil)
	h.stack(PrimaryName).set(snap, nil)
	h.waitRouter("primary", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })
	h.stack("b").set(snap, nil)
	before := h.waitRouter("both", func(c *router.Config) bool { return len(c.LocalAddrs) == 4 })

	// Record virtual addresses for each tailnet before restart.
	primarySelfBefore := h.virtual(remap.Owner(PrimaryName), mpa("100.64.0.1"))
	primaryPeerBefore := h.virtual(remap.Owner(PrimaryName), mpa("100.64.0.2"))
	bSelfBefore := h.virtual(remap.Owner("b"), mpa("100.64.0.1"))
	bPeerBefore := h.virtual(remap.Owner("b"), mpa("100.64.0.2"))
	h.u.Close()

	h2 := mustHarness(t, func(h2 *harness) { h2.opts.StateDir = h.opts.StateDir; h2.opts.Pool6 = netip.Prefix{} })
	h2.start()
	h2.stack("b").set(snap, nil) // b first this time
	h2.waitRouter("b", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })
	h2.stack(PrimaryName).set(snap, nil)
	after := h2.waitRouter("both", func(c *router.Config) bool { return len(c.LocalAddrs) == 4 })
	if !after.Equal(before) {
		t.Errorf("after restart\n got %+v\nwant %+v", after, before)
	}

	// Verify virtual addresses are unchanged for each tailnet.
	if got := h2.virtual(remap.Owner(PrimaryName), mpa("100.64.0.1")); got != primarySelfBefore {
		t.Errorf("primary self: got %v, want %v", got, primarySelfBefore)
	}
	if got := h2.virtual(remap.Owner(PrimaryName), mpa("100.64.0.2")); got != primaryPeerBefore {
		t.Errorf("primary peer: got %v, want %v", got, primaryPeerBefore)
	}
	if got := h2.virtual(remap.Owner("b"), mpa("100.64.0.1")); got != bSelfBefore {
		t.Errorf("b self: got %v, want %v", got, bSelfBefore)
	}
	if got := h2.virtual(remap.Owner("b"), mpa("100.64.0.2")); got != bPeerBefore {
		t.Errorf("b peer: got %v, want %v", got, bPeerBefore)
	}
}

func TestRemapLoadErrorLogged(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(RemapPath(stateDir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(RemapPath(stateDir), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := mustHarness(t, func(h *harness) { h.opts.StateDir = stateDir })
	if h.logs.count("discarded saved state") != 1 {
		t.Error("discarded remap state not logged")
	}
}

func TestCloseOrder(t *testing.T) {
	tstest.ResourceCheck(t)
	h := mustHarness(t, nil)
	h.start()
	h.waitRouter("emptied", func(c *router.Config) bool { return c.Equal(&router.Config{}) })
	if err := h.u.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"stack " + PrimaryName, "stack b", "router", "dns", "tun"}
	if got := h.events.get(); !slices.Equal(got, want) {
		t.Errorf("close order %q, want %q", got, want)
	}
	if err := h.u.Close(); err != nil {
		t.Fatal(err)
	}
	if got := h.events.get(); len(got) != len(want) {
		t.Errorf("second Close closed more: %q", got)
	}
	// Observers firing during and after Close do not block.
	h.stack(PrimaryName).notify()
	h.stack(PrimaryName).notify()

	// Close without Start.
	h2 := mustHarness(t, nil)
	if err := h2.u.Close(); err != nil {
		t.Fatal(err)
	}
	if got := h2.events.get(); !slices.Equal(got, want) {
		t.Errorf("close order without Start %q, want %q", got, want)
	}
}

func TestCloseErrors(t *testing.T) {
	h := mustHarness(t, func(h *harness) { h.opts.HostDNS = errDNS{} })
	if err := h.u.Close(); err == nil || !strings.Contains(err.Error(), "dns close failed") {
		t.Fatalf("Close = %v", err)
	}
}

type errDNS struct{ dns.OSConfigurator }

func (errDNS) Close() error { return errors.New("dns close failed") }

func TestDoneAndErr(t *testing.T) {
	h := mustHarness(t, nil)
	h.start()
	if h.u.Err() != nil {
		t.Fatal("Err before failure")
	}
	h.host.Close() // the host TUN fails underneath
	select {
	case <-h.u.Done():
	case <-time.After(testTimeout):
		t.Fatal("Done not closed")
	}
	if err := h.u.Err(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Err = %v", err)
	}
}

func TestAccessorsWithoutLiveStacks(t *testing.T) {
	h := mustHarness(t, nil)
	if st := h.u.Stack(PrimaryName); st != nil {
		t.Errorf("Stack = %v", st)
	}
	if st := h.u.Stack("nope"); st != nil {
		t.Errorf("Stack(nope) = %v", st)
	}
	if sts := h.u.Stacks(); len(sts) != 0 {
		t.Errorf("Stacks = %v", sts)
	}
	if st, err := newLiveStack(stack.Config{}); err == nil || st != nil {
		t.Errorf("newLiveStack with an empty config = %v, %v", st, err)
	}
}

// readOne returns the next packet the loop injected into dev.
func readOne(t *testing.T, dev *chantun.Device) []byte {
	t.Helper()
	type result struct {
		p   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		slab := make([]byte, 1<<17)
		pkts := make([]tun.ReadPacket, 1)
		n, err := dev.Read(slab, pkts)
		if n == 0 {
			ch <- result{err: err}
			return
		}
		ch <- result{p: slices.Clone(slab[pkts[0].Offset : pkts[0].Offset+pkts[0].Size])}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("reading the stack's device: %v", r.err)
		}
		return r.p
	case <-time.After(testTimeout):
		t.Fatal("no packet reached the stack") // the reader exits when dev is closed
		return nil
	}
}

// nextHostPacket returns the next packet the loop wrote to the host.
func nextHostPacket(t *testing.T, host *chantun.Device) []byte {
	t.Helper()
	select {
	case p := <-host.Packets():
		return p
	case <-time.After(testTimeout):
		t.Fatal("no packet reached the host")
		return nil
	}
}

func TestDefaults(t *testing.T) {
	tstest.ResourceCheck(t)
	h := mustHarness(t, func(h *harness) { h.opts.Logf = nil; h.opts.Clock = nil })
	if h.u.clock == nil {
		t.Fatal("no clock")
	}
	// Link changes before the worker runs are coalesced, not blocking.
	h.u.linkChange()
	h.u.linkChange()
	h.start()
	h.waitRouter("emptied", func(c *router.Config) bool { return c.Equal(&router.Config{}) })
}

// A full remap pool leaves addresses unreachable from the host; the rest
// of the tailnet still works.
func TestRemapPoolFull(t *testing.T) {
	h := mustHarness(t, func(h *harness) {
		h.opts.Pool4 = mpp("198.18.0.0/32")
		h.opts.Pool6 = mpp("fd00:1::/128")
	})
	h.start()
	snap := running(selfPfx, peerPfx, nil)
	h.stack(PrimaryName).set(snap, nil)
	h.waitRouter("primary", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })
	h.stack("b").set(snap, nil)
	cfg := h.waitRouter("b's self", func(c *router.Config) bool { return len(c.LocalAddrs) == 4 })
	if want := sortedPrefixes(selfPfx, prefixes("198.18.0.0/32", "fd00:1::/128")); !slices.Equal(cfg.LocalAddrs, want) {
		t.Errorf("LocalAddrs %v, want %v", cfg.LocalAddrs, want)
	}
	if want := sortedPrefixes(peerPfx, quad100); !slices.Equal(cfg.Routes, want) {
		t.Errorf("Routes %v, want the primary's peers and quad-100 only: %v", cfg.Routes, want)
	}
	h.waitFor("pool full logged", func() bool { return h.logs.count(`"b": remap pool full`) == 1 })
}

// Failing to save the remap table is logged; the table keeps working in
// memory.
func TestRemapSaveErrors(t *testing.T) {
	h := mustHarness(t, nil)
	if err := os.MkdirAll(RemapPath(h.opts.StateDir), 0o700); err != nil {
		t.Fatal(err)
	}
	h.start()
	p := h.stack(PrimaryName)
	p.set(running(selfPfx, peerPfx, nil), nil)
	h.waitRouter("primary", func(c *router.Config) bool { return len(c.LocalAddrs) == 2 })
	h.waitFor("sync save error", func() bool { return h.logs.count(`tailnet "default": remap: saving state`) == 1 })
	p.set(ipnlocal.RoutingSnapshot{State: ipn.Stopped}, nil)
	h.waitRouter("stopped", func(c *router.Config) bool { return len(c.LocalAddrs) == 0 })
	h.clock.Advance(remap.DefaultGCAfter + expireInterval)
	h.waitFor("expire save error", func() bool { return h.logs.count("unify: remap: saving state") == 1 })
	if n := len(h.u.table.Mappings()); n != 0 {
		t.Errorf("%d mappings left in memory", n)
	}
}

// TestStartHostLinkUp checks that Start calls Options.HostLinkUp once, with
// the host TUN, after the host router is up and before any stack starts.
func TestStartHostLinkUp(t *testing.T) {
	var calls []string
	h := mustHarness(t, func(h2 *harness) {
		h2.opts.HostLinkUp = func(dev tun.Device) {
			if d, ok := dev.(eventTUN); !ok || d.Device != h2.host {
				t.Errorf("HostLinkUp(%v), want the host TUN", dev)
			}
			h2.router.mu.Lock()
			ups := h2.router.ups
			h2.router.mu.Unlock()
			calls = append(calls, fmt.Sprintf("linkUp ups=%d starts=%d", ups, h2.stack(PrimaryName).starts))
		}
	})
	if err := h.u.Start(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"linkUp ups=1 starts=0"}; !slices.Equal(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}
