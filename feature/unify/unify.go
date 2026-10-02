// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/feature/unify/chantun"
	"tailscale.com/feature/unify/osglue"
	"tailscale.com/feature/unify/remap"
	"tailscale.com/feature/unify/stack"
	"tailscale.com/feature/unify/xlate"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

const (
	// settleDelay is how long the worker waits after a stack reports a
	// change before applying it, so a burst of changes (a netmap and the
	// state transitions around it) is applied once.
	settleDelay = 50 * time.Millisecond

	// expireInterval is how often unused remap mappings are released.
	expireInterval = time.Hour

	// stackQueueDepth is the number of packets buffered in each direction
	// of a stack's device: more than one batch of the host's TUN.
	stackQueueDepth = 2 * conn.IdealBatchSize
)

// Options configures [New].
type Options struct {
	// Logf is the base logger. Each stack's lines are prefixed with
	// "[unify:<name>] ". If nil, logs are discarded.
	Logf logger.Logf

	// StateDir is tailscaled's state directory. The remap table is saved
	// at [RemapPath] and the other tailnets keep their state in
	// [TailnetDir]. Required.
	StateDir string

	// Primary configures the primary tailnet's stack.
	Primary PrimaryOptions

	// Tailnets lists the other tailnets in configured order, as in
	// [Config] (see [LoadConfig]). Their ports are [Config.Ports] of
	// Primary.Port.
	Tailnets []TailnetConfig

	// HostTUN is the host's real TUN device. Required. Unify owns it
	// once New is called, even if New fails: its packet loop reads and
	// writes it and closes it.
	HostTUN tun.Device

	// HostRouter is the host's real router, configured on HostTUN.
	// Required. Start brings it up, and it is then given the merged
	// configuration of the running stacks (see [osglue.MergeRouter]).
	// Unify closes it, even if New fails.
	HostRouter router.Router

	// HostBus is the event bus HostRouter was created on. The primary
	// stack's magicsock port updates are published on it, so the router
	// can let that port bypass the tunnel. The other stacks' ports are
	// not (they rely on NAT traversal and DERP). If nil, nothing is
	// published.
	HostBus *eventbus.Bus

	// HostDNS is the host's OS DNS configurator. The primary stack
	// configures it through a passthrough; the other stacks' DNS
	// configuration is only recorded. Unify closes it, even if New fails.
	// If nil, the primary's DNS configuration is only recorded too.
	HostDNS dns.OSConfigurator

	// Pool4 and Pool6 are the remap pools (see [remap.Config]). Zero
	// values take remap's defaults: Pool6 is generated once and saved.
	Pool4, Pool6 netip.Prefix

	// LocalPrefixes returns the networks the host is directly connected
	// to, which are never mapped as they are (see [remap.Table.SetLocal]).
	// It is called by Start and after each link change NetMon reports.
	// If nil, the prefixes of NetMon's interfaces other than loopback and
	// HostTUN are used, or none without NetMon.
	LocalPrefixes func() []netip.Prefix

	// NetMon is the daemon's network monitor, if any. Unify re-reads the
	// local networks when it reports a change.
	NetMon *netmon.Monitor

	// Clock is used for remap timestamps and the hourly expiry. If nil,
	// the system clock is used.
	Clock tstime.Clock
}

// PrimaryOptions configures the primary tailnet's stack, which uses
// tailscaled's usual state.
type PrimaryOptions struct {
	// Dir is tailscaled's state directory for the backend: its VarRoot,
	// and the home of tailscaled.state if Store is nil.
	Dir string

	// Store is tailscaled's state store. If nil, a file store in Dir.
	Store ipn.StateStore

	// Ephemeral registers the node as ephemeral, as tailscaled does
	// with an in-memory state store.
	Ephemeral bool

	// Port is tailscaled's --port. The other tailnets' default ports
	// follow it.
	Port uint16

	// LogID is tailscaled's log ID.
	LogID logid.PublicID

	// SocketPath is tailscaled's LocalAPI socket (--socket). The other
	// tailnets' sockets are next to it (see [TailnetSocket]).
	SocketPath string
}

// tailnetStack is a stack as unify drives it. Tests substitute fakes for
// the real stacks ([liveStack]).
type tailnetStack interface {
	RoutingSnapshot() ipnlocal.RoutingSnapshot
	SetRoutingObserver(func())
	// Start starts the backend as tailscaled does: if it has valid
	// prefs.
	Start() error
	Close() error
}

// liveStack is a [stack.Stack] as a tailnetStack.
type liveStack struct{ *stack.Stack }

func newLiveStack(cfg stack.Config) (tailnetStack, error) {
	st, err := stack.New(cfg)
	if err != nil {
		return nil, err
	}
	return liveStack{st}, nil
}

func (s liveStack) RoutingSnapshot() ipnlocal.RoutingSnapshot {
	return s.LocalBackend().RoutingSnapshot()
}

func (s liveStack) SetRoutingObserver(f func()) { s.LocalBackend().SetRoutingObserver(f) }

func (s liveStack) Start() error {
	lb := s.LocalBackend()
	if !lb.Prefs().Valid() {
		return nil
	}
	return lb.Start(ipn.Options{})
}

// tailnet is one tailnet's stack and what unify gave it.
type tailnet struct {
	name    string
	owner   remap.Owner
	primary bool
	dev     *chantun.Device // the stack's TUN, read by the loop
	router  *osglue.Router  // the stack's router stub
	st      tailnetStack
}

// Unify runs one stack per tailnet and connects them to the host's TUN,
// router and DNS configurator.
//
// A single worker goroutine keeps the host in step with the stacks. Each
// stack's LocalBackend signals it after every reconfiguration and state
// change; the worker then reads every stack's routing snapshot, maps new
// addresses (remap), updates the translator (xlate) and gives the host
// router the merged configuration. It also follows the host's local
// networks and releases mappings unused for long (hourly).
type Unify struct {
	logf  logger.Logf
	errf  logger.Logf // rate-limited, for repeated errors
	clock tstime.Clock

	table      *remap.Table
	tr         *xlate.Translator
	loop       *loop
	tailnets   []*tailnet // configured order, primary first
	hostTUN    tun.Device
	hostRouter router.Router
	hostDNS    dns.OSConfigurator
	portClient *eventbus.Client // publishes the primary's port updates; nil without Options.HostBus
	netMon     *netmon.Monitor

	// localPrefixes returns the host's networks, or is nil.
	localPrefixes func() []netip.Prefix

	settle      time.Duration // settleDelay; tests shorten it
	changed     chan struct{} // capacity 1: a stack's routing may have changed
	linkChanged chan struct{} // capacity 1: the host's networks may have changed

	ctx        context.Context // canceled by Close
	cancel     context.CancelFunc
	workerDone chan struct{} // closed when the worker returns

	mu         sync.Mutex
	started    bool   // Start was called
	running    bool   // the worker was started
	closed     bool   // Close was called
	unregister func() // the NetMon callback, or nil

	closeOnce sync.Once
	closeErr  error

	// Owned by the worker (and by Start before it runs it).
	applied     *router.Config // last configuration the host router accepted
	exitIgnored []remap.Owner  // last tailnets whose exit node was not used
	local       []netip.Prefix // last networks given to SetLocal
}

// New builds a stack for every tailnet and the packet loop between them
// and the host. The stacks' backends are not started yet: see
// [Unify.Start]. If New fails, everything it was given is closed.
func New(opts Options) (*Unify, error) {
	return newUnify(opts, newLiveStack)
}

func newUnify(opts Options, build func(stack.Config) (tailnetStack, error)) (_ *Unify, err error) {
	logf := opts.Logf
	if logf == nil {
		logf = logger.Discard
	}
	clock := opts.Clock
	if clock == nil {
		clock = tstime.StdClock{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := &Unify{
		logf:        logf,
		errf:        logger.RateLimitedFn(logf, 10*time.Second, 3, 16),
		clock:       clock,
		hostTUN:     opts.HostTUN,
		hostRouter:  opts.HostRouter,
		hostDNS:     opts.HostDNS,
		netMon:      opts.NetMon,
		settle:      settleDelay,
		changed:     make(chan struct{}, 1),
		linkChanged: make(chan struct{}, 1),
		ctx:         ctx,
		cancel:      cancel,
		workerDone:  make(chan struct{}),
	}
	defer func() {
		if err != nil {
			u.Close()
			err = fmt.Errorf("unify: %w", err)
		}
	}()

	switch {
	case opts.StateDir == "":
		return nil, errors.New("Options.StateDir is required")
	case opts.HostTUN == nil:
		return nil, errors.New("Options.HostTUN is required")
	case opts.HostRouter == nil:
		return nil, errors.New("Options.HostRouter is required")
	}
	cfg := Config{Tailnets: opts.Tailnets}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ports, err := cfg.Ports(opts.Primary.Port)
	if err != nil {
		return nil, err
	}

	u.table, err = remap.New(remap.Config{Pool4: opts.Pool4, Pool6: opts.Pool6, Now: clock.Now}, remap.FileStore{Path: RemapPath(opts.StateDir)})
	if err != nil {
		return nil, err
	}
	if err := u.table.LoadErr(); err != nil {
		logf("unify: %v", err)
	}
	u.tr = xlate.New(u.table, append([]netip.Prefix{tsaddr.CGNATRange(), tsaddr.TailscaleULARange()}, u.table.Pools()...))
	if u.loop, err = newLoop(loopConfig{host: opts.HostTUN, tr: u.tr, logf: logf}); err != nil {
		return nil, err
	}

	u.localPrefixes = opts.LocalPrefixes
	if u.localPrefixes == nil && opts.NetMon != nil {
		hostName, _ := opts.HostTUN.Name()
		u.localPrefixes = func() []netip.Prefix {
			return interfacePrefixes(opts.NetMon.InterfaceState(), hostName)
		}
	}

	var portUpdate func(router.PortUpdate)
	if opts.HostBus != nil {
		u.portClient = opts.HostBus.Client("unify.portbridge")
		portUpdate = eventbus.Publish[router.PortUpdate](u.portClient).Publish
	}
	primaryDNS := osglue.NewDNS(nil)
	if opts.HostDNS != nil {
		primaryDNS = osglue.NewPassthroughDNS(opts.HostDNS, nil)
	}
	if err := u.addTailnet(build, PrimaryName, primaryDNS, stack.Config{
		Dir:          opts.Primary.Dir,
		Store:        opts.Primary.Store,
		Ephemeral:    opts.Primary.Ephemeral,
		Port:         opts.Primary.Port,
		LogID:        opts.Primary.LogID,
		SocketPath:   opts.Primary.SocketPath,
		OnPortUpdate: portUpdate,
	}); err != nil {
		return nil, err
	}
	for i, t := range opts.Tailnets {
		if err := u.addTailnet(build, t.Name, osglue.NewDNS(nil), stack.Config{
			Dir:        TailnetDir(opts.StateDir, t.Name),
			Port:       ports[i],
			SocketPath: TailnetSocket(opts.Primary.SocketPath, t.Name),
		}); err != nil {
			return nil, err
		}
	}

	// Each stack keeps its device for life: the loop must drain it even
	// while the tailnet is down, and xlate drops traffic for tailnets
	// that are not running.
	devs := make(map[remap.Owner]*chantun.Device, len(u.tailnets))
	for _, t := range u.tailnets {
		devs[t.owner] = t.dev
	}
	u.loop.SetStacks(devs)
	return u, nil
}

// addTailnet builds the stack of tailnet name from cfg, giving it a
// device, a router stub and d, and watches its routing.
func (u *Unify) addTailnet(build func(stack.Config) (tailnetStack, error), name string, d *osglue.DNS, cfg stack.Config) error {
	dev, err := chantun.New("unify-"+name, int(tstun.DefaultTUNMTU()), conn.IdealBatchSize, stackQueueDepth)
	if err != nil {
		return err
	}
	r := osglue.NewRouter(u.routingChanged)
	cfg.Name = name
	cfg.Logf = u.logf
	cfg.Tun, cfg.Router, cfg.DNS = dev, r, d
	st, err := build(cfg)
	if err != nil {
		dev.Close()
		r.Close()
		d.Close()
		return fmt.Errorf("tailnet %q: %w", name, err)
	}
	st.SetRoutingObserver(u.routingChanged)
	u.tailnets = append(u.tailnets, &tailnet{
		name:    name,
		owner:   remap.Owner(name),
		primary: name == PrimaryName,
		dev:     dev,
		router:  r,
		st:      st,
	})
	return nil
}

// routingChanged is every stack's routing observer. LocalBackend calls it
// with its lock held, so it only signals the worker.
func (u *Unify) routingChanged() {
	select {
	case u.changed <- struct{}{}:
	default:
	}
}

// linkChange signals the worker that the host's networks may have changed.
func (u *Unify) linkChange() {
	select {
	case u.linkChanged <- struct{}{}:
	default:
	}
}

// Start brings up the host router, reads the host's local networks, starts
// the worker and starts each stack's backend if it has valid prefs, as
// tailscaled does. A backend without them waits for a LocalAPI client
// (tailscale up). Start may be called once, and not concurrently with
// Close; if it fails, call Close.
func (u *Unify) Start() error {
	u.mu.Lock()
	if u.started || u.closed {
		u.mu.Unlock()
		return errors.New("unify: Start called twice or after Close")
	}
	u.started = true
	u.mu.Unlock()

	if err := u.hostRouter.Up(); err != nil {
		return fmt.Errorf("unify: bringing up the host router: %w", err)
	}
	u.refreshLocal()
	u.mu.Lock()
	if u.netMon != nil {
		u.unregister = u.netMon.RegisterChangeCallback(func(*netmon.ChangeDelta) { u.linkChange() })
	}
	// The ticker is made before the worker runs, so no tick of a test
	// clock is missed.
	expiry, tick := u.clock.NewTicker(expireInterval)
	u.running = true
	go u.worker(expiry, tick)
	u.mu.Unlock()
	u.routingChanged() // apply the initial state, whatever the stacks do

	for _, t := range u.tailnets {
		if err := t.st.Start(); err != nil {
			return fmt.Errorf("unify: starting tailnet %q: %w", t.name, err)
		}
	}
	return nil
}

// Close stops the worker, closes every stack, then the host router and DNS
// configurator, and finally closes the packet loop (closing the host's TUN).
// It is safe to call more than once.
func (u *Unify) Close() error {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed = true
		running, unregister := u.running, u.unregister
		u.mu.Unlock()
		if unregister != nil {
			unregister()
		}
		u.cancel()
		if running {
			<-u.workerDone
		}

		var errs []error
		for _, t := range u.tailnets {
			errs = append(errs, t.st.Close())
		}
		if u.portClient != nil {
			u.portClient.Close()
		}
		if u.loop != nil {
			errs = append(errs, u.loop.Close())
		} else if u.hostTUN != nil {
			errs = append(errs, u.hostTUN.Close())
		}
		if u.hostRouter != nil {
			errs = append(errs, u.hostRouter.Close())
		}
		if u.hostDNS != nil {
			errs = append(errs, u.hostDNS.Close())
		}
		u.closeErr = errors.Join(errs...)
	})
	return u.closeErr
}

// Done is closed when the packet loop stops reading the host's TUN: after
// Close, or when the device fails (see Err). The daemon should then shut
// down.
func (u *Unify) Done() <-chan struct{} { return u.loop.Done() }

// Err returns the error that stopped the packet loop reading the host's
// TUN, or nil if it is running or was closed.
func (u *Unify) Err() error { return u.loop.Err() }

// Stack returns the stack of tailnet name (PrimaryName for the primary),
// or nil if there is none.
func (u *Unify) Stack(name string) *stack.Stack {
	for _, t := range u.tailnets {
		if t.name == name {
			if s, ok := t.st.(liveStack); ok {
				return s.Stack
			}
		}
	}
	return nil
}

// Stacks returns every tailnet's stack in configured order, the primary
// first.
func (u *Unify) Stacks() []*stack.Stack {
	var out []*stack.Stack
	for _, t := range u.tailnets {
		if s, ok := t.st.(liveStack); ok {
			out = append(out, s.Stack)
		}
	}
	return out
}

// worker applies the stacks' routing to the host until Close.
func (u *Unify) worker(expiry tstime.TickerController, tick <-chan time.Time) {
	defer close(u.workerDone)
	defer expiry.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-u.changed:
			if !u.settled() {
				return
			}
			u.reconcile()
		case <-u.linkChanged:
			u.refreshLocal()
		case <-tick:
			// Sync every running stack first, so that only mappings of
			// tailnets that are away can expire (R15).
			u.reconcile()
			u.expire()
		}
	}
}

// settled waits out the settle delay, then takes any change signal that
// came in meanwhile, which the coming reconcile covers. It reports false
// if Close was called.
func (u *Unify) settled() bool {
	t := time.NewTimer(u.settle)
	defer t.Stop()
	select {
	case <-u.ctx.Done():
		return false
	case <-t.C:
	}
	select {
	case <-u.changed:
	default:
	}
	return true
}

// reconcile reads every stack's routing and applies it: remap, xlate and
// the host router, in that order, so that addresses are mapped and
// translated before the host routes to them.
func (u *Unify) reconcile() {
	now := u.clock.Now()
	in := make([]tailnetState, len(u.tailnets))
	for i, t := range u.tailnets {
		in[i] = tailnetState{owner: t.owner, primary: t.primary, snap: t.st.RoutingSnapshot()}
	}
	plans, exitIgnored := planRouting(in)
	if !slices.Equal(exitIgnored, u.exitIgnored) {
		u.exitIgnored = exitIgnored
		if len(exitIgnored) > 0 {
			u.logf("unify: warning: only one tailnet's exit node can be used; ignoring the exit node of %v", exitIgnored)
		}
	}

	var stacks []xlate.Stack
	var merge []osglue.Stack
	for i, p := range plans {
		if !p.running {
			continue
		}
		ch, err := u.table.Sync(p.owner, p.sync, now)
		if err != nil {
			u.errf("unify: tailnet %q: %v", p.owner, err)
		}
		if len(ch.Added) > 0 {
			u.logf("unify: tailnet %q: mapped %v", p.owner, ch.Added)
		}
		if len(ch.Unmapped) > 0 {
			u.errf("unify: tailnet %q: remap pool full; unreachable from this host: %v", p.owner, ch.Unmapped)
		}
		stacks = append(stacks, p.xlate)
		m := p.merge
		m.Captured = u.tailnets[i].router.Config()
		merge = append(merge, m)
	}
	if err := u.tr.SetStacks(stacks); err != nil {
		u.errf("unify: %v", err) // planRouting makes valid sets; never expected
	}
	cfg := osglue.MergeRouter(merge, u.table.Mappings())
	if cfg.Equal(u.applied) {
		return
	}
	if err := u.hostRouter.Set(cfg); err != nil {
		// Retried on the next change.
		u.errf("unify: configuring the host router: %v", err)
		return
	}
	u.applied = cfg
}

// refreshLocal gives remap the host's local networks, if they changed,
// and logs mappings that overlap them.
func (u *Unify) refreshLocal() {
	if u.localPrefixes == nil {
		return
	}
	ps := u.localPrefixes()
	if slices.Equal(ps, u.local) {
		return
	}
	u.local = ps
	for _, c := range u.table.SetLocal(ps) {
		m := c.Mapping
		u.logf("unify: warning: tailnet %q's %v (virtual %v) overlaps local network %v", m.Owner, m.Real, m.Virtual, c.Local)
	}
}

// expire releases mappings unused for longer than remap's GC interval.
func (u *Unify) expire() {
	ch, err := u.table.Expire(u.clock.Now())
	if err != nil {
		u.errf("unify: %v", err)
	}
	if len(ch.Removed) > 0 {
		u.logf("unify: released unused mappings %v", ch.Removed)
	}
}

// interfacePrefixes returns the networks of st's interfaces other than
// loopback ones and exclude (the host's tailnet TUN), masked, sorted and
// without duplicates.
func interfacePrefixes(st *netmon.State, exclude string) []netip.Prefix {
	if st == nil {
		return nil
	}
	var out []netip.Prefix
	for name, ps := range st.InterfaceIPs {
		if name == exclude || st.Interface[name].IsLoopback() {
			continue
		}
		for _, p := range ps {
			out = append(out, p.Masked())
		}
	}
	tsaddr.SortPrefixes(out)
	return slices.Compact(out)
}
