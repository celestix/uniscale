// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/feature/unify/stack"
	"tailscale.com/ipn"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

// netnsEnv is set in a test process that runInNetns started in its own
// user and network namespace.
const netnsEnv = "TS_UNIFY_TEST_IN_NETNS"

// TestCollidingSelfListeners checks that stacks never listen on their real
// self addresses through the kernel. In the integration topology both
// tailnets give this node 100.64.0.2, which the primary keeps as its
// address on the host. A kernel listener of b's on it would answer the
// primary's peers, as b, under b's ACLs and identities. Peers still reach
// each stack's peerapi and serve ports, through the stack's own netstack.
//
// The test runs itself again in a user and network namespace when it
// can, with the colliding self addresses on a dummy "tailscale0" that is
// the Tailscale interface, as tailscaled sets it up. There a kernel
// listener on them binds, and the test checks that the kernel has none.
func TestCollidingSelfListeners(t *testing.T) {
	tstest.ResourceCheck(t)
	// The peers register first, so the stacks get these.
	wantSelf4 := mpa("100.64.0.2")
	wantSelf6 := tsaddr.Tailscale4To6(wantSelf4)
	inNetns := os.Getenv(netnsEnv) != ""
	if inNetns {
		setUpNetns(t, wantSelf4, wantSelf6)
	} else {
		t.Run("netns", func(t *testing.T) { runInNetns(t, "TestCollidingSelfListeners") })
	}
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
	th := startUnify(t, t.TempDir())
	th.login(ctx, PrimaryName, urlA)
	snapA := th.running(PrimaryName)
	th.login(ctx, "b", urlB)
	snapB := th.running("b")
	self4, self6 := first4(snapA.Self), first6(snapA.Self)
	if !slices.Equal(snapA.Self, snapB.Self) || self4 != wantSelf4 || self6 != wantSelf6 {
		t.Fatalf("selves do not collide as expected: A %v, B %v", snapA.Self, snapB.Self)
	}

	stA, stB := th.u.Stack(PrimaryName), th.u.Stack("b")
	cases := []struct {
		peer *tsnet.Server
		st   *stack.Stack
	}{{peerA, stA}, {peerB, stB}}

	// Each stack serves TCP port 8080 from a backend of its own, which
	// names the stack.
	for _, c := range cases {
		backend := serveGreeting(t, "served by "+c.st.Name())
		sc := &ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{8080: {TCPForward: backend}}}
		if err := c.st.LocalBackend().SetServeConfig(sc, ""); err != nil {
			t.Fatalf("%s: SetServeConfig: %v", c.st.Name(), err)
		}
	}
	// Peerapi is set up for every self address with the netmap.
	if err := tstest.WaitFor(integrationTimeout, func() error {
		for _, c := range cases {
			for _, a := range []netip.Addr{self4, self6} {
				if _, ok := c.st.LocalBackend().GetPeerAPIPort(a); !ok {
					return fmt.Errorf("%s: no peerapi on %v yet", c.st.Name(), a)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("no kernel listeners", func(t *testing.T) {
		for _, c := range cases {
			for _, a := range []netip.Addr{self4, self6} {
				// The netstack-only listener has port 1; a kernel
				// listener has any other.
				if port, _ := c.st.LocalBackend().GetPeerAPIPort(a); port != 1 {
					t.Errorf("%s: peerapi on %v listens through the kernel on port %d", c.st.Name(), a, port)
				}
			}
		}
		if !inNetns {
			return // the selves are not this host's addresses: nothing can bind them
		}
		if ls := kernelListeners(t, self4, self6); len(ls) > 0 {
			t.Errorf("kernel listeners on the real selves: %v", ls)
		}
	})

	waitHomeDERP(t, ctx, stA.Sys())
	waitHomeDERP(t, ctx, stB.Sys())
	waitPeerReachable(t, stA.LocalBackend(), peerKey(t, ctx, peerA))
	waitPeerReachable(t, stB.LocalBackend(), peerKey(t, ctx, peerB))

	t.Run("peerapi through netstack", func(t *testing.T) {
		for _, c := range cases {
			port, _ := c.st.LocalBackend().GetPeerAPIPort(self4)
			url := fmt.Sprintf("http://%v/", netip.AddrPortFrom(self4, port))
			var body []byte
			if err := tstest.WaitFor(integrationTimeout, func() error {
				rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
				defer rcancel()
				req, err := http.NewRequestWithContext(rctx, "GET", url, nil)
				if err != nil {
					return err
				}
				res, err := c.peer.HTTPClient().Do(req)
				if err != nil {
					return err
				}
				defer res.Body.Close()
				if body, err = io.ReadAll(res.Body); err != nil {
					return err
				}
				if res.StatusCode != http.StatusOK {
					return fmt.Errorf("%s: %s", res.Status, body)
				}
				return nil
			}); err != nil {
				t.Fatalf("%s: GET %s: %v", c.peer.Hostname, url, err)
			}
			// The stack of the peer's own tailnet answered: it knows the
			// peer by name.
			if want := "Your device is " + c.peer.Hostname; !bytes.Contains(body, []byte(want)) {
				t.Errorf("%s: peerapi of %s answered %q, want %q", c.peer.Hostname, c.st.Name(), body, want)
			}
		}
	})

	t.Run("serve through netstack", func(t *testing.T) {
		for _, c := range cases {
			want := "served by " + c.st.Name()
			var got string
			if err := tstest.WaitFor(integrationTimeout, func() error {
				dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
				defer dcancel()
				conn, err := c.peer.Dial(dctx, "tcp", netip.AddrPortFrom(self4, 8080).String())
				if err != nil {
					return err
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return err
				}
				got = strings.TrimSpace(line)
				return nil
			}); err != nil {
				t.Fatalf("%s: dial %v:8080: %v", c.peer.Hostname, self4, err)
			}
			if got != want {
				t.Errorf("%s: port 8080 answered %q, want %q", c.peer.Hostname, got, want)
			}
		}
	})
}

// serveGreeting serves TCP on 127.0.0.1 until the test ends, writing
// greeting and a newline to every connection, and returns its address.
func serveGreeting(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, greeting+"\n")
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// runInNetns runs test name of this test binary in a new user and network
// namespace, with netnsEnv set, and fails if it does not pass there. It
// skips if the system cannot make such namespaces.
func runInNetns(t *testing.T, name string) {
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("no unshare: %v", err)
	}
	if out, err := exec.Command(unshare, "-rn", "true").CombinedOutput(); err != nil {
		t.Skipf("cannot make a user and network namespace: %v: %s", err, out)
	}
	cmd := exec.CommandContext(t.Context(), unshare, "-rn", os.Args[0], "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), netnsEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: "+name+" ")) {
		t.Fatalf("%s in a network namespace: %v\n%s", name, err, out)
	}
	for line := range strings.Lines(string(out)) {
		if strings.Contains(line, "--- ") {
			t.Logf("in the namespace: %s", strings.TrimSpace(line))
		}
	}
}

// setUpNetns prepares the namespace runInNetns made: loopback up, a
// dummy "eth0" with the default route, so the network counts as up, and
// selves on a dummy "tailscale0" that is the Tailscale interface.
func setUpNetns(t *testing.T, selves ...netip.Addr) {
	t.Helper()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	eth0 := addDummy(t, "eth0", mpp("10.99.0.1/24"))
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: eth0.Attrs().Index, Gw: net.IPv4(10, 99, 0, 2)}); err != nil {
		t.Fatalf("adding the default route: %v", err)
	}
	var ps []netip.Prefix
	for _, a := range selves {
		ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
	}
	addDummy(t, "tailscale0", ps...)
	netmon.SetTailscaleInterfaceProps("tailscale0", 0)
	t.Cleanup(func() { netmon.SetTailscaleInterfaceProps("", 0) })
}

// addDummy adds a dummy interface that is up and has addrs.
func addDummy(t *testing.T, name string, addrs ...netip.Prefix) netlink.Link {
	t.Helper()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("adding %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	for _, p := range addrs {
		addr, err := netlink.ParseAddr(p.String())
		if err != nil {
			t.Fatal(err)
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatalf("adding %v to %s: %v", p, name, err)
		}
	}
	return link
}

// kernelListeners returns the TCP sockets listening on addrs in this
// network namespace.
func kernelListeners(t *testing.T, addrs ...netip.Addr) []netip.AddrPort {
	t.Helper()
	var out []netip.AddrPort
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			const listen = "0A"
			if len(f) < 4 || f[3] != listen {
				continue
			}
			ap, err := parseProcNetAddr(f[1])
			if err != nil {
				t.Fatalf("%s: %q: %v", file, line, err)
			}
			if slices.Contains(addrs, ap.Addr()) {
				out = append(out, ap)
			}
		}
	}
	return out
}

// parseProcNetAddr parses an address of /proc/net/tcp or tcp6: the IP as
// 32-bit words in host byte order, in hex, a colon and the port in hex.
func parseProcNetAddr(s string) (netip.AddrPort, error) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("no port")
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", ipHex)
	}
	ip := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	port, err := hex.DecodeString(portHex)
	if err != nil || len(port) != 2 {
		return netip.AddrPort{}, fmt.Errorf("bad port %q", portHex)
	}
	a, _ := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(port)), nil
}
