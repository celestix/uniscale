// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsconst"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/linuxfw"
	"tailscale.com/util/set"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine/router"
)

type Config = router.Config

func TestRouterStates(t *testing.T) {
	basic := `
ip rule add -4 pref 5210 fwmark 0x80000/0xff0000 table main
ip rule add -4 pref 5230 fwmark 0x80000/0xff0000 table default
ip rule add -4 pref 5250 fwmark 0x80000/0xff0000 type unreachable
ip rule add -4 pref 5270 table 52
ip rule add -6 pref 5210 fwmark 0x80000/0xff0000 table main
ip rule add -6 pref 5230 fwmark 0x80000/0xff0000 table default
ip rule add -6 pref 5250 fwmark 0x80000/0xff0000 type unreachable
ip rule add -6 pref 5270 table 52
`
	states := []struct {
		name string
		in   *Config
		want string
	}{
		{
			name: "no-config",
			in:   nil,
			want: `
up` + basic,
		},
		{
			name: "local-addr-only",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0` + basic,
		},

		{
			name: "addr-and-routes",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "192.168.16.0/24"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add 192.168.16.0/24 dev tailscale0 table 52` + basic,
		},

		{
			name: "addr-routes-and-subnet-routes",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "192.168.16.0/24"),
				SubnetRoutes:  mustCIDRs("200.0.0.0/8"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add 192.168.16.0/24 dev tailscale0 table 52` + basic,
		},

		{
			name: "addr-routes-subnet-routes-with-netfilter",
			in: &Config{
				LocalAddrs:        mustCIDRs("100.101.102.104/10"),
				Routes:            mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:      mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes:  true,
				StatefulFiltering: true,
				NetfilterMode:     netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
		{
			name: "addr-routes-subnet-routes-netfilter-no-stateful",
			in: &Config{
				LocalAddrs:        mustCIDRs("100.101.102.104/10"),
				Routes:            mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:      mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes:  true,
				StatefulFiltering: false,
				NetfilterMode:     netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
		{
			name: "addr-and-routes-with-netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
`,
		},

		{
			name: "addr-routes-subnet-routes-netfilter-no-SNAT",
			in: &Config{
				LocalAddrs:       mustCIDRs("100.101.102.104/10"),
				Routes:           mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:     mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes: false,
				NetfilterMode:    netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr-and-routes-with-netfilter-2",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
`,
		},

		{
			name: "addr-and-routes-with-half-netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterNoDivert,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
`,
		},
		{
			name: "addr-and-routes-with-netfilter2",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr-routes-local-routes-with-netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "0.0.0.0/0"),
				LocalRoutes:   mustCIDRs("10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 0.0.0.0/0 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add throw 10.0.0.0/8 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr-routes-local-routes-no-netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "0.0.0.0/0"),
				LocalRoutes:   mustCIDRs("10.0.0.0/8", "192.168.0.0/24"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 0.0.0.0/0 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add throw 10.0.0.0/8 table 52
ip route add throw 192.168.0.0/24 table 52` + basic,
		},
		{
			name: "subnet-routes-connmark-for-rp_filter",
			in: &Config{
				LocalAddrs:       mustCIDRs("100.101.102.104/10"),
				Routes:           mustCIDRs("100.100.100.100/32"),
				SubnetRoutes:     mustCIDRs("10.0.0.0/16"),
				SNATSubnetRoutes: true,
				NetfilterMode:    netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
		{
			name: "subnet-routes-connmark-always-enabled",
			in: &Config{
				LocalAddrs:       mustCIDRs("100.101.102.104/10"),
				Routes:           mustCIDRs("100.100.100.100/32"),
				SubnetRoutes:     mustCIDRs("10.0.0.0/16"),
				SNATSubnetRoutes: true,
				NetfilterMode:    netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
		{
			name: "connmark-with-stateful-filtering",
			in: &Config{
				LocalAddrs:        mustCIDRs("100.101.102.104/10"),
				Routes:            mustCIDRs("100.100.100.100/32"),
				SubnetRoutes:      mustCIDRs("10.0.0.0/16"),
				SNATSubnetRoutes:  true,
				StatefulFiltering: true,
				NetfilterMode:     netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/mangle/OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/mangle/PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
	}

	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	defer mon.Close()

	fake := NewFakeOS(t)
	ht := health.NewTracker(bus)
	router, err := newUserspaceRouterAdvanced(t.Logf, "tailscale0", mon, fake, ht, bus)
	router.(*linuxRouter).nfr = fake.nfr
	// Don't consult the live /proc for the tun's IPv6 state in tests; the
	// fake netfilter runner's HasIPV6 (noV6) is the authoritative v6 signal
	// here. See #20447.
	router.(*linuxRouter).interfaceV6Usable = func() bool { return true }
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}
	if err := router.Up(); err != nil {
		t.Fatalf("failed to up router: %v", err)
	}

	testState := func(t *testing.T, i int) {
		t.Helper()
		if err := router.Set(states[i].in); err != nil {
			t.Fatalf("failed to set router config: %v", err)
		}
		got := fake.String()
		want := adjustFwmask(t, strings.TrimSpace(states[i].want))
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("unexpected OS state (-got+want):\n%s", diff)
		}
	}

	for i, state := range states {
		t.Run(state.name, func(t *testing.T) { testState(t, i) })
	}

	// Cycle through a bunch of states in pseudorandom order, to
	// verify that we transition cleanly from state to state no matter
	// the order.
	for randRun := 0; randRun < 5*len(states); randRun++ {
		i := rand.Intn(len(states))
		state := states[i]
		t.Run(state.name, func(t *testing.T) { testState(t, i) })
	}
}

type fakeIPTablesRunner struct {
	t    *testing.T
	ipt4 map[string][]string
	ipt6 map[string][]string
	// we always assume ipv6 and ipv6 nat are enabled when testing, unless
	// noV6 is set.
	noV6 bool

	addChainsErr          error // if non-nil, AddChains returns it instead of setting up chains
	addConnmarkSaveCalls  int
	addExternalCGNATCalls int
}

func newIPTablesRunner(t *testing.T) linuxfw.NetfilterRunner {
	return &fakeIPTablesRunner{
		t: t,
		ipt4: map[string][]string{
			"filter/INPUT":      nil,
			"filter/OUTPUT":     nil,
			"filter/FORWARD":    nil,
			"nat/PREROUTING":    nil,
			"nat/OUTPUT":        nil,
			"nat/POSTROUTING":   nil,
			"mangle/PREROUTING": nil,
			"mangle/OUTPUT":     nil,
		},
		ipt6: map[string][]string{
			"filter/INPUT":      nil,
			"filter/OUTPUT":     nil,
			"filter/FORWARD":    nil,
			"nat/PREROUTING":    nil,
			"nat/OUTPUT":        nil,
			"nat/POSTROUTING":   nil,
			"mangle/PREROUTING": nil,
			"mangle/OUTPUT":     nil,
		},
	}
}

func insertRule(n *fakeIPTablesRunner, curIPT map[string][]string, chain, newRule string) error {
	// Get current rules for filter/ts-input chain with according IP version
	curTSInputRules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
		return fmt.Errorf("no %s chain exists", chain)
	}

	// Add new rule to top of filter/ts-input
	curTSInputRules = append(curTSInputRules, "")
	copy(curTSInputRules[1:], curTSInputRules)
	curTSInputRules[0] = newRule
	curIPT[chain] = curTSInputRules
	return nil
}

func insertRuleAt(n *fakeIPTablesRunner, curIPT map[string][]string, chain string, pos int, newRule string) {
	rules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
	}

	// If the given position is after the end of the chain, error.
	if pos > len(rules) {
		n.t.Fatalf("position %d > len(chain %s) %d", pos, chain, len(chain))
	}

	// Insert the rule at the given position
	rules = slices.Insert(rules, pos, newRule)
	curIPT[chain] = rules
}

func appendRule(n *fakeIPTablesRunner, curIPT map[string][]string, chain, newRule string) error {
	// Get current rules for filter/ts-input chain with according IP version
	curTSInputRules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
		return fmt.Errorf("no %s chain exists", chain)
	}

	// Add new rule to end of filter/ts-input
	curTSInputRules = append(curTSInputRules, newRule)
	curIPT[chain] = curTSInputRules
	return nil
}

func deleteRule(n *fakeIPTablesRunner, curIPT map[string][]string, chain, delRule string) error {
	// Get current rules for filter/ts-input chain with according IP version
	curTSInputRules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
		return fmt.Errorf("no %s chain exists", chain)
	}

	// Remove rule from filter/ts-input
	for i, rule := range curTSInputRules {
		if rule == delRule {
			curTSInputRules = append(curTSInputRules[:i], curTSInputRules[i+1:]...)
			break
		}
	}
	curIPT[chain] = curTSInputRules
	return nil
}

func (n *fakeIPTablesRunner) AddLoopbackRule(addr netip.Addr) error {
	curIPT := n.ipt4
	if addr.Is6() {
		curIPT = n.ipt6
	}
	newRule := fmt.Sprintf("-i lo -s %s -j ACCEPT", addr.String())

	return insertRule(n, curIPT, "filter/ts-input", newRule)
}

func (n *fakeIPTablesRunner) AddBase(tunname string) error {
	if err := n.addBase4(tunname); err != nil {
		return err
	}
	if n.HasIPV6() {
		if err := n.addBase6(tunname); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddDNATRule(origDst, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DNATWithLoadBalancer(netip.Addr, []netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) EnsureSNATForDst(src, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DNATNonTailscaleTraffic(exemptInterface string, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm linuxfw.PortMap) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm linuxfw.PortMap) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pm []linuxfw.PortMap) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) ClampMSSToPMTU(tun string, addr netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) EnsureDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DeleteDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	return errors.New("not implemented")
}

type iptRule struct{ chain, rule string }

func (n *fakeIPTablesRunner) addBase4(tunname string) error {
	curIPT := n.ipt4
	newRules := []iptRule{
		{"filter/ts-forward", fmt.Sprintf("-i %s -j MARK --set-mark %s/%s", tunname, tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-m mark --mark %s/%s -j ACCEPT", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-o %s -s %s -j DROP", tunname, tsaddr.CGNATRange().String())},
		{"filter/ts-forward", fmt.Sprintf("-o %s -j ACCEPT", tunname)},
	}
	for _, rule := range newRules {
		if err := appendRule(n, curIPT, rule.chain, rule.rule); err != nil {
			return fmt.Errorf("add rule %q to chain %q: %w", rule.rule, rule.chain, err)
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) addBase6(tunname string) error {
	curIPT := n.ipt6
	newRules := []iptRule{
		{"filter/ts-forward", fmt.Sprintf("-i %s -j MARK --set-mark %s/%s", tunname, tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-m mark --mark %s/%s -j ACCEPT", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-o %s -j ACCEPT", tunname)},
	}
	for _, rule := range newRules {
		if err := appendRule(n, curIPT, rule.chain, rule.rule); err != nil {
			return fmt.Errorf("add rule %q to chain %q: %w", rule.rule, rule.chain, err)
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelLoopbackRule(addr netip.Addr) error {
	curIPT := n.ipt4
	if addr.Is6() {
		curIPT = n.ipt6
	}

	delRule := fmt.Sprintf("-i lo -s %s -j ACCEPT", addr.String())

	return deleteRule(n, curIPT, "filter/ts-input", delRule)
}

func (n *fakeIPTablesRunner) AddHooks() error {
	newRules := []iptRule{
		{"filter/INPUT", "-j ts-input"},
		{"filter/FORWARD", "-j ts-forward"},
		{"nat/POSTROUTING", "-j ts-postrouting"},
	}
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, r := range newRules {
			if err := insertRule(n, ipt, r.chain, r.rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelHooks(logf logger.Logf) error {
	delRules := []iptRule{
		{"filter/INPUT", "-j ts-input"},
		{"filter/FORWARD", "-j ts-forward"},
		{"nat/POSTROUTING", "-j ts-postrouting"},
	}
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, r := range delRules {
			if err := deleteRule(n, ipt, r.chain, r.rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddChains() error {
	if n.addChainsErr != nil {
		return n.addChainsErr
	}
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, chain := range []string{"filter/ts-input", "filter/ts-forward", "nat/ts-postrouting"} {
			ipt[chain] = nil
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelChains() error {
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for chain := range ipt {
			if strings.HasPrefix(chain, "filter/ts-") || strings.HasPrefix(chain, "nat/ts-") {
				delete(ipt, chain)
			}
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelBase() error {
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, chain := range []string{"filter/ts-input", "filter/ts-forward", "nat/ts-postrouting"} {
			ipt[chain] = nil
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddSNATRule() error {
	newRule := fmt.Sprintf("-m mark --mark %s/%s -j MASQUERADE", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := appendRule(n, ipt, "nat/ts-postrouting", newRule); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelSNATRule() error {
	delRule := fmt.Sprintf("-m mark --mark %s/%s -j MASQUERADE", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := deleteRule(n, ipt, "nat/ts-postrouting", delRule); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddStatefulRule(tunname string) error {
	newRule := fmt.Sprintf("-o %s -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP", tunname)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		// Mimic the real runner and insert after the 'accept all' rule
		wantRule := fmt.Sprintf("-o %s -j ACCEPT", tunname)

		const chain = "filter/ts-forward"
		pos := slices.Index(ipt[chain], wantRule)
		if pos < 0 {
			n.t.Fatalf("no rule %q in chain %s", wantRule, chain)
		}

		insertRuleAt(n, ipt, chain, pos, newRule)
	}
	return nil
}

func (n *fakeIPTablesRunner) DelStatefulRule(tunname string) error {
	delRule := fmt.Sprintf("-o %s -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP", tunname)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := deleteRule(n, ipt, "filter/ts-forward", delRule); err != nil {
			return err
		}
	}
	return nil
}

// buildMagicsockPortRule builds a fake rule to use in AddMagicsockPortRule and
// DelMagicsockPortRule below.
func buildMagicsockPortRule(port uint16) string {
	return fmt.Sprintf("-p udp --dport %v -j ACCEPT", port)
}

// AddMagicsockPortRule implements the NetfilterRunner interface, but stores
// rules in fakeIPTablesRunner's internal maps rather than actually calling out
// to iptables. This is mainly to test the linux router implementation.
func (n *fakeIPTablesRunner) AddMagicsockPortRule(port uint16, network string) error {
	var ipt map[string][]string
	switch network {
	case "udp4":
		ipt = n.ipt4
	case "udp6":
		ipt = n.ipt6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	rule := buildMagicsockPortRule(port)

	if err := appendRule(n, ipt, "filter/ts-input", rule); err != nil {
		return err
	}

	return nil
}

// DelMagicsockPortRule implements the NetfilterRunner interface, but removes
// rules from fakeIPTablesRunner's internal maps rather than actually calling
// out to iptables. This is mainly to test the linux router implementation.
func (n *fakeIPTablesRunner) DelMagicsockPortRule(port uint16, network string) error {
	var ipt map[string][]string
	switch network {
	case "udp4":
		ipt = n.ipt4
	case "udp6":
		ipt = n.ipt6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	rule := buildMagicsockPortRule(port)

	if err := deleteRule(n, ipt, "filter/ts-input", rule); err != nil {
		return err
	}

	return nil
}

func (n *fakeIPTablesRunner) AddConnmarkSaveRule() error {
	n.addConnmarkSaveCalls++
	// PREROUTING rule: restore mark from conntrack
	prerouteRule := "-m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000"
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := insertRule(n, ipt, "mangle/PREROUTING", prerouteRule); err != nil {
			return err
		}
	}

	// OUTPUT rule: save mark to conntrack for NEW connections
	outputRule := "-m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000"
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := insertRule(n, ipt, "mangle/OUTPUT", outputRule); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelConnmarkSaveRule() error {
	prerouteRule := "-m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000"
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		deleteRule(n, ipt, "mangle/PREROUTING", prerouteRule) // ignore errors
	}

	outputRule := "-m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000"
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		deleteRule(n, ipt, "mangle/OUTPUT", outputRule) // ignore errors
	}
	return nil
}

func buildExternalCGNATRules(mode linuxfw.CGNATMode, tunname string) ([]iptRule, error) {
	switch mode {
	case linuxfw.CGNATModeDrop:
		return []iptRule{
			{"filter/ts-input", fmt.Sprintf("! -i %s -s %s -j RETURN", tunname, tsaddr.ChromeOSVMRange().String())},
			{"filter/ts-input", fmt.Sprintf("! -i %s -s %s -j DROP", tunname, tsaddr.CGNATRange().String())},
		}, nil
	case linuxfw.CGNATModeReturn:
		return []iptRule{
			{"filter/ts-input", fmt.Sprintf("! -i %s -s %s -j RETURN", tunname, tsaddr.CGNATRange().String())},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported mode %q", mode)
	}
}

func (n *fakeIPTablesRunner) AddExternalCGNATRules(mode linuxfw.CGNATMode, tunname string) error {
	n.addExternalCGNATCalls++
	rules, err := buildExternalCGNATRules(mode, tunname)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := appendRule(n, n.ipt4, rule.chain, rule.rule); err != nil {
			return fmt.Errorf("add rule %q to chain %q: %w", rule.rule, rule.chain, err)
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelExternalCGNATRules(mode linuxfw.CGNATMode, tunname string) error {
	rules, err := buildExternalCGNATRules(mode, tunname)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := deleteRule(n, n.ipt4, rule.chain, rule.rule); err != nil {
			return fmt.Errorf("del rule %q to chain %q: %w", rule.rule, rule.chain, err)
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) HasIPV6() bool       { return !n.noV6 }
func (n *fakeIPTablesRunner) HasIPV6NAT() bool    { return true }
func (n *fakeIPTablesRunner) HasIPV6Filter() bool { return true }

// fakeOS implements commandRunner and provides v4 and v6
// netfilterRunners, but captures changes without touching the OS.
type fakeOS struct {
	t      *testing.T
	up     bool
	ips    []string
	routes []string
	rules  []string
	// calls is every command run, in order, as space-joined arguments.
	calls []string
	// This test tests on the router level, so we will not bother
	// with using iptables or nftables, chose the simpler one.
	nfr linuxfw.NetfilterRunner
}

func NewFakeOS(t *testing.T) *fakeOS {
	return &fakeOS{
		t:   t,
		nfr: newIPTablesRunner(t),
	}
}

var errExec = errors.New("execution failed")

func (o *fakeOS) String() string {
	var b strings.Builder
	if o.up {
		b.WriteString("up\n")
	} else {
		b.WriteString("down\n")
	}

	for _, ip := range o.ips {
		fmt.Fprintf(&b, "ip addr add %s\n", ip)
	}

	for _, route := range o.routes {
		fmt.Fprintf(&b, "ip route add %s\n", route)
	}

	for _, rule := range o.rules {
		fmt.Fprintf(&b, "ip rule add %s\n", rule)
	}

	var chains []string
	for chain := range o.nfr.(*fakeIPTablesRunner).ipt4 {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		for _, rule := range o.nfr.(*fakeIPTablesRunner).ipt4[chain] {
			fmt.Fprintf(&b, "v4/%s %s\n", chain, rule)
		}
	}

	chains = nil
	for chain := range o.nfr.(*fakeIPTablesRunner).ipt6 {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		for _, rule := range o.nfr.(*fakeIPTablesRunner).ipt6[chain] {
			fmt.Fprintf(&b, "v6/%s %s\n", chain, rule)
		}
	}

	return b.String()[:len(b.String())-1]
}

func (o *fakeOS) run(args ...string) error {
	o.calls = append(o.calls, strings.Join(args, " "))
	unexpected := func() error {
		o.t.Errorf("unexpected invocation %q", strings.Join(args, " "))
		return errors.New("unrecognized invocation")
	}
	if args[0] != "ip" {
		return unexpected()
	}

	if len(args) == 2 && args[1] == "rule" {
		// naked invocation of `ip rule` is a feature test. Return
		// successfully.
		return nil
	}

	family := ""
	rest := strings.Join(args[3:], " ")
	if args[1] == "-4" || args[1] == "-6" {
		family = args[1]
		copy(args[1:], args[2:])
		args = args[:len(args)-1]
		rest = family + " " + strings.Join(args[3:], " ")
	}

	var ls *[]string
	switch args[1] {
	case "link":
		got := strings.Join(args[2:], " ")
		switch got {
		case "set dev tailscale0 up":
			o.up = true
		case "set dev tailscale0 down":
			o.up = false
		default:
			return unexpected()
		}
		return nil
	case "addr":
		ls = &o.ips
	case "route":
		ls = &o.routes
	case "rule":
		ls = &o.rules
	default:
		return unexpected()
	}

	// same reports whether two entries of ls are the same entry. Routes
	// match as in the kernel, regardless of their preferred source.
	same := func(a, b string) bool { return a == b }
	if args[1] == "route" {
		same = func(a, b string) bool { return routeKey(a) == routeKey(b) }
		if err := o.checkRouteSrc(rest); err != nil {
			return err
		}
	}

	switch args[2] {
	case "add":
		if slices.ContainsFunc(*ls, func(e string) bool { return same(e, rest) }) {
			// addAddress uses netlink AddrReplace in production, which is
			// idempotent; model that for addresses rather than erroring.
			// Routes/rules keep strict add semantics.
			if args[1] == "addr" {
				return nil
			}
			o.t.Errorf("can't add %q, already present", rest)
			return errors.New("already exists")
		}
		*ls = append(*ls, rest)
		sort.Strings(*ls)
	case "replace":
		if args[1] != "route" {
			return unexpected()
		}
		*ls = slices.DeleteFunc(*ls, func(e string) bool { return same(e, rest) })
		*ls = append(*ls, rest)
		sort.Strings(*ls)
	case "del":
		found := false
		for i, el := range *ls {
			if same(el, rest) {
				found = true
				*ls = append((*ls)[:i], (*ls)[i+1:]...)
				break
			}
		}
		if found && args[1] == "addr" {
			o.addrRemoved(rest)
		}
		if !found {
			o.t.Logf("note: can't delete %q, not present", rest)
			// 'ip rule del' exits with code 2 when a row is
			// missing. We don't want to consider that an error,
			// for cleanup purposes.

			// TODO(apenwarr): this is a hack.
			// I'd like to return an exec.ExitError(2) here, but
			// I can't, because the ExitCode is implemented in
			// os.ProcessState, which is an opaque object I can't
			// instantiate or modify. Go's 75 levels of abstraction
			// between me and an 8-bit int are really paying off
			// here, as you can see.
			return errors.New("exitcode:2")
		}
	default:
		return unexpected()
	}

	return nil
}

// routeKey returns the identity of a route entry of fakeOS.routes: the
// entry without its preferred source ("src <addr>"), which the kernel does
// not match on when replacing or deleting a route.
func routeKey(route string) string {
	f := strings.Fields(route)
	if i := slices.Index(f, "src"); i >= 0 && i+1 < len(f) {
		f = slices.Delete(f, i, i+2)
	}
	return strings.Join(f, " ")
}

// routeSrc returns the preferred source of a route entry, or "".
func routeSrc(route string) string {
	f := strings.Fields(route)
	if i := slices.Index(f, "src"); i >= 0 && i+1 < len(f) {
		return f[i+1]
	}
	return ""
}

// checkRouteSrc fails like the kernel when route asks for a preferred
// source that is not an address of the host.
func (o *fakeOS) checkRouteSrc(route string) error {
	src := routeSrc(route)
	if src == "" {
		return nil
	}
	for _, e := range o.ips {
		cidr, _, _ := strings.Cut(e, " ")
		if p, err := netip.ParsePrefix(cidr); err == nil && p.Addr().String() == src {
			return nil
		}
	}
	return fmt.Errorf("RTNETLINK answers: Invalid argument (src %s not assigned)", src)
}

// addrRemoved models what the kernel does to routes when the address of
// entry ("<cidr> dev <ifname>") is deleted: IPv4 routes using it as their
// preferred source are flushed, IPv6 routes lose their preferred source.
func (o *fakeOS) addrRemoved(entry string) {
	cidr, _, _ := strings.Cut(entry, " ")
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	src := p.Addr().String()
	var routes []string
	for _, r := range o.routes {
		switch {
		case routeSrc(r) != src:
			routes = append(routes, r)
		case p.Addr().Is6():
			routes = append(routes, routeKey(r))
		}
	}
	o.routes = routes
	sort.Strings(o.routes)
}

func (o *fakeOS) output(args ...string) ([]byte, error) {
	got := strings.Join(args, " ")
	o.calls = append(o.calls, got)

	if dev, ok := strings.CutPrefix(got, "ip -oneline addr show dev "); ok {
		// Render o.ips (entries look like "<cidr> dev <ifname>") in a simplified
		// `ip -oneline addr show` format that exposes the family token the parser
		// keys off of. Only addresses on the requested device are returned, so the
		// fake models a real multi-interface host: `show dev tailscale0` never
		// reports an address that lives on eth0.
		var ret []string
		for _, e := range o.ips {
			cidr, rest, _ := strings.Cut(e, " ")
			if rest != "dev "+dev {
				continue // address is on a different interface
			}
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			fam := "inet"
			if p.Addr().Is6() {
				fam = "inet6"
			}
			ret = append(ret, fmt.Sprintf("3: %s    %s %s scope global %s", dev, fam, cidr, dev))
		}
		return []byte(strings.Join(ret, "\n")), nil
	}

	want := "ip rule list priority 10000"
	if got != want {
		o.t.Errorf("unexpected command that wants output: %v", got)
		return nil, errExec
	}

	var ret []string
	for _, rule := range o.rules {
		if strings.Contains(rule, "10000") {
			ret = append(ret, rule)
		}
	}
	return []byte(strings.Join(ret, "\n")), nil
}

var tunTestNum int64

func createTestTUN(t *testing.T) tun.Device {
	const minimalMTU = 1280
	tunName := fmt.Sprintf("tuntest%d", atomic.AddInt64(&tunTestNum, 1))
	tun, err := tun.CreateTUN(tunName, minimalMTU)
	if err != nil {
		t.Fatalf("CreateTUN(%q): %v", tunName, err)
	}
	return tun
}

type linuxTest struct {
	tun       tun.Device
	mon       *netmon.Monitor
	r         *linuxRouter
	logOutput tstest.MemLogger
}

func (lt *linuxTest) Close() error {
	if lt.tun != nil {
		lt.tun.Close()
	}
	if lt.mon != nil {
		lt.mon.Close()
	}
	return nil
}

func newLinuxRootTest(t *testing.T) (*linuxTest, *eventbus.Bus) {
	tstest.RequireRoot(t)

	lt := new(linuxTest)
	lt.tun = createTestTUN(t)

	logf := lt.logOutput.Logf

	bus := eventbustest.NewBus(t)

	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		lt.Close()
		t.Fatal(err)
	}
	mon.Start()
	lt.mon = mon

	r, err := newUserspaceRouter(logf, lt.tun, mon, nil, bus)
	if err != nil {
		lt.Close()
		t.Fatal(err)
	}
	lr := r.(*linuxRouter)
	if err := lr.upInterface(); err != nil {
		lt.Close()
		t.Fatal(err)
	}
	lt.r = lr
	return lt, bus
}

func TestRuleDeletedEvent(t *testing.T) {
	fake := NewFakeOS(t)
	lt, bus := newLinuxRootTest(t)
	lt.r.nfr = fake.nfr
	defer lt.Close()
	event := netmon.RuleDeleted{
		Table:    52,
		Priority: 5210,
	}
	tw := eventbustest.NewWatcher(t, bus)

	t.Logf("Value before: %t", lt.r.ruleRestorePending.Load())
	if lt.r.ruleRestorePending.Load() {
		t.Errorf("rule deletion already ongoing")
	}
	injector := eventbustest.NewInjector(t, bus)
	eventbustest.Inject(injector, event)
	eventbustest.Expect(tw, eventbustest.Type[AddIPRules]())
}

func TestDelRouteIdempotent(t *testing.T) {
	fake := NewFakeOS(t)
	lt, _ := newLinuxRootTest(t)
	lt.r.nfr = fake.nfr
	defer lt.Close()

	for _, s := range []string{
		"192.0.2.0/24",  // RFC 5737
		"2001:DB8::/32", // RFC 3849
	} {
		cidr := netip.MustParsePrefix(s)
		if err := lt.r.addRoute(cidr); err != nil {
			t.Error(err)
			continue
		}
		for i := range 2 {
			if err := lt.r.delRoute(cidr); err != nil {
				t.Errorf("delRoute(i=%d): %v", i, err)
			}
		}
	}

	if t.Failed() {
		out := lt.logOutput.String()
		t.Logf("Log output:\n%s", out)
	}
}

func TestAddRemoveRules(t *testing.T) {
	fake := NewFakeOS(t)
	lt, _ := newLinuxRootTest(t)
	lt.r.nfr = fake.nfr
	defer lt.Close()
	r := lt.r

	step := func(name string, f func() error) {
		t.Logf("Doing %v ...", name)
		if err := f(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rules, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.Priority >= 5000 && r.Priority <= 5999 {
				t.Logf("Rule: %+v", r)
			}
		}
	}

	step("init_del_and_add", r.addIPRules)
	step("dup_add", r.justAddIPRules)
	step("del", r.delIPRules)
	step("dup_del", r.delIPRules)
}

func TestDebugListLinks(t *testing.T) {
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range links {
		t.Logf("Link: %+v", ln)
	}
}

func TestDebugListRoutes(t *testing.T) {
	// We need to pass a non-nil route to RouteListFiltered, along
	// with the netlink.RT_FILTER_TABLE bit set in the filter
	// mask, otherwise it ignores non-main routes.
	filter := &netlink.Route{}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		t.Logf("Route: %+v", r)
	}
}

var famName = map[int]string{
	netlink.FAMILY_ALL: "all",
	netlink.FAMILY_V4:  "v4",
	netlink.FAMILY_V6:  "v6",
}

func TestDebugListRules(t *testing.T) {
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6, netlink.FAMILY_ALL} {
		t.Run(famName[fam], func(t *testing.T) {
			rules, err := netlink.RuleList(fam)
			if err != nil {
				t.Skipf("skip; RuleList fails with: %v", err)
			}
			for _, r := range rules {
				t.Logf("Rule: %+v", r)
			}
		})
	}
}

func TestCheckIPRuleSupportsV6(t *testing.T) {
	err := linuxfw.CheckIPRuleSupportsV6(t.Logf)
	if err != nil && os.Getuid() != 0 {
		t.Skipf("skipping, error when not root: %v", err)
	}
	// Just log it. For interactive testing only.
	// Some machines running our tests might not have IPv6.
	t.Logf("Got: %v", err)
}

func TestBusyboxParseVersion(t *testing.T) {
	input := `BusyBox v1.34.1 (2022-09-01 16:10:29 UTC) multi-call binary.
BusyBox is copyrighted by many authors between 1998-2015.
Licensed under GPLv2. See source distribution for detailed
copyright notices.

Usage: busybox [function [arguments]...]
   or: busybox --list[-full]
   or: busybox --show SCRIPT
   or: busybox --install [-s] [DIR]
   or: function [arguments]...

	BusyBox is a multi-call binary that combines many common Unix
	utilities into a single executable.  Most people will create a
	link to busybox for each function they wish to use and BusyBox
	will act like whatever it was invoked as.
`

	v1, v2, v3, err := busyboxParseVersion(input)
	if err != nil {
		t.Fatalf("busyboxParseVersion() failed: %v", err)
	}

	if got, want := fmt.Sprintf("%d.%d.%d", v1, v2, v3), "1.34.1"; got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
}

func TestCIDRDiff(t *testing.T) {
	pfx := func(p ...string) []netip.Prefix {
		var ret []netip.Prefix
		for _, s := range p {
			ret = append(ret, netip.MustParsePrefix(s))
		}
		return ret
	}
	tests := []struct {
		old     []netip.Prefix
		new     []netip.Prefix
		wantAdd []netip.Prefix
		wantDel []netip.Prefix
		final   []netip.Prefix
	}{
		{
			old:     nil,
			new:     pfx("1.1.1.1/32"),
			wantAdd: pfx("1.1.1.1/32"),
			final:   pfx("1.1.1.1/32"),
		},
		{
			old:   pfx("1.1.1.1/32"),
			new:   pfx("1.1.1.1/32"),
			final: pfx("1.1.1.1/32"),
		},
		{
			old:     pfx("1.1.1.1/32", "2.3.4.5/32"),
			new:     pfx("1.1.1.1/32"),
			wantDel: pfx("2.3.4.5/32"),
			final:   pfx("1.1.1.1/32"),
		},
		{
			old:     pfx("1.1.1.1/32", "2.3.4.5/32"),
			new:     pfx("1.0.0.0/32", "3.4.5.6/32"),
			wantDel: pfx("1.1.1.1/32", "2.3.4.5/32"),
			wantAdd: pfx("1.0.0.0/32", "3.4.5.6/32"),
			final:   pfx("1.0.0.0/32", "3.4.5.6/32"),
		},
	}
	for _, tc := range tests {
		om := make(map[netip.Prefix]bool)
		for _, p := range tc.old {
			om[p] = true
		}
		var added []netip.Prefix
		var deleted []netip.Prefix
		fm, err := cidrDiff("test", om, tc.new, func(p netip.Prefix) error {
			if len(deleted) > 0 {
				t.Error("delete called before add")
			}
			added = append(added, p)
			return nil
		}, func(p netip.Prefix) error {
			deleted = append(deleted, p)
			return nil
		}, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		slices.SortFunc(added, netipx.ComparePrefix)
		slices.SortFunc(deleted, netipx.ComparePrefix)
		if !reflect.DeepEqual(added, tc.wantAdd) {
			t.Errorf("added = %v, want %v", added, tc.wantAdd)
		}
		if !reflect.DeepEqual(deleted, tc.wantDel) {
			t.Errorf("deleted = %v, want %v", deleted, tc.wantDel)
		}

		// Check that the final state is correct.
		if len(fm) != len(tc.final) {
			t.Fatalf("final state = %v, want %v", fm, tc.final)
		}
		for _, p := range tc.final {
			if !fm[p] {
				t.Errorf("final state = %v, want %v", fm, tc.final)
			}
		}
	}
}

var (
	fwmaskSupported     bool
	fwmaskSupportedOnce sync.Once
	fwmaskAdjustRe      = regexp.MustCompile(`(?m)(fwmark 0x[0-9a-f]+)/0x[0-9a-f]+`)
)

// adjustFwmask removes the "/0xmask" string from fwmask stanzas if the
// installed 'ip' binary does not support that format.
func adjustFwmask(t *testing.T, s string) string {
	t.Helper()
	fwmaskSupportedOnce.Do(func() {
		fwmaskSupported, _ = ipCmdSupportsFwmask()
	})
	if fwmaskSupported {
		return s
	}

	return fwmaskAdjustRe.ReplaceAllString(s, "$1")
}

func TestIPRulesForUBNT(t *testing.T) {
	// Override the global getDistroFunc
	getDistroFunc = func() distro.Distro {
		return distro.UBNT
	}
	defer func() { getDistroFunc = distro.Get }() // Restore original after the test

	expected := ubntIPRules
	actual := ipRules()

	if len(expected) != len(actual) {
		t.Fatalf("Expected %d rules, got %d", len(expected), len(actual))
	}

	for i, rule := range expected {
		if rule != actual[i] {
			t.Errorf("Rule mismatch at index %d: expected %+v, got %+v", i, rule, actual[i])
		}
	}
}

func TestUpdateMagicsockPortChange(t *testing.T) {
	nfr := &fakeIPTablesRunner{
		t:    t,
		ipt4: make(map[string][]string),
		ipt6: make(map[string][]string),
	}
	nfr.ipt4["filter/ts-input"] = []string{}

	r := &linuxRouter{
		logf:          logger.Discard,
		health:        new(health.Tracker),
		netfilterMode: netfilterOn,
		nfr:           nfr,
	}

	if err := r.updateMagicsockPort(12345, "udp4"); err != nil {
		t.Fatalf("failed to set initial port: %v", err)
	}

	if err := r.updateMagicsockPort(54321, "udp4"); err != nil {
		t.Fatalf("failed to update port: %v", err)
	}

	newPortRule := buildMagicsockPortRule(54321)
	hasNewRule := slices.Contains(nfr.ipt4["filter/ts-input"], newPortRule)

	if !hasNewRule {
		t.Errorf("firewall rule for NEW port 54321 not found.\nExpected: %s\nActual rules: %v",
			newPortRule, nfr.ipt4["filter/ts-input"])
	}

	oldPortRule := buildMagicsockPortRule(12345)
	hasOldRule := slices.Contains(nfr.ipt4["filter/ts-input"], oldPortRule)

	if hasOldRule {
		t.Errorf("firewall rule for OLD port 12345 still exists (should be deleted).\nFound: %s\nAll rules: %v",
			oldPortRule, nfr.ipt4["filter/ts-input"])
	}
}

// TestSetSkipsNetfilterAddonsWhenSetupFails verifies that Set does not invoke
// rule-management methods that depend on the ts-* chains existing when chain
// setup failed.
func TestSetSkipsNetfilterAddonsWhenSetupFails(t *testing.T) {
	nfr := newIPTablesRunner(t).(*fakeIPTablesRunner)
	nfr.addChainsErr = errors.New("kernel lacks netfilter support")

	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	defer mon.Close()

	fake := NewFakeOS(t)
	ht := health.NewTracker(bus)
	r, err := newUserspaceRouterAdvanced(logger.Discard, "tailscale0", mon, fake, ht, bus)
	if err != nil {
		t.Fatalf("newUserspaceRouterAdvanced: %v", err)
	}
	lr := r.(*linuxRouter)
	lr.nfr = nfr
	// Keep the fake netfilter runner's HasIPV6 the sole v6 signal; don't
	// consult the live /proc for the tun's IPv6 state. See #20447.
	lr.interfaceV6Usable = func() bool { return true }
	if err := lr.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	defer lr.Close()

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.101.102.103/10"),
		NetfilterMode: netfilterOn,
	}
	// Set must return an error (chain setup failed) but must not panic.
	if err := lr.Set(cfg); err == nil {
		t.Fatal("Set returned nil; want error because AddChains failed")
	}
	if lr.netfilterMode != netfilterOff {
		t.Errorf("netfilterMode = %v; want netfilterOff after failed AddChains", lr.netfilterMode)
	}
	if nfr.addConnmarkSaveCalls != 0 {
		t.Errorf("AddConnmarkSaveRule called %d times; want 0 when chain setup failed",
			nfr.addConnmarkSaveCalls)
	}
	if nfr.addExternalCGNATCalls != 0 {
		t.Errorf("AddExternalCGNATRules called %d times; want 0 when chain setup failed",
			nfr.addExternalCGNATCalls)
	}
}

// newTestLinuxRouter builds a linuxRouter backed by a fakeOS, brought up and
// ready for Set, mirroring TestSetSkipsNetfilterAddonsWhenSetupFails.
func newTestLinuxRouter(t *testing.T) (*linuxRouter, *fakeOS) {
	t.Helper()
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	t.Cleanup(func() { mon.Close() })

	fake := NewFakeOS(t)
	ht := health.NewTracker(bus)
	r, err := newUserspaceRouterAdvanced(logger.Discard, "tailscale0", mon, fake, ht, bus)
	if err != nil {
		t.Fatalf("newUserspaceRouterAdvanced: %v", err)
	}
	lr := r.(*linuxRouter)
	lr.nfr = fake.nfr
	// Keep the fake netfilter runner's HasIPV6 (noV6) the sole v6 signal;
	// don't consult the live /proc for the tun's IPv6 state. See #20447.
	lr.interfaceV6Usable = func() bool { return true }
	if err := lr.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	t.Cleanup(func() { lr.Close() })
	return lr, fake
}

// TestSetRemovesOrphanedTailscaleAddrs verifies that Set removes Tailscale-range
// addresses left on the interface by a previous instance (issue 19974), even
// though they're absent from the in-memory r.addrs map.
func TestSetRemovesOrphanedTailscaleAddrs(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)

	// Simulate a tailscale0 that survived a restart still carrying a prior
	// profile's CGNAT v4 and Tailscale ULA v6 addresses, plus a non-Tailscale
	// address that must be left alone.
	fake.ips = []string{
		"100.64.0.99/32 dev tailscale0",         // CGNAT v4 orphan
		"fd7a:115c:a1e0::99/128 dev tailscale0", // ULA v6 orphan
		"192.168.1.5/24 dev tailscale0",         // non-Tailscale, leave alone
	}
	slices.Sort(fake.ips)

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if !slices.Contains(fake.ips, "100.64.0.1/32 dev tailscale0") {
		t.Errorf("desired addr 100.64.0.1/32 not present; ips=%q", fake.ips)
	}
	for _, gone := range []string{
		"100.64.0.99/32 dev tailscale0",
		"fd7a:115c:a1e0::99/128 dev tailscale0",
	} {
		if slices.Contains(fake.ips, gone) {
			t.Errorf("orphaned Tailscale addr %q was not removed; ips=%q", gone, fake.ips)
		}
	}
	// Non-Tailscale address must be untouched.
	if !slices.Contains(fake.ips, "192.168.1.5/24 dev tailscale0") {
		t.Errorf("non-Tailscale addr 192.168.1.5/24 was wrongly removed; ips=%q", fake.ips)
	}
}

// TestSetRemovesOrphanWithNetfilter verifies orphan removal also works with
// netfilter enabled, where delAddress additionally tears down the address's
// loopback rule. An orphan from a previous instance has no such rule, so this
// guards that removing it isn't blocked by the loopback-rule deletion (see the
// iptables DelLoopbackRule DeleteIfExists handling).
func TestSetRemovesOrphanWithNetfilter(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)

	fake.ips = []string{
		"100.64.0.99/32 dev tailscale0", // CGNAT v4 orphan, no loopback rule
	}

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		NetfilterMode: netfilterOn,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if slices.Contains(fake.ips, "100.64.0.99/32 dev tailscale0") {
		t.Errorf("orphan was not removed with netfilter on; ips=%q", fake.ips)
	}
	if !slices.Contains(fake.ips, "100.64.0.1/32 dev tailscale0") {
		t.Errorf("desired addr 100.64.0.1/32 not present; ips=%q", fake.ips)
	}
}

// TestSetInstallsLoopbackRuleForExistingAddr covers the persisted-interface
// restart case: the node's own address is already on tailscale0 (so the kernel
// reports it), but its per-address loopback rule was flushed when the netfilter
// chains were rebuilt. Set must still install the loopback rule, i.e. it must
// not skip addAddress just because the address is already present -- which it
// would if a desired address were folded into the orphan set. See #19974.
func TestSetInstallsLoopbackRuleForExistingAddr(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)

	// The node's own address persisted on the interface across the restart.
	fake.ips = []string{
		"100.64.0.1/32 dev tailscale0",
	}

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		NetfilterMode: netfilterOn,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	nfr := fake.nfr.(*fakeIPTablesRunner)
	wantRule := "-i lo -s 100.64.0.1 -j ACCEPT"
	if !slices.Contains(nfr.ipt4["filter/ts-input"], wantRule) {
		t.Errorf("loopback rule %q not installed for already-present addr; ts-input=%q",
			wantRule, nfr.ipt4["filter/ts-input"])
	}
}

// TestSetOrphanScanGatedByAddrChange verifies the interface is scanned for
// orphans on the first Set and when LocalAddrs changes, but not for route-only
// updates -- so a subnet router churning routes doesn't pay for a scan on every
// Set.
func TestSetOrphanScanGatedByAddrChange(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)

	// First Set establishes steady state (scans, finds nothing to remove).
	if err := lr.Set(&Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		NetfilterMode: netfilterOff,
	}); err != nil {
		t.Fatalf("Set 1: %v", err)
	}

	// An orphan appears afterward. A route-only update leaves LocalAddrs
	// unchanged, so the scan is skipped and the orphan stays in place.
	fake.ips = append(fake.ips, "100.64.0.99/32 dev tailscale0")
	slices.Sort(fake.ips)
	if err := lr.Set(&Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		Routes:        mustCIDRs("10.0.0.0/24"),
		NetfilterMode: netfilterOff,
	}); err != nil {
		t.Fatalf("Set 2 (route-only): %v", err)
	}
	if !slices.Contains(fake.ips, "100.64.0.99/32 dev tailscale0") {
		t.Errorf("orphan removed on a route-only update; scan should have been skipped; ips=%q", fake.ips)
	}

	// When LocalAddrs changes, the scan runs again and the orphan is removed.
	if err := lr.Set(&Config{
		LocalAddrs:    mustCIDRs("100.64.0.2/32"),
		Routes:        mustCIDRs("10.0.0.0/24"),
		NetfilterMode: netfilterOff,
	}); err != nil {
		t.Fatalf("Set 3 (addr change): %v", err)
	}
	if slices.Contains(fake.ips, "100.64.0.99/32 dev tailscale0") {
		t.Errorf("orphan not removed after LocalAddrs change; ips=%q", fake.ips)
	}
}

// TestSetOrphanScanNotRetriedOnDuplicateLocalAddrs verifies the scan gate
// compares the desired address set rather than its length against r.addrs. A
// duplicate in LocalAddrs (or, equivalently, an address that fails to install)
// leaves r.addrs smaller than len(LocalAddrs); a length-based gate would then
// rescan on every Set. The set comparison treats the desired set as unchanged.
func TestSetOrphanScanNotRetriedOnDuplicateLocalAddrs(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)

	// LocalAddrs with a duplicate: cidrDiff dedups, so r.addrs ends up smaller
	// than len(LocalAddrs).
	dupCfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32", "100.64.0.1/32"),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(dupCfg); err != nil {
		t.Fatalf("Set 1: %v", err)
	}

	// An orphan appears; re-applying the same (duplicated) LocalAddrs must not
	// trigger a rescan, so the orphan stays.
	fake.ips = append(fake.ips, "100.64.0.99/32 dev tailscale0")
	slices.Sort(fake.ips)
	if err := lr.Set(dupCfg); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	if !slices.Contains(fake.ips, "100.64.0.99/32 dev tailscale0") {
		t.Errorf("rescan ran for an unchanged (duplicated) LocalAddrs; ips=%q", fake.ips)
	}
}

// TestSetKeepsNonTailscaleAddrs is the safety check: Set must never remove
// addresses outside Tailscale's ranges, even when they're not in the config.
func TestSetKeepsNonTailscaleAddrs(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)

	keep := []string{
		"192.168.1.5/24 dev tailscale0",        // non-Tailscale v4
		"fe80::1/64 dev tailscale0",            // link-local v6
		"100.115.92.5/32 dev tailscale0",       // ChromeOS VM range: in CGNAT, not a Tailscale IP
		"100.63.0.1/32 dev tailscale0",         // just below CGNAT 100.64.0.0/10
		"100.128.0.1/32 dev tailscale0",        // just above CGNAT
		"fd7a:115c:a1e1::1/128 dev tailscale0", // adjacent to the Tailscale ULA /48, not in it
	}
	fake.ips = append([]string(nil), keep...)
	slices.Sort(fake.ips)

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	for _, k := range keep {
		if !slices.Contains(fake.ips, k) {
			t.Errorf("non-Tailscale addr %q was wrongly removed; ips=%q", k, fake.ips)
		}
	}
}

func TestOrphanedAddrs(t *testing.T) {
	p := netip.MustParsePrefix
	// orphanedAddrs yields in kernelAddrs order, but compare as sets to be safe.
	got := set.SetOf(slices.Collect(orphanedAddrs(
		slices.Values([]netip.Prefix{p("100.64.0.1/32"), p("100.64.0.99/32"), p("fd7a:115c:a1e0::99/128")}),
		[]netip.Prefix{p("100.64.0.1/32")},
	)))
	want := set.SetOf([]netip.Prefix{p("100.64.0.99/32"), p("fd7a:115c:a1e0::99/128")})
	if !got.Equal(want) {
		t.Errorf("orphanedAddrs = %v; want %v", got.Slice(), want.Slice())
	}
	if got := slices.Collect(orphanedAddrs(slices.Values([]netip.Prefix(nil)), []netip.Prefix{p("100.64.0.1/32")})); got != nil {
		t.Errorf("orphanedAddrs(nil, ...) = %v; want nil", got)
	}
}

// TestGetV6AvailableNilNFR verifies the v6-availability checks don't panic when
// r.nfr is nil, which happens if setupNetfilterLocked failed earlier in Set.
// The orphan sweep reaches getV6Available via isDeletableAddr, so this
// must not deref a nil runner.
func TestGetV6AvailableNilNFR(t *testing.T) {
	r := &linuxRouter{} // nfr left nil
	if r.getV6Available() {
		t.Error("getV6Available() = true with nil nfr; want false")
	}
	if r.getV6FilteringAvailable() {
		t.Error("getV6FilteringAvailable() = true with nil nfr; want false")
	}
	if r.isDeletableAddr(netip.MustParseAddr("fd7a:115c:a1e0::99")) {
		t.Error("isDeletableAddr(v6) = true with nil nfr; want false")
	}
}

// TestSetSkipsV6OrphansWhenV6Unavailable verifies that when IPv6 is
// unavailable, Set does not enumerate v6 orphans for removal. delAddress
// no-ops on v6 in that state, so enumerating them would let cidrDiff record a
// delete that never happened; instead we leave them out of the reconcile.
func TestSetSkipsV6OrphansWhenV6Unavailable(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	fake.nfr.(*fakeIPTablesRunner).noV6 = true

	fake.ips = []string{
		"100.64.0.99/32 dev tailscale0",         // CGNAT v4 orphan, removable
		"fd7a:115c:a1e0::99/128 dev tailscale0", // ULA v6 orphan, not removable without v6
	}
	slices.Sort(fake.ips)

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32"),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// The v4 orphan is removed; the v6 orphan is left in place rather than
	// being treated as removed via a no-op delete.
	if slices.Contains(fake.ips, "100.64.0.99/32 dev tailscale0") {
		t.Errorf("v4 orphan was not removed; ips=%q", fake.ips)
	}
	if !slices.Contains(fake.ips, "fd7a:115c:a1e0::99/128 dev tailscale0") {
		t.Errorf("v6 orphan should be left alone when v6 is unavailable; ips=%q", fake.ips)
	}
}

// TestSetSkipsV6WhenInterfaceV6Unusable verifies that when global IPv6 is
// available (the netfilter runner reports HasIPV6) but the kernel has not
// enabled IPv6 on the tunnel interface itself -- e.g. the tun MTU is below the
// 1280-byte IPv6 minimum -- Set skips the v6 address rather than failing. This
// is the #20447 scenario: historically the v6 addAddress errored, aborting the
// whole router pass, which in turn suppressed DNS configuration.
func TestSetSkipsV6WhenInterfaceV6Unusable(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	// Global v6 is fine (fake nfr HasIPV6 defaults true), but the tun
	// interface has no usable v6.
	lr.interfaceV6Usable = func() bool { return false }

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32", "fd7a:115c:a1e0::1/128"),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// The v4 address is programmed; the v6 address is skipped rather than
	// attempted (which would have errored on a v6-less interface).
	if !slices.Contains(fake.ips, "100.64.0.1/32 dev tailscale0") {
		t.Errorf("v4 address was not programmed; ips=%q", fake.ips)
	}
	if slices.Contains(fake.ips, "fd7a:115c:a1e0::1/128 dev tailscale0") {
		t.Errorf("v6 address should be skipped when the interface has no usable v6; ips=%q", fake.ips)
	}
}

// TestSetSnapshotsV6Usable verifies that a single Set consults the
// per-interface IPv6 check (which reads /proc) once, rather than once per
// address and route, even though many getV6Available calls happen within it.
func TestSetSnapshotsV6Usable(t *testing.T) {
	lr, _ := newTestLinuxRouter(t)
	var calls int
	lr.interfaceV6Usable = func() bool {
		calls++
		return true
	}

	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.1/32", "fd7a:115c:a1e0::1/128"),
		Routes:        mustCIDRs("10.0.0.0/8", "fd00::/8"),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if calls != 1 {
		t.Errorf("interfaceV6Usable called %d times during one Set; want 1 (snapshotted)", calls)
	}
}

// TestCleanUpRemovesAllTailscaleAddrs verifies the teardown path removes every
// Tailscale-range address (IPv4 CGNAT and IPv6 ULA) while leaving non-Tailscale
// addresses alone.
func TestCleanUpRemovesAllTailscaleAddrs(t *testing.T) {
	fake := NewFakeOS(t)
	fake.ips = []string{
		"100.64.0.1/32 dev tailscale0",         // CGNAT v4
		"fd7a:115c:a1e0::1/128 dev tailscale0", // ULA v6
		"192.168.1.5/24 dev tailscale0",        // non-Tailscale, leave alone
		"fe80::1/64 dev tailscale0",            // link-local v6, leave alone
	}
	slices.Sort(fake.ips)

	removeOrphanedAddrsForCleanup(t.Logf, fake, "tailscale0")

	for _, gone := range []string{
		"100.64.0.1/32 dev tailscale0",
		"fd7a:115c:a1e0::1/128 dev tailscale0",
	} {
		if slices.Contains(fake.ips, gone) {
			t.Errorf("Tailscale addr %q was not removed during cleanup; ips=%q", gone, fake.ips)
		}
	}
	for _, keep := range []string{
		"192.168.1.5/24 dev tailscale0",
		"fe80::1/64 dev tailscale0",
	} {
		if !slices.Contains(fake.ips, keep) {
			t.Errorf("non-Tailscale addr %q was wrongly removed during cleanup; ips=%q", keep, fake.ips)
		}
	}
}

// TestCleanUpRemovesV6OrphanWithoutNetfilter is the teardown counterpart to
// TestSetSkipsV6OrphansWhenV6Unavailable: with a nil netfilter runner (so
// getV6Available is false), cleanup must still remove an IPv6 ULA orphan.
func TestCleanUpRemovesV6OrphanWithoutNetfilter(t *testing.T) {
	fake := NewFakeOS(t)
	fake.ips = []string{
		"fd7a:115c:a1e0::99/128 dev tailscale0", // ULA v6 orphan
	}

	removeOrphanedAddrsForCleanup(t.Logf, fake, "tailscale0")

	if slices.Contains(fake.ips, "fd7a:115c:a1e0::99/128 dev tailscale0") {
		t.Errorf("v6 orphan was not removed during cleanup; ips=%q", fake.ips)
	}
}

// TestCleanUpKeepsNearRangeAddrs verifies the teardown sweep removes real
// Tailscale orphans while leaving addresses at the edges of Tailscale's ranges
// untouched. In particular the ChromeOS VM range is inside CGNAT 100.64.0.0/10
// but excluded by tsaddr.IsTailscaleIP, so a naive CGNAT-prefix check would
// wrongly delete it.
func TestCleanUpKeepsNearRangeAddrs(t *testing.T) {
	fake := NewFakeOS(t)
	remove := []string{
		"100.64.0.99/32 dev tailscale0",         // CGNAT v4 orphan
		"fd7a:115c:a1e0::99/128 dev tailscale0", // Tailscale ULA v6 orphan
	}
	keep := []string{
		"100.115.92.5/32 dev tailscale0",       // ChromeOS VM range: in CGNAT, not a Tailscale IP
		"100.63.0.1/32 dev tailscale0",         // just below CGNAT
		"100.128.0.1/32 dev tailscale0",        // just above CGNAT
		"fd7a:115c:a1e1::1/128 dev tailscale0", // adjacent to the Tailscale ULA /48
		"192.168.1.5/24 dev tailscale0",        // non-Tailscale v4
		"fe80::1/64 dev tailscale0",            // link-local v6
	}
	fake.ips = append(append([]string(nil), remove...), keep...)
	slices.Sort(fake.ips)

	removeOrphanedAddrsForCleanup(t.Logf, fake, "tailscale0")

	for _, r := range remove {
		if slices.Contains(fake.ips, r) {
			t.Errorf("orphan %q was not removed during cleanup; ips=%q", r, fake.ips)
		}
	}
	for _, k := range keep {
		if !slices.Contains(fake.ips, k) {
			t.Errorf("near-range non-Tailscale addr %q was wrongly removed during cleanup; ips=%q", k, fake.ips)
		}
	}
}

// TestCleanUpOnlyTouchesTunInterface guards that the sweep is scoped to the
// tunnel interface. 100.64.0.0/10 is shared ISP CGNAT space, so a host may carry
// a non-Tailscale CGNAT address on its WAN/other interface; the sweep enumerates
// and deletes only on tailscale0, so such an address on eth0 must never be
// touched even though it's in the CGNAT range.
func TestCleanUpOnlyTouchesTunInterface(t *testing.T) {
	fake := NewFakeOS(t)
	fake.ips = []string{
		"100.64.0.99/32 dev tailscale0", // our orphan on the tun -> removed
		"100.64.0.5/32 dev eth0",        // someone else's CGNAT on WAN -> must survive
	}
	slices.Sort(fake.ips)

	removeOrphanedAddrsForCleanup(t.Logf, fake, "tailscale0")

	if slices.Contains(fake.ips, "100.64.0.99/32 dev tailscale0") {
		t.Errorf("tailscale0 orphan was not removed; ips=%q", fake.ips)
	}
	if !slices.Contains(fake.ips, "100.64.0.5/32 dev eth0") {
		t.Errorf("non-Tailscale CGNAT addr on eth0 was wrongly removed; ips=%q", fake.ips)
	}
}

// routeSourceSteps are router configurations that add, change and remove
// addresses and routes of both families, with a reset in between.
func routeSourceSteps() []*Config {
	return []*Config{
		{
			LocalAddrs:    mustCIDRs("100.64.0.2/32", "fd7a:115c:a1e0::2/128", "198.18.0.0/32"),
			Routes:        mustCIDRs("100.64.0.1/32", "198.18.0.1/32", "fd7a:115c:a1e0::1/128", "10.0.0.0/24"),
			NetfilterMode: netfilterOn,
		},
		{
			LocalAddrs:    mustCIDRs("100.64.0.2/32", "fd7a:115c:a1e0::2/128", "198.18.0.4/32"),
			Routes:        mustCIDRs("100.64.0.1/32", "198.18.0.5/32", "fd7a:115c:a1e0::1/128", "fd00:1::/64"),
			NetfilterMode: netfilterOn,
		},
		nil,
		{
			LocalAddrs:    mustCIDRs("100.64.0.2/32"),
			Routes:        mustCIDRs("100.64.0.1/32"),
			NetfilterMode: netfilterOff,
		},
	}
}

// TestSetEmptyRouteSourcesUnchanged pins the commands Set runs for
// configurations without route sources. A nil RouteSources, an empty one
// and one naming only routes that are not in Routes all give exactly the
// commands the router ran before route sources existed.
func TestSetEmptyRouteSourcesUnchanged(t *testing.T) {
	want := [][]string{
		{
			"ip -oneline addr show dev tailscale0",
			"ip addr add 100.64.0.2/32 dev tailscale0",
			"ip addr add 198.18.0.0/32 dev tailscale0",
			"ip addr add fd7a:115c:a1e0::2/128 dev tailscale0",
			"ip route add 10.0.0.0/24 dev tailscale0 table 52",
			"ip route add 100.64.0.1/32 dev tailscale0 table 52",
			"ip route add 198.18.0.1/32 dev tailscale0 table 52",
			"ip route add fd7a:115c:a1e0::1/128 dev tailscale0 table 52",
		},
		{
			"ip -oneline addr show dev tailscale0",
			"ip addr add 198.18.0.4/32 dev tailscale0",
			"ip addr del 198.18.0.0/32 dev tailscale0",
			"ip route add 198.18.0.5/32 dev tailscale0 table 52",
			"ip route add fd00:1::/64 dev tailscale0 table 52",
			"ip route del 10.0.0.0/24 dev tailscale0 table 52",
			"ip route del 198.18.0.1/32 dev tailscale0 table 52",
		},
		{
			"ip -oneline addr show dev tailscale0",
			"ip addr del 100.64.0.2/32 dev tailscale0",
			"ip addr del 198.18.0.4/32 dev tailscale0",
			"ip addr del fd7a:115c:a1e0::2/128 dev tailscale0",
			"ip route del 100.64.0.1/32 dev tailscale0 table 52",
			"ip route del 198.18.0.5/32 dev tailscale0 table 52",
			"ip route del fd00:1::/64 dev tailscale0 table 52",
			"ip route del fd7a:115c:a1e0::1/128 dev tailscale0 table 52",
		},
		{
			"ip -oneline addr show dev tailscale0",
			"ip addr add 100.64.0.2/32 dev tailscale0",
			"ip route add 100.64.0.1/32 dev tailscale0 table 52",
		},
	}
	for _, tc := range []struct {
		name    string
		sources map[netip.Prefix]netip.Addr
	}{
		{"nil", nil},
		{"empty", map[netip.Prefix]netip.Addr{}},
		{"unknown routes", map[netip.Prefix]netip.Addr{
			netip.MustParsePrefix("100.64.0.9/32"):         netip.MustParseAddr("100.64.0.2"),
			netip.MustParsePrefix("fd7a:115c:a1e0::9/128"): netip.MustParseAddr("fd7a:115c:a1e0::2"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lr, fake := newTestLinuxRouter(t)
			var got [][]string
			for i, cfg := range routeSourceSteps() {
				if cfg != nil {
					cfg.RouteSources = tc.sources
				}
				fake.calls = nil
				if err := lr.Set(cfg); err != nil {
					t.Fatalf("Set %d: %v", i, err)
				}
				// cidrDiff walks maps, so only the set of commands per
				// Set is stable, not their order.
				calls := slices.Clone(fake.calls)
				slices.Sort(calls)
				got = append(got, calls)
			}
			if d := cmp.Diff(want, got); d != "" {
				t.Errorf("commands (-want +got):\n%s", d)
			}
		})
	}
}

// routeSources builds a RouteSources map from route, source pairs.
func routeSources(kv ...string) map[netip.Prefix]netip.Addr {
	m := make(map[netip.Prefix]netip.Addr)
	for i := 0; i < len(kv); i += 2 {
		m[netip.MustParsePrefix(kv[i])] = netip.MustParseAddr(kv[i+1])
	}
	return m
}

// setCalls runs Set and returns the commands it ran, sorted.
func setCalls(t *testing.T, lr *linuxRouter, fake *fakeOS, cfg *Config) []string {
	t.Helper()
	fake.calls = nil
	if err := lr.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}
	calls := slices.Clone(fake.calls)
	slices.Sort(calls)
	return calls
}

func wantRoutes(t *testing.T, fake *fakeOS, want ...string) {
	t.Helper()
	slices.Sort(want)
	if d := cmp.Diff(want, fake.routes); d != "" {
		t.Errorf("routes (-want +got):\n%s", d)
	}
}

// replaceCalls returns the "ip route replace" commands of calls.
func replaceCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "ip route replace ") {
			out = append(out, c)
		}
	}
	return out
}

func TestSetRouteSources(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	addrs := mustCIDRs(
		"100.64.0.2/32", "fd7a:115c:a1e0::2/128", // tailnet a's self
		"198.18.0.0/32", "fd00:1::/128", // tailnet b's virtual self
	)
	routes := mustCIDRs(
		"100.64.0.1/32", "fd7a:115c:a1e0::1/128", // a's peer
		"198.18.0.1/32", "fd00:1::1/128", // b's peer
		"100.100.100.100/32", "fd7a:115c:a1e0::53/128", // quad-100
		"10.0.0.0/24", // no source
	)
	cfg := func(addrs []netip.Prefix, routes []netip.Prefix, kv ...string) *Config {
		return &Config{
			LocalAddrs:    addrs,
			Routes:        routes,
			RouteSources:  routeSources(kv...),
			NetfilterMode: netfilterOn,
		}
	}
	first := cfg(addrs, routes,
		"100.64.0.1/32", "100.64.0.2",
		"fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2",
		"198.18.0.1/32", "198.18.0.0",
		"fd00:1::1/128", "fd00:1::",
		"100.100.100.100/32", "100.64.0.2",
		"fd7a:115c:a1e0::53/128", "fd7a:115c:a1e0::2",
	)

	t.Run("after addresses", func(t *testing.T) {
		fake.calls = nil
		if err := lr.Set(first); err != nil {
			t.Fatalf("Set: %v", err) // the fake rejects unassigned sources
		}
		calls := fake.calls
		// Routes are added as before, then given their source once the
		// address is on the interface.
		for _, r := range routes {
			addAt := slices.Index(calls, fmt.Sprintf("ip route add %s dev tailscale0 table 52", r))
			if addAt < 0 {
				t.Errorf("route %v not added; calls %q", r, calls)
				continue
			}
			src, ok := first.RouteSources[r]
			if !ok {
				continue
			}
			repAt := slices.Index(calls, fmt.Sprintf("ip route replace %s dev tailscale0 src %s table 52", r, src))
			addrAt := slices.IndexFunc(calls, func(c string) bool {
				return strings.HasPrefix(c, fmt.Sprintf("ip addr add %s/", src))
			})
			if repAt < addAt || repAt < addrAt || addrAt < 0 {
				t.Errorf("route %v: add at %d, address %v at %d, source at %d; calls %q", r, addAt, src, addrAt, repAt, calls)
			}
		}
		if n := len(replaceCalls(calls)); n != len(first.RouteSources) {
			t.Errorf("%d replace commands, want %d: %q", n, len(first.RouteSources), calls)
		}
		wantRoutes(t, fake,
			"10.0.0.0/24 dev tailscale0 table 52",
			"100.100.100.100/32 dev tailscale0 src 100.64.0.2 table 52",
			"100.64.0.1/32 dev tailscale0 src 100.64.0.2 table 52",
			"198.18.0.1/32 dev tailscale0 src 198.18.0.0 table 52",
			"fd00:1::1/128 dev tailscale0 src fd00:1:: table 52",
			"fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52",
			"fd7a:115c:a1e0::53/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52",
		)
		// Setting the same configuration again changes nothing.
		if calls := setCalls(t, lr, fake, first.Clone()); len(calls) != 0 {
			t.Errorf("same config ran %q", calls)
		}
	})

	t.Run("change and removal", func(t *testing.T) {
		c := first.Clone()
		c.RouteSources[netip.MustParsePrefix("100.100.100.100/32")] = netip.MustParseAddr("198.18.0.0")
		delete(c.RouteSources, netip.MustParsePrefix("fd00:1::1/128"))
		got := setCalls(t, lr, fake, c)
		want := []string{
			"ip route replace 100.100.100.100/32 dev tailscale0 src 198.18.0.0 table 52",
			"ip route replace fd00:1::1/128 dev tailscale0 table 52",
		}
		if d := cmp.Diff(want, got); d != "" {
			t.Errorf("commands (-want +got):\n%s", d)
		}
		wantRoutes(t, fake,
			"10.0.0.0/24 dev tailscale0 table 52",
			"100.100.100.100/32 dev tailscale0 src 198.18.0.0 table 52",
			"100.64.0.1/32 dev tailscale0 src 100.64.0.2 table 52",
			"198.18.0.1/32 dev tailscale0 src 198.18.0.0 table 52",
			"fd00:1::1/128 dev tailscale0 table 52",
			"fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52",
			"fd7a:115c:a1e0::53/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52",
		)
	})

	// b's virtual self moves. Deleting its old IPv4 address makes the
	// kernel flush the routes using it as their source, and deleting the
	// IPv6 one strips it from routes; the new sources bring them back.
	moved := cfg(mustCIDRs("100.64.0.2/32", "fd7a:115c:a1e0::2/128", "198.18.0.4/32", "fd00:1::4/128"), routes,
		"100.64.0.1/32", "100.64.0.2",
		"fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2",
		"198.18.0.1/32", "198.18.0.4",
		"fd00:1::1/128", "fd00:1::4",
		"100.100.100.100/32", "198.18.0.4",
		"fd7a:115c:a1e0::53/128", "fd00:1::4",
	)
	t.Run("self moves", func(t *testing.T) {
		got := replaceCalls(setCalls(t, lr, fake, moved))
		want := []string{
			"ip route replace 100.100.100.100/32 dev tailscale0 src 198.18.0.4 table 52",
			"ip route replace 198.18.0.1/32 dev tailscale0 src 198.18.0.4 table 52",
			"ip route replace fd00:1::1/128 dev tailscale0 src fd00:1::4 table 52",
			"ip route replace fd7a:115c:a1e0::53/128 dev tailscale0 src fd00:1::4 table 52",
		}
		if d := cmp.Diff(want, got); d != "" {
			t.Errorf("replace commands (-want +got):\n%s", d)
		}
		wantRoutes(t, fake,
			"10.0.0.0/24 dev tailscale0 table 52",
			"100.100.100.100/32 dev tailscale0 src 198.18.0.4 table 52",
			"100.64.0.1/32 dev tailscale0 src 100.64.0.2 table 52",
			"198.18.0.1/32 dev tailscale0 src 198.18.0.4 table 52",
			"fd00:1::1/128 dev tailscale0 src fd00:1::4 table 52",
			"fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52",
			"fd7a:115c:a1e0::53/128 dev tailscale0 src fd00:1::4 table 52",
		)
	})

	// A route that goes away takes its source with it: when it comes
	// back, it gets its source again.
	t.Run("route removal clears tracking", func(t *testing.T) {
		without := moved.Clone()
		without.Routes = slices.DeleteFunc(without.Routes, func(p netip.Prefix) bool {
			return p == netip.MustParsePrefix("198.18.0.1/32") || p == netip.MustParsePrefix("fd00:1::1/128")
		})
		got := setCalls(t, lr, fake, without)
		want := []string{
			"ip route del 198.18.0.1/32 dev tailscale0 table 52",
			"ip route del fd00:1::1/128 dev tailscale0 table 52",
		}
		if d := cmp.Diff(want, got); d != "" {
			t.Errorf("commands (-want +got):\n%s", d)
		}
		for _, p := range mustCIDRs("198.18.0.1/32", "fd00:1::1/128") {
			if src, ok := lr.routeSrc[p]; ok {
				t.Errorf("removed route %v still tracked with source %v", p, src)
			}
		}
		got = setCalls(t, lr, fake, moved.Clone())
		want = []string{
			"ip route add 198.18.0.1/32 dev tailscale0 table 52",
			"ip route add fd00:1::1/128 dev tailscale0 table 52",
			"ip route replace 198.18.0.1/32 dev tailscale0 src 198.18.0.4 table 52",
			"ip route replace fd00:1::1/128 dev tailscale0 src fd00:1::4 table 52",
		}
		if d := cmp.Diff(want, got); d != "" {
			t.Errorf("commands (-want +got):\n%s", d)
		}
	})

	t.Run("reset", func(t *testing.T) {
		setCalls(t, lr, fake, nil)
		wantRoutes(t, fake)
		if len(lr.routeSrc) != 0 {
			t.Errorf("sources tracked after reset: %v", lr.routeSrc)
		}
		if got := replaceCalls(setCalls(t, lr, fake, first.Clone())); len(got) != len(first.RouteSources) {
			t.Errorf("after reset, replace commands %q", got)
		}
	})

	t.Run("close", func(t *testing.T) {
		if err := lr.Close(); err != nil {
			t.Fatal(err)
		}
		if lr.routeSrc != nil {
			t.Errorf("sources tracked after Close: %v", lr.routeSrc)
		}
	})
}

// TestSetRouteSourcesIgnored checks that sources the kernel would reject
// are left out instead of failing Set, and that a route whose source
// becomes unusable loses it.
func TestSetRouteSourcesIgnored(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	var logs tstest.MemLogger
	lr.logf = logs.Logf
	cfg := &Config{
		LocalAddrs: mustCIDRs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
		Routes:     mustCIDRs("100.64.0.1/32", "100.64.0.3/32", "100.64.0.4/32", "fd7a:115c:a1e0::1/128"),
		RouteSources: map[netip.Prefix]netip.Addr{
			netip.MustParsePrefix("100.64.0.1/32"):         netip.MustParseAddr("fd7a:115c:a1e0::2"), // wrong family
			netip.MustParsePrefix("100.64.0.3/32"):         netip.MustParseAddr("100.64.0.9"),        // not local
			netip.MustParsePrefix("100.64.0.4/32"):         {},                                       // zero
			netip.MustParsePrefix("fd7a:115c:a1e0::1/128"): netip.MustParseAddr("fd7a:115c:a1e0::2"),
		},
		NetfilterMode: netfilterOff,
	}
	got := replaceCalls(setCalls(t, lr, fake, cfg))
	want := []string{"ip route replace fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52"}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("replace commands (-want +got):\n%s", d)
	}
	wantLog := "ignoring the sources of 2 routes (first: route 100.64.0.1/32, source fd7a:115c:a1e0::2)"
	if !strings.Contains(logs.String(), wantLog) {
		t.Errorf("no log %q in:\n%s", wantLog, logs.String())
	}
	if strings.Contains(logs.String(), "100.64.0.4/32") {
		t.Errorf("zero source logged:\n%s", logs.String())
	}

	// The IPv6 self goes away while the hint still names it: the route
	// keeps working without a source.
	cfg = cfg.Clone()
	cfg.LocalAddrs = mustCIDRs("100.64.0.2/32")
	got = replaceCalls(setCalls(t, lr, fake, cfg))
	want = []string{"ip route replace fd7a:115c:a1e0::1/128 dev tailscale0 table 52"}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("replace commands (-want +got):\n%s", d)
	}
	if len(lr.routeSrc) != 0 {
		t.Errorf("tracked %v", lr.routeSrc)
	}
}

// TestSetRouteSourcesV6Unavailable checks that IPv6 route sources are
// skipped, like IPv6 routes and addresses, when IPv6 is unavailable.
func TestSetRouteSourcesV6Unavailable(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	fake.nfr.(*fakeIPTablesRunner).noV6 = true
	cfg := &Config{
		LocalAddrs:    mustCIDRs("100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
		Routes:        mustCIDRs("100.64.0.1/32", "fd7a:115c:a1e0::1/128"),
		RouteSources:  routeSources("100.64.0.1/32", "100.64.0.2", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2"),
		NetfilterMode: netfilterOff,
	}
	got := replaceCalls(setCalls(t, lr, fake, cfg))
	want := []string{"ip route replace 100.64.0.1/32 dev tailscale0 src 100.64.0.2 table 52"}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("replace commands (-want +got):\n%s", d)
	}
	wantRoutes(t, fake, "100.64.0.1/32 dev tailscale0 src 100.64.0.2 table 52")
}

// TestSetRouteSourceFailure checks that a source the kernel refuses (for
// example an IPv6 address whose duplicate address detection has not
// finished) fails Set, leaves the route and its tracked source as they
// were, and is applied by the next Set of the same configuration.
func TestSetRouteSourceFailure(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	route := netip.MustParsePrefix("fd7a:115c:a1e0::1/128")
	self2, self3 := netip.MustParseAddr("fd7a:115c:a1e0::2"), netip.MustParseAddr("fd7a:115c:a1e0::3")
	cfg := &Config{
		LocalAddrs:    mustCIDRs("fd7a:115c:a1e0::2/128"),
		Routes:        []netip.Prefix{route},
		RouteSources:  map[netip.Prefix]netip.Addr{route: self2},
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatal(err)
	}

	// The source moves to a new address the kernel can't use yet.
	cfg = cfg.Clone()
	cfg.LocalAddrs = append(cfg.LocalAddrs, netip.PrefixFrom(self3, 128))
	cfg.RouteSources[route] = self3
	lr.cmd = pendingAddrRunner{fake, "ip addr add fd7a:115c:a1e0::3/128 dev tailscale0"}
	err := lr.Set(cfg)
	if err == nil || !strings.Contains(err.Error(), "Invalid argument") {
		t.Fatalf("Set = %v, want the kernel's error", err)
	}
	if got := lr.routeSrc[route]; got != self2 {
		t.Errorf("tracked source after failure = %v, want %v", got, self2)
	}
	wantRoutes(t, fake, "fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::2 table 52")

	// The address is ready now: the same configuration applies the source.
	fake.ips = append(fake.ips, "fd7a:115c:a1e0::3/128 dev tailscale0")
	slices.Sort(fake.ips)
	lr.cmd = fake
	got := setCalls(t, lr, fake, cfg)
	want := []string{"ip route replace fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::3 table 52"}
	if d := cmp.Diff(want, got); d != "" {
		t.Errorf("commands (-want +got):\n%s", d)
	}
	if got := lr.routeSrc[route]; got != self3 {
		t.Errorf("tracked source = %v, want %v", got, self3)
	}
	wantRoutes(t, fake, "fd7a:115c:a1e0::1/128 dev tailscale0 src fd7a:115c:a1e0::3 table 52")
}

// pendingAddrRunner is a commandRunner whose command add succeeds
// without adding the address to the fake OS, like an IPv6 address the
// kernel does not accept as a route source until its duplicate address
// detection finishes.
type pendingAddrRunner struct {
	*fakeOS
	add string
}

func (r pendingAddrRunner) run(args ...string) error {
	if cmd := strings.Join(args, " "); cmd == r.add {
		r.calls = append(r.calls, cmd)
		return nil
	}
	return r.fakeOS.run(args...)
}

// TestRouteSourcesNetlink applies route sources through netlink to a real
// TUN and checks what the kernel stores and which source it picks. It
// needs root; unshare -rn (a user and network namespace) also works. It
// only uses documentation prefixes, and its ip rules match only those.
func TestRouteSourcesNetlink(t *testing.T) {
	fake := NewFakeOS(t)
	lt, _ := newLinuxRootTest(t)
	defer lt.Close()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("router log:\n%s", lt.logOutput.String())
		}
	})
	r := lt.r
	r.nfr = fake.nfr
	if !r.ipRuleAvailable {
		t.Skip("no policy routing")
	}
	link, err := r.link()
	if err != nil {
		t.Fatal(err)
	}
	for _, dst := range mustCIDRs("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32") {
		rule := netlink.NewRule()
		rule.Priority = 5280
		rule.Table = tailscaleRouteTable.Num
		rule.Dst = netipx.PrefixIPNet(dst)
		rule.Family = netlink.FAMILY_V4
		if dst.Addr().Is6() {
			rule.Family = netlink.FAMILY_V6
		}
		if err := netlink.RuleAdd(rule); err != nil {
			t.Fatalf("adding rule for %v: %v", dst, err)
		}
		defer netlink.RuleDel(rule)
	}

	// stored returns the preferred sources of the TUN's routes in table 52.
	stored := func() map[netip.Prefix]netip.Addr {
		t.Helper()
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
			&netlink.Route{Table: tailscaleRouteTable.Num, LinkIndex: link.Attrs().Index},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
		if err != nil {
			t.Fatal(err)
		}
		m := make(map[netip.Prefix]netip.Addr)
		for _, rt := range routes {
			p, _ := netipx.FromStdIPNet(rt.Dst)
			src, _ := netip.AddrFromSlice(rt.Src)
			m[p] = src.Unmap()
		}
		return m
	}
	// picked returns the source the kernel picks for traffic to dst.
	picked := func(dst string) netip.Addr {
		t.Helper()
		routes, err := netlink.RouteGet(net.ParseIP(dst))
		if err != nil || len(routes) == 0 {
			t.Fatalf("route get %v: %v %v", dst, routes, err)
		}
		src, _ := netip.AddrFromSlice(routes[0].Src)
		return src.Unmap()
	}
	set := func(cfg *Config) {
		t.Helper()
		if err := r.Set(cfg); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	a := netip.MustParseAddr
	routes := mustCIDRs("192.0.2.2/32", "198.51.100.2/32", "2001:db8:a::2/128", "2001:db8:b::2/128", "203.0.113.0/24")
	cfg := func(selfB4, selfB6 string, withSources bool) *Config {
		c := &Config{
			LocalAddrs:    mustCIDRs("192.0.2.1/32", "2001:db8:a::1/128", selfB4+"/32", selfB6+"/128"),
			Routes:        routes,
			NetfilterMode: netfilterOff,
		}
		if withSources {
			c.RouteSources = routeSources(
				"192.0.2.2/32", "192.0.2.1",
				"2001:db8:a::2/128", "2001:db8:a::1",
				"198.51.100.2/32", selfB4,
				"2001:db8:b::2/128", selfB6,
			)
		}
		return c
	}
	check := func(selfB4, selfB6 string) {
		t.Helper()
		want := map[netip.Prefix]netip.Addr{
			netip.MustParsePrefix("192.0.2.2/32"):      a("192.0.2.1"),
			netip.MustParsePrefix("2001:db8:a::2/128"): a("2001:db8:a::1"),
			netip.MustParsePrefix("198.51.100.2/32"):   a(selfB4),
			netip.MustParsePrefix("2001:db8:b::2/128"): a(selfB6),
			netip.MustParsePrefix("203.0.113.0/24"):    {},
		}
		if d := cmp.Diff(want, stored(), cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{})); d != "" {
			t.Errorf("stored sources (-want +got):\n%s", d)
		}
		for dst, src := range map[string]netip.Addr{
			"192.0.2.2": a("192.0.2.1"), "198.51.100.2": a(selfB4),
			"2001:db8:a::2": a("2001:db8:a::1"), "2001:db8:b::2": a(selfB6),
		} {
			if got := picked(dst); got != src {
				t.Errorf("kernel picks %v for %v, want %v", got, dst, src)
			}
		}
	}

	// The addresses are new: the sources go in right after them.
	set(cfg("198.51.100.1", "2001:db8:b::1", true))
	check("198.51.100.1", "2001:db8:b::1")

	// b's self moves. Deleting its old IPv4 address flushes the routes
	// that use it, deleting the IPv6 one clears it from routes.
	set(cfg("198.51.100.3", "2001:db8:b::3", true))
	check("198.51.100.3", "2001:db8:b::3")

	// Without sources, the routes are as the router always made them.
	set(cfg("198.51.100.3", "2001:db8:b::3", false))
	for p, src := range stored() {
		if src.IsValid() {
			t.Errorf("route %v keeps source %v", p, src)
		}
	}
	t.Logf("without sources the kernel picks %v for 192.0.2.2 and %v for 198.51.100.2", picked("192.0.2.2"), picked("198.51.100.2"))

	set(nil)
	if got := stored(); len(got) != 0 {
		t.Errorf("routes left after reset: %v", got)
	}
}

// TestSetRouteSourceTentative checks that an IPv6 source the kernel
// refuses with EINVAL, as it does for a moment after the address is added
// (while it is tentative), is retried a bounded number of times, and that
// other failures are not.
func TestSetRouteSourceTentative(t *testing.T) {
	tstest.Replace(t, &srcRetryDelay, time.Microsecond)
	tests := []struct {
		name      string
		src       string
		refusals  int  // replace commands refused before one succeeds
		wantTries int  // replace commands run
		wantErr   bool // Set fails
	}{
		{"v6 ready after retries", "fd7a:115c:a1e0::2", 3, 4, false},
		{"v6 never ready", "fd7a:115c:a1e0::2", 1000, srcRetries + 1, true},
		{"v4 not retried", "100.64.0.2", 1000, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lr, fake := newTestLinuxRouter(t)
			src := netip.MustParseAddr(tt.src)
			route := netip.PrefixFrom(src.Next(), src.BitLen())
			runner := &refusingRunner{fakeOS: fake, refusals: tt.refusals}
			lr.cmd = runner
			err := lr.Set(&Config{
				LocalAddrs:    []netip.Prefix{netip.PrefixFrom(src, src.BitLen())},
				Routes:        []netip.Prefix{route},
				RouteSources:  map[netip.Prefix]netip.Addr{route: src},
				NetfilterMode: netfilterOff,
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Set = %v, want error %v", err, tt.wantErr)
			}
			if runner.tries != tt.wantTries {
				t.Errorf("%d replace commands, want %d", runner.tries, tt.wantTries)
			}
			if got, want := lr.routeSrc[route].IsValid(), !tt.wantErr; got != want {
				t.Errorf("source tracked = %v, want %v", got, want)
			}
		})
	}
}

// TestSetRouteSourceTentativeBudget checks that the IPv6 tentative-source
// retry budget is shared per source within a Set, not per route.
func TestSetRouteSourceTentativeBudget(t *testing.T) {
	tstest.Replace(t, &srcRetryDelay, time.Microsecond)
	tests := []struct {
		name      string
		sources   []string
		routes    []string
		wantTries int
		wantErr   bool
	}{
		{
			name:      "one source, three routes",
			sources:   []string{"fd7a:115c:a1e0::2"},
			routes:    []string{"fd7a:115c:a1e0::3/128", "fd7a:115c:a1e0::4/128", "fd7a:115c:a1e0::5/128"},
			wantTries: srcRetries + 3, // srcRetries for the source + 1 per route = 50 + 3
			wantErr:   true,
		},
		{
			name:      "two sources, two routes each",
			sources:   []string{"fd7a:115c:a1e0::2", "fd7a:115c:a1e0::12"},
			routes:    []string{"fd7a:115c:a1e0::3/128", "fd7a:115c:a1e0::4/128", "fd7a:115c:a1e0::13/128", "fd7a:115c:a1e0::14/128"},
			wantTries: 2*(srcRetries+1) + 2, // 2 sources: (srcRetries+1) each + 2 routes = 102 + 2
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lr, fake := newTestLinuxRouter(t)

			// Parse sources and routes
			srcAddrs := make([]netip.Addr, len(tt.sources))
			for i, s := range tt.sources {
				srcAddrs[i] = netip.MustParseAddr(s)
			}

			routePrefixes := mustCIDRs(tt.routes...)
			tsaddr.SortPrefixes(routePrefixes)

			// Build RouteSources map: assign sources to routes based on name prefix
			routeSources := make(map[netip.Prefix]netip.Addr)
			for _, route := range routePrefixes {
				routeIP := route.Addr().String()
				// Assign sources based on whether route IP contains ::3/::4 (src 0) or ::13/::14 (src 1)
				if len(srcAddrs) == 1 {
					routeSources[route] = srcAddrs[0]
				} else if strings.Contains(routeIP, "::13") || strings.Contains(routeIP, "::14") {
					routeSources[route] = srcAddrs[1]
				} else {
					routeSources[route] = srcAddrs[0]
				}
			}

			runner := &refusingRunner{fakeOS: fake, refusals: 1000}
			lr.cmd = runner

			localAddrs := make([]netip.Prefix, len(srcAddrs))
			for i, addr := range srcAddrs {
				localAddrs[i] = netip.PrefixFrom(addr, 128)
			}

			err := lr.Set(&Config{
				LocalAddrs:    localAddrs,
				Routes:        routePrefixes,
				RouteSources:  routeSources,
				NetfilterMode: netfilterOff,
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("Set error = %v, want error %v", err, tt.wantErr)
			}
			if runner.tries != tt.wantTries {
				t.Errorf("%d replace commands, want %d", runner.tries, tt.wantTries)
			}
			if len(lr.routeSrc) != 0 {
				t.Errorf("tracked %v, want empty", lr.routeSrc)
			}
		})
	}
}

// TestSetRouteSourceFailures checks that Set reports every route whose
// source fails, wrapping the first error, and tracks none of them.
func TestSetRouteSourceFailures(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	lr.cmd = &refusingRunner{fakeOS: fake, refusals: 1000}
	err := lr.Set(&Config{
		LocalAddrs:    mustCIDRs("100.64.0.2/32"),
		Routes:        mustCIDRs("100.64.0.1/32", "100.64.0.3/32"),
		RouteSources:  routeSources("100.64.0.1/32", "100.64.0.2", "100.64.0.3/32", "100.64.0.2"),
		NetfilterMode: netfilterOff,
	})
	if err == nil || !strings.Contains(err.Error(), "2 route source failures") || !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Set = %v", err)
	}
	if len(lr.routeSrc) != 0 {
		t.Errorf("tracked %v", lr.routeSrc)
	}
	wantRoutes(t, fake, "100.64.0.1/32 dev tailscale0 table 52", "100.64.0.3/32 dev tailscale0 table 52")
}

// refusingRunner is a commandRunner that refuses the first refusals
// route replace commands with EINVAL, as the kernel does for a source
// address that is still tentative.
type refusingRunner struct {
	*fakeOS
	refusals int
	tries    int
}

func (r *refusingRunner) run(args ...string) error {
	if len(args) > 2 && args[1] == "route" && args[2] == "replace" {
		r.tries++
		if r.tries <= r.refusals {
			return fmt.Errorf("RTNETLINK answers: %w", syscall.EINVAL)
		}
	}
	return r.fakeOS.run(args...)
}
