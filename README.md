# Uniscale

Run several Tailscale tailnets at once, as one network.

Uniscale is a fork of [Tailscale](https://github.com/tailscale/tailscale)
whose daemon, `uniscaled`, joins your work, personal and friends' tailnets
at the same time. Each tailnet runs in its own stack, with its own node
identity, ACLs and login. The host sees one network: where two tailnets
(or a tailnet and your LAN) use the same addresses, Uniscale remaps the
colliding ones into a shared address space (198.18.0.0/15 and a ULA /48),
so every peer stays reachable and the other ends see you as usual.

Uniscale is not affiliated with or endorsed by Tailscale Inc.
"Tailscale" is a trademark of Tailscale Inc.

## Differences from Tailscale

| | Tailscale | Uniscale |
|---|---|---|
| Daemon / CLI | `tailscaled` / `tailscale` | `uniscaled` / `uniscale` |
| State | `/var/lib/tailscale` | `/var/lib/uniscale` |
| LocalAPI socket | `/run/tailscale/tailscaled.sock` | `/run/uniscale/uniscaled.sock` |
| TUN device | `tailscale0` | `uniscale0` |
| systemd unit | `tailscaled.service` | `uniscaled.service` |
| Several tailnets | no | `uniscaled --unify` |

Uniscale can be installed next to Tailscale without touching its state,
but only one of them can run at a time (they use the same routing table).
When `controlplane.tailscale.com` is unreachable, Uniscale logs in through
`login.tailscale.com`, the same control plane.

## Building and installing (Linux)

```sh
make uniscale                 # builds bin/uniscaled and bin/uniscale
sudo make install-uniscale    # /usr/sbin/uniscaled, /usr/bin/uniscale, uniscaled.service
sudo systemctl disable --now tailscaled   # if Tailscale is installed
```

## Running several tailnets

List the tailnets besides the primary one in
`/var/lib/uniscale/unify/config.json`:

```json
{"tailnets": [{"name": "work"}, {"name": "friends"}]}
```

Add `--unify` to `FLAGS` in `/etc/default/uniscaled`, start the service,
and log in to each tailnet through its own socket:

```sh
sudo systemctl enable --now uniscaled
sudo uniscale up                                                  # primary
sudo uniscale --socket=/run/uniscale/uniscaled-work.sock up       # "work"
sudo uniscale --socket=/run/uniscale/uniscaled-friends.sock up    # "friends"
```

The design, and the current limitations, are in
[docs/specs/2026-10-01-tailnet-unification-design.md](docs/specs/2026-10-01-tailnet-unification-design.md).

---

The rest of this file is the upstream Tailscale README.

# Tailscale

https://tailscale.com

Private WireGuard® networks made easy

## Overview

This repository contains the majority of Tailscale's open source code.
Notably, it includes the `tailscaled` daemon and
the `tailscale` CLI tool. The `tailscaled` daemon runs on Linux, Windows,
[macOS](https://tailscale.com/kb/1065/macos-variants/), and to varying degrees
on FreeBSD and OpenBSD. The Tailscale iOS and Android apps use this repo's
code, but this repo doesn't contain the mobile GUI code.

Other [Tailscale repos](https://github.com/orgs/tailscale/repositories) of note:

* the Android app is at https://github.com/tailscale/tailscale-android
* the Synology package is at https://github.com/tailscale/tailscale-synology
* the QNAP package is at https://github.com/tailscale/tailscale-qpkg
* the Chocolatey packaging is at https://github.com/tailscale/tailscale-chocolatey

For background on which parts of Tailscale are open source and why,
see [https://tailscale.com/opensource/](https://tailscale.com/opensource/).

## Using

We serve packages for a variety of distros and platforms at
[https://pkgs.tailscale.com](https://pkgs.tailscale.com/).

## Other clients

The [macOS, iOS, and Windows clients](https://tailscale.com/download)
use the code in this repository but additionally include small GUI
wrappers. The GUI wrappers on non-open source platforms are themselves
not open source.

## Building

We always require the latest Go release, currently Go 1.27. (While we build
releases with our [Go fork](https://github.com/tailscale/go/), its use is not
required.)

```
go install tailscale.com/cmd/tailscale{,d}
```

If you're packaging Tailscale for distribution, use `build_dist.sh`
instead, to burn commit IDs and version info into the binaries:

```
./build_dist.sh tailscale.com/cmd/tailscale
./build_dist.sh tailscale.com/cmd/tailscaled
```

If your distro has conventions that preclude the use of
`build_dist.sh`, please do the equivalent of what it does in your
distro's way, so that bug reports contain useful version information.

## Bugs

Please file any issues about this code or the hosted service on
[the issue tracker](https://github.com/tailscale/tailscale/issues).

## Contributing

PRs welcome! But please file bugs. Commit messages should [reference
bugs](https://docs.github.com/en/github/writing-on-github/autolinked-references-and-urls).

We require [Developer Certificate of
Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin)
`Signed-off-by` lines in commits.

See [commit-messages.md](docs/commit-messages.md) (or skim `git log`) for our commit message style.

## About Us

[Tailscale](https://tailscale.com/) is primarily developed by the
people at https://github.com/orgs/tailscale/people. For other contributors,
see:

* https://github.com/tailscale/tailscale/graphs/contributors
* https://github.com/tailscale/tailscale-android/graphs/contributors

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
