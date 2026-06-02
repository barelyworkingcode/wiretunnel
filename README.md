# wiretunnel

A small, cross-platform console application that joins a WireGuard network
**entirely in userspace** — no TUN device, no routing-table changes, no admin or
root — and proxies ports arriving over the tunnel to services reachable from the
host's normal network.

It is a userspace **beachhead** for secured developer environments: drop it
inside the environment, point a forwarding rule at a local service (for example
tunnel port `22` → `127.0.0.1:22`), and reach that service from across the
WireGuard network. The tunnel address also answers ICMP echo, so you can `ping`
it to verify connectivity.

## Features

- **Unprivileged** — runs as a normal user on macOS and Windows; never touches
  the host network stack.
- **TCP and UDP forwarding** — per-port rules from a simple JSON file.
- **Answers ping** — the tunnel address replies to ICMP echo.
- **Built-in connectivity test** — `-ping` pings any host over the tunnel.
- **Live dashboard** — `-tui` shows connections, targets, and throughput.
- **Graceful shutdown** — `Ctrl-C` closes listeners and in-flight connections.

## How it works

`wiretunnel` uses [`wireguard-go`](https://git.zx2c4.com/wireguard-go/) together
with gVisor's `netstack`. The entire TCP/IP stack runs in-process; WireGuard
packets are encrypted/decrypted in userland and the resulting flows never touch
the host's interfaces or routing table. That is what lets it run **unprivileged**
on macOS and Windows.

```
   WireGuard peer ──encrypted UDP──▶ wiretunnel (userspace WG + netstack)
                                          │  accepts <wg-addr>:<listen> in-process
                                          ▼
                                     host network  ──▶  target host:port
```

- **Inbound** (the tunnel side) is served by the in-process netstack.
- **Outbound** (to the target) uses the host's ordinary network stack.
- **Ping**: gVisor replies to ICMP echo on the tunnel address automatically.

## Requirements

- [Go 1.26+](https://go.dev/dl/) to build (no runtime dependencies — the result
  is a single static binary).

## Build

```sh
# Build for the current platform → ./wiretunnel (or wiretunnel.exe on Windows)
go build -o wiretunnel .

# Cross-compile (Go makes this trivial; set GOOS/GOARCH):
GOOS=windows GOARCH=amd64 go build -o wiretunnel.exe .      # Windows x64
GOOS=windows GOARCH=arm64 go build -o wiretunnel-arm64.exe . # Windows ARM
GOOS=darwin  GOARCH=arm64 go build -o wiretunnel-mac-arm .   # Apple Silicon
GOOS=darwin  GOARCH=amd64 go build -o wiretunnel-mac-x64 .   # Intel Mac
GOOS=linux   GOARCH=amd64 go build -o wiretunnel-linux .     # Linux x64
```

The Windows build is a **console** executable and enables ANSI/VT processing
automatically so the dashboard renders correctly on Windows 10+.

## Configuration

Two files:

### 1. WireGuard config (`-wg`, default `wiretunnel.conf`)

Standard `wg-quick` INI format. Only the directives meaningful to a
routing-free userspace tunnel are used — `PrivateKey`, `Address`, `DNS`, `MTU`,
`[Peer]` `PublicKey`/`PresharedKey`/`Endpoint`/`AllowedIPs`/`PersistentKeepalive`.
Host-network directives (`Table`, `PreUp`, `PostUp`, …) are ignored because this
app never manages the host network. Endpoints given as DNS names are resolved to
`ip:port` automatically.

Copy [`wiretunnel.example.conf`](wiretunnel.example.conf) to your own
`.conf` and fill in real keys. Real configs are git-ignored — **never commit a
file containing a private key**.

### 2. Forwarding rules (`-rules`, default `tunnel.json`)

JSON expansion of the shorthand `{ port, proto, target }`:

```json
{
  "forwards": [
    { "listen": 22,   "proto": "tcp", "target": "127.0.0.1" },
    { "listen": 1433, "proto": "tcp", "target": "127.0.0.1", "targetPort": 1433 }
  ]
}
```

| field        | meaning                                                        |
|--------------|----------------------------------------------------------------|
| `listen`     | port to accept on, over the tunnel (1–65535)                   |
| `proto`      | `tcp` or `udp`                                                 |
| `target`     | host to proxy to, reachable from the host network              |
| `targetPort` | optional; defaults to `listen`                                 |

So `{ "listen": 22, "proto": "tcp", "target": "127.0.0.1" }` listens for TCP on
the tunnel's port 22 and forwards it to the local SSH server.

## Usage

```sh
./wiretunnel                      # uses wiretunnel.conf + tunnel.json
./wiretunnel -wg my.conf -rules forwards.json
./wiretunnel -tui                 # live dashboard (below)
./wiretunnel -ping 10.0.0.1   # connectivity test over the tunnel, then exit
./wiretunnel -v                   # verbose (includes wireguard-go device logs)
```

| flag      | default             | meaning                                                   |
|-----------|---------------------|-----------------------------------------------------------|
| `-wg`     | `wiretunnel.conf` | WireGuard config file                                     |
| `-rules`  | `tunnel.json`       | forwarding rules file                                     |
| `-tui`    | off                 | show the live dashboard instead of log lines              |
| `-ping`   | (none)              | bring the tunnel up, ping a host over it, print, and exit |
| `-v`      | off                 | verbose logging                                           |

`Ctrl-C` (SIGINT/SIGTERM) shuts the tunnel and all forwards down gracefully.

### Live dashboard (`-tui`)

```
  wiretunnel — 10.0.0.2         uptime 00:04:12

  PORT    PROTO  TARGET                    CONNS          UP/s        DOWN/s
  -------------------------------------------------------------------------
  22      tcp    127.0.0.1:22                  2     12.3 KB/s      1.1 MB/s
  1433    tcp    127.0.0.1:1433                0         0 B/s         0 B/s

  connections   active 2   total 17
  throughput    now  ↑ 12.3 KB/s   ↓ 1.1 MB/s
                avg  ↑ 3.2 KB/s    ↓ 220.0 KB/s
  transferred   ↑ 1.4 MB   ↓ 96.0 MB

  Ctrl-C to quit
```

`UP/s` is traffic from the tunnel client toward the target; `DOWN/s` is the
reply direction. `now` is the last second; `avg` is the average since start.

### Verifying ping

The tunnel address (e.g. `10.0.0.2`) is **not** assigned to any host
interface — it lives only inside the userspace stack — so you cannot `ping` it
from the machine running `wiretunnel`. It responds to pings two ways:

- **Inbound**: another peer on the WireGuard network pings the tunnel address and
  gets a reply (gVisor answers ICMP echo automatically).
- **Outbound**: `./wiretunnel -ping <addr>` brings the tunnel up and pings a host
  *over* it from the tunnel address, e.g.:

  ```
  PING 10.0.0.1 from 10.0.0.2 over the tunnel:
    reply from 10.0.0.1: icmp_seq=1 time=23.85 ms
    reply from 10.0.0.1: icmp_seq=2 time=6.81 ms
  --- 10.0.0.1 ping statistics ---
  4 transmitted, 4 received
  ```

> **Tip — keep the beachhead reachable.** If the remote peer initiates
> connections *to* this host, add `PersistentKeepalive = 45` to the `[Peer]`
> section. WireGuard handshakes lazily, so without periodic keepalives a NAT
> mapping toward this host can expire and the peer won't reach the forwarded
> ports.

## Testing

```sh
go test ./...          # full suite
go test -race ./...    # with the race detector
go test -short ./...   # skips the end-to-end tunnel test
```

The suite includes config/rules parsing, the relay and byte counters, the
dashboard formatters, and an **end-to-end test** that stands up two userspace
WireGuard devices over localhost and verifies TCP forwarding, UDP forwarding,
ICMP echo replies, live metrics, and graceful shutdown — no privileges or
external connectivity required.

## Security & acceptable use

This tool forwards network traffic between a WireGuard network and host-reachable
services. Use it **only** on systems and networks you own or are explicitly
authorized to access. You are responsible for complying with all applicable laws
and for any use of this software. As stated in the [LICENSE](LICENSE), it is
provided "as is", without warranty, and the authors accept no liability for any
use or misuse.

Other notes:

- Forwarded ports are exposed to every peer that can reach the tunnel address —
  scope your `AllowedIPs` and forwarding rules to what you actually need.
- Keys live in the WireGuard config file; protect it with appropriate file
  permissions and never commit real keys to source control.

## License

[MIT](LICENSE) © 2026 barelyworkingcode

## Layout

```
main.go                 CLI, logging, signal handling, mode selection
ping.go                 -ping connectivity self-test
tui.go                  -tui live dashboard (ANSI, no dependencies)
events.go               last-warning/error capture for the dashboard footer
vt_windows.go           enables ANSI/VT processing on Windows
vt_other.go             no-op on macOS/Linux
internal/wgconf/        wg-quick config -> wireguard-go UAPI
internal/rules/         forwarding rules JSON
internal/tunnel/        userspace WireGuard device + netstack
internal/proxy/         per-rule listeners, TCP/UDP relays, live metrics
e2e_test.go             two-device end-to-end tunnel test
```
