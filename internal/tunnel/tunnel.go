// Package tunnel brings up a userspace WireGuard interface backed by gVisor's
// netstack. No TUN device is created and no host routing is touched, so it runs
// without elevated privileges on macOS and Windows. The entire TCP/IP stack
// lives in-process; callers reach the WireGuard network through the returned
// *netstack.Net.
package tunnel

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/wgconf"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Tunnel is a running userspace WireGuard device. Net is the in-process network
// stack used to listen and dial on the WireGuard network.
type Tunnel struct {
	dev *device.Device
	Net *netstack.Net
}

// Start creates the netstack TUN and configures the WireGuard device from cfg,
// but does NOT bring it up — call Up once any listeners and stack handlers are in
// place, so the device only starts processing packets after the proxy is fully
// wired. When verbose is true, wireguard-go's own device logs are emitted;
// otherwise only errors are logged.
func Start(cfg *wgconf.Config, log *slog.Logger, verbose bool) (*Tunnel, error) {
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("config has no interface address")
	}

	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create userspace tun: %w", err)
	}

	level := device.LogLevelError
	if verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(level, "wireguard: "))

	uapi, err := cfg.UAPI()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("build device config: %w", err)
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("apply device config: %w", err)
	}

	log.Debug("wireguard device configured", "addresses", cfg.Addresses, "mtu", cfg.MTU, "peers", len(cfg.Peers))
	return &Tunnel{dev: dev, Net: tnet}, nil
}

// Up brings the WireGuard device up so it begins processing packets. Install any
// netstack handlers (e.g. the proxy's wildcard forwarder) before calling it.
func (t *Tunnel) Up() error {
	if err := t.dev.Up(); err != nil {
		return fmt.Errorf("bring device up: %w", err)
	}
	return nil
}

// Close shuts the WireGuard device down.
func (t *Tunnel) Close() error {
	t.dev.Close()
	return nil
}

// PeerStat is a point-in-time view of one WireGuard peer, surfaced to the live
// dashboard so the operator can see whether the tunnel is actually connected.
type PeerStat struct {
	Endpoint      string    // current peer endpoint host:port, empty until known
	LastHandshake time.Time // zero if the peer has never completed a handshake
	RxBytes       int64     // bytes received from the peer
	TxBytes       int64     // bytes sent to the peer
}

// Connected reports whether a recent handshake suggests the tunnel is live. A
// WireGuard handshake is renewed at least every ~2 minutes on an active
// session, so a handshake within 3 minutes is treated as connected.
func (p PeerStat) Connected(now time.Time) bool {
	return !p.LastHandshake.IsZero() && now.Sub(p.LastHandshake) < 3*time.Minute
}

// Peers returns live statistics for every configured WireGuard peer by querying
// the device's UAPI. It is cheap enough to call once per dashboard frame.
func (t *Tunnel) Peers() ([]PeerStat, error) {
	uapi, err := t.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parsePeers(uapi), nil
}

// parsePeers extracts per-peer stats from wireguard-go's UAPI "get" output. Each
// peer block begins with a public_key line; the handshake timestamp arrives as
// split sec/nsec fields, and a zero timestamp means "never handshaked".
func parsePeers(uapi string) []PeerStat {
	var peers []PeerStat
	var cur *PeerStat
	var hsSec, hsNano int64

	flush := func() {
		if cur == nil {
			return
		}
		if hsSec != 0 || hsNano != 0 {
			cur.LastHandshake = time.Unix(hsSec, hsNano)
		}
		peers = append(peers, *cur)
		cur, hsSec, hsNano = nil, 0, 0
	}

	for _, line := range strings.Split(uapi, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			flush() // end the previous peer before starting this one
			cur = &PeerStat{}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = val
			}
		case "last_handshake_time_sec":
			hsSec, _ = strconv.ParseInt(val, 10, 64)
		case "last_handshake_time_nsec":
			hsNano, _ = strconv.ParseInt(val, 10, 64)
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(val, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(val, 10, 64)
			}
		}
	}
	flush()
	return peers
}
