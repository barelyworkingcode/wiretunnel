// Package tunnel brings up a userspace WireGuard interface backed by gVisor's
// netstack. No TUN device is created and no host routing is touched, so it runs
// without elevated privileges on macOS and Windows. The entire TCP/IP stack
// lives in-process; callers reach the WireGuard network through the returned
// *netstack.Net.
package tunnel

import (
	"fmt"
	"log/slog"

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
