// Command wiretunnel joins a WireGuard network entirely in userspace — no TUN
// device, no routing changes, no elevated privileges — and proxies ports that
// arrive over the tunnel to targets reachable from the host's normal network.
//
// It is a small beachhead for secured developer environments: deploy it inside
// the environment, point a forwarding rule at a local service (for example
// tunnel port 22 -> 127.0.0.1:22), and reach that service from across the
// WireGuard network. The tunnel address also answers ICMP echo (ping) so
// connectivity can be verified.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/barelyworkingcode/wiretunnel/internal/proxy"
	"github.com/barelyworkingcode/wiretunnel/internal/rules"
	"github.com/barelyworkingcode/wiretunnel/internal/tunnel"
	"github.com/barelyworkingcode/wiretunnel/internal/wgconf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "wiretunnel: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	wgPath := flag.String("wg", "wiretunnel.conf", "path to the WireGuard configuration file")
	rulesPath := flag.String("rules", "tunnel.json", "path to the forwarding rules JSON file")
	pingTarget := flag.String("ping", "", "bring the tunnel up, ICMP-ping this address over it, print results, and exit (connectivity test)")
	tuiMode := flag.Bool("tui", false, "show a live text dashboard of connections and throughput")
	verbose := flag.Bool("v", false, "verbose logging (includes wireguard-go device logs)")
	flag.Parse()

	// In dashboard mode normal logs would corrupt the redrawing screen, so route
	// logging to a handler that only retains the latest warning/error for the
	// dashboard footer. Otherwise log to stderr as usual.
	var log *slog.Logger
	var events *lastEventHandler
	if *tuiMode {
		events = &lastEventHandler{}
		log = slog.New(events)
	} else {
		level := slog.LevelInfo
		if *verbose {
			level = slog.LevelDebug
		}
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}

	wcfg, err := wgconf.ParseFile(*wgPath)
	if err != nil {
		return fmt.Errorf("load wireguard config %q: %w", *wgPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, err := tunnel.Start(wcfg, log, *verbose)
	if err != nil {
		return fmt.Errorf("start tunnel: %w", err)
	}
	defer t.Close()

	logUp := func() {
		for _, addr := range wcfg.Addresses {
			log.Info("tunnel up", "address", addr.String(), "mtu", wcfg.MTU, "ping", "enabled")
		}
	}

	// Connectivity self-test mode: ping a host over the tunnel and exit.
	if *pingTarget != "" {
		target, err := netip.ParseAddr(*pingTarget)
		if err != nil {
			return fmt.Errorf("invalid -ping address %q: %w", *pingTarget, err)
		}
		if err := t.Up(); err != nil {
			return err
		}
		logUp()
		return pingOverTunnel(t.Net, wcfg.Addresses[0], target, 4)
	}

	rcfg, err := rules.ParseFile(*rulesPath)
	if err != nil {
		return fmt.Errorf("load rules %q: %w", *rulesPath, err)
	}

	// Bind listeners and install the catch-all handler before the device comes
	// up, so the stack is fully wired before any packet is processed.
	p := proxy.New(t.Net, log)
	if err := p.Start(ctx, rcfg.Forwards); err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	if rcfg.ForwardAll.Enabled {
		if err := p.StartWildcard(ctx, rcfg.ForwardAll.Target); err != nil {
			return fmt.Errorf("start wildcard forwarding: %w", err)
		}
	}

	if err := t.Up(); err != nil {
		return err
	}
	logUp()

	if *tuiMode {
		runDashboard(ctx, p, wcfg.Addresses[0].String(), events)
	} else {
		log.Info("ready", "forwards", len(rcfg.Forwards), "wildcard", rcfg.ForwardAll.Enabled)
		<-ctx.Done()
		log.Info("shutting down")
	}

	p.Wait()
	return nil
}
