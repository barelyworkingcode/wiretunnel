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
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/barelyworkingcode/wiretunnel/internal/proxy"
	"github.com/barelyworkingcode/wiretunnel/internal/rules"
	"github.com/barelyworkingcode/wiretunnel/internal/seal"
	"github.com/barelyworkingcode/wiretunnel/internal/tunnel"
	"github.com/barelyworkingcode/wiretunnel/internal/webssh"
	"github.com/barelyworkingcode/wiretunnel/internal/wgconf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "wiretunnel: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	wgPath := flag.String("wg", "wiretunnel.conf", "path to the WireGuard configuration file (plaintext or DPAPI-sealed)")
	rulesPath := flag.String("rules", "tunnel.json", "path to the forwarding rules JSON file")
	pingTarget := flag.String("ping", "", "bring the tunnel up, ICMP-ping this address over it, print results, and exit (connectivity test)")
	tuiMode := flag.Bool("tui", false, "show a live text dashboard of connections and throughput")
	verbose := flag.Bool("v", false, "verbose logging (includes wireguard-go device logs)")
	sealPath := flag.String("seal", "", "one-shot: DPAPI-seal the plaintext config at this path to the current host, write it, and exit")
	sealOut := flag.String("out", "", "output path for -seal (default: <config>.dpapi)")
	sealScope := flag.String("scope", "user", "binding for -seal: \"user\" (this machine + account) or \"machine\" (this machine, any account)")
	flag.Parse()

	// Enrollment is a self-contained mode: seal the given plaintext config and
	// exit. It never brings up a tunnel.
	if *sealPath != "" {
		return sealConfig(*sealPath, *sealOut, *sealScope)
	}

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

	wcfg, err := loadWGConfig(*wgPath)
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

	// Browser terminal (webssh), served directly on the WireGuard netstack so it
	// is reachable ONLY over the tunnel — no host socket is ever opened. Bind it
	// before Up() so its listener is in place (and wins over any forwardAll
	// catch-all on the same port) before packets start flowing.
	var ws *webssh.Server
	if rcfg.WebSSHEnabled() {
		ln, err := t.Net.ListenTCP(&net.TCPAddr{Port: rcfg.WebSSHPort})
		if err != nil {
			return fmt.Errorf("listen webssh on tunnel port %d: %w", rcfg.WebSSHPort, err)
		}
		ws, err = webssh.New(webssh.Config{
			Hostname:  rcfg.Hostname,
			Port:      rcfg.WebSSHPort,
			TunnelIPs: tunnelIPs(wcfg.Addresses),
			Logger:    log,
		})
		if err != nil {
			ln.Close()
			return fmt.Errorf("init webssh: %w", err)
		}
		if err := ws.Start(ctx, ln); err != nil {
			ln.Close()
			return fmt.Errorf("start webssh: %w", err)
		}
	}

	if err := t.Up(); err != nil {
		return err
	}
	logUp()

	if *tuiMode {
		websshURL := ""
		if ws != nil {
			websshURL = ws.URL()
		}
		runDashboard(ctx, p, t, wcfg.Addresses[0].String(), websshURL, events)
	} else {
		log.Info("ready", "forwards", len(rcfg.Forwards), "wildcard", rcfg.ForwardAll.Enabled, "webSSH", rcfg.WebSSHEnabled())
		<-ctx.Done()
		log.Info("shutting down")
	}

	p.Wait()
	if ws != nil {
		ws.Wait()
	}
	return nil
}

// tunnelIPs converts the tunnel's interface addresses to net.IP so they can be
// added to the webssh leaf certificate's SANs — letting it validate when the
// box is reached by tunnel IP rather than by hostname.
func tunnelIPs(addrs []netip.Addr) []net.IP {
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IP(a.AsSlice()))
	}
	return out
}

// loadWGConfig reads the WireGuard config at path, transparently unsealing it
// first if it is a DPAPI-sealed container. A plaintext config is still accepted
// so existing deployments keep working.
func loadWGConfig(path string) (*wgconf.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if seal.IsSealed(data) {
		data, err = seal.Unseal(data)
		if err != nil {
			return nil, fmt.Errorf("unseal: %w (the file may have been copied from "+
				"another host, or sealed under a different account/scope)", err)
		}
	}
	return wgconf.Parse(bytes.NewReader(data))
}

// sealConfig implements the -seal enrollment mode: validate the plaintext
// config parses, bind it to this host with DPAPI, and write the container. The
// operator then deletes the plaintext and points -wg at the sealed file.
func sealConfig(inPath, outPath, scopeStr string) error {
	var scope seal.Scope
	switch scopeStr {
	case "user":
		scope = seal.ScopeUser
	case "machine":
		scope = seal.ScopeMachine
	default:
		return fmt.Errorf("invalid -scope %q (want \"user\" or \"machine\")", scopeStr)
	}

	plain, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	if seal.IsSealed(plain) {
		return fmt.Errorf("%s is already sealed", inPath)
	}
	// Fail before writing anything if the input is not a usable config.
	if _, err := wgconf.Parse(bytes.NewReader(plain)); err != nil {
		return fmt.Errorf("refusing to seal: %s does not parse as a WireGuard config: %w", inPath, err)
	}

	sealed, err := seal.Seal(plain, scope)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	if outPath == "" {
		outPath = inPath + ".dpapi"
	}
	if err := os.WriteFile(outPath, sealed, 0o600); err != nil {
		return fmt.Errorf("write sealed config: %w", err)
	}

	fmt.Printf("Sealed %s -> %s (scope=%s).\n", inPath, outPath, scopeStr)
	fmt.Printf("Now delete the plaintext %s and run with -wg %s\n", inPath, outPath)
	return nil
}
