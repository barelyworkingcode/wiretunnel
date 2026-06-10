package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/proxy"
	"github.com/barelyworkingcode/wiretunnel/internal/tunnel"
)

// ANSI control sequences. Windows enables VT processing in enableVirtualTerminal.
const (
	ansiHome       = "\033[H" // move cursor to top-left
	ansiClearBelow = "\033[J" // clear from cursor to end of screen
	ansiHideCursor = "\033[?25l"
	ansiShowCursor = "\033[?25h"
)

// runDashboard renders a live view of proxy activity once per second until ctx
// is cancelled. t supplies live WireGuard peer stats for the header; websshURL
// is the browser-terminal address shown there, or "" when webssh is disabled.
// lastEvent supplies the most recent warning/error to show in the footer (it
// may be nil).
func runDashboard(ctx context.Context, p *proxy.Proxy, t *tunnel.Tunnel, tunnelAddr, websshURL string, lastEvent *lastEventHandler) {
	enableVirtualTerminal() // no-op on non-Windows

	fmt.Fprint(os.Stdout, ansiHideCursor)
	defer fmt.Fprint(os.Stdout, ansiShowCursor+ansiHome+ansiClearBelow)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	wildTarget, wildEnabled := p.Wildcard()
	wildcard := ""
	if wildEnabled {
		wildcard = wildTarget
	}

	start := time.Now()
	prev := p.Snapshot()
	prevAt := start

	render := func(now time.Time) {
		cur := p.Snapshot()
		dt := now.Sub(prevAt).Seconds()
		if dt <= 0 {
			dt = 1
		}
		peers, _ := t.Peers() // best-effort; an empty slice just omits the peer lines
		frame := buildFrame(cur, prev, dt, now.Sub(start), now, peers, tunnelAddr, websshURL, wildcard, lastEvent)
		prev, prevAt = cur, now
		fmt.Fprint(os.Stdout, ansiHome+frame+ansiClearBelow)
	}

	render(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			render(t)
		}
	}
}

// buildFrame renders one dashboard frame. cur/prev are snapshots dt seconds
// apart (for per-forward rates); uptime drives the average rates; now timestamps
// peer handshake ages. peers are the live WireGuard peers (may be empty).
// websshURL is the browser-terminal address (or "" when disabled); wildcard is
// the catch-all target, or "" when wildcard forwarding is off.
func buildFrame(cur, prev []proxy.ForwardSnapshot, dt float64, uptime time.Duration, now time.Time, peers []tunnel.PeerStat, tunnelAddr, websshURL, wildcard string, lastEvent *lastEventHandler) string {
	var b strings.Builder

	fmt.Fprintf(&b, "  wiretunnel — %-22s uptime %s\n", tunnelAddr, humanDuration(uptime))
	if websshURL != "" {
		fmt.Fprintf(&b, "  webssh    %s  (tunnel-only)\n", websshURL)
	}
	for _, pr := range peers {
		endpoint := pr.Endpoint
		if endpoint == "" {
			endpoint = "(no endpoint)"
		}
		handshake := "never"
		if !pr.LastHandshake.IsZero() {
			handshake = humanShort(now.Sub(pr.LastHandshake)) + " ago"
		}
		status := "down"
		if pr.Connected(now) {
			status = "up"
		}
		fmt.Fprintf(&b, "  peer      %-21s %-4s handshake %-9s ↑ %s ↓ %s\n",
			truncate(endpoint, 21), status, handshake,
			humanBytes(float64(pr.TxBytes)), humanBytes(float64(pr.RxBytes)))
	}
	fmt.Fprint(&b, "\n")
	fmt.Fprintf(&b, "  %-7s %-6s %-24s %6s  %12s  %12s\n", "PORT", "PROTO", "TARGET", "CONNS", "UP/s", "DOWN/s")
	fmt.Fprintf(&b, "  %s\n", strings.Repeat("-", 73))

	// Match by (proto, port) rather than slice index: wildcard rows are discovered
	// at runtime, so a new port appearing would otherwise misattribute every rate
	// below it for one frame.
	prevByKey := make(map[string]proxy.ForwardSnapshot, len(prev))
	for _, f := range prev {
		prevByKey[snapKey(f)] = f
	}

	var totalActive, totalConns, totalUp, totalDown int64
	var nowUp, nowDown float64
	var anyWild bool
	for _, f := range cur {
		upRate, downRate := 0.0, 0.0
		if pf, ok := prevByKey[snapKey(f)]; ok {
			upRate = float64(f.BytesUp-pf.BytesUp) / dt
			downRate = float64(f.BytesDown-pf.BytesDown) / dt
		}
		port := strconv.Itoa(f.Listen)
		if f.Wildcard {
			port += "*"
			anyWild = true
		}
		fmt.Fprintf(&b, "  %-7s %-6s %-24s %6d  %12s  %12s\n",
			port, f.Proto, truncate(f.Target, 24), f.Active, humanRate(upRate), humanRate(downRate))

		totalActive += f.Active
		totalConns += f.Total
		totalUp += f.BytesUp
		totalDown += f.BytesDown
		nowUp += upRate
		nowDown += downRate
	}

	if wildcard != "" {
		fmt.Fprintf(&b, "  %-7s %-6s %-24s %6s  %12s  %12s\n",
			"*", "tcp+udp", truncate(wildcard+":*", 24), "", "", "")
	}

	secs := uptime.Seconds()
	avgUp, avgDown := 0.0, 0.0
	if secs > 0 {
		avgUp = float64(totalUp) / secs
		avgDown = float64(totalDown) / secs
	}

	if anyWild {
		fmt.Fprint(&b, "\n  * dynamic port served by the catch-all (wildcard) forward\n")
	}
	fmt.Fprintf(&b, "\n  connections   active %d   total %d\n", totalActive, totalConns)
	fmt.Fprintf(&b, "  throughput    now  ↑ %-11s ↓ %-11s\n", humanRate(nowUp), humanRate(nowDown))
	fmt.Fprintf(&b, "                avg  ↑ %-11s ↓ %-11s\n", humanRate(avgUp), humanRate(avgDown))
	fmt.Fprintf(&b, "  transferred   ↑ %s   ↓ %s\n", humanBytes(float64(totalUp)), humanBytes(float64(totalDown)))

	if lastEvent != nil {
		if msg, when := lastEvent.last(); msg != "" {
			fmt.Fprintf(&b, "\n  last event    %s (%s ago)\n", truncate(msg, 60), humanDuration(time.Since(when)))
		}
	}
	fmt.Fprint(&b, "\n  Ctrl-C to quit\n")
	return b.String()
}

// snapKey identifies a forward row across frames by protocol and tunnel port,
// which is stable even as wildcard rows come and go.
func snapKey(f proxy.ForwardSnapshot) string {
	return f.Proto + ":" + strconv.Itoa(f.Listen)
}

// humanBytes formats a byte count as a human-readable size.
func humanBytes(n float64) string {
	const unit = 1024.0
	if n < unit {
		return fmt.Sprintf("%.0f B", n)
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	v, i := n, -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// humanRate formats a bytes-per-second value.
func humanRate(bytesPerSec float64) string {
	return humanBytes(bytesPerSec) + "/s"
}

// humanDuration formats d as HH:MM:SS.
func humanDuration(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, (s%3600)/60, s%60)
}

// humanShort formats a duration compactly for the "handshake … ago" readout:
// "23s", "4m", "1h2m". A negative duration (clock skew) reads as 0s.
func humanShort(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}
