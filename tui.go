package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/proxy"
)

// ANSI control sequences. Windows enables VT processing in enableVirtualTerminal.
const (
	ansiHome       = "\033[H" // move cursor to top-left
	ansiClearBelow = "\033[J" // clear from cursor to end of screen
	ansiHideCursor = "\033[?25l"
	ansiShowCursor = "\033[?25h"
)

// runDashboard renders a live view of proxy activity once per second until ctx
// is cancelled. lastEvent supplies the most recent warning/error to show in the
// footer (it may be nil).
func runDashboard(ctx context.Context, p *proxy.Proxy, tunnelAddr string, lastEvent *lastEventHandler) {
	enableVirtualTerminal() // no-op on non-Windows

	fmt.Fprint(os.Stdout, ansiHideCursor)
	defer fmt.Fprint(os.Stdout, ansiShowCursor+ansiHome+ansiClearBelow)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	start := time.Now()
	prev := p.Snapshot()
	prevAt := start

	render := func(now time.Time) {
		cur := p.Snapshot()
		dt := now.Sub(prevAt).Seconds()
		if dt <= 0 {
			dt = 1
		}
		frame := buildFrame(cur, prev, dt, now.Sub(start), tunnelAddr, lastEvent)
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
// apart (for per-forward rates); uptime drives the average rates.
func buildFrame(cur, prev []proxy.ForwardSnapshot, dt float64, uptime time.Duration, tunnelAddr string, lastEvent *lastEventHandler) string {
	var b strings.Builder

	fmt.Fprintf(&b, "  wiretunnel — %-22s uptime %s\n\n", tunnelAddr, humanDuration(uptime))
	fmt.Fprintf(&b, "  %-7s %-6s %-24s %6s  %12s  %12s\n", "PORT", "PROTO", "TARGET", "CONNS", "UP/s", "DOWN/s")
	fmt.Fprintf(&b, "  %s\n", strings.Repeat("-", 73))

	var totalActive, totalConns, totalUp, totalDown int64
	var nowUp, nowDown float64
	for i, f := range cur {
		upRate, downRate := 0.0, 0.0
		if i < len(prev) {
			upRate = float64(f.BytesUp-prev[i].BytesUp) / dt
			downRate = float64(f.BytesDown-prev[i].BytesDown) / dt
		}
		fmt.Fprintf(&b, "  %-7d %-6s %-24s %6d  %12s  %12s\n",
			f.Listen, f.Proto, truncate(f.Target, 24), f.Active, humanRate(upRate), humanRate(downRate))

		totalActive += f.Active
		totalConns += f.Total
		totalUp += f.BytesUp
		totalDown += f.BytesDown
		nowUp += upRate
		nowDown += downRate
	}

	secs := uptime.Seconds()
	avgUp, avgDown := 0.0, 0.0
	if secs > 0 {
		avgUp = float64(totalUp) / secs
		avgDown = float64(totalDown) / secs
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}
