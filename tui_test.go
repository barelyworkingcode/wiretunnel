package main

import (
	"strings"
	"testing"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/proxy"
	"github.com/barelyworkingcode/wiretunnel/internal/tunnel"
)

// TestBuildFrameWildcard checks that a dynamically-discovered wildcard port is
// rendered (marked with *), that the catch-all destination line appears, and
// that rates are matched to the prior frame by (proto, port) rather than slice
// position — a wildcard row inserted above an explicit one must not steal its rate.
func TestBuildFrameWildcard(t *testing.T) {
	prev := []proxy.ForwardSnapshot{
		{Listen: 22, Proto: "tcp", Target: "127.0.0.1:22", BytesUp: 100, BytesDown: 200},
	}
	cur := []proxy.ForwardSnapshot{
		{Listen: 22, Proto: "tcp", Target: "127.0.0.1:22", Active: 1, BytesUp: 100, BytesDown: 200},
		{Listen: 8080, Proto: "tcp", Target: "127.0.0.1:8080", Wildcard: true, Active: 2, BytesUp: 1100, BytesDown: 200},
	}

	now := time.Unix(1_000_000, 0)
	peers := []tunnel.PeerStat{
		{Endpoint: "203.0.113.5:51820", LastHandshake: now.Add(-23 * time.Second), TxBytes: 1234, RxBytes: 5678},
	}
	frame := buildFrame(cur, prev, 1.0, time.Minute, now, peers, "10.0.0.2", "https://devbox:8022", "127.0.0.1", nil)

	if !strings.Contains(frame, "webssh    https://devbox:8022  (tunnel-only)") {
		t.Errorf("webssh header line missing:\n%s", frame)
	}
	// The peer line shows the endpoint, an "up" status (handshake within 3m),
	// and the compact handshake age.
	if !strings.Contains(frame, "peer      203.0.113.5:51820") {
		t.Errorf("peer endpoint line missing:\n%s", frame)
	}
	if !strings.Contains(frame, "up") || !strings.Contains(frame, "23s ago") {
		t.Errorf("peer status/handshake age missing:\n%s", frame)
	}
	if !strings.Contains(frame, "8080*") {
		t.Errorf("wildcard port not marked with *:\n%s", frame)
	}
	if !strings.Contains(frame, "127.0.0.1:*") {
		t.Errorf("catch-all destination line missing:\n%s", frame)
	}
	if !strings.Contains(frame, "dynamic port served by the catch-all") {
		t.Errorf("wildcard footnote missing:\n%s", frame)
	}
	// Port 22 was unchanged frame-to-frame, so its UP/s must read 0 — proving the
	// new 8080 row (with +1000 bytes) did not shift port 22's prev match.
	for _, line := range strings.Split(frame, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "22 ") && !strings.Contains(line, "0 B/s") {
			t.Errorf("port 22 should show 0 B/s up (unchanged), got: %q", line)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{5 * 1024 * 1024, "5.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHumanRate(t *testing.T) {
	if got := humanRate(2048); got != "2.0 KB/s" {
		t.Errorf("humanRate(2048) = %q, want 2.0 KB/s", got)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "00:00:00"},
		{45 * time.Second, "00:00:45"},
		{90 * time.Second, "00:01:30"},
		{3661 * time.Second, "01:01:01"},
	}
	for _, c := range cases {
		if got := humanDuration(c.in); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 24); got != "short" {
		t.Errorf("truncate kept-as-is = %q", got)
	}
	if got := truncate("a-very-long-target-hostname.example", 10); got != "a-very-lo…" {
		t.Errorf("truncate long = %q", got)
	}
}
