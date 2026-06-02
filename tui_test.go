package main

import (
	"testing"
	"time"
)

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
