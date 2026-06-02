package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// lastEventHandler is a minimal slog.Handler that retains only the most recent
// warning/error record. The dashboard shows it in the footer so problems
// (e.g. a target refusing connections) stay visible even though normal logging
// is suppressed in TUI mode.
type lastEventHandler struct {
	mu  sync.Mutex
	msg string
	at  time.Time
}

func (h *lastEventHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}

func (h *lastEventHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})

	h.mu.Lock()
	h.msg = b.String()
	h.at = r.Time
	h.mu.Unlock()
	return nil
}

func (h *lastEventHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *lastEventHandler) WithGroup(string) slog.Handler      { return h }

// last returns the most recent warning/error message and when it occurred.
func (h *lastEventHandler) last() (string, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.msg, h.at
}
