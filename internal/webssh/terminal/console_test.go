package terminal

import (
	"testing"
	"time"
)

// TestSnapshotReflectsSessions verifies Snapshot lists exactly the live
// sessions, then drops them once killed.
func TestSnapshotReflectsSessions(t *testing.T) {
	m := NewManager(Config{Shell: testShell(), Scrollback: 1 << 16, MaxSessions: 10})

	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("expected no sessions initially, got %d", len(got))
	}

	if _, err := m.getOrCreate("alpha"); err != nil {
		t.Fatalf("create alpha: %v", err)
	}
	if _, err := m.getOrCreate("beta"); err != nil {
		t.Fatalf("create beta: %v", err)
	}
	defer m.Kill("alpha")
	defer m.Kill("beta")

	snap := m.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(snap))
	}
	ids := map[string]bool{}
	for _, s := range snap {
		ids[s.ID] = true
		if s.Connections != 0 {
			t.Errorf("session %s: expected 0 connections, got %d", s.ID, s.Connections)
		}
	}
	if !ids["alpha"] || !ids["beta"] {
		t.Fatalf("snapshot missing expected ids: %+v", snap)
	}
}

// TestSnapshotBusyIdle checks the output-activity heuristic: output within
// busyWindow reads as "busy", staler output as "idle". It builds the session
// by hand (no PTY/goroutine) so lastOutput is not overwritten under it.
func TestSnapshotBusyIdle(t *testing.T) {
	m := NewManager(Config{MaxSessions: 10})
	now := time.Now()
	m.sessions["s"] = &Session{
		id:         "s",
		clients:    make(map[int]*client),
		createdAt:  now,
		lastOutput: now,
	}

	state := func() string {
		snap := m.Snapshot()
		if len(snap) != 1 {
			t.Fatalf("expected 1 session, got %d", len(snap))
		}
		return snap[0].State
	}

	if got := state(); got != "busy" {
		t.Fatalf("recent output should report busy, got %q", got)
	}
	m.sessions["s"].lastOutput = now.Add(-2 * busyWindow)
	if got := state(); got != "idle" {
		t.Fatalf("stale output should report idle, got %q", got)
	}
}

// TestTitleScanner exercises the OSC title parser: BEL- and ST-terminated
// sequences, both title codes, sequences split across feeds, and non-title OSC
// codes that must be ignored.
func TestTitleScanner(t *testing.T) {
	// Whole sequence in one feed, BEL-terminated, OSC 0.
	var ts titleScanner
	if title, ok := ts.feed([]byte("out \x1b]0;hello\x07more")); !ok || title != "hello" {
		t.Fatalf("OSC 0 + BEL: got (%q, %v), want (\"hello\", true)", title, ok)
	}

	// OSC 2 terminated by ST (ESC \) instead of BEL.
	ts = titleScanner{}
	if title, ok := ts.feed([]byte("\x1b]2;C:\\work\x1b\\")); !ok || title != `C:\work` {
		t.Fatalf("OSC 2 + ST: got (%q, %v), want (%q, true)", title, ok, `C:\work`)
	}

	// A sequence split across two feeds is still recognized.
	ts = titleScanner{}
	if _, ok := ts.feed([]byte("\x1b]0;par")); ok {
		t.Fatal("incomplete sequence should not yield a title yet")
	}
	if title, ok := ts.feed([]byte("tial\x07")); !ok || title != "partial" {
		t.Fatalf("split sequence: got (%q, %v), want (\"partial\", true)", title, ok)
	}

	// Non-title OSC codes (here OSC 8 hyperlink) are parsed but ignored.
	ts = titleScanner{}
	if title, ok := ts.feed([]byte("\x1b]8;;https://x\x07")); ok {
		t.Fatalf("OSC 8 should be ignored, got title %q", title)
	}
}

// TestKill terminates a live session and reports correctly on a missing one.
func TestKill(t *testing.T) {
	m := NewManager(Config{Shell: testShell(), Scrollback: 1 << 16, MaxSessions: 10})
	if _, err := m.getOrCreate("k"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !m.Kill("k") {
		t.Fatal("Kill returned false for an existing session")
	}
	if m.Kill("k") {
		t.Fatal("Kill returned true for an already-removed session")
	}
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("expected no sessions after kill, got %d", len(got))
	}
}
