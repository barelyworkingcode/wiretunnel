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
