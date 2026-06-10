package terminal

import (
	"bytes"
	"io"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
)

// TestPTYSpawnsShell verifies a real PTY can launch a shell and stream output.
// This exercises ConPTY on Windows and the unix PTY elsewhere.
func TestPTYSpawnsShell(t *testing.T) {
	ptmx, err := pty.New()
	if err != nil {
		t.Fatalf("pty.New: %v", err)
	}
	// Close exactly once (double-closing a ConPTY corrupts the heap).
	var closeOnce sync.Once
	closePTY := func() { closeOnce.Do(func() { _ = ptmx.Close() }) }
	defer closePTY()

	var name string
	var args []string
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("pwsh"); err == nil {
			name = p
		} else {
			name = "powershell.exe"
		}
		args = []string{"-NoProfile", "-Command", "Write-Output MARKER_OK_123"}
	} else {
		name = "/bin/sh"
		args = []string{"-c", "echo MARKER_OK_123"}
	}

	cmd := ptmx.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}

	got := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, ptmx)
		got <- buf.Bytes()
	}()

	_ = cmd.Wait()
	closePTY()

	select {
	case out := <-got:
		if !bytes.Contains(out, []byte("MARKER_OK_123")) {
			t.Fatalf("marker not found in PTY output; got %q", out)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for PTY output")
	}
}
