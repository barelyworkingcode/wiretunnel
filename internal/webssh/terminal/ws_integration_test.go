package terminal

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testShell() string {
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("pwsh"); err == nil {
			return p
		}
		return "powershell.exe"
	}
	return "/bin/sh"
}

// TestImagePasteOverWebsocket drives the real websocket: it sends an "image"
// control frame and asserts the server writes the bytes to the uploads dir.
func TestImagePasteOverWebsocket(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(Config{Shell: testShell(), UploadsDir: dir, MaxUpload: 25 << 20, Scrollback: 1 << 16})

	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	header := http.Header{}
	header.Set("Origin", srv.URL) // satisfy the same-origin check

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Drain server output so its writer never blocks.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":80,"rows":24}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	want := []byte("\x89PNG\r\n\x1a\nwebsocket-image-bytes")
	payload := base64.StdEncoding.EncodeToString(want)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"image","mime":"image/png","data":"`+payload+`"}`)); err != nil {
		t.Fatalf("write image: %v", err)
	}

	// Poll for the saved file.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(dir, "paste-*.png"))
		if len(matches) == 1 {
			got, err := os.ReadFile(matches[0])
			if err != nil {
				t.Fatalf("read saved image: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("saved content mismatch: got %q want %q", got, want)
			}
			return // success
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the pasted image to be saved")
}
