package terminal

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// dialSession connects a websocket to the handler for a given session id.
func dialSession(t *testing.T, srv *httptest.Server, id string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "?session=" + id
	header := http.Header{}
	header.Set("Origin", srv.URL)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// readUntil reads frames until the marker appears in cumulative binary output
// or the deadline passes.
func readUntil(conn *websocket.Conn, marker string, d time.Duration) bool {
	var acc bytes.Buffer
	_ = conn.SetReadDeadline(time.Now().Add(d))
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return false
		}
		if mt == websocket.BinaryMessage {
			acc.Write(data)
			if bytes.Contains(acc.Bytes(), []byte(marker)) {
				return true
			}
		}
	}
}

// TestSessionReattachReplays verifies that reconnecting with the same session id
// attaches to the same shell and replays its prior output.
func TestSessionReattachReplays(t *testing.T) {
	h := NewHandler(Config{
		Shell:       testShell(),
		UploadsDir:  t.TempDir(),
		MaxUpload:   1 << 20,
		Scrollback:  1 << 16,
		MaxSessions: 10,
	})
	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()

	const id = "stickytest"
	const marker = "STICKYMARKER123"

	// First connection: type a marker; the shell echoes it back, so it lands in
	// the replay buffer.
	a := dialSession(t, srv, id)
	if err := a.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":80,"rows":24}`)); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if err := a.WriteMessage(websocket.BinaryMessage, []byte(marker)); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if !readUntil(a, marker, 10*time.Second) {
		t.Fatal("first connection never saw the echoed marker")
	}
	a.Close() // detach; the session must stay alive

	time.Sleep(200 * time.Millisecond)

	// Second connection with the same id should replay the buffer containing the
	// marker, proving it re-attached to the same shell rather than starting new.
	b := dialSession(t, srv, id)
	defer b.Close()
	if !readUntil(b, marker, 10*time.Second) {
		t.Fatal("reattached connection did not replay the prior marker")
	}
}

// TestSessionDistinctIDs verifies different ids get independent shells (no
// replay bleed-through).
func TestSessionDistinctIDs(t *testing.T) {
	h := NewHandler(Config{
		Shell:       testShell(),
		UploadsDir:  t.TempDir(),
		MaxUpload:   1 << 20,
		Scrollback:  1 << 16,
		MaxSessions: 10,
	})
	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()

	const marker = "ONLYINFIRST456"
	a := dialSession(t, srv, "sess-A")
	if err := a.WriteMessage(websocket.BinaryMessage, []byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !readUntil(a, marker, 10*time.Second) {
		t.Fatal("session A never echoed its marker")
	}
	a.Close()

	b := dialSession(t, srv, "sess-B")
	defer b.Close()
	// A different session must NOT contain A's marker in its replay.
	if readUntil(b, marker, 2*time.Second) {
		t.Fatal("session B leaked session A's output")
	}
}
