// Package terminal bridges browser xterm.js sessions to local PTYs over
// websockets. PTYs are owned by a Manager and keyed by a session ID, so they
// outlive any single websocket: refreshing the browser re-attaches to the same
// running shell. Each session ID corresponds to one shell; opening a new tab
// without an ID yields a new session.
package terminal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Handler upgrades websocket requests and attaches them to sessions.
type Handler struct {
	mgr        *Manager
	uploadsDir string
	maxUpload  int64
	upgrader   websocket.Upgrader
}

func NewHandler(cfg Config) *Handler {
	return &Handler{
		mgr:        NewManager(cfg),
		uploadsDir: cfg.UploadsDir,
		maxUpload:  cfg.MaxUpload,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			// Reject cross-origin handshakes: the Origin host must match the
			// host the request was served on. Combined with the SameSite
			// session cookie this blocks cross-site websocket hijacking.
			CheckOrigin: sameOrigin,
		},
	}
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// Sessions reports every live session as JSON for the admin console. It is
// registered behind the same passkey gate as the terminal websocket.
func (h *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": h.mgr.Snapshot()})
}

// KillSession terminates the session named in the JSON body ({"id":"…"}),
// disconnecting any attached clients and reaping its shell.
func (h *Handler) KillSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"killed": h.mgr.Kill(req.ID)})
}

// control is a JSON message sent by the client over text frames. Keystrokes
// travel as binary frames instead, so the two never collide.
type control struct {
	Type string          `json:"type"`
	Cols int             `json:"cols"`
	Rows int             `json:"rows"`
	Mime string          `json:"mime"` // for type "image"
	Data string          `json:"data"` // for type "image": base64-encoded bytes
	T    json.RawMessage `json:"t"`    // for type "ping": echoed verbatim in the pong
}

// ServeWS attaches a websocket to the session named by ?session=<id>, creating
// it on first use.
func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(h.maxUpload + h.maxUpload/2 + 4096)

	id := r.URL.Query().Get("session")
	if id == "" {
		id = NewID()
	}

	s, err := h.mgr.getOrCreate(id)
	if err != nil {
		frame, _ := json.Marshal(map[string]string{"type": "error", "message": err.Error()})
		_ = conn.WriteMessage(websocket.TextMessage, frame)
		conn.Close()
		return
	}

	_, cid := s.attach(conn)
	defer s.detach(cid)

	// websocket -> PTY. Text frames carry control messages (resize, pasted
	// images); binary frames carry raw keystrokes.
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		s.touch()
		if mt == websocket.TextMessage {
			var msg control
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			switch msg.Type {
			case "resize":
				s.resize(msg.Cols, msg.Rows)
			case "image":
				h.handleImage(s, cid, &msg)
			case "ping":
				// Echo the client's timestamp straight back so it can measure
				// the round trip. Going through the normal write path means the
				// reading reflects real conditions, not just raw network time.
				if len(msg.T) > 0 {
					frame, err := json.Marshal(struct {
						Type string          `json:"type"`
						T    json.RawMessage `json:"t"`
					}{"pong", msg.T})
					if err == nil {
						s.sendControl(cid, frame)
					}
				}
			}
			continue
		}
		s.writeInput(data)
	}
}

// handleImage decodes a pasted image, writes it to a file, and types the file's
// path at the prompt. Tools that accept image paths — like Claude Code — then
// read it as if it had been dragged in.
func (h *Handler) handleImage(s *Session, cid int, msg *control) {
	path, err := h.saveImage(msg.Mime, msg.Data)
	if err != nil {
		s.notify(cid, err.Error())
		return
	}
	if path == "" {
		return
	}
	s.writeInput([]byte(injectText(path)))
}

// saveImage decodes base64 image bytes and writes them to a uniquely named file
// in the uploads directory, returning the path. An empty image yields ("", nil).
func (h *Handler) saveImage(mime, data string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", errors.New("could not decode pasted image")
	}
	if int64(len(raw)) > h.maxUpload {
		return "", errors.New("pasted image too large")
	}
	if len(raw) == 0 {
		return "", nil
	}
	if err := os.MkdirAll(h.uploadsDir, 0o700); err != nil {
		return "", errors.New("could not create uploads directory")
	}
	path := filepath.Join(h.uploadsDir, "paste-"+randHex(8)+extForMime(mime))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", errors.New("could not save pasted image")
	}
	return path, nil
}

// injectText renders a path for typing at the prompt, quoting it when it
// contains whitespace, and adds a trailing space so the user can keep typing.
func injectText(path string) string {
	if strings.ContainsAny(path, " \t") {
		return "\"" + path + "\" "
	}
	return path + " "
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func extForMime(mime string) string {
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "image/png":
		return ".png"
	case "image/jpeg", "image/jpg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "image/bmp":
		return ".bmp"
	case "image/svg+xml":
		return ".svg"
	default:
		return ".png"
	}
}

// StartUploadPruner prunes dir once immediately and then on an interval for the
// life of the process, so the uploads directory does not grow without bound on
// a long-running server.
func StartUploadPruner(dir string, maxAge time.Duration) {
	PruneUploads(dir, maxAge)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			PruneUploads(dir, maxAge)
		}
	}()
}

// PruneUploads removes saved images older than maxAge so the uploads directory
// does not grow without bound.
func PruneUploads(dir string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
