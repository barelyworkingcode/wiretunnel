package terminal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/aymanbagabas/go-pty"
	"github.com/gorilla/websocket"
)

// clearSeq resets the client screen and scrollback before replaying a
// session's buffer, so a reattach restores state without duplicating content.
var clearSeq = []byte("\x1b[H\x1b[2J\x1b[3J")

// busyWindow: a session that has produced PTY output within this window is
// reported as "busy" (a command is running and printing); otherwise "idle"
// (sitting at a prompt waiting for input). This is a heuristic — a command
// blocked on input, or computing silently without printing, reads as idle.
const busyWindow = 1500 * time.Millisecond

var errTooManySessions = errors.New("too many active sessions")

// Config controls session behavior.
type Config struct {
	Shell       string
	ShellArgs   []string
	StartDir    string // working directory each new shell starts in (empty = current dir)
	UploadsDir  string
	MaxUpload   int64
	Scrollback  int           // bytes of recent output retained for replay
	IdleTimeout time.Duration // detached sessions idle longer than this are reaped (0 = never)
	MaxSessions int
}

// NewID returns an unguessable URL-safe session identifier.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// outMsg is a websocket frame queued for a client.
type outMsg struct {
	mt   int
	data []byte
}

// client is one websocket attached to a session. A dedicated writePump
// goroutine is the sole writer, satisfying gorilla's single-writer rule.
type client struct {
	conn *websocket.Conn
	send chan outMsg
	once sync.Once
}

func (c *client) enqueue(m outMsg) bool {
	select {
	case c.send <- m:
		return true
	default:
		return false // buffer full; caller drops this client
	}
}

func (c *client) writePump(initial []byte) {
	if len(initial) > 0 {
		if err := c.conn.WriteMessage(websocket.BinaryMessage, initial); err != nil {
			c.conn.Close()
			return
		}
	}
	for m := range c.send {
		if err := c.conn.WriteMessage(m.mt, m.data); err != nil {
			break
		}
	}
	c.conn.Close()
}

// Session owns a long-lived PTY and the set of websockets currently attached to
// it. It outlives any single connection, so refreshing the browser re-attaches.
type Session struct {
	id   string
	ptmx pty.Pty
	cmd  *pty.Cmd
	mgr  *Manager

	writeMu sync.Mutex // serializes PTY input/resize operations

	mu         sync.Mutex
	clients    map[int]*client
	nextID     int
	buf        []byte // rolling replay buffer
	maxBuf     int
	createdAt  time.Time
	lastActive time.Time // last attach/detach/keystroke; drives idle reaping
	lastOutput time.Time // last PTY output; drives busy/idle reporting
	title      string    // latest OSC 0/2 window title from PTY output

	// titleScan parses OSC title sequences out of the PTY stream. It is touched
	// only by outputPump (the lone reader of the PTY), so it needs no lock.
	titleScan titleScanner

	closeOnce sync.Once
}

func (s *Session) appendOutput(p []byte) {
	s.buf = append(s.buf, p...)
	if s.maxBuf > 0 && len(s.buf) > s.maxBuf {
		trimmed := make([]byte, s.maxBuf)
		copy(trimmed, s.buf[len(s.buf)-s.maxBuf:])
		s.buf = trimmed
	}
}

// broadcast fans a message out to every attached client. Callers hold s.mu. A
// client whose buffer is full is dropped (its writePump will close the socket).
func (s *Session) broadcast(m outMsg) {
	for id, c := range s.clients {
		if !c.enqueue(m) {
			s.removeClientLocked(id)
		}
	}
}

func (s *Session) removeClientLocked(id int) {
	if c, ok := s.clients[id]; ok {
		delete(s.clients, id)
		c.once.Do(func() { close(c.send) })
	}
}

// outputPump streams PTY output into the replay buffer and to all clients until
// the shell exits or the PTY closes.
func (s *Session) outputPump() {
	buf := make([]byte, 32*1024)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			// Sniff the chunk for a window-title update before locking: the
			// scanner is single-goroutine state, so it stays outside s.mu.
			title, gotTitle := s.titleScan.feed(chunk)
			s.mu.Lock()
			s.appendOutput(chunk)
			s.lastOutput = time.Now()
			if gotTitle {
				s.title = title
			}
			s.broadcast(outMsg{websocket.BinaryMessage, chunk})
			s.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	s.shutdown(true)
}

// attach registers a websocket and hands its writePump the clear+replay
// snapshot so the client sees the current screen.
func (s *Session) attach(conn *websocket.Conn) (*client, int) {
	c := &client{conn: conn, send: make(chan outMsg, 256)}
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.clients[id] = c
	s.lastActive = time.Now()
	snapshot := make([]byte, 0, len(clearSeq)+len(s.buf))
	snapshot = append(snapshot, clearSeq...)
	snapshot = append(snapshot, s.buf...)
	s.mu.Unlock()
	go c.writePump(snapshot)
	return c, id
}

func (s *Session) detach(id int) {
	s.mu.Lock()
	s.removeClientLocked(id)
	s.lastActive = time.Now()
	s.mu.Unlock()
	// The PTY keeps running with zero clients; that is what makes it sticky.
}

func (s *Session) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *Session) writeInput(p []byte) {
	s.writeMu.Lock()
	_, _ = s.ptmx.Write(p)
	s.writeMu.Unlock()
}

func (s *Session) resize(cols, rows int) {
	if cols <= 0 || rows <= 0 {
		return
	}
	s.writeMu.Lock()
	_ = s.ptmx.Resize(cols, rows)
	s.writeMu.Unlock()
}

// notify queues a one-off yellow notice to a single client, identified by id.
// It runs under s.mu and only enqueues if the client is still attached, so it
// cannot race removeClientLocked into a send on an already-closed channel.
func (s *Session) notify(id int, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return
	}
	if !c.enqueue(outMsg{websocket.BinaryMessage, []byte("\r\n\x1b[33m[webssh: " + msg + "]\x1b[0m\r\n")}) {
		s.removeClientLocked(id)
	}
}

// sendControl enqueues a one-off text frame to a single client by id, dropping
// the client if its buffer is full. Used for control replies such as the pong
// that answers a latency ping.
func (s *Session) sendControl(id int, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return
	}
	if !c.enqueue(outMsg{websocket.TextMessage, data}) {
		s.removeClientLocked(id)
	}
}

// shutdown ends the session exactly once: it closes the PTY, removes itself
// from the manager, optionally tells clients the shell exited, and disconnects
// them.
func (s *Session) shutdown(shellExited bool) {
	s.closeOnce.Do(func() {
		_ = s.ptmx.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		_ = s.cmd.Wait()
		s.mgr.remove(s.id, s)

		s.mu.Lock()
		if shellExited {
			s.broadcast(outMsg{websocket.TextMessage, []byte(`{"type":"exit"}`)})
		}
		for id := range s.clients {
			s.removeClientLocked(id)
		}
		s.mu.Unlock()
	})
}

// Manager owns all live sessions.
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewManager(cfg Config) *Manager {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 50
	}
	m := &Manager{cfg: cfg, sessions: make(map[string]*Session)}
	go m.reaper()
	return m
}

func (m *Manager) getOrCreate(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		// Bump lastActive while still holding the manager lock so the reaper
		// cannot reap this session in the window before the caller attaches.
		s.mu.Lock()
		s.lastActive = time.Now()
		s.mu.Unlock()
		return s, nil
	}
	if len(m.sessions) >= m.cfg.MaxSessions {
		return nil, errTooManySessions
	}
	ptmx, err := pty.New()
	if err != nil {
		return nil, err
	}
	cmd := ptmx.Command(m.cfg.Shell, m.cfg.ShellArgs...)
	cmd.Dir = m.cfg.StartDir
	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	now := time.Now()
	s := &Session{
		id:         id,
		ptmx:       ptmx,
		cmd:        cmd,
		mgr:        m,
		clients:    make(map[int]*client),
		maxBuf:     m.cfg.Scrollback,
		createdAt:  now,
		lastActive: now,
		lastOutput: now,
	}
	m.sessions[id] = s
	go s.outputPump()
	return s, nil
}

func (m *Manager) remove(id string, s *Session) {
	m.mu.Lock()
	// Only unmap if this exact session is still registered: a reaped id may
	// already have been reused by a freshly created session.
	if m.sessions[id] == s {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
}

// SessionInfo is a point-in-time view of one live session, surfaced to the
// admin console.
type SessionInfo struct {
	ID          string `json:"id"`
	Title       string `json:"title"`       // latest window title the shell/program set (OSC 0/2)
	Connections int    `json:"connections"` // websockets currently attached
	State       string `json:"state"`       // "busy" or "idle"
	IdleSeconds int    `json:"idleSeconds"` // seconds since the last PTY output
	AgeSeconds  int    `json:"ageSeconds"`  // seconds since the session was created
}

// Snapshot returns a view of every live session, newest-first so the list is
// stable across refreshes. State is derived from recent PTY output: a session
// that printed within busyWindow is "busy", otherwise "idle".
func (m *Manager) Snapshot() []SessionInfo {
	now := time.Now()
	m.mu.Lock()
	out := make([]SessionInfo, 0, len(m.sessions))
	for id, s := range m.sessions {
		s.mu.Lock()
		conns := len(s.clients)
		sinceOut := now.Sub(s.lastOutput)
		age := now.Sub(s.createdAt)
		title := s.title
		s.mu.Unlock()
		state := "idle"
		if sinceOut < busyWindow {
			state = "busy"
		}
		out = append(out, SessionInfo{
			ID:          id,
			Title:       title,
			Connections: conns,
			State:       state,
			IdleSeconds: int(sinceOut.Seconds()),
			AgeSeconds:  int(age.Seconds()),
		})
	}
	m.mu.Unlock()
	// Newest first; break ties by id so ordering is deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgeSeconds != out[j].AgeSeconds {
			return out[i].AgeSeconds < out[j].AgeSeconds
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Kill terminates the session with the given id, disconnecting any attached
// clients and reaping its shell. It reports whether a session was found. The
// session is unmapped under the manager lock first so a racing reconnect mints
// a fresh session rather than re-attaching to the one being torn down.
func (m *Manager) Kill(id string) bool {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	// shellExited=true so attached browsers see {"type":"exit"} and stop
	// reconnecting (otherwise they would immediately spawn a fresh shell).
	s.shutdown(true)
	return true
}

// reaper periodically kills detached sessions that have been idle too long.
func (m *Manager) reaper() {
	if m.cfg.IdleTimeout <= 0 {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var victims []*Session
		m.mu.Lock()
		for id, s := range m.sessions {
			s.mu.Lock()
			idle := len(s.clients) == 0 && now.Sub(s.lastActive) > m.cfg.IdleTimeout
			s.mu.Unlock()
			if idle {
				// Unmap under the manager lock so a concurrent getOrCreate for
				// this id creates a fresh session rather than handing a caller
				// the one we are about to shut down.
				delete(m.sessions, id)
				victims = append(victims, s)
			}
		}
		m.mu.Unlock()
		for _, s := range victims {
			s.shutdown(false)
		}
	}
}

// titleScanner extracts the window title from a PTY byte stream as it arrives in
// arbitrary chunks. A terminal sets its title with OSC 0 (icon name + title) or
// OSC 2 (title): "ESC ] 0 ; <text> BEL" — or terminated by ST ("ESC \") instead
// of BEL. ConPTY on Windows emits these when the console title changes, as do
// shells and TUIs (vim, tmux, oh-my-posh, …) everywhere. The scanner is a tiny
// state machine, so a sequence split across two reads is still recognized.
type titleScanner struct {
	state titleState
	buf   []byte // OSC payload accumulated after "ESC ]"
}

type titleState int

const (
	titleNormal titleState = iota // ordinary output
	titleEsc                      // saw ESC
	titleOSC                      // inside "ESC ] …", collecting the payload
	titleOSCEsc                   // inside OSC, saw ESC (maybe the ST terminator)
)

// maxTitleLen caps the buffered payload so a stream that opens an OSC and never
// terminates it cannot grow the buffer without bound.
const maxTitleLen = 1024

// feed consumes a chunk and returns the most recent complete title found in it,
// if any. Only OSC 0 and OSC 2 (the title codes) yield a title; other OSC
// sequences (colors, hyperlinks, clipboard, …) are parsed through and ignored.
func (ts *titleScanner) feed(p []byte) (title string, found bool) {
	for _, b := range p {
		switch ts.state {
		case titleNormal:
			if b == 0x1b {
				ts.state = titleEsc
			}
		case titleEsc:
			switch b {
			case ']':
				ts.state = titleOSC
				ts.buf = ts.buf[:0]
			case 0x1b:
				// A run of ESCs: stay armed for the next byte.
			default:
				ts.state = titleNormal
			}
		case titleOSC:
			switch b {
			case 0x07: // BEL terminates the OSC
				if t, ok := parseTitleOSC(ts.buf); ok {
					title, found = t, true
				}
				ts.state = titleNormal
			case 0x1b:
				ts.state = titleOSCEsc
			default:
				if len(ts.buf) < maxTitleLen {
					ts.buf = append(ts.buf, b)
				}
			}
		case titleOSCEsc:
			switch b {
			case '\\': // ESC \ = ST, also terminates the OSC
				if t, ok := parseTitleOSC(ts.buf); ok {
					title, found = t, true
				}
				ts.state = titleNormal
			case 0x1b:
				// Another ESC: ST may still follow.
			default:
				// ESC then a non-'\' byte: this OSC is malformed, abandon it.
				ts.state = titleNormal
			}
		}
	}
	return title, found
}

// parseTitleOSC interprets an OSC payload "Ps;Pt", returning Pt when Ps selects
// a title (0 = icon name + title, 2 = title). Any other code returns ok=false.
func parseTitleOSC(buf []byte) (string, bool) {
	i := bytes.IndexByte(buf, ';')
	if i < 0 {
		return "", false
	}
	switch string(buf[:i]) {
	case "0", "2":
		return string(buf[i+1:]), true
	default:
		return "", false
	}
}
