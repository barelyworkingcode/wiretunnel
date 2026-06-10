// Package webssh serves an xterm.js browser terminal — dropping the visitor
// into a local PowerShell session — directly on the WireGuard netstack, so it
// is reachable ONLY over the tunnel. Unlike the standalone webssh, this server
// never opens a host socket: it is handed a gVisor netstack listener bound to
// the tunnel address, which makes "tunnel-only access" a structural property
// rather than a firewall convention. It cannot be reached from 0.0.0.0,
// localhost, or any host interface.
//
// Access is still gated by a passkey (WebAuthn) for defense in depth, which is
// why the server speaks HTTPS with a self-signed CA + leaf chain generated on
// first run (WebAuthn requires a secure context off localhost). The leaf's SANs
// cover the hostname and the tunnel addresses, so the certificate validates
// however the box is reached over the tunnel.
package webssh

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/webssh/auth"
	"github.com/barelyworkingcode/wiretunnel/internal/webssh/shortcuts"
	"github.com/barelyworkingcode/wiretunnel/internal/webssh/terminal"
	"github.com/barelyworkingcode/wiretunnel/internal/webssh/tlscert"
)

//go:embed all:web
var webFS embed.FS

// Config controls the webssh server. Only Hostname and Port are typically set
// by callers; everything else has a sensible default applied in New.
type Config struct {
	Hostname  string   // TLS SAN + WebAuthn relying-party ID; defaults to os.Hostname()
	Port      int      // tunnel port the server is reached on (origin + display only)
	ConfigDir string   // dir holding cert/key/ca/store; defaults to <UserConfigDir>/wiretunnel
	TunnelIPs []net.IP // extra leaf IP SANs (the WireGuard tunnel addresses)

	Shell          string        // shell command line; defaults to pwsh → powershell → $SHELL
	StartDir       string        // working directory for new shells; defaults to the home dir
	UploadsDir     string        // directory for pasted images; defaults to <temp>/wiretunnel-webssh-uploads
	MaxUploadMB    int64         // max size of a single pasted image; defaults to 50
	SessionTimeout time.Duration // reap a detached session idle this long; defaults to 1h (0 = never)
	ScrollbackKB   int           // KiB of recent output replayed on reattach; defaults to 256

	Logger *slog.Logger
}

// Server is a configured-but-not-yet-serving webssh instance. Build it with New
// and run it with Start.
type Server struct {
	cfg Config
	log *slog.Logger
	srv *http.Server

	certPath, keyPath, caPath string

	wg sync.WaitGroup
}

// New validates cfg, applies defaults, and wires up the HTTP handler (passkey
// gate + terminal websocket + session console). It does not bind or serve —
// call Start with a listener for that.
func New(cfg Config) (*Server, error) {
	applyDefaults(&cfg)

	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		certPath: filepath.Join(cfg.ConfigDir, "cert.pem"),
		keyPath:  filepath.Join(cfg.ConfigDir, "key.pem"),
		caPath:   filepath.Join(cfg.ConfigDir, "ca.pem"),
	}

	rpID := strings.ToLower(cfg.Hostname)
	if net.ParseIP(rpID) != nil {
		s.log.Warn("webssh hostname is an IP address; WebAuthn needs a registrable hostname, "+
			"so passkeys will not work in the browser — set \"hostname\" in tunnel.json", "hostname", rpID)
	}

	// The browser reaches the server at https://<hostname>:<port> over the
	// tunnel; WebAuthn checks the request origin against this and anchors the
	// credential to the relying-party ID (the hostname, no port).
	origins := []string{originURL("https", rpID, cfg.Port)}
	storePath := filepath.Join(cfg.ConfigDir, "store.json")
	authMgr, err := auth.New(rpID, origins, storePath, true /* secure: always HTTPS */)
	if err != nil {
		return nil, fmt.Errorf("auth init: %w", err)
	}

	// One-click shell shortcuts, stored on the machine next to the passkey store
	// so they survive restarts and are shared by every browser over the tunnel.
	scStore, err := shortcuts.New(filepath.Join(cfg.ConfigDir, "shortcuts.json"))
	if err != nil {
		return nil, fmt.Errorf("shortcuts init: %w", err)
	}

	shellTokens := splitCommand(cfg.Shell)
	if len(shellTokens) == 0 {
		return nil, fmt.Errorf("empty shell")
	}

	// Prune images from previous runs now and periodically thereafter so the
	// uploads dir does not grow without bound over a long-running server.
	terminal.StartUploadPruner(cfg.UploadsDir, 24*time.Hour)
	term := terminal.NewHandler(terminal.Config{
		Shell:       shellTokens[0],
		ShellArgs:   shellTokens[1:],
		StartDir:    cfg.StartDir,
		UploadsDir:  cfg.UploadsDir,
		MaxUpload:   cfg.MaxUploadMB << 20,
		Scrollback:  cfg.ScrollbackKB << 10,
		IdleTimeout: cfg.SessionTimeout,
		MaxSessions: 50,
	})

	staticFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Static assets (index, app.js, vendored xterm) are public; the page gates
	// functionality client-side based on /api/status. A bare visit to "/" is
	// redirected to a URL carrying a fresh session ID, so a later refresh keeps
	// the ID and re-attaches to the same running shell.
	fileServer := http.FileServer(http.FS(staticFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.URL.Query().Get("session") == "" {
			http.Redirect(w, r, "/?session="+terminal.NewID(), http.StatusSeeOther)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	// Lets a client download the CA certificate to trust it locally. This is the
	// CA, not the leaf the server presents: Firefox/NSS only accepts a CA as a
	// trusted authority, and trusting the CA validates the leaf.
	mux.HandleFunc("/webssh-ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="webssh-ca.pem"`)
		http.ServeFile(w, r, s.caPath)
	})

	mux.HandleFunc("/api/status", authMgr.Status)
	mux.HandleFunc("/api/register/begin", authMgr.RegisterBegin)
	mux.HandleFunc("/api/register/finish", authMgr.RegisterFinish)
	mux.HandleFunc("/api/login/begin", authMgr.LoginBegin)
	mux.HandleFunc("/api/login/finish", authMgr.LoginFinish)
	mux.HandleFunc("/api/logout", authMgr.Logout)

	// The admin console page is public like index.html (it gates itself on the
	// API response); its backing API requires an authenticated session, just
	// like the terminal websocket.
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "console.html")
	})

	// Certificate-trust instructions. Public, and reachable before sign-in: a
	// visitor whose browser does not yet trust the CA (so passkeys are blocked)
	// is sent here to download and trust it.
	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "cert.html")
	})
	mux.HandleFunc("/api/sessions", authMgr.Require(term.Sessions))
	mux.HandleFunc("/api/sessions/kill", authMgr.Require(term.KillSession))

	// Shortcuts CRUD, gated by the same passkey session as the console it backs.
	mux.HandleFunc("/api/shortcuts", authMgr.Require(scStore.Handle))
	mux.HandleFunc("/api/shortcuts/delete", authMgr.Require(scStore.HandleDelete))

	// The terminal websocket requires an authenticated session.
	mux.HandleFunc("/ws", authMgr.Require(term.ServeWS))

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return s, nil
}

// Start ensures the TLS material exists (generating the CA + leaf chain on first
// run) and begins serving HTTPS over ln in the background. ln is expected to be
// a WireGuard netstack listener, so the server is reachable only over the
// tunnel. It returns once serving has started; a context cancellation later
// triggers a graceful shutdown. Call Wait to block until that drains.
func (s *Server) Start(ctx context.Context, ln net.Listener) error {
	created, err := tlscert.Ensure(s.certPath, s.keyPath, s.caPath, s.cfg.Hostname, s.cfg.TunnelIPs)
	if err != nil {
		return fmt.Errorf("tls cert: %w", err)
	}
	if created {
		s.log.Info("generated self-signed CA + leaf certificate", "host", s.cfg.Hostname, "ca", s.caPath)
	}

	visitURL := originURL("https", s.cfg.Hostname, s.cfg.Port)
	s.log.Info("webssh up", "url", visitURL, "console", visitURL+"/console", "access", "tunnel-only")
	s.log.Info("webssh: trust the CA once per browser", "download", visitURL+"/webssh-ca.pem")

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Cert/key already exist (Ensure ran); ServeTLS loads them from disk.
		if err := s.srv.ServeTLS(ln, s.certPath, s.keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("webssh serve failed", "err", err)
		}
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()
	return nil
}

// Wait blocks until the server has fully shut down, which happens after the
// context passed to Start is cancelled.
func (s *Server) Wait() { s.wg.Wait() }

// URL is the browser address the terminal is reached at over the tunnel, using
// the resolved hostname and port.
func (s *Server) URL() string { return originURL("https", s.cfg.Hostname, s.cfg.Port) }

// applyDefaults fills any unset Config field with its default.
func applyDefaults(cfg *Config) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Hostname == "" {
		cfg.Hostname = defaultHostname()
	}
	if cfg.Port == 0 {
		cfg.Port = 8022
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = defaultConfigDir()
	}
	if cfg.Shell == "" {
		cfg.Shell = defaultShell()
	}
	if cfg.StartDir == "" {
		cfg.StartDir = defaultStartDir()
	}
	if cfg.UploadsDir == "" {
		cfg.UploadsDir = filepath.Join(os.TempDir(), "wiretunnel-webssh-uploads")
	}
	if cfg.MaxUploadMB == 0 {
		cfg.MaxUploadMB = 50
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = time.Hour
	}
	if cfg.ScrollbackKB == 0 {
		cfg.ScrollbackKB = 256
	}
}

// originURL builds a browser origin, omitting the port when it is the default
// for the scheme.
func originURL(scheme, host string, port int) string {
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func defaultHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return strings.ToLower(h)
	}
	return "localhost"
}

// defaultConfigDir returns <UserConfigDir>/wiretunnel, where the TLS material
// and the passkey store live. It falls back to the current directory if the
// user config dir cannot be determined.
func defaultConfigDir() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "wiretunnel-config"
	}
	return filepath.Join(dir, "wiretunnel")
}

// defaultShell picks a sensible interactive shell. PowerShell 7 (pwsh) is
// preferred everywhere since it is cross-platform; on Windows we fall back to
// the built-in Windows PowerShell, and on Unix to the user's login shell.
func defaultShell() string {
	if p, err := exec.LookPath("pwsh"); err == nil {
		return quoteIfSpaced(p)
	}
	if runtime.GOOS == "windows" {
		return "powershell.exe"
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		return quoteIfSpaced(sh)
	}
	return "/bin/bash"
}

// defaultStartDir returns the directory new shells start in: the user's home
// directory. If it cannot be determined, the empty string falls back to the
// server process's current directory.
func defaultStartDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return ""
}

// quoteIfSpaced wraps a path in double quotes when it contains whitespace, so
// splitCommand keeps it as a single token.
func quoteIfSpaced(p string) string {
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}

// splitCommand splits a shell command line into the executable and its
// arguments, honoring double quotes so a quoted path containing spaces stays a
// single token (e.g. `"C:\Program Files\PowerShell\7\pwsh.exe" -NoLogo`).
func splitCommand(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuotes, started := false, false
	flush := func() {
		if started {
			tokens = append(tokens, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			started = true
		case (r == ' ' || r == '\t') && !inQuotes:
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return tokens
}
