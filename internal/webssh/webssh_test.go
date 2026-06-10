package webssh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServerEndToEnd starts a real webssh server over an injected loopback
// listener (the same seam main.go uses to hand it the WireGuard netstack
// listener) and exercises the public surface: certificate generation, HTTPS
// serving, the "/" → "/?session=…" redirect, and the CA download. Trusting the
// generated CA and connecting to 127.0.0.1 also confirms the leaf's loopback IP
// SAN validates.
func TestServerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{
		Hostname:  "testhost",
		ConfigDir: dir,
		// Keep PTY sessions out of this test; we only hit static/redirect routes.
		UploadsDir: filepath.Join(dir, "uploads"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		srv.Wait()
	}()
	if err := srv.Start(ctx, ln); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// The CA + leaf chain must have been generated on first start.
	for _, f := range []string{"cert.pem", "key.pem", "ca.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("expected %s to be generated: %v", f, err)
		}
	}

	// A client that trusts the generated CA; connecting to 127.0.0.1 validates
	// the leaf's loopback IP SAN.
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load generated CA")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		// Don't follow redirects, so we can assert the "/" → session redirect.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	base := "https://" + ln.Addr().String()

	// "/" issues a fresh-session redirect so a later refresh re-attaches.
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET / status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/?session=") {
		t.Errorf("GET / Location = %q, want /?session=…", loc)
	}

	// The CA is downloadable so a browser can trust it once.
	resp, err = client.Get(base + "/webssh-ca.pem")
	if err != nil {
		t.Fatalf("GET /webssh-ca.pem: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /webssh-ca.pem status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Errorf("GET /webssh-ca.pem body is not a PEM certificate")
	}

	// The certificate-setup page is public (reachable before sign-in) and links
	// the CA download.
	resp, err = client.Get(base + "/cert")
	if err != nil {
		t.Fatalf("GET /cert: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /cert status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "/webssh-ca.pem") {
		t.Errorf("GET /cert page does not link the CA download")
	}

	// The terminal websocket is passkey-gated; with no session it must be denied.
	resp, err = client.Get(base + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/sessions status = %d, want 401 (passkey-gated)", resp.StatusCode)
	}

	// Shortcuts are gated by the same passkey session as the console.
	resp, err = client.Get(base + "/api/shortcuts")
	if err != nil {
		t.Fatalf("GET /api/shortcuts: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/shortcuts status = %d, want 401 (passkey-gated)", resp.StatusCode)
	}
}
