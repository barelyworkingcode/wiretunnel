package tlscert

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureRegeneratesOnHostnameChange verifies the cache behavior: a set is
// generated on first run, reused when it already covers the hostname, and
// regenerated when the configured hostname is no longer covered (e.g. the
// operator corrected "hostname" in tunnel.json). It also checks the tunnel IP
// lands in the leaf SANs and the CA subject is wiretunnel-specific.
func TestEnsureRegeneratesOnHostnameChange(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	ca := filepath.Join(dir, "ca.pem")
	tunnelIP := net.IPv4(10, 189, 176, 247)

	// First run generates the set.
	created, err := Ensure(cert, key, ca, "host-a", []net.IP{tunnelIP})
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if !created {
		t.Fatal("first Ensure created=false, want true")
	}
	leaf := readLeaf(t, cert)
	if leaf.VerifyHostname("host-a") != nil {
		t.Error("leaf should cover host-a")
	}
	if leaf.Issuer.CommonName != "wiretunnel Local CA" {
		t.Errorf("CA CommonName = %q, want wiretunnel Local CA", leaf.Issuer.CommonName)
	}
	var hasTunnelIP bool
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(tunnelIP) {
			hasTunnelIP = true
		}
	}
	if !hasTunnelIP {
		t.Errorf("leaf SANs %v missing tunnel IP %v", leaf.IPAddresses, tunnelIP)
	}

	// Same hostname reuses the cached set.
	created, err = Ensure(cert, key, ca, "host-a", []net.IP{tunnelIP})
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if created {
		t.Error("second Ensure created=true, want false (cache hit)")
	}

	// A changed hostname forces regeneration covering the new name.
	created, err = Ensure(cert, key, ca, "host-b", []net.IP{tunnelIP})
	if err != nil {
		t.Fatalf("third Ensure: %v", err)
	}
	if !created {
		t.Error("third Ensure created=false, want true (hostname changed)")
	}
	leaf = readLeaf(t, cert)
	if leaf.VerifyHostname("host-b") != nil {
		t.Error("regenerated leaf should cover host-b")
	}
	if leaf.VerifyHostname("host-a") == nil {
		t.Error("regenerated leaf should no longer cover host-a")
	}
}

func readLeaf(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
