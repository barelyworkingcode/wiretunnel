// Package tlscert generates and persists a self-signed TLS certificate so the
// server can offer HTTPS (required for WebAuthn outside of localhost).
//
// It creates a small two-cert chain rather than a single self-signed cert: a
// local CA that only signs, and a leaf (the cert the server actually presents)
// signed by that CA. This matters for Firefox/NSS, which refuses a CA
// certificate used directly as the end-entity (MOZILLA_PKIX_ERROR_CA_CERT_
// USED_AS_END_ENTITY) and only lets you trust a *CA* as an authority — a bare
// self-signed leaf can only be added as a per-site exception, over which
// Firefox blocks WebAuthn. Clients trust the CA once; everything is persisted
// to disk and reused across restarts.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Ensure makes sure a usable CA + leaf cert/key set exists at the given paths,
// generating one for hostname (plus localhost) if any is missing. certPath
// holds the leaf chain (leaf followed by CA) that the server presents; caPath
// holds the CA alone, which is the cert clients import and trust. extraIPs are
// added to the leaf's IP SANs — for wiretunnel these are the WireGuard tunnel
// addresses, so the certificate also validates when the server is reached by
// tunnel IP rather than by hostname.
//
// A cached set is regenerated if the existing leaf does not cover hostname (for
// example because "hostname" in tunnel.json changed since it was first issued),
// so a corrected hostname takes effect on the next start with no manual cleanup.
// It reports whether a new set was generated.
func Ensure(certPath, keyPath, caPath, hostname string, extraIPs []net.IP) (created bool, err error) {
	if fileExists(certPath) && fileExists(keyPath) && fileExists(caPath) && leafCovers(certPath, hostname) {
		return false, nil
	}
	if err := generate(certPath, keyPath, caPath, hostname, extraIPs); err != nil {
		return false, err
	}
	return true, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// leafCovers reports whether the leaf certificate at certPath is valid for
// hostname (matched against its SANs). An empty hostname always passes; an
// unreadable or unparseable cert never does, which forces regeneration.
func leafCovers(certPath, hostname string) bool {
	if hostname == "" {
		return true
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data) // the leaf is the first PEM block in the chain
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.VerifyHostname(hostname) == nil
}

func generate(certPath, keyPath, caPath, hostname string, extraIPs []net.IP) error {
	// --- Certificate authority: signs the leaf; this is what clients trust. ---
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := randSerial()
	if err != nil {
		return err
	}
	caTmpl := x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "wiretunnel Local CA", Organization: []string{"wiretunnel"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // may sign leaves, not sub-CAs
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	// --- Leaf: the cert the server presents. NOT a CA, so Firefox/NSS accepts
	// it as an end-entity instead of rejecting the connection. ---
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafSerial, err := randSerial()
	if err != nil {
		return err
	}
	leafTmpl := x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"wiretunnel"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Subject Alternative Names: browsers validate against these, not CN.
	dns := map[string]bool{"localhost": true}
	var ips []net.IP
	seenIP := map[string]bool{}
	addIP := func(ip net.IP) {
		if ip == nil || seenIP[ip.String()] {
			return
		}
		seenIP[ip.String()] = true
		ips = append(ips, ip)
	}
	if ip := net.ParseIP(hostname); ip != nil {
		addIP(ip)
	} else if hostname != "" {
		dns[hostname] = true
	}
	addIP(net.IPv4(127, 0, 0, 1))
	addIP(net.IPv6loopback)
	// Tunnel addresses, so the leaf also validates when reached by tunnel IP.
	for _, ip := range extraIPs {
		addIP(ip)
	}
	for name := range dns {
		leafTmpl.DNSNames = append(leafTmpl.DNSNames, name)
	}
	leafTmpl.IPAddresses = ips

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Leaf first, then CA: the order ServeTLS expects for a presented chain.
	if err := os.WriteFile(certPath, append(leafPEM, caPEM...), 0o644); err != nil {
		return err
	}
	// CA alone: the file a client imports as a trusted authority.
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}

	if !fileExists(certPath) || !fileExists(keyPath) || !fileExists(caPath) {
		return fmt.Errorf("certificate files were not written")
	}
	return nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
