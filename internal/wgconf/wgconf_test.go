package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Test fixtures use throwaway keys and example hosts — never real credentials.
const (
	testPrivKey = "k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw="
	testPubKey  = "GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw="
)

// sampleConf is a representative wg-quick config (with placeholder values).
const sampleConf = `[Interface]
PrivateKey=k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
Address=10.0.0.2/32
DNS=10.0.0.1
MTU=1412
[Peer]
PublicKey=GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
Endpoint=vpn.example.com:51820
AllowedIPs=0.0.0.0/0
`

func TestParseSample(t *testing.T) {
	cfg, err := Parse(strings.NewReader(sampleConf))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if cfg.PrivateKey != testPrivKey {
		t.Errorf("PrivateKey = %q", cfg.PrivateKey)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.0.0.2" {
		t.Errorf("Addresses = %v, want [10.0.0.2]", cfg.Addresses)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "10.0.0.1" {
		t.Errorf("DNS = %v, want [10.0.0.1]", cfg.DNS)
	}
	if cfg.MTU != 1412 {
		t.Errorf("MTU = %d, want 1412", cfg.MTU)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers = %d, want 1", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.PublicKey != testPubKey {
		t.Errorf("PublicKey = %q", p.PublicKey)
	}
	if p.Endpoint != "vpn.example.com:51820" {
		t.Errorf("Endpoint = %q", p.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %v, want [0.0.0.0/0]", p.AllowedIPs)
	}
}

func TestParseDefaultsAndComments(t *testing.T) {
	conf := `# a comment
[Interface]
PrivateKey = k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
Address = 10.0.0.2/24, fd00::2/64
; ignored host directive
Table = off

[Peer]
PublicKey = GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
AllowedIPs = 10.0.0.0/24
`
	cfg, err := Parse(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.MTU != defaultMTU {
		t.Errorf("MTU = %d, want default %d", cfg.MTU, defaultMTU)
	}
	if len(cfg.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want 2 entries", cfg.Addresses)
	}
	if cfg.Addresses[0].String() != "10.0.0.2" || cfg.Addresses[1].String() != "fd00::2" {
		t.Errorf("Addresses = %v", cfg.Addresses)
	}
}

func TestUAPI(t *testing.T) {
	conf := `[Interface]
PrivateKey=k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
Address=10.0.0.2/32
[Peer]
PublicKey=GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
Endpoint=127.0.0.1:51820
AllowedIPs=0.0.0.0/0
PersistentKeepalive=25
`
	cfg, err := Parse(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	uapi, err := cfg.UAPI()
	if err != nil {
		t.Fatalf("UAPI: %v", err)
	}

	want := []string{
		"private_key=" + mustHex(t, testPrivKey),
		"public_key=" + mustHex(t, testPubKey),
		"endpoint=127.0.0.1:51820",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
	}
	for _, w := range want {
		if !strings.Contains(uapi, w) {
			t.Errorf("UAPI missing %q\ngot:\n%s", w, uapi)
		}
	}

	// The interface private key must precede the peer's public key, or
	// wireguard-go assigns the peer fields to the wrong section.
	if strings.Index(uapi, "private_key=") > strings.Index(uapi, "public_key=") {
		t.Errorf("private_key must come before public_key:\n%s", uapi)
	}
}

func TestUAPIResolvesIPLiteralWithoutDNS(t *testing.T) {
	// An IP-literal endpoint must pass straight through, normalized.
	got, err := resolveEndpoint("10.0.0.1:51820")
	if err != nil {
		t.Fatalf("resolveEndpoint: %v", err)
	}
	if got != "10.0.0.1:51820" {
		t.Errorf("resolveEndpoint = %q, want 10.0.0.1:51820", got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"missing private key": `[Interface]
Address=10.0.0.1/32
[Peer]
PublicKey=GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
`,
		"missing address": `[Interface]
PrivateKey=k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
[Peer]
PublicKey=GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
`,
		"no peer": `[Interface]
PrivateKey=k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
Address=10.0.0.1/32
`,
		"bad private key length": `[Interface]
PrivateKey=dG9vc2hvcnQ=
Address=10.0.0.1/32
[Peer]
PublicKey=GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
`,
		"bad address": `[Interface]
PrivateKey=k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
Address=not-an-ip
[Peer]
PublicKey=GrBdLG/vGt9ic9LZNDS79VBciGsfK+ettJ8lAhg8viw=
`,
		"key before section": `PrivateKey=k4mGYU0i+8TmLmHyeVIGbUkAI7l6rvftv4Rb5w4EzEw=
`,
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(conf)); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

func mustHex(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode %q: %v", b64, err)
	}
	return hex.EncodeToString(raw)
}
