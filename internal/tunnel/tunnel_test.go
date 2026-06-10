package tunnel

import (
	"testing"
	"time"
)

// TestParsePeers checks that the UAPI "get" output is split into per-peer stats:
// a peer with a non-zero handshake and a peer that has never handshaked (zero
// timestamp → zero time, no endpoint).
func TestParsePeers(t *testing.T) {
	const uapi = "private_key=00\n" +
		"listen_port=12345\n" +
		"public_key=aa\n" +
		"preshared_key=00\n" +
		"protocol_version=1\n" +
		"endpoint=203.0.113.5:51820\n" +
		"last_handshake_time_sec=1000000\n" +
		"last_handshake_time_nsec=0\n" +
		"tx_bytes=1234\n" +
		"rx_bytes=5678\n" +
		"persistent_keepalive_interval=45\n" +
		"allowed_ip=10.0.0.0/24\n" +
		"public_key=bb\n" +
		"protocol_version=1\n" +
		"last_handshake_time_sec=0\n" +
		"last_handshake_time_nsec=0\n" +
		"tx_bytes=0\n" +
		"rx_bytes=0\n"

	peers := parsePeers(uapi)
	if len(peers) != 2 {
		t.Fatalf("parsePeers returned %d peers, want 2", len(peers))
	}

	p0 := peers[0]
	if p0.Endpoint != "203.0.113.5:51820" {
		t.Errorf("peer0 Endpoint = %q, want 203.0.113.5:51820", p0.Endpoint)
	}
	if !p0.LastHandshake.Equal(time.Unix(1000000, 0)) {
		t.Errorf("peer0 LastHandshake = %v, want %v", p0.LastHandshake, time.Unix(1000000, 0))
	}
	if p0.TxBytes != 1234 || p0.RxBytes != 5678 {
		t.Errorf("peer0 tx/rx = %d/%d, want 1234/5678", p0.TxBytes, p0.RxBytes)
	}
	if !p0.Connected(time.Unix(1000000, 30)) {
		t.Error("peer0 should be Connected 30s after its handshake")
	}
	if p0.Connected(time.Unix(1000000+600, 0)) {
		t.Error("peer0 should not be Connected 10m after its handshake")
	}

	p1 := peers[1]
	if !p1.LastHandshake.IsZero() {
		t.Errorf("peer1 LastHandshake = %v, want zero (never handshaked)", p1.LastHandshake)
	}
	if p1.Endpoint != "" {
		t.Errorf("peer1 Endpoint = %q, want empty", p1.Endpoint)
	}
	if p1.Connected(time.Unix(1000000, 0)) {
		t.Error("peer1 never handshaked, should not be Connected")
	}
}
