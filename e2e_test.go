package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/barelyworkingcode/wiretunnel/internal/proxy"
	"github.com/barelyworkingcode/wiretunnel/internal/rules"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// protocolICMP is the IANA protocol number for ICMPv4, used by icmp.ParseMessage.
const protocolICMP = 1

// TestTunnelEndToEnd stands up two userspace WireGuard devices wired to each
// other over localhost UDP — no privileges, no TUN device, no host routing. One
// device ("server") runs the wiretunnel proxy forwarding tunnel ports to local
// echo services; the other ("client") reaches them across the tunnel. It proves
// the whole path: WireGuard handshake -> netstack listener -> host-side dial ->
// bytes round-trip, plus ICMP echo replies for ping.
func TestTunnelEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end tunnel test in -short mode")
	}

	logLevel := device.LogLevelSilent
	if testing.Verbose() {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, "")
	serverAddr := netip.MustParseAddr("10.64.0.1")
	clientAddr := netip.MustParseAddr("10.64.0.2")

	serverPriv, serverPub := keyPair(t)
	clientPriv, clientPub := keyPair(t)

	// Local echo services on the host network that the proxy forwards to. Two are
	// reached through explicit forwards; the third is reached only through the
	// catch-all (wildcard) forward, which proxies any unmapped tunnel port to the
	// same port on 127.0.0.1.
	tcpEchoPort := startTCPEcho(t)
	udpEchoPort := startUDPEcho(t)
	wildEchoPort := startTCPEcho(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The proxy must register its explicit listeners and the stack-wide wildcard
	// handler before the server device comes up, so packet processing never races
	// the (unsynchronized) handler install. newDeviceWith provides that hook.
	var p *proxy.Proxy
	_, serverDev := newDeviceWith(t, logger, serverAddr, serverPriv, func(n *netstack.Net, _ *device.Device) {
		p = proxy.New(n, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err := p.Start(ctx, []rules.Forward{
			{Listen: 8022, Proto: rules.TCP, Target: "127.0.0.1", TargetPort: tcpEchoPort},
			{Listen: 9053, Proto: rules.UDP, Target: "127.0.0.1", TargetPort: udpEchoPort},
		}); err != nil {
			t.Fatalf("proxy start: %v", err)
		}
		if err := p.StartWildcard(ctx, "127.0.0.1"); err != nil {
			t.Fatalf("proxy wildcard start: %v", err)
		}
	})
	defer serverDev.Close()
	clientNet, clientDev := newDevice(t, logger, clientAddr, clientPriv)
	defer clientDev.Close()

	// Wire the peers together. Only the client carries an endpoint + keepalive,
	// so only the client initiates the handshake; the server stays passive and
	// learns the client's endpoint via roaming. If both initiated at once their
	// in-progress handshakes would clobber each other and never settle.
	serverPort := listenPort(t, serverDev)
	peerInto(t, clientDev, serverPub, serverPort, serverAddr)
	peerInto(t, serverDev, clientPub, 0, clientAddr)

	// Ping first: it's connectionless and warms the WireGuard handshake.
	t.Run("ping", func(t *testing.T) { testPing(t, clientNet, clientAddr, serverAddr) })
	t.Run("tcp", func(t *testing.T) { testTCP(t, clientNet, serverAddr, p) })
	t.Run("udp", func(t *testing.T) { testUDP(t, clientNet, serverAddr) })
	t.Run("wildcard", func(t *testing.T) { testWildcard(t, clientNet, serverAddr, wildEchoPort, p) })

	// Graceful shutdown: a connection still open at cancel time must be closed
	// by the proxy so Wait returns promptly instead of blocking on it.
	lingering := dialTunnelTCP(t, clientNet, netip.AddrPortFrom(serverAddr, 8022))
	defer lingering.Close()

	cancel()
	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not shut down within 5s with a connection still open")
	}
}

// --- subtests ---

func testPing(t *testing.T, clientNet *netstack.Net, from, to netip.Addr) {
	pinger, err := clientNet.DialPingAddr(from, to)
	if err != nil {
		t.Fatalf("dial ping: %v", err)
	}
	defer pinger.Close()

	req, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 0xabcd, Seq: 1, Data: []byte("are-you-there")},
	}).Marshal(nil)
	if err != nil {
		t.Fatalf("marshal icmp: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	reply := make([]byte, 1500)
	for {
		_ = pinger.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := pinger.Write(req); err != nil {
			t.Fatalf("send ping: %v", err)
		}
		n, err := pinger.Read(reply)
		if err == nil {
			msg, perr := icmp.ParseMessage(protocolICMP, reply[:n])
			if perr != nil {
				t.Fatalf("parse icmp reply: %v", perr)
			}
			if msg.Type != ipv4.ICMPTypeEchoReply {
				t.Fatalf("got icmp type %v, want echo reply", msg.Type)
			}
			return // success
		}
		if time.Now().After(deadline) {
			t.Fatalf("no ping reply within deadline: %v", err)
		}
	}
}

func testTCP(t *testing.T, clientNet *netstack.Net, serverAddr netip.Addr, p *proxy.Proxy) {
	conn := dialTunnelTCP(t, clientNet, netip.AddrPortFrom(serverAddr, 8022))
	defer conn.Close()

	msg := []byte("hello over wireguard")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}

	// The connection is still open and a full echo round-trip has completed, so
	// the proxy's live metrics must reflect it.
	fs := snapshotForPort(t, p, 8022)
	if fs.Active < 1 {
		t.Errorf("active connections = %d, want >= 1", fs.Active)
	}
	if fs.Total < 1 {
		t.Errorf("total connections = %d, want >= 1", fs.Total)
	}
	if fs.BytesUp < int64(len(msg)) {
		t.Errorf("bytesUp = %d, want >= %d", fs.BytesUp, len(msg))
	}
	if fs.BytesDown < int64(len(msg)) {
		t.Errorf("bytesDown = %d, want >= %d", fs.BytesDown, len(msg))
	}
}

// testWildcard reaches a port with no explicit rule and proves the catch-all
// forward carried it to the same port on 127.0.0.1, surfacing as a wildcard row.
func testWildcard(t *testing.T, clientNet *netstack.Net, serverAddr netip.Addr, port int, p *proxy.Proxy) {
	conn := dialTunnelTCP(t, clientNet, netip.AddrPortFrom(serverAddr, uint16(port)))
	defer conn.Close()

	msg := []byte("through the wildcard")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("wildcard echo = %q, want %q", got, msg)
	}

	fs := snapshotForPort(t, p, port)
	if !fs.Wildcard {
		t.Errorf("port %d should be served by the wildcard forward", port)
	}
	if fs.Total < 1 {
		t.Errorf("wildcard total connections = %d, want >= 1", fs.Total)
	}
}

func snapshotForPort(t *testing.T, p *proxy.Proxy, port int) proxy.ForwardSnapshot {
	t.Helper()
	for _, f := range p.Snapshot() {
		if f.Listen == port {
			return f
		}
	}
	t.Fatalf("no forward snapshot for port %d", port)
	return proxy.ForwardSnapshot{}
}

func testUDP(t *testing.T, clientNet *netstack.Net, serverAddr netip.Addr) {
	raddr := &net.UDPAddr{IP: net.IP(serverAddr.AsSlice()), Port: 9053}
	conn, err := clientNet.DialUDP(nil, raddr)
	if err != nil {
		t.Fatalf("dial udp over tunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("datagram over wireguard")
	deadline := time.Now().Add(5 * time.Second)
	got := make([]byte, len(msg))
	for {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write udp: %v", err)
		}
		n, err := conn.Read(got)
		if err == nil {
			if !bytes.Equal(got[:n], msg) {
				t.Fatalf("udp echo = %q, want %q", got[:n], msg)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no udp echo within deadline: %v", err)
		}
	}
}

// --- helpers ---

func dialTunnelTCP(t *testing.T, n *netstack.Net, addr netip.AddrPort) net.Conn {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := n.DialContextTCPAddrPort(dctx, addr)
		dcancel()
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s over tunnel: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// newDevice creates a userspace WireGuard device at addr, keyed with privHex,
// bound to an ephemeral localhost UDP port, and brought up.
func newDevice(t *testing.T, logger *device.Logger, addr netip.Addr, privHex string) (*netstack.Net, *device.Device) {
	return newDeviceWith(t, logger, addr, privHex, nil)
}

// newDeviceWith is newDevice with a hook invoked after the device is configured
// but before it is brought up — the point at which netstack handlers like the
// proxy's wildcard forwarder must be installed so their stack-wide registration
// happens-before any packet is processed.
func newDeviceWith(t *testing.T, logger *device.Logger, addr netip.Addr, privHex string, beforeUp func(*netstack.Net, *device.Device)) (*netstack.Net, *device.Device) {
	t.Helper()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("create netstack tun: %v", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", privHex)); err != nil {
		t.Fatalf("set private key: %v", err)
	}
	if beforeUp != nil {
		beforeUp(tnet, dev)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("device up: %v", err)
	}
	return tnet, dev
}

// peerInto adds peer (pubHex), permitting traffic to/from peerAddr. When
// endpointPort is non-zero the peer is given that localhost endpoint and a 1s
// keepalive, making this device the handshake initiator; a zero port leaves the
// peer endpoint-less so it stays passive and roams to the observed source.
func peerInto(t *testing.T, dev *device.Device, pubHex string, endpointPort int, peerAddr netip.Addr) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\nallowed_ip=%s/32\n", pubHex, peerAddr)
	if endpointPort != 0 {
		fmt.Fprintf(&b, "endpoint=127.0.0.1:%d\npersistent_keepalive_interval=1\n", endpointPort)
	}
	if err := dev.IpcSet(b.String()); err != nil {
		t.Fatalf("set peer: %v", err)
	}
}

func listenPort(t *testing.T, dev *device.Device) int {
	t.Helper()
	cfg, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("ipc get: %v", err)
	}
	for _, line := range strings.Split(cfg, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			p, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatalf("parse listen_port %q: %v", v, err)
			}
			return p
		}
	}
	t.Fatal("no listen_port in IpcGet output")
	return 0
}

func keyPair(t *testing.T) (privHex, pubHex string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	return hex.EncodeToString(priv[:]), hex.EncodeToString(pub)
}

// startTCPEcho starts a loopback TCP echo server and returns its port.
func startTCPEcho(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// startUDPEcho starts a loopback UDP echo server and returns its port.
func startUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}
