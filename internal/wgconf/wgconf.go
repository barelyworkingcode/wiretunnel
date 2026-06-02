// Package wgconf parses wg-quick style WireGuard configuration files and
// translates them into the UAPI configuration string consumed by
// wireguard-go's device.IpcSet.
//
// Only the subset of directives meaningful to a userspace, routing-free tunnel
// is interpreted (keys, addresses, DNS, MTU, endpoint, allowed IPs, keepalive).
// wg-quick directives that manage the host network stack — Table, PreUp,
// PostUp, and friends — are intentionally ignored, since this application never
// touches the host's routing table or interfaces.
package wgconf

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// defaultMTU matches the value wireguard-go's netstack examples use when a
// config omits MTU.
const defaultMTU = 1420

// keyLen is the byte length of a Curve25519 WireGuard key.
const keyLen = 32

// Peer is a single [Peer] section.
type Peer struct {
	PublicKey    string   // base64, as written in the file
	PresharedKey string   // base64, optional
	Endpoint     string   // host:port, as written (may be a DNS name)
	AllowedIPs   []string // CIDRs
	Keepalive    int      // persistent keepalive seconds; 0 means disabled
}

// Config is the parsed, validated representation of a WireGuard config file.
type Config struct {
	PrivateKey string       // base64, as written in the file
	Addresses  []netip.Addr // interface addresses (host part of each Address CIDR)
	DNS        []netip.Addr // DNS server addresses (search domains are ignored)
	MTU        int
	ListenPort int // 0 selects an ephemeral UDP source port
	Peers      []Peer
}

// ParseFile reads and parses the WireGuard config at path.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads a wg-quick style config from r.
func Parse(r io.Reader) (*Config, error) {
	cfg := &Config{MTU: defaultMTU}

	sc := bufio.NewScanner(r)
	section := ""
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				cfg.Peers = append(cfg.Peers, Peer{})
			}
			continue
		}

		// Split on the first '=' only: base64 keys end in '=' padding.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key=value, got %q", lineNo, line)
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])

		switch section {
		case "interface":
			if err := cfg.setInterface(key, val); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "peer":
			if err := setPeer(&cfg.Peers[len(cfg.Peers)-1], key, val); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			return nil, fmt.Errorf("line %d: key %q before any [Interface]/[Peer] section", lineNo, key)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) setInterface(key, val string) error {
	switch key {
	case "privatekey":
		c.PrivateKey = val
	case "address":
		for _, a := range splitList(val) {
			addr, err := hostAddr(a)
			if err != nil {
				return fmt.Errorf("invalid Address %q: %w", a, err)
			}
			c.Addresses = append(c.Addresses, addr)
		}
	case "dns":
		for _, d := range splitList(val) {
			// A DNS entry may be a search domain rather than an IP; keep only IPs.
			if addr, err := netip.ParseAddr(d); err == nil {
				c.DNS = append(c.DNS, addr)
			}
		}
	case "mtu":
		m, err := strconv.Atoi(val)
		if err != nil || m <= 0 {
			return fmt.Errorf("invalid MTU %q", val)
		}
		c.MTU = m
	case "listenport":
		p, err := parsePort(val)
		if err != nil {
			return fmt.Errorf("invalid ListenPort %q", val)
		}
		c.ListenPort = p
	default:
		// Ignore host-network directives (Table, PreUp, PostUp, ...) and any
		// unknown keys; they have no meaning for a userspace tunnel.
	}
	return nil
}

func setPeer(p *Peer, key, val string) error {
	switch key {
	case "publickey":
		p.PublicKey = val
	case "presharedkey":
		p.PresharedKey = val
	case "endpoint":
		p.Endpoint = val
	case "allowedips":
		for _, a := range splitList(val) {
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err2 := netip.ParseAddr(a); err2 != nil {
					return fmt.Errorf("invalid AllowedIPs %q: %w", a, err)
				}
			}
			p.AllowedIPs = append(p.AllowedIPs, a)
		}
	case "persistentkeepalive":
		k, err := strconv.Atoi(val)
		if err != nil || k < 0 {
			return fmt.Errorf("invalid PersistentKeepalive %q", val)
		}
		p.Keepalive = k
	default:
		// Ignore unknown peer keys.
	}
	return nil
}

func (c *Config) validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("missing PrivateKey in [Interface]")
	}
	if _, err := keyToHex(c.PrivateKey); err != nil {
		return fmt.Errorf("PrivateKey: %w", err)
	}
	if len(c.Addresses) == 0 {
		return fmt.Errorf("missing Address in [Interface]")
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("config defines no [Peer]")
	}
	for i := range c.Peers {
		if c.Peers[i].PublicKey == "" {
			return fmt.Errorf("peer %d: missing PublicKey", i)
		}
		if _, err := keyToHex(c.Peers[i].PublicKey); err != nil {
			return fmt.Errorf("peer %d PublicKey: %w", i, err)
		}
	}
	return nil
}

// UAPI builds the wireguard-go IpcSet configuration string. Peer endpoints
// given as DNS names are resolved to IP:port here, because wireguard-go's UAPI
// only accepts numeric address:port endpoints.
func (c *Config) UAPI() (string, error) {
	var b strings.Builder

	priv, err := keyToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("PrivateKey: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}

	for i := range c.Peers {
		p := &c.Peers[i]
		pub, err := keyToHex(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer %d PublicKey: %w", i, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)

		if p.PresharedKey != "" {
			psk, err := keyToHex(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer %d PresharedKey: %w", i, err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		if p.Endpoint != "" {
			resolved, err := resolveEndpoint(p.Endpoint)
			if err != nil {
				return "", fmt.Errorf("peer %d Endpoint %q: %w", i, p.Endpoint, err)
			}
			fmt.Fprintf(&b, "endpoint=%s\n", resolved)
		}
		if p.Keepalive != 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		for _, aip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", aip)
		}
	}
	return b.String(), nil
}

// keyToHex decodes a base64 WireGuard key and re-encodes it as the lowercase
// hex string the UAPI expects.
func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != keyLen {
		return "", fmt.Errorf("must be %d bytes, got %d", keyLen, len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// resolveEndpoint turns host:port into a numeric addr:port, resolving DNS names
// (preferring IPv4) so wireguard-go's netip-based parser accepts it.
func resolveEndpoint(ep string) (string, error) {
	if ap, err := netip.ParseAddrPort(ep); err == nil {
		return ap.String(), nil
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return "", err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port %q", portStr)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	chosen, ok := preferIPv4(ips)
	if !ok {
		return "", fmt.Errorf("no usable address for %q", host)
	}
	return netip.AddrPortFrom(chosen, uint16(port)).String(), nil
}

func preferIPv4(ips []net.IP) (netip.Addr, bool) {
	var fallback netip.Addr
	haveFallback := false
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			return addr, true
		}
		if !haveFallback {
			fallback, haveFallback = addr, true
		}
	}
	return fallback, haveFallback
}

// hostAddr parses an "Address" entry that may be a CIDR (10.0.0.1/32) or a bare
// address, returning just the host address. The prefix length is irrelevant to
// the userspace stack, which assigns the address to its single NIC.
func hostAddr(s string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return p, nil
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
