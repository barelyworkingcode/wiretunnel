// Package rules parses the JSON forwarding rules that tell wiretunnel which
// ports to listen on over the WireGuard tunnel and where to proxy them.
//
// Each rule is the JSON expansion of the shorthand "{ port, proto, target }":
//
//	{ "listen": 22, "proto": "tcp", "target": "127.0.0.1" }
//
// listens on tunnel port 22 and forwards to 127.0.0.1:22 reachable from the
// host's normal network. An optional "targetPort" overrides the destination
// port when it differs from the listen port.
//
// An optional top-level "forwardAll" turns on a catch-all: every tunnel port
// that has no explicit rule is proxied to the same port on a default target
// (127.0.0.1 unless overridden), so the explicit list is only needed for
// "remote" forwards that point somewhere other than localhost:same-port.
// Explicit rules always take precedence over the catch-all.
package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

// Protocol is the transport a forward operates on.
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// Forward is a single listen-and-proxy rule.
type Forward struct {
	Listen     int      `json:"listen"`               // port to accept on, over the tunnel
	Proto      Protocol `json:"proto"`                // "tcp" or "udp"
	Target     string   `json:"target"`               // host to proxy to (host network)
	TargetPort int      `json:"targetPort,omitempty"` // defaults to Listen when 0
}

// effectiveTargetPort returns TargetPort, defaulting to Listen.
func (f Forward) effectiveTargetPort() int {
	if f.TargetPort != 0 {
		return f.TargetPort
	}
	return f.Listen
}

// TargetAddr is the host:port the forward dials on the host network.
func (f Forward) TargetAddr() string {
	return net.JoinHostPort(f.Target, strconv.Itoa(f.effectiveTargetPort()))
}

// ForwardAll is the optional catch-all (wildcard) rule. When enabled, any tunnel
// port without an explicit forward is proxied to Target on the same port — so a
// connection to <wg-addr>:N is relayed to Target:N on the host network. Explicit
// forwards always take precedence.
//
// In JSON it accepts either a bool or an object:
//
//	"forwardAll": true                      // catch-all to 127.0.0.1
//	"forwardAll": { "target": "10.0.0.5" }  // catch-all to another host
type ForwardAll struct {
	Enabled bool
	Target  string // host to proxy to; defaults to 127.0.0.1 when enabled
}

// UnmarshalJSON accepts the bool shorthand or the object form.
func (fa *ForwardAll) UnmarshalJSON(b []byte) error {
	// Bool shorthand: `"forwardAll": true`.
	var enabled bool
	if err := json.Unmarshal(b, &enabled); err == nil {
		fa.Enabled = enabled
		return nil
	}
	// Object form: `"forwardAll": { "target": "host" }`.
	var obj struct {
		Target string `json:"target"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("parse forwardAll: %w", err)
	}
	fa.Enabled = true
	fa.Target = obj.Target
	return nil
}

// defaultWebSSHPort is the tunnel port the browser terminal listens on when the
// rules file does not specify one.
const defaultWebSSHPort = 8022

// Config is the parsed rules file.
type Config struct {
	ForwardAll ForwardAll `json:"forwardAll"`
	Forwards   []Forward  `json:"forwards"`

	// WebSSH toggles the in-tunnel browser terminal. It is a *bool so an omitted
	// key defaults to enabled (nil), while an explicit "webSSH": false disables
	// it. Use WebSSHEnabled rather than reading this directly.
	WebSSH *bool `json:"webSSH"`
	// Hostname is the browser-facing hostname for the terminal: the TLS SAN and
	// the WebAuthn relying-party ID. Empty means "use the OS hostname".
	Hostname string `json:"hostname"`
	// WebSSHPort is the tunnel port the terminal is served on; 0 means the
	// default (8022).
	WebSSHPort int `json:"webSSHPort,omitempty"`
}

// WebSSHEnabled reports whether the browser terminal should run. It is on
// unless the rules file explicitly sets "webSSH": false.
func (c *Config) WebSSHEnabled() bool {
	return c.WebSSH == nil || *c.WebSSH
}

// ParseFile reads and parses the rules JSON at path.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads rules JSON from r and validates it.
func Parse(r io.Reader) (*Config, error) {
	var c Config
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse rules JSON: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.ForwardAll.Enabled && c.ForwardAll.Target == "" {
		c.ForwardAll.Target = "127.0.0.1"
	}
	if c.WebSSHPort == 0 {
		c.WebSSHPort = defaultWebSSHPort
	}
	if !validPort(c.WebSSHPort) {
		return fmt.Errorf("webSSHPort %d out of range 1-65535", c.WebSSHPort)
	}
	// The browser terminal counts as something to serve, so a webSSH-only config
	// (no forwards, no forwardAll) is valid.
	if len(c.Forwards) == 0 && !c.ForwardAll.Enabled && !c.WebSSHEnabled() {
		return fmt.Errorf("nothing to do: no forwards, no forwardAll, and webSSH is disabled")
	}
	seen := make(map[string]bool, len(c.Forwards))
	for i, f := range c.Forwards {
		switch f.Proto {
		case TCP, UDP:
		case "":
			return fmt.Errorf("forward %d: missing proto", i)
		default:
			return fmt.Errorf("forward %d: invalid proto %q (want tcp or udp)", i, f.Proto)
		}
		if !validPort(f.Listen) {
			return fmt.Errorf("forward %d: listen port %d out of range 1-65535", i, f.Listen)
		}
		if f.TargetPort != 0 && !validPort(f.TargetPort) {
			return fmt.Errorf("forward %d: targetPort %d out of range 1-65535", i, f.TargetPort)
		}
		if f.Target == "" {
			return fmt.Errorf("forward %d: missing target", i)
		}
		// webSSH binds the tunnel's webSSHPort itself; a TCP forward on the same
		// port would race it for the listener, so reject the collision up front.
		if c.WebSSHEnabled() && f.Proto == TCP && f.Listen == c.WebSSHPort {
			return fmt.Errorf("forward %d: tcp listen port %d collides with webSSH (change webSSHPort or the forward, or disable webSSH)", i, f.Listen)
		}
		key := string(f.Proto) + ":" + strconv.Itoa(f.Listen)
		if seen[key] {
			return fmt.Errorf("forward %d: duplicate %s listen port %d", i, f.Proto, f.Listen)
		}
		seen[key] = true
	}
	return nil
}

func validPort(p int) bool {
	return p >= 1 && p <= 65535
}
