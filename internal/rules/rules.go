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
package rules

import (
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

// Config is the parsed rules file.
type Config struct {
	Forwards []Forward `json:"forwards"`
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
	if len(c.Forwards) == 0 {
		return fmt.Errorf("no forwards defined")
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
