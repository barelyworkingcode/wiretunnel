package rules

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	in := `{
		"forwards": [
			{ "listen": 22, "proto": "tcp", "target": "127.0.0.1" },
			{ "listen": 1433, "proto": "tcp", "target": "db.local", "targetPort": 1433 },
			{ "listen": 53, "proto": "udp", "target": "10.0.0.53", "targetPort": 5353 }
		]
	}`
	cfg, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Forwards) != 3 {
		t.Fatalf("Forwards = %d, want 3", len(cfg.Forwards))
	}

	// targetPort defaults to listen port.
	if got := cfg.Forwards[0].TargetAddr(); got != "127.0.0.1:22" {
		t.Errorf("Forwards[0].TargetAddr() = %q, want 127.0.0.1:22", got)
	}
	if got := cfg.Forwards[1].TargetAddr(); got != "db.local:1433" {
		t.Errorf("Forwards[1].TargetAddr() = %q, want db.local:1433", got)
	}
	if got := cfg.Forwards[2].TargetAddr(); got != "10.0.0.53:5353" {
		t.Errorf("Forwards[2].TargetAddr() = %q, want 10.0.0.53:5353", got)
	}
}

func TestParseInvalid(t *testing.T) {
	cases := map[string]string{
		// webSSH defaults to on, which on its own is "something to serve"; these
		// two assert the empty case, so they disable it to test the bare error.
		"empty forwards":   `{"forwards": [], "webSSH": false}`,
		"missing forwards": `{"webSSH": false}`,
		"bad proto":        `{"forwards":[{"listen":22,"proto":"sctp","target":"127.0.0.1"}]}`,
		"missing proto":    `{"forwards":[{"listen":22,"target":"127.0.0.1"}]}`,
		"listen zero":      `{"forwards":[{"listen":0,"proto":"tcp","target":"127.0.0.1"}]}`,
		"listen too high":  `{"forwards":[{"listen":70000,"proto":"tcp","target":"127.0.0.1"}]}`,
		"bad target port":  `{"forwards":[{"listen":22,"proto":"tcp","target":"127.0.0.1","targetPort":99999}]}`,
		"missing target":   `{"forwards":[{"listen":22,"proto":"tcp"}]}`,
		"duplicate":        `{"forwards":[{"listen":22,"proto":"tcp","target":"a"},{"listen":22,"proto":"tcp","target":"b"}]}`,
		"unknown field":    `{"forwards":[{"listen":22,"proto":"tcp","target":"a","frobnicate":true}]}`,
		"not json":         `nonsense`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// TestSameListenPortDifferentProto confirms tcp/22 and udp/22 do not collide.
func TestSameListenPortDifferentProto(t *testing.T) {
	in := `{"forwards":[
		{"listen":22,"proto":"tcp","target":"127.0.0.1"},
		{"listen":22,"proto":"udp","target":"127.0.0.1"}
	]}`
	if _, err := Parse(strings.NewReader(in)); err != nil {
		t.Errorf("tcp/22 and udp/22 should coexist: %v", err)
	}
}

// TestForwardAll covers the catch-all opt-in: the bool shorthand defaults the
// target to 127.0.0.1, the object form overrides it, and enabling it makes an
// otherwise-empty forwards list valid (the wildcard carries the load).
func TestForwardAll(t *testing.T) {
	t.Run("bool shorthand defaults to localhost", func(t *testing.T) {
		cfg, err := Parse(strings.NewReader(`{"forwardAll": true}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !cfg.ForwardAll.Enabled {
			t.Fatal("ForwardAll.Enabled = false, want true")
		}
		if cfg.ForwardAll.Target != "127.0.0.1" {
			t.Errorf("ForwardAll.Target = %q, want 127.0.0.1", cfg.ForwardAll.Target)
		}
	})

	t.Run("object form overrides target", func(t *testing.T) {
		cfg, err := Parse(strings.NewReader(`{"forwardAll": {"target": "10.0.0.5"}}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !cfg.ForwardAll.Enabled || cfg.ForwardAll.Target != "10.0.0.5" {
			t.Errorf("ForwardAll = %+v, want {Enabled:true Target:10.0.0.5}", cfg.ForwardAll)
		}
	})

	t.Run("coexists with explicit overrides", func(t *testing.T) {
		in := `{"forwardAll": true, "forwards": [
			{"listen": 1433, "proto": "tcp", "target": "db.local", "targetPort": 1433}
		]}`
		cfg, err := Parse(strings.NewReader(in))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !cfg.ForwardAll.Enabled || len(cfg.Forwards) != 1 {
			t.Errorf("got ForwardAll=%v forwards=%d, want enabled with 1 explicit forward", cfg.ForwardAll.Enabled, len(cfg.Forwards))
		}
	})

	t.Run("false leaves empty forwards invalid", func(t *testing.T) {
		// webSSH also disabled, so there is genuinely nothing to serve.
		if _, err := Parse(strings.NewReader(`{"forwardAll": false, "webSSH": false}`)); err == nil {
			t.Error("expected error: no forwards, no wildcard, and webSSH disabled")
		}
	})

	t.Run("rejects unknown object field", func(t *testing.T) {
		if _, err := Parse(strings.NewReader(`{"forwardAll": {"targit": "x"}}`)); err == nil {
			t.Error("expected error for unknown forwardAll field")
		}
	})
}

// TestWebSSH covers the browser-terminal config: it defaults to enabled on port
// 8022, an explicit false disables it, a webSSH-only file is valid on its own,
// the hostname round-trips, and a forward colliding with the webSSH port is
// rejected.
func TestWebSSH(t *testing.T) {
	t.Run("defaults to enabled on port 8022", func(t *testing.T) {
		cfg, err := Parse(strings.NewReader(`{"forwardAll": true}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !cfg.WebSSHEnabled() {
			t.Error("WebSSHEnabled() = false, want true (default)")
		}
		if cfg.WebSSHPort != 8022 {
			t.Errorf("WebSSHPort = %d, want 8022 (default)", cfg.WebSSHPort)
		}
	})

	t.Run("explicit false disables", func(t *testing.T) {
		cfg, err := Parse(strings.NewReader(`{"forwardAll": true, "webSSH": false}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.WebSSHEnabled() {
			t.Error("WebSSHEnabled() = true, want false")
		}
	})

	t.Run("webSSH-only config is valid", func(t *testing.T) {
		cfg, err := Parse(strings.NewReader(`{"webSSH": true, "hostname": "baaqmd-devbox"}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.Hostname != "baaqmd-devbox" {
			t.Errorf("Hostname = %q, want baaqmd-devbox", cfg.Hostname)
		}
	})

	t.Run("custom port", func(t *testing.T) {
		cfg, err := Parse(strings.NewReader(`{"webSSH": true, "webSSHPort": 9443}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.WebSSHPort != 9443 {
			t.Errorf("WebSSHPort = %d, want 9443", cfg.WebSSHPort)
		}
	})

	t.Run("port out of range rejected", func(t *testing.T) {
		if _, err := Parse(strings.NewReader(`{"webSSH": true, "webSSHPort": 70000}`)); err == nil {
			t.Error("expected error for webSSHPort out of range")
		}
	})

	t.Run("forward colliding with webSSH port rejected", func(t *testing.T) {
		in := `{"webSSHPort": 8022, "forwards": [
			{"listen": 8022, "proto": "tcp", "target": "127.0.0.1"}
		]}`
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Error("expected error: tcp forward collides with the webSSH port")
		}
	})

	t.Run("udp forward on webSSH port is fine", func(t *testing.T) {
		// webSSH is TCP-only, so a UDP forward on the same port does not collide.
		in := `{"webSSHPort": 8022, "forwards": [
			{"listen": 8022, "proto": "udp", "target": "127.0.0.1"}
		]}`
		if _, err := Parse(strings.NewReader(in)); err != nil {
			t.Errorf("udp/8022 should coexist with webSSH: %v", err)
		}
	})
}
