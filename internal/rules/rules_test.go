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
		"empty forwards":   `{"forwards": []}`,
		"missing forwards": `{}`,
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
