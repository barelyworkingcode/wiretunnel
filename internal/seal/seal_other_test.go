//go:build !windows

package seal

import (
	"errors"
	"testing"
)

// On platforms without a DPAPI backend, a well-formed container must surface
// ErrUnsupported (not panic) so callers can fall back or report cleanly.
func TestUnsealUnsupportedPlatform(t *testing.T) {
	blob := append([]byte(magic), version, scopeUserByte)
	blob = append(blob, "ciphertext"...)
	if _, err := Unseal(blob); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

func TestSealUnsupportedPlatform(t *testing.T) {
	if _, err := Seal([]byte("data"), ScopeUser); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}
