//go:build windows

package seal

import (
	"bytes"
	"testing"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	plain := []byte("[Interface]\nPrivateKey = aGVsbG8td29ybGQtdGhpcy1pcy0zMi1ieXRlcyE=\n")

	for _, tc := range []struct {
		name  string
		scope Scope
	}{
		{"user", ScopeUser},
		{"machine", ScopeMachine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := Seal(plain, tc.scope)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if !IsSealed(sealed) {
				t.Fatal("Seal output lacks container header")
			}
			if bytes.Contains(sealed, plain) {
				t.Fatal("plaintext leaked into sealed container")
			}

			got, err := Unseal(sealed)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round trip mismatch: got %q want %q", got, plain)
			}
		})
	}
}

func TestUnsealDetectsTampering(t *testing.T) {
	plain := []byte("[Interface]\nPrivateKey = secret\n")
	sealed, err := Seal(plain, ScopeUser)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a bit deep inside the DPAPI ciphertext (well past the header).
	sealed[len(sealed)-1] ^= 0xFF
	if _, err := Unseal(sealed); err == nil {
		t.Fatal("tampered container unsealed without error")
	}
}
