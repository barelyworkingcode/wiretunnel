package seal

import (
	"strings"
	"testing"
)

func TestIsSealed(t *testing.T) {
	if !IsSealed([]byte("WTSEAL\x01\x01ciphertext")) {
		t.Error("sealed container not recognized")
	}
	if IsSealed([]byte("[Interface]\nPrivateKey = ...")) {
		t.Error("plaintext config misidentified as sealed")
	}
	if IsSealed([]byte("WT")) {
		t.Error("short prefix misidentified as sealed")
	}
}

func TestUnsealRejectsPlaintext(t *testing.T) {
	_, err := Unseal([]byte("[Interface]\nPrivateKey = abc\n"))
	if err == nil || !strings.Contains(err.Error(), "not a sealed container") {
		t.Fatalf("want not-a-container error, got %v", err)
	}
}

func TestUnsealRejectsUnknownVersion(t *testing.T) {
	// Header is validated before any platform DPAPI call, so this check holds
	// identically on every OS.
	blob := append([]byte(magic), 0x02, scopeUserByte)
	blob = append(blob, "payload"...)
	_, err := Unseal(blob)
	if err == nil || !strings.Contains(err.Error(), "unsupported container version") {
		t.Fatalf("want version error, got %v", err)
	}
}

func TestUnsealRejectsTruncatedHeader(t *testing.T) {
	_, err := Unseal([]byte(magic)) // magic only, no version/scope bytes
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("want truncation error, got %v", err)
	}
}
