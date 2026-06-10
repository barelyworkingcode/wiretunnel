// Package seal binds a secret file (here, a WireGuard config) to the host it
// was sealed on, so that copying the file to another machine renders it
// useless. It is the at-rest counterpart to the unavoidable fact that the
// WireGuard private key must exist in plaintext in process memory while the
// tunnel runs: sealing protects the file an attacker can pull off disk, not the
// live process.
//
// On Windows the binding is provided by DPAPI (CryptProtectData). Two scopes
// are offered:
//
//   - ScopeUser   — decryptable only by the same Windows account on the same
//     machine. The strongest option when the enrolling account and the runtime
//     account are the same (the common case for a service that logs on as a
//     specific user).
//   - ScopeMachine — decryptable by any account on the same machine. Useful
//     when whoever seals the file is not the account that will later unseal it.
//
// In both scopes the ciphertext is dead the moment it leaves the host. Neither
// scope defends against an attacker with live administrative control of the
// running machine — such an attacker can read the key from process memory or
// simply run the program, which unseals by design. Limiting that residual risk
// is a job for the network-authorization layer (least-privilege AllowedIPs,
// short-lived keys), not file encryption.
//
// On non-Windows platforms every operation returns ErrUnsupported.
package seal

import (
	"errors"
	"fmt"
)

// ErrUnsupported is returned by Seal and Unseal on platforms without a DPAPI
// backend (everything except Windows).
var ErrUnsupported = errors.New("seal: DPAPI sealing is only supported on Windows")

// Scope selects which DPAPI master key protects the container.
type Scope int

const (
	// ScopeUser binds the container to the current machine and Windows account.
	ScopeUser Scope = iota
	// ScopeMachine binds the container to the current machine only.
	ScopeMachine
)

// Container header layout: magic ("WTSEAL") | version (1 byte) | scope (1 byte)
// | DPAPI ciphertext. The scope is recorded so Unseal can request the matching
// master key, and the whole header lets the loader auto-detect a sealed file
// versus a plaintext config.
const (
	magic        = "WTSEAL"
	version byte = 1

	scopeMachineByte byte = 0
	scopeUserByte    byte = 1

	headerLen = len(magic) + 2
)

// appEntropy is mixed into every DPAPI operation as secondary entropy. It is
// baked into the binary and is therefore not a secret; its only purpose is to
// stop a generic DPAPI-unprotect tool, run as the same account, from decrypting
// the blob without knowing it belongs to wiretunnel.
var appEntropy = []byte("wiretunnel/dpapi/v1")

// IsSealed reports whether b begins with the sealed-container magic. It lets a
// caller decide between Unseal and treating the bytes as a plaintext config.
func IsSealed(b []byte) bool {
	return len(b) >= len(magic) && string(b[:len(magic)]) == magic
}

// Seal wraps plain in a DPAPI-protected container bound according to scope.
func Seal(plain []byte, scope Scope) ([]byte, error) {
	machine := scope == ScopeMachine
	ct, err := protect(plain, appEntropy, machine)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(ct))
	out = append(out, magic...)
	out = append(out, version)
	if machine {
		out = append(out, scopeMachineByte)
	} else {
		out = append(out, scopeUserByte)
	}
	return append(out, ct...), nil
}

// Unseal reverses Seal. It fails if b was not produced by Seal, or — crucially
// — if the current machine/account cannot decrypt it (for example because the
// file was copied from another host, or sealed under a different account).
func Unseal(b []byte) ([]byte, error) {
	if !IsSealed(b) {
		return nil, errors.New("seal: not a sealed container")
	}
	if len(b) < headerLen {
		return nil, errors.New("seal: truncated container header")
	}
	if v := b[len(magic)]; v != version {
		return nil, fmt.Errorf("seal: unsupported container version %d", v)
	}
	machine := b[len(magic)+1] == scopeMachineByte
	return unprotect(b[headerLen:], appEntropy, machine)
}
