//go:build !windows

package seal

// DPAPI is a Windows facility; on other platforms sealing is unavailable. The
// stubs let the package compile cross-platform (and the loader fall back to
// plaintext configs) without a build-tag maze in callers.

func protect(plain, entropy []byte, machine bool) ([]byte, error) {
	return nil, ErrUnsupported
}

func unprotect(blob, entropy []byte, machine bool) ([]byte, error) {
	return nil, ErrUnsupported
}
