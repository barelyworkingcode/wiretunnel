//go:build windows

package seal

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI flags (dpapi.h).
const (
	cryptProtectUIForbidden  = 0x1
	cryptProtectLocalMachine = 0x4
)

var (
	crypt32       = windows.NewLazySystemDLL("crypt32.dll")
	procProtect   = crypt32.NewProc("CryptProtectData")
	procUnprotect = crypt32.NewProc("CryptUnprotectData")
)

// dataBlob mirrors the Win32 DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) dataBlob {
	if len(d) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

// bytes copies the DPAPI-allocated buffer into Go-managed memory so the caller
// can LocalFree the original.
func (b dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func protect(plain, entropy []byte, machine bool) ([]byte, error) {
	return dpapi(procProtect, plain, entropy, machine)
}

func unprotect(blob, entropy []byte, machine bool) ([]byte, error) {
	return dpapi(procUnprotect, blob, entropy, machine)
}

// dpapi invokes CryptProtectData or CryptUnprotectData, which share a calling
// convention. CRYPTPROTECT_UI_FORBIDDEN is always set so the call never blocks
// on a UI prompt (this runs unattended), and CRYPTPROTECT_LOCAL_MACHINE selects
// the machine master key for ScopeMachine.
func dpapi(proc *windows.LazyProc, in, entropy []byte, machine bool) ([]byte, error) {
	inBlob := newBlob(in)
	entBlob := newBlob(entropy)
	var out dataBlob

	flags := uintptr(cryptProtectUIForbidden)
	if machine {
		flags |= cryptProtectLocalMachine
	}

	r, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // szDataDescr
		uintptr(unsafe.Pointer(&entBlob)),
		0, // pvReserved
		0, // pPromptStruct
		flags,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(in)
	runtime.KeepAlive(entropy)
	if r == 0 {
		return nil, fmt.Errorf("%s: %w", proc.Name, callErr)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}
