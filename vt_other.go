//go:build !windows

package main

// enableVirtualTerminal is a no-op on platforms whose terminals handle ANSI
// escape sequences natively (macOS, Linux).
func enableVirtualTerminal() {}
