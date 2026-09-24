//go:build !windows

package main

// enableVirtualTerminal is a no-op: Unix terminals interpret ANSI escapes natively.
func enableVirtualTerminal() {}
