// +build !windows

package logger

import (
	"syscall"
	"unsafe"
)

// isatty returns true if the given file descriptor is a terminal
func isatty(fd uintptr) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

const ioctlReadTermios = 0x5401 // TCGETS