//go:build linux

package server

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func enableSavedSYN(ln net.Listener) error {
	tcpListener, ok := ln.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("unsupported listener type %T", ln)
	}

	rawConn, err := tcpListener.SyscallConn()
	if err != nil {
		return fmt.Errorf("getting raw connection: %w", err)
	}

	var setSockOptErr error
	err = rawConn.Control(func(fd uintptr) {
		setSockOptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if setSockOptErr != nil {
		return fmt.Errorf("setsockopt: %w", setSockOptErr)
	}
	return nil
}

func savedSYN(conn *net.TCPConn) ([]byte, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("getting raw connection: %w", err)
	}

	buf := make([]byte, 128)
	size := uint32(len(buf))
	var errno unix.Errno
	err = rawConn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_SAVED_SYN, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if errno != 0 {
		return nil, fmt.Errorf("getsockopt: %w", errno)
	}
	return buf[:size], nil
}
