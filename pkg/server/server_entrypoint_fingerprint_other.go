//go:build !linux

package server

import (
	"errors"
	"net"
)

func enableSavedSYN(_ net.Listener) error {
	return errors.New("TCP fingerprinting is only supported on Linux")
}

func savedSYN(_ *net.TCPConn) ([]byte, error) {
	return nil, nil
}
