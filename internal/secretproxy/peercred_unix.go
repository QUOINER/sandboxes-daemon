//go:build linux || darwin

package secretproxy

import (
	"net"
	"os"
)

// peerOwnerUID reports the effective UID of the process that opened the other
// end of a Unix-domain connection. It returns false when the platform or the
// connection type cannot establish the peer credential.
func peerOwnerUID(conn net.Conn) (uint64, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var uid uint64
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		if uid, credErr = soPeerCredUID(fd); credErr != nil {
			uid = 0
		}
	}); err != nil || credErr != nil {
		return 0, false
	}
	return uid, true
}

// currentUID returns the daemon's effective UID for peer comparison.
func currentUID() uint64 {
	// Effective UIDs are non-negative; clamp instead of wrapping on the
	// theoretical negative value so the comparison stays meaningful.
	if euid := os.Geteuid(); euid >= 0 {
		return uint64(euid)
	}
	return 0
}
