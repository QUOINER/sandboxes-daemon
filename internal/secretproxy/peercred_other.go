//go:build !linux && !darwin

package secretproxy

import "net"

// peerOwnerUID is unsupported on this platform; callers treat the result as
// "peer unverifiable" and the listener fails closed only when verification is
// mandatory. Windows IPC uses named pipes with their own ACL model.
func peerOwnerUID(net.Conn) (uint64, bool) { return 0, false }

// currentUID reports 0 where no comparable POSIX effective UID exists.
func currentUID() uint64 { return 0 }
