//go:build linux

package secretproxy

import "golang.org/x/sys/unix"

func soPeerCredUID(fd uintptr) (uint64, error) {
	cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return uint64(cred.Uid), nil
}
