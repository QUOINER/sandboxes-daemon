//go:build darwin

package secretproxy

import "golang.org/x/sys/unix"

func soPeerCredUID(fd uintptr) (uint64, error) {
	cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return uint64(cred.Uid), nil
}
