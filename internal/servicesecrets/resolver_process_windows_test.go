//go:build windows

package servicesecrets

import (
	"strconv"
	"testing"
)

func TestResolverWindowsProcessIDRange(t *testing.T) {
	valid := []int{1}
	if strconv.IntSize > 32 {
		valid = append(valid, int(uint64(^uint32(0))))
	}
	for _, pid := range valid {
		got, err := windowsProcessID(pid)
		if err != nil || uint64(got) != uint64(pid) {
			t.Fatalf("windowsProcessID(%d) = %d, %v", pid, got, err)
		}
	}
	for _, pid := range []int{0, -1} {
		if _, err := windowsProcessID(pid); err == nil {
			t.Errorf("windowsProcessID(%d) accepted an invalid process ID", pid)
		}
	}
	if strconv.IntSize > 32 {
		overflow := int(uint64(^uint32(0)) + 1)
		if _, err := windowsProcessID(overflow); err == nil {
			t.Errorf("windowsProcessID(%d) accepted an out-of-range process ID", overflow)
		}
	}
}
