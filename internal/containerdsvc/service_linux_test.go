//go:build linux

package containerdsvc

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestCloseAfterStartFailureDetachesKeeper(t *testing.T) {
	svc := &Service{done: make(chan struct{})}
	if err := svc.closeAfterStartFailure(); err != nil {
		t.Fatalf("close after readiness failure: %v", err)
	}
	if !svc.closing.Load() {
		t.Fatal("service watcher was not told to detach")
	}
	select {
	case <-svc.done:
		t.Fatal("detaching readiness-failed service unexpectedly completed keeper")
	default:
	}
}

func TestManagedLauncherFailsClosedWithoutMountNamespaceCapability(t *testing.T) {
	hasSysAdmin, err := effectiveCapability(21)
	if err != nil {
		t.Fatal(err)
	}
	if hasSysAdmin {
		t.Skip("test requires a process without CAP_SYS_ADMIN")
	}

	serviceDir := t.TempDir()
	cmd, err := newCommand("/bin/true", Plan{ServiceDir: serviceDir, Binary: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err == nil {
		_ = cmd.Wait()
		t.Fatal("managed launcher started without CAP_SYS_ADMIN; expected fail-closed CLONE_NEWNS rejection")
	} else if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("managed launcher error = %v, want EPERM", err)
	}
}

func effectiveCapability(number uint) (bool, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			continue
		}
		caps, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return false, err
		}
		return caps&(uint64(1)<<number) != 0, nil
	}
	return false, errors.New("CapEff missing from /proc/self/status")
}
