//go:build linux

package containerdsvc

import (
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
