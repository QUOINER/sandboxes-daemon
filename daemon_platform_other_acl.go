//go:build !darwin

package daemon

func validateDaemonSocketACL(string) error { return nil }
