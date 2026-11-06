//go:build windows

package servicesecrets

import (
	"strings"
	"testing"
)

func testPrintCommand() string {
	return "echo  synthetic-value "
}

func testFailCommand() string {
	return "echo synthetic-provider-error 1>&2 & exit /b 7"
}

func testWaitCommand() string {
	return "ping -n 30 127.0.0.1 >nul"
}

func TestWindowsResolverEnvironmentPreservesProviderConfigLocations(t *testing.T) {
	keys := []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
	for _, key := range keys {
		t.Setenv(key, "C:\\synthetic\\resolver\\"+key)
	}
	env := strings.Join(resolverEnvironment(Source{}), "\n")
	for _, key := range keys {
		value := "C:\\synthetic\\resolver\\" + key
		if !strings.Contains(env, key+"="+value) {
			t.Errorf("resolver environment does not preserve %s", key)
		}
	}
}
