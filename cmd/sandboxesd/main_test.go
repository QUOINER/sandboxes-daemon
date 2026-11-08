package main

import "testing"

func TestConfigureExperimentalIPv6DisabledDoesNotRequireConfigurator(t *testing.T) {
	if err := configureExperimentalIPv6(false, nil); err != nil {
		t.Fatalf("configureExperimentalIPv6(false, nil) error = %v, want nil", err)
	}
}

func TestConfigureExperimentalIPv6Enabled(t *testing.T) {
	configurator := &testIPv6Configurator{}
	if err := configureExperimentalIPv6(true, configurator); err != nil {
		t.Fatalf("configureExperimentalIPv6(true, configurator) error = %v, want nil", err)
	}
	if configurator.calls != 1 {
		t.Fatalf("SetIPv6Enabled calls = %d, want 1", configurator.calls)
	}
	if !configurator.enabled {
		t.Fatal("SetIPv6Enabled argument = false, want true")
	}
}

func TestConfigureExperimentalIPv6UnsupportedFailsClosed(t *testing.T) {
	err := configureExperimentalIPv6(true, struct{}{})
	if err == nil {
		t.Fatal("configureExperimentalIPv6(true, unsupported) error = nil, want error")
	}
	if got, want := err.Error(), "configured gateway module does not support experimental IPv6"; got != want {
		t.Fatalf("configureExperimentalIPv6 error = %q, want %q", got, want)
	}
}

type testIPv6Configurator struct {
	calls   int
	enabled bool
}

func (configurator *testIPv6Configurator) SetIPv6Enabled(enabled bool) error {
	configurator.calls++
	configurator.enabled = enabled
	return nil
}
