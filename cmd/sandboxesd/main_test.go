package main

import "testing"

func TestIPv6RuleCapabilityRequiresFlagAndGateway(t *testing.T) {
	for _, test := range []struct {
		name string
		opts options
		want bool
	}{
		{name: "defaults off", opts: options{}, want: false},
		{name: "flag without gvproxy", opts: options{ipv6Experimental: true}, want: false},
		{name: "gvproxy without flag", opts: options{gvproxyPath: "/bin/gvproxy"}, want: false},
		{name: "flag and gvproxy", opts: options{ipv6Experimental: true, gvproxyPath: "/bin/gvproxy"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ipv6RuleCapability(&test.opts); got != test.want {
				t.Fatalf("ipv6RuleCapability(%+v) = %v, want %v", test.opts, got, test.want)
			}
		})
	}
}

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

func TestConfigureExperimentalQUICDisabledDoesNotRequireConfigurator(t *testing.T) {
	if err := configureExperimentalQUIC(false, nil); err != nil {
		t.Fatalf("configureExperimentalQUIC(false, nil) error = %v, want nil", err)
	}
}

func TestConfigureExperimentalQUICEnabled(t *testing.T) {
	configurator := &testQUICConfigurator{}
	if err := configureExperimentalQUIC(true, configurator); err != nil {
		t.Fatalf("configureExperimentalQUIC(true, configurator) error = %v, want nil", err)
	}
	if configurator.calls != 1 {
		t.Fatalf("SetQUICEnabled calls = %d, want 1", configurator.calls)
	}
	if !configurator.enabled {
		t.Fatal("SetQUICEnabled argument = false, want true")
	}
}

func TestConfigureExperimentalQUICUnsupportedFailsClosed(t *testing.T) {
	err := configureExperimentalQUIC(true, struct{}{})
	if err == nil {
		t.Fatal("configureExperimentalQUIC(true, unsupported) error = nil, want error")
	}
	if got, want := err.Error(), "configured gateway module does not support experimental QUIC"; got != want {
		t.Fatalf("configureExperimentalQUIC error = %q, want %q", got, want)
	}
}

type testQUICConfigurator struct {
	calls   int
	enabled bool
}

func (configurator *testQUICConfigurator) SetQUICEnabled(enabled bool) error {
	configurator.calls++
	configurator.enabled = enabled
	return nil
}
