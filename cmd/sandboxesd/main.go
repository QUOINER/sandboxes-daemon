package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	gateway "github.com/rheic/sandboxes-gateway"
	runtime "github.com/rheic/sandboxes-runtime"
	runtimectr "github.com/rheic/sandboxes-runtime/ctr"

	daemon "github.com/rheic/sandboxes-daemon"
	"github.com/rheic/sandboxes-daemon/internal/containerdsvc"
	daemonnetwork "github.com/rheic/sandboxes-daemon/internal/network"
	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/policysync"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/settings"
	"github.com/rheic/sandboxes-daemon/internal/version"
)

type options struct {
	socketPath            string
	stateDir              string
	containerdPath        string
	ctrPath               string
	runtimeDir            string
	runtimeAssets         string
	snapshotter           string
	image                 string
	fifoDir               string
	gvproxyPath           string
	runDir                string
	proxyHelperPath       string
	dnsUpstream           string
	settingsPath          string
	defaultPolicyProfile  string
	defaultCPUs           uint32
	defaultMemoryMiB      uint32
	dockerVolumeSize      string
	mcpRemoteAllowedHosts []string
	registryPrivateHost   string
	registryPrivateSvc    string
	registryPrivateRealms []string
	registryPrivateRedirs []string
	registryPrivateCAPath string
	ipv6Experimental      bool
	quicExperimental      bool
	orgPolicyEnforce      bool
	orgPolicyOrg          string
	policySyncURL         string
	policySyncOrg         string
	policySyncPublicKey   string
	policySyncTokenFile   string
	policySyncInterval    time.Duration
	showVersion           bool
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) > 1 && os.Args[1] == containerdsvc.LauncherArgument {
		return containerdsvc.RunLauncher(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == gateway.SupervisorArgument {
		if err := gateway.RunSupervisor(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "gateway supervisor:", err)
			return 1
		}
		return 0
	}
	opts := parseOptions()
	if opts.showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version.Version)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	privateCA, caErr := readPrivateRegistryCA(opts.registryPrivateCAPath)
	if caErr != nil {
		slog.Error("read private registry CA", "error", caErr)
		return 1
	}
	policySync, syncErr := loadPolicySync(&opts)
	if syncErr != nil {
		slog.Error("load policy sync configuration", "error", syncErr)
		return 1
	}
	lost := make(chan string, 8)
	err := daemon.Run(ctx, daemon.Config{
		SocketPath: opts.socketPath,
		StateDir:   opts.stateDir,
		BackendFactory: func(runCtx context.Context) (runtime.Backend, func() error, <-chan error, error) {
			return buildBackend(runCtx, &opts, lost)
		},
		DefaultImage:             opts.image,
		IPv6Enabled:              ipv6RuleCapability(&opts),
		QUICEnabled:              quicRuleCapability(&opts),
		OrgPolicyEnforce:         opts.orgPolicyEnforce,
		OrgPolicyOrg:             opts.orgPolicyOrg,
		OAuthProviders:           dockerOAuthProviders(),
		DNSUpstream:              opts.dnsUpstream,
		DefaultPolicyProfile:     opts.defaultPolicyProfile,
		DefaultCPUs:              opts.defaultCPUs,
		DefaultMemoryMiB:         opts.defaultMemoryMiB,
		DockerVolumeSize:         opts.dockerVolumeSize,
		MCPRemoteAllowedHosts:    opts.mcpRemoteAllowedHosts,
		RegistryPrivateHost:      opts.registryPrivateHost,
		RegistryPrivateService:   opts.registryPrivateSvc,
		RegistryPrivateRealms:    opts.registryPrivateRealms,
		RegistryPrivateRedirects: opts.registryPrivateRedirs,
		RegistryPrivateCA:        privateCA,
		GatewayLost:              lost,
		ProxyHelperPath:          opts.proxyHelperPath,
		PolicySync:               policySync,
	})
	if err != nil {
		slog.Error("daemon stopped", "error", err)
		return 1
	}
	return 0
}

func parseOptions() options {
	var opts options
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultState := filepath.Join(home, ".sandboxes")
	flag.StringVar(&opts.stateDir, "state", defaultState, "state directory")
	flag.StringVar(&opts.socketPath, "socket", filepath.Join(defaultState, "sandboxesd.sock"), "local daemon endpoint")
	flag.StringVar(&opts.containerdPath, "containerd", "", "absolute containerd binary path; empty keeps state-only mode")
	flag.StringVar(&opts.ctrPath, "ctr", "", "absolute ctr binary path for the managed containerd service")
	flag.StringVar(&opts.runtimeDir, "runtime-dir", "", "absolute directory containing the nerdbox shim")
	flag.StringVar(&opts.runtimeAssets, "runtime-assets", "", "absolute directory containing the pinned libkrun runtime assets")
	flag.StringVar(&opts.snapshotter, "snapshotter", "erofs", "containerd snapshotter")
	flag.StringVar(&opts.image, "image", "alpine:3.22", "default image")
	flag.StringVar(&opts.fifoDir, "fifo-dir", "", "runtime FIFO directory")
	flag.StringVar(&opts.gvproxyPath, "gvproxy", "", "patched gvproxy binary; empty disables networking")
	flag.StringVar(&opts.runDir, "run-dir", "", "gateway runtime directory")
	flag.StringVar(&opts.proxyHelperPath, "proxy-helper", "", "static Linux guest proxy helper; empty disables service proxy")
	flag.StringVar(&opts.dnsUpstream, "dns-upstream", "", "optional DNS upstream")
	flag.BoolVar(&opts.ipv6Experimental, "ipv6-experimental", false, "enable the experimental IPv6 guest datapath (acceptance only)")
	flag.BoolVar(&opts.quicExperimental, "quic-experimental", false, "enable experimental UDP domain policy backed by QUIC classification (acceptance only)")
	flag.StringVar(&opts.settingsPath, "settings", settings.DefaultPath(), "user settings file")
	flag.BoolVar(&opts.showVersion, "version", false, "print version")
	flag.Parse()
	values, err := settings.Load(opts.settingsPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "load settings:", err)
		os.Exit(2)
	}
	if opts.dnsUpstream == "" {
		opts.dnsUpstream = values.DNSUpstream
	}
	opts.defaultPolicyProfile = values.DefaultPolicyProfile
	opts.defaultCPUs = values.DefaultCPUs
	opts.defaultMemoryMiB = values.DefaultMemoryMiB
	opts.dockerVolumeSize = values.DockerVolumeSize
	opts.mcpRemoteAllowedHosts = values.MCPRemoteAllowedHosts
	opts.registryPrivateHost = values.RegistryPrivateHost
	opts.registryPrivateSvc = values.RegistryPrivateService
	opts.registryPrivateRealms = values.RegistryPrivateRealms
	opts.registryPrivateRedirs = values.RegistryPrivateRedirects
	opts.registryPrivateCAPath = values.RegistryPrivateCA
	opts.orgPolicyEnforce = values.OrgPolicyEnforce
	opts.orgPolicyOrg = values.OrgPolicyOrg
	opts.policySyncURL = values.PolicySyncURL
	opts.policySyncOrg = values.PolicySyncOrg
	opts.policySyncPublicKey = values.PolicySyncPublicKeyFile
	opts.policySyncTokenFile = values.PolicySyncTokenFile
	opts.policySyncInterval = values.PolicySyncInterval
	return opts
}

// loadPolicySync reads the protected token and public-key files only when the
// all-or-none settings block is present. The token is never accepted from a
// command-line flag, so it cannot leak through the process list.
func loadPolicySync(opts *options) (*daemon.PolicySyncConfig, error) {
	if opts.policySyncURL == "" {
		return nil, nil //nolint:nilnil // nil config means policy sync is disabled.
	}
	publicKey, err := policysync.LoadPublicKeyFile(opts.policySyncPublicKey)
	if err != nil {
		return nil, err
	}
	token, err := policysync.LoadTokenFile(opts.policySyncTokenFile)
	if err != nil {
		return nil, err
	}
	client, err := policysync.New(policysync.Config{
		BaseURL:   opts.policySyncURL,
		OrgID:     opts.policySyncOrg,
		Token:     token,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}
	return &daemon.PolicySyncConfig{Client: client, Interval: opts.policySyncInterval}, nil
}

func dockerOAuthProviders() map[string]service.OAuthProvider {
	provider, err := oauthsession.NewDockerHubProvider(http.DefaultTransport)
	if err != nil {
		slog.Error("Docker Hub OAuth provider configuration is invalid", "error", err)
		return nil
	}
	openai, err := oauthsession.NewOpenAICodexProvider(http.DefaultTransport)
	if err != nil {
		slog.Error("OpenAI OAuth provider configuration is invalid", "error", err)
		return nil
	}
	return map[string]service.OAuthProvider{
		"docker": {
			Device:         provider,
			RevokeEndpoint: oauthsession.DockerOAuthRevokeURL,
			DeviceHandoff: func(ctx context.Context, _ string, verificationURI string) error {
				return oauthsession.OpenBrowser(ctx, verificationURI)
			},
		},
		"openai": {
			Config: openai,
			RevokeToken: func(ctx context.Context, token string) error {
				return oauthsession.RevokeOpenAI(ctx, openai.Transport, token)
			},
			OpenBrowser: oauthsession.OpenBrowser,
		},
	}
}

func managedRuntimeConfig(opts *options, socket string) runtimectr.Config {
	return runtimectr.Config{
		Socket:      socket,
		Namespace:   containerdsvc.Namespace,
		CTR:         opts.ctrPath,
		Runtime:     filepath.Join(opts.runtimeDir, "containerd-shim-nerdbox-v1"),
		Snapshotter: opts.snapshotter,
	}
}

func buildBackend(ctx context.Context, opts *options, gatewayLost chan<- string) (runtime.Backend, func() error, <-chan error, error) {
	if opts.containerdPath == "" {
		if opts.ctrPath != "" || opts.runtimeDir != "" || opts.runtimeAssets != "" {
			return nil, nil, nil, fmt.Errorf("--ctr, --runtime-dir, and --runtime-assets require managed --containerd")
		}
		return nil, nil, nil, nil
	}
	launcher, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("locate daemon launcher: %w", err)
	}
	managed, err := containerdsvc.Start(ctx, containerdsvc.Config{
		Binary:        opts.containerdPath,
		CTR:           opts.ctrPath,
		RuntimeDir:    opts.runtimeDir,
		RuntimeAssets: opts.runtimeAssets,
		StateDir:      opts.stateDir,
	}, launcher)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("start managed containerd: %w", err)
	}
	fifoDir := opts.fifoDir
	if fifoDir == "" {
		fifoDir = filepath.Join(opts.stateDir, "fifo")
	}
	if err := os.MkdirAll(fifoDir, 0o700); err != nil {
		return nil, nil, nil, errors.Join(fmt.Errorf("create fifo dir: %w", err), managed.Close())
	}
	network, manager, err := buildNetwork(opts, gatewayLost)
	if err != nil {
		return nil, nil, nil, errors.Join(err, managed.Close())
	}
	backend, err := runtimectr.NewBackend(managedRuntimeConfig(opts, managed.Socket()), runtimectr.BackendOptions{Image: opts.image, FIFODir: fifoDir, Network: network})
	if err != nil {
		var closeErr error
		if manager != nil {
			closeErr = manager.Close(context.Background())
		}
		return nil, nil, nil, errors.Join(fmt.Errorf("create runtime backend: %w", err), closeErr, managed.Close())
	}
	cleanup := func() error {
		var result error
		if manager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := manager.Close(ctx); err != nil {
				result = errors.Join(result, fmt.Errorf("cleanup gateway manager: %w", err))
			}
		}
		return errors.Join(result, managed.Close())
	}
	return backend, cleanup, managed.Failures(), nil
}

func buildNetwork(opts *options, gatewayLost chan<- string) (runtime.Network, *gateway.Manager, error) {
	if opts.gvproxyPath == "" {
		return nil, nil, nil
	}
	runDir := opts.runDir
	if runDir == "" {
		runDir = filepath.Join(opts.stateDir, "run")
	}
	supervisor, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("locate gateway supervisor: %w", err)
	}
	manager, err := gateway.New(gateway.Config{
		GVProxy:     opts.gvproxyPath,
		Supervisor:  supervisor,
		RunDir:      runDir,
		DNSUpstream: opts.dnsUpstream,
		OnExit: func(name string) {
			select {
			case gatewayLost <- name:
			default:
				slog.Warn("gateway loss event dropped", "sandbox", name)
			}
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create gateway manager: %w", err)
	}
	if err := configureExperimentalIPv6(opts.ipv6Experimental, manager); err != nil {
		return nil, nil, err
	}
	if err := configureExperimentalQUIC(opts.quicExperimental, manager); err != nil {
		return nil, nil, err
	}
	return daemonnetwork.New(manager, runDir), manager, nil
}

type experimentalIPv6Configurator interface {
	SetIPv6Enabled(bool) error
}

type experimentalQUICConfigurator interface {
	SetQUICEnabled(bool) error
}

// ipv6RuleCapability is true only when the operator asked for the
// experimental datapath and a patched gvproxy is configured. Without gvproxy
// the gateway capability cannot be enabled, so v6 rules stay rejected.
func ipv6RuleCapability(opts *options) bool {
	return opts.ipv6Experimental && opts.gvproxyPath != ""
}

// quicRuleCapability mirrors ipv6RuleCapability for UDP domain policy. The
// gateway only accepts UDP domain rules when the patched datapath is present
// and the operator enabled it explicitly.
func quicRuleCapability(opts *options) bool {
	return opts.quicExperimental && opts.gvproxyPath != ""
}

func configureExperimentalIPv6(enabled bool, target any) error {
	if !enabled {
		return nil
	}
	configurator, ok := target.(experimentalIPv6Configurator)
	if !ok {
		return errors.New("configured gateway module does not support experimental IPv6")
	}
	if err := configurator.SetIPv6Enabled(true); err != nil {
		return fmt.Errorf("enable experimental IPv6 gateway: %w", err)
	}
	return nil
}

func configureExperimentalQUIC(enabled bool, target any) error {
	if !enabled {
		return nil
	}
	configurator, ok := target.(experimentalQUICConfigurator)
	if !ok {
		return errors.New("configured gateway module does not support experimental QUIC")
	}
	if err := configurator.SetQUICEnabled(true); err != nil {
		return fmt.Errorf("enable experimental QUIC gateway: %w", err)
	}
	return nil
}

func readPrivateRegistryCA(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("private registry CA must be a regular file under 1 MiB")
	}
	return os.ReadFile(path) //nolint:gosec // trusted host-only settings path, validated as a regular file under 1 MiB.
}
