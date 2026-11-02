package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	gateway "github.com/KLORQ/sandboxes-gateway"
	runtime "github.com/KLORQ/sandboxes-runtime"
	runtimectr "github.com/KLORQ/sandboxes-runtime/ctr"

	daemon "github.com/KLORQ/sandboxes-daemon"
	daemonnetwork "github.com/KLORQ/sandboxes-daemon/internal/network"
	"github.com/KLORQ/sandboxes-daemon/internal/oauthsession"
	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/settings"
	"github.com/KLORQ/sandboxes-daemon/internal/version"
)

type options struct {
	socketPath           string
	stateDir             string
	containerdPath       string
	ctrPath              string
	runtimeName          string
	snapshotter          string
	image                string
	fifoDir              string
	gvproxyPath          string
	runDir               string
	proxyHelperPath      string
	dnsUpstream          string
	settingsPath         string
	defaultPolicyProfile string
	defaultCPUs          uint32
	defaultMemoryMiB     uint32
	dockerVolumeSize     string
	showVersion          bool
}

func main() {
	os.Exit(run())
}

func run() int {
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
	lost := make(chan string, 8)
	backend, cleanup, err := buildBackend(&opts, lost)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = daemon.Run(ctx, daemon.Config{
		SocketPath:           opts.socketPath,
		StateDir:             opts.stateDir,
		Backend:              backend,
		DefaultImage:         opts.image,
		Cleanup:              cleanup,
		OAuthProviders:       dockerOAuthProviders(),
		DNSUpstream:          opts.dnsUpstream,
		DefaultPolicyProfile: opts.defaultPolicyProfile,
		DefaultCPUs:          opts.defaultCPUs,
		DefaultMemoryMiB:     opts.defaultMemoryMiB,
		DockerVolumeSize:     opts.dockerVolumeSize,
		GatewayLost:          lost,
		ProxyHelperPath:      opts.proxyHelperPath,
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
	flag.StringVar(&opts.socketPath, "socket", filepath.Join(defaultState, "sandboxesd.sock"), "unix socket path")
	flag.StringVar(&opts.containerdPath, "containerd", "", "containerd socket; empty keeps state-only mode")
	flag.StringVar(&opts.ctrPath, "ctr", "ctr", "ctr binary path")
	flag.StringVar(&opts.runtimeName, "runtime", "io.containerd.nerdbox.v1", "containerd runtime name")
	flag.StringVar(&opts.snapshotter, "snapshotter", "erofs", "containerd snapshotter")
	flag.StringVar(&opts.image, "image", "alpine:3.22", "default image")
	flag.StringVar(&opts.fifoDir, "fifo-dir", "", "runtime FIFO directory")
	flag.StringVar(&opts.gvproxyPath, "gvproxy", "", "patched gvproxy binary; empty disables networking")
	flag.StringVar(&opts.runDir, "run-dir", "", "gateway runtime directory")
	flag.StringVar(&opts.proxyHelperPath, "proxy-helper", "", "static Linux guest proxy helper; empty disables service proxy")
	flag.StringVar(&opts.dnsUpstream, "dns-upstream", "", "optional DNS upstream")
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
	return opts
}

func dockerOAuthProviders() map[string]service.OAuthProvider {
	provider, err := oauthsession.NewDockerHubProvider(http.DefaultTransport)
	if err != nil {
		slog.Error("Docker Hub OAuth provider configuration is invalid", "error", err)
		return nil
	}
	return map[string]service.OAuthProvider{"docker": {
		Device:         provider,
		RevokeEndpoint: oauthsession.DockerOAuthRevokeURL,
		DeviceHandoff: func(ctx context.Context, _ string, verificationURI string) error {
			return oauthsession.OpenBrowser(ctx, verificationURI)
		},
	}}
}

func buildBackend(opts *options, gatewayLost chan<- string) (runtime.Backend, func() error, error) {
	if opts.containerdPath == "" {
		return nil, nil, nil
	}
	fifoDir := opts.fifoDir
	if fifoDir == "" {
		fifoDir = filepath.Join(opts.stateDir, "fifo")
	}
	if err := os.MkdirAll(fifoDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create fifo dir: %w", err)
	}
	network, manager, err := buildNetwork(opts, gatewayLost)
	if err != nil {
		return nil, nil, err
	}
	backend, err := runtimectr.NewBackend(runtimectr.Config{
		Socket:      opts.containerdPath,
		CTR:         opts.ctrPath,
		Runtime:     opts.runtimeName,
		Snapshotter: opts.snapshotter,
	}, runtimectr.BackendOptions{Image: opts.image, FIFODir: fifoDir, Network: network})
	if err != nil {
		return nil, nil, fmt.Errorf("create runtime backend: %w", err)
	}
	cleanup := func() error {
		if manager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := manager.Close(ctx); err != nil {
				return fmt.Errorf("cleanup gateway manager: %w", err)
			}
		}
		return nil
	}
	return backend, cleanup, nil
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
	return daemonnetwork.New(manager, runDir), manager, nil
}
