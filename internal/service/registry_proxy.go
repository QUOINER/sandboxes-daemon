package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	gatewaypolicy "github.com/rheic/sandboxes-gateway/policy"
	"github.com/rheic/sandboxes-gateway/registryauth"

	"github.com/rheic/sandboxes-daemon/internal/network"
	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
)

const (
	dockerHubProxyService = "docker-hub"
	dockerHubRegistryHost = "registry-1.docker.io"
	dockerHubAuthHost     = "auth.docker.io"
	dockerHubTokenService = "registry.docker.io"
	dockerHubGuestPort    = uint16(43134)
	registryMirrorURL     = "http://127.0.0.1:43134"
)

type sandboxRegistryTransportFactory struct {
	service   *Service
	sandboxID string
}

func (f sandboxRegistryTransportFactory) Registry(ctx context.Context, authority string) (*registryauth.RegistryTransport, error) {
	if authority != dockerHubRegistryHost {
		return nil, errors.New("untrusted Docker Hub registry authority")
	}
	prefixes, err := f.allowedPrefixes(ctx, authority)
	if err != nil {
		return nil, err
	}
	return registryauth.NewRegistryTransport(authority, prefixes, nil)
}

func (f sandboxRegistryTransportFactory) Token(ctx context.Context, realm registryauth.Realm) (*registryauth.TokenTransport, error) {
	if realm.Host != dockerHubAuthHost || realm.Path != "/token" {
		return nil, errors.New("untrusted Docker Hub token realm")
	}
	prefixes, err := f.allowedPrefixes(ctx, realm.Host)
	if err != nil {
		return nil, err
	}
	return registryauth.NewTokenTransport(realm, prefixes, nil)
}

func (f sandboxRegistryTransportFactory) Redirect(ctx context.Context, authority string) (http.RoundTripper, error) {
	if authority != "production.cloudfront.docker.com" {
		return nil, errors.New("untrusted Docker Hub blob redirect authority")
	}
	prefixes, err := f.allowedPrefixes(ctx, authority)
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr().String())
	}
	var next atomic.Uint64
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: authority},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(authority, "443") {
				return nil, errors.New("redirect transport rejected unexpected destination")
			}
			start := 0
			for offset := uint64(0); offset < next.Add(1)%uint64(len(addresses)); offset++ {
				start++
			}
			var failures []error
			for offset := range addresses {
				ip := addresses[(start+offset)%len(addresses)]
				conn, dialErr := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, "443"))
				if dialErr == nil {
					return conn, nil
				}
				failures = append(failures, dialErr)
			}
			return nil, errors.Join(failures...)
		},
	}, nil
}

func (f sandboxRegistryTransportFactory) allowedPrefixes(ctx context.Context, host string) ([]netip.Prefix, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("docker Hub endpoint DNS lookup failed")
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !network.IsPublicUnicast(address) {
			return nil, errors.New("docker Hub endpoint resolved to a non-public address")
		}
		decision, err := f.service.checkResolvedEgress(ctx, f.sandboxID, host, address)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	if len(prefixes) == 0 {
		return nil, errors.New("sandbox policy denied Docker Hub endpoint")
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	return prefixes, nil
}

func (s *Service) checkResolvedEgress(ctx context.Context, sandboxID, host string, address netip.Addr) (PolicyDecision, error) {
	allow, deny, err := s.checkPolicyRules(ctx, sandboxID)
	if err != nil {
		return PolicyDecision{}, err
	}
	convert := func(rules []sandbox.NetworkRule, action gatewaypolicy.Action) []gatewaypolicy.Rule {
		converted := make([]gatewaypolicy.Rule, 0, len(rules))
		for _, rule := range rules {
			converted = append(converted, gatewaypolicy.Rule{ID: rule.RuleID, Action: action,
				Protocol: rule.Protocol, Domain: rule.Domain, CIDR: rule.CIDR, Port: rule.Port})
		}
		return converted
	}
	decision := gatewaypolicy.Check(convert(allow, gatewaypolicy.Allow), convert(deny, gatewaypolicy.Deny), gatewaypolicy.Request{
		Protocol: tcpProtocol, Address: address.String(), Domain: host, Port: 443,
	})
	return PolicyDecision{Allowed: decision.Allow, RuleID: decision.RuleID, Reason: decision.Reason}, nil
}

func (s *Service) buildDockerHubProxy(_ context.Context, sb sandbox.Sandbox, scope registrycredentials.Scope) (secretproxy.RouteConfig, string, error) {
	if s.registryCredentials == nil || (scope != registrycredentials.ScopeSandbox && scope != registrycredentials.ScopeAllSandboxes) {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: Docker Hub registry broker is unavailable", core.ErrConflict)
	}
	proxy, err := registrycredentials.NewPullProxy(s.registryCredentials, registrycredentials.PullProxyConfig{
		Registry: dockerHubRegistry, Authority: dockerHubRegistryHost, SandboxName: sb.Name,
		CredentialScope: scope, Service: dockerHubTokenService,
		Realms:           []registryauth.Realm{{Host: dockerHubAuthHost, Path: "/token"}},
		TransportFactory: sandboxRegistryTransportFactory{service: s, sandboxID: sb.ID},
		Limiter:          s.registryPullLimiter,
		MaxBytes:         16 << 30,
	})
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("configure Docker Hub pull broker: %w", err)
	}
	token, err := newProxyToken()
	if err != nil {
		return secretproxy.RouteConfig{}, "", err
	}
	return secretproxy.RouteConfig{
		Service: secretproxy.Service{Upstream: "https://" + dockerHubRegistryHost, CredentialScope: string(scope)},
		Handler: proxy, Token: token,
	}, fmt.Sprintf("%s=%s:%d", dockerHubProxyService, dockerHubRegistryHost, dockerHubGuestPort), nil
}

func (s *Service) availableDockerHubScope(ctx context.Context, sandboxName string, allowAll bool) (registrycredentials.Scope, error) {
	if s.registryCredentials == nil {
		return "", nil
	}
	if credential, err := s.registryCredentials.Load(ctx, dockerHubRegistry, registrycredentials.ScopeSandbox, sandboxName); err == nil {
		clear(credential.Password)
		return registrycredentials.ScopeSandbox, nil
	} else if !errors.Is(err, registrycredentials.ErrNotFound) {
		return "", err
	}
	if !allowAll {
		return "", nil
	}
	if credential, err := s.registryCredentials.Load(ctx, dockerHubRegistry, registrycredentials.ScopeAllSandboxes, ""); err == nil {
		clear(credential.Password)
		return registrycredentials.ScopeAllSandboxes, nil
	} else if !errors.Is(err, registrycredentials.ErrNotFound) {
		return "", err
	}
	return "", nil
}

var _ registrycredentials.PullProxyTransportFactory = sandboxRegistryTransportFactory{}
