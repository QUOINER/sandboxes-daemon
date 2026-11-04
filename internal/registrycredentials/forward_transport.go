package registrycredentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// NewForwardRegistryTransport returns a host-only transport pinned to the
// supplied, policy-approved addresses. It permits only supported Docker
// Distribution pull and push operations at one HTTPS authority.
func NewForwardRegistryTransport(authority string, prefixes []netip.Prefix, roots *x509.CertPool) (http.RoundTripper, error) {
	endpoint, err := forwardRegistryEndpoint(authority)
	if err != nil {
		return nil, err
	}
	allowed, err := exactRegistryPrefixes(prefixes)
	if err != nil {
		return nil, err
	}
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: endpoint.Hostname()},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialPinnedRegistry(ctx, network, address, endpoint.Hostname(), allowed)
		},
	}
	return &forwardRegistryTransport{authority: endpoint.Host, transport: transport}, nil
}

func forwardRegistryEndpoint(authority string) (*url.URL, error) {
	endpoint, err := url.Parse(registryHTTPScheme + "://" + authority)
	if err != nil || authority == "" || endpoint.Host != authority || endpoint.Hostname() == "" ||
		(endpoint.Port() != "" && endpoint.Port() != "443") || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("invalid forward registry transport configuration")
	}
	return endpoint, nil
}

func exactRegistryPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	if len(prefixes) == 0 {
		return nil, errors.New("invalid forward registry transport configuration")
	}
	allowed := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		if !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
			return nil, errors.New("invalid forward registry address prefix")
		}
		address := prefix.Addr().Unmap()
		allowed[i] = netip.PrefixFrom(address, address.BitLen())
	}
	return allowed, nil
}

type forwardRegistryTransport struct {
	authority string
	transport http.RoundTripper
}

func (t *forwardRegistryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.transport == nil || request == nil || request.URL == nil || request.URL.Scheme != registryHTTPScheme ||
		!strings.EqualFold(request.URL.Host, t.authority) || request.URL.User != nil || request.URL.Opaque != "" ||
		request.URL.Fragment != "" || request.URL.RawPath != "" || request.RequestURI != "" ||
		(request.Host != "" && !strings.EqualFold(request.Host, t.authority)) {
		return nil, errors.New("forward registry request authority is invalid")
	}
	if _, err := parseRegistryOperation(request.Method, request.URL, t.authority); err != nil {
		return nil, errors.New("forward registry operation is unsupported")
	}
	return t.transport.RoundTrip(request) // #nosec G704 -- URL is fixed to one authority and DialContext pins the checked IP set.
}

func dialPinnedRegistry(ctx context.Context, network, address, authority string, prefixes []netip.Prefix) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || network != "tcp" || !strings.EqualFold(host, authority) || port != "443" {
		return nil, errors.New("forward registry transport rejected an unexpected destination")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var failures []error
	for _, prefix := range prefixes {
		ip := prefix.Addr().Unmap()
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		failures = append(failures, dialErr)
	}
	return nil, errors.Join(failures...)
}
