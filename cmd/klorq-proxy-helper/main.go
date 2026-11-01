// Command klorq-proxy-helper runs inside a sandbox and forwards HTTP requests
// over the per-VM vsock channel to the host broker. The broker owns the real
// service credential; the helper only carries the per-VM token.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	tokenHeader = "X-Klorq-Proxy-Token" //nolint:gosec // HTTP header name, not a credential.
	afVsock     = 40
)

type sockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	CID       uint32
	Flags     uint8
	Zero      [3]byte
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "guest loopback listen address")
	cid := flag.Int("cid", 2, "host vsock context id")
	port := flag.Int("port", 1027, "host vsock port")
	unixSocket := flag.String("unix-socket", "", "host unix socket (test/preview transport)")
	serviceHost := flag.String("service-host", "", "upstream host the broker authorizes")
	flag.Parse()
	if *serviceHost == "" {
		log.Fatal("service-host is required")
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		if *unixSocket != "" {
			var d net.Dialer
			return d.DialContext(ctx, "unix", *unixSocket)
		}
		return dialVsock(*cid, *port)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
	}
	handler := newHandler(*serviceHost, transport)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("proxy helper listening on %s for %s", *listen, *serviceHost)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func fetchToken(ctx context.Context, transport http.RoundTripper) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://broker/__klorq/proxy/token", http.NoBody)
	if err != nil {
		return "", err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		return "", errors.New("proxy bootstrap was denied")
	}
	token, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil || len(token) != 64 {
		return "", errors.New("proxy bootstrap returned an invalid token")
	}
	decoded := make([]byte, hex.DecodedLen(len(token)))
	if _, err := hex.Decode(decoded, token); err != nil {
		return "", errors.New("proxy bootstrap returned an invalid token")
	}
	return string(token), nil
}

func newHandler(serviceHost string, transport http.RoundTripper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "connect tunnels are not supported", http.StatusMethodNotAllowed)
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.URL.Scheme = "http"
		out.URL.Host = serviceHost
		out.Host = serviceHost
		token, err := fetchToken(r.Context(), transport)
		if err != nil {
			http.Error(w, "proxy channel unavailable", http.StatusBadGateway)
			return
		}
		out.Header.Set(tokenHeader, token)
		out.Header.Del("Proxy-Connection")
		out.Header.Del("Proxy-Authorization")
		resp, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(w, "proxy channel unavailable", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func dialVsock(cid, port int) (net.Conn, error) {
	if err := ensureVsockDevice(); err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		_ = syscall.Close(fd)
		return nil, errors.New("vsock port out of range")
	}
	sa := sockaddrVM{Family: afVsock, Port: uint32(port), CID: uint32(cid)} //nolint:gosec // port range validated above.
	//nolint:gosec // syscall connect requires the sockaddr pointer.
	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock connect: %w", errno)
	}
	file := os.NewFile(uintptr(fd), "vsock")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return conn, nil
}

// ensureVsockDevice creates /dev/vsock from the dynamic misc minor.
func ensureVsockDevice() error {
	if _, err := os.Stat("/dev/vsock"); err == nil {
		return nil
	}
	data, err := os.ReadFile("/proc/misc")
	if err != nil {
		return err
	}
	minor := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "vsock" {
			minor, _ = strconv.Atoi(fields[0])
		}
	}
	if minor == 0 {
		return errors.New("vsock misc device not found")
	}
	return syscall.Mknod("/dev/vsock", syscall.S_IFCHR|0o666, (10<<8)|minor)
}
