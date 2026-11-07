package registrycredentials

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

const (
	dockerHubAuthAuthority  = "auth.docker.io"
	dockerHubBlobAuthority  = "production.cloudfront.docker.com"
	maxForwardTokens        = 256
	maxUploadSessions       = 1024
	maxBlobRedirectSessions = 1024
	blobRedirectUses        = 16
	blobRedirectLifetime    = 15 * time.Minute
	maxRegistryRequestBody  = int64(16 << 30)
	maxRegistryErrorBody    = int64(64 << 10)
	registryManifestsPath   = "manifests"
)

type registryOperation struct {
	repository string
	action     string
	kind       string
	uploadID   string
}

func (p *PullProxy) serveForwardRequest(w http.ResponseWriter, r *http.Request) {
	if !requestHostMatchesTLS(r) {
		http.Error(w, "TLS host does not match CONNECT target", http.StatusMisdirectedRequest)
		return
	}
	host := strings.ToLower(strings.TrimSuffix(r.TLS.ServerName, "."))
	// A registry may serve its token endpoint on the registry host itself, so
	// an exact realm path wins over the registry route on the same host.
	if realm, ok := p.realmForPath(host, r.URL.Path); ok {
		p.serveTokenRequest(w, r, realm)
		return
	}
	if strings.EqualFold(host, p.authority) {
		p.serveRegistryForward(w, r, host)
		return
	}
	if realm, ok := p.authRealm(host); ok {
		p.serveTokenRequest(w, r, realm)
		return
	}
	if p.isRedirectHost(host) {
		p.serveBlobRedirectRequest(w, r, host)
		return
	}
	http.Error(w, "registry proxy host is not authorized", http.StatusForbidden)
}

func requestHostMatchesTLS(r *http.Request) bool {
	if r == nil || r.TLS == nil || r.TLS.ServerName == "" || r.Host == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(r.Host, "."))
	if parsedHost, port, err := net.SplitHostPort(host); err == nil {
		if port != "443" {
			return false
		}
		host = strings.ToLower(strings.TrimSuffix(parsedHost, "."))
	}
	return host == strings.ToLower(strings.TrimSuffix(r.TLS.ServerName, "."))
}

func (p *PullProxy) serveTokenRequest(w http.ResponseWriter, r *http.Request, realm registryauth.Realm) {
	repository, actions, status := requestedTokenScope(r, p.service, realm.Path)
	if status != http.StatusOK {
		message := "registry token request is invalid"
		if status == http.StatusForbidden {
			message = "registry token request is unsupported"
		}
		http.Error(w, message, status)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if !p.limiter.acquire(ctx) {
		if r.Context().Err() != nil {
			return
		}
		writeRegistryBusy(w)
		return
	}
	defer p.limiter.release()
	transport, err := p.tokenTransportFor(ctx, realm)
	if err != nil {
		http.Error(w, "registry authentication unavailable", http.StatusBadGateway)
		return
	}
	scope := "repository:" + repository + ":" + strings.Join(sortedActions(actions), ",")
	_, err = p.store.ExchangeScopedToken(ctx, transport, p.registry, p.credentialScope, p.sandboxName, p.service, scope, p.realms)
	if err != nil {
		http.Error(w, "registry authentication failed", http.StatusUnauthorized)
		return
	}
	writeSentinelToken(w, p, repository, actions)
}

func requestedTokenScope(r *http.Request, service, tokenPath string) (string, map[string]struct{}, int) {
	if !validTokenRequestEnvelope(r, tokenPath) {
		return "", nil, http.StatusForbidden
	}
	repository, actions, ok, valid := parseTokenRequestScope(r.URL.RawQuery, service)
	if !valid {
		return "", nil, http.StatusBadRequest
	}
	if !ok {
		return "", nil, http.StatusForbidden
	}
	return repository, actions, http.StatusOK
}

func validTokenRequestEnvelope(r *http.Request, tokenPath string) bool {
	return r != nil && r.URL != nil && r.Method == http.MethodGet && r.URL.Path == tokenPath && r.URL.RawPath == "" &&
		r.URL.Opaque == "" && r.URL.Fragment == "" && r.URL.User == nil && r.ContentLength == 0 && len(r.TransferEncoding) == 0
}

func parseTokenRequestScope(rawQuery, service string) (string, map[string]struct{}, bool, bool) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil || !tokenQueryKeysAllowed(values) || values.Get("service") != service || len(values["service"]) != 1 || len(values["scope"]) == 0 {
		return "", nil, false, false
	}
	// Docker sends one scope parameter per requested grant; pull+push yields
	// repeated scopes for the same repository.
	repository := ""
	actions := make(map[string]struct{})
	for _, raw := range values["scope"] {
		current, currentActions, ok := parseRepositoryScope(raw)
		if !ok {
			return "", nil, false, true
		}
		if repository == "" {
			repository = current
		} else if !strings.EqualFold(repository, current) {
			return "", nil, false, true
		}
		for action := range currentActions {
			actions[action] = struct{}{}
		}
	}
	if repository == "" {
		return "", nil, false, true
	}
	return repository, actions, true, true
}

func writeSentinelToken(w http.ResponseWriter, proxy *PullProxy, repository string, actions map[string]struct{}) {
	sentinel, err := proxy.issueToken(repository, actions)
	if err != nil {
		http.Error(w, "registry authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := json.Marshal(struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
		IssuedAt  string `json:"issued_at"`
	}{Token: sentinel, ExpiresIn: 300, IssuedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		http.Error(w, "registry authentication unavailable", http.StatusInternalServerError)
		return
	}
	defer clear(body)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func tokenQueryKeysAllowed(values url.Values) bool {
	for key, items := range values {
		if key == "scope" {
			if len(items) == 0 {
				return false
			}
			continue
		}
		if len(items) != 1 || (key != "service" && key != "account" && key != "client_id") {
			return false
		}
	}
	return true
}

func parseRepositoryScope(scope string) (string, map[string]struct{}, bool) {
	separator := strings.LastIndex(scope, ":")
	if separator <= 0 || separator == len(scope)-1 {
		return "", nil, false
	}
	resource, actionText := scope[:separator], scope[separator+1:]
	if !strings.HasPrefix(resource, "repository:") {
		return "", nil, false
	}
	repository := strings.TrimPrefix(resource, "repository:")
	if repository == "" || len(repository) > 255 || strings.ContainsAny(repository, "?#%\\\x00\r\n") {
		return "", nil, false
	}
	for _, component := range strings.Split(repository, "/") {
		if !validRepoComponent(component) {
			return "", nil, false
		}
	}
	actions := make(map[string]struct{}, 2)
	for _, action := range strings.Split(actionText, ",") {
		if action != registryActionPull && action != registryActionPush {
			return "", nil, false
		}
		if _, exists := actions[action]; exists {
			return "", nil, false
		}
		actions[action] = struct{}{}
	}
	return repository, actions, len(actions) > 0
}

func sortedActions(actions map[string]struct{}) []string {
	out := make([]string, 0, len(actions))
	for action := range actions {
		out = append(out, action)
	}
	sort.Strings(out)
	return out
}

func (p *PullProxy) issueToken(repository string, actions map[string]struct{}) (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	token := "rheic-" + base64.RawURLEncoding.EncodeToString(random[:])
	clear(random[:])
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	now := time.Now()
	for key, grant := range p.tokens {
		if !grant.expiresAt.After(now) {
			delete(p.tokens, key)
		}
	}
	if len(p.tokens) >= maxForwardTokens {
		return "", errors.New("registry token cache is full")
	}
	copyActions := make(map[string]struct{}, len(actions))
	for action := range actions {
		copyActions[action] = struct{}{}
	}
	p.tokens[token] = tokenGrant{repository: repository, actions: copyActions, expiresAt: now.Add(5 * time.Minute)}
	return token, nil
}

func (p *PullProxy) authorizeToken(token, repository, action string) bool {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	grant, ok := p.tokens[token]
	if !ok {
		return false
	}
	if !grant.expiresAt.After(time.Now()) {
		delete(p.tokens, token)
		return false
	}
	_, allowed := grant.actions[action]
	return allowed && grant.repository == repository
}

func (p *PullProxy) serveRegistryForward(w http.ResponseWriter, r *http.Request, host string) {
	endpoint, err := registryEndpointFromRequest(r, host)
	if err != nil {
		http.Error(w, "invalid registry URL", http.StatusBadRequest)
		return
	}
	if endpoint.Path == registryV2Path && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	operation, err := parseRegistryOperation(r.Method, endpoint, host)
	if err != nil {
		http.Error(w, "unsupported registry operation", http.StatusForbidden)
		return
	}
	endpoint, ok := p.prepareRegistryRequest(w, r, endpoint, operation)
	if !ok {
		return
	}
	token := strings.TrimSpace(r.Header.Get("Authorization"))
	if token == "" {
		p.writeRegistryChallenge(w, operation)
		return
	}
	if !p.authorizeGuestOperation(w, r, operation, token) {
		return
	}
	p.forwardRegistryOperation(w, r, endpoint, operation)
}

func registryEndpointFromRequest(r *http.Request, host string) (*url.URL, error) {
	if r == nil || r.URL == nil || r.URL.Opaque != "" || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.RawPath != "" {
		return nil, errors.New("invalid registry request URL")
	}
	return &url.URL{Scheme: registryHTTPScheme, Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}, nil
}

func (p *PullProxy) prepareRegistryRequest(w http.ResponseWriter, r *http.Request, endpoint *url.URL, operation registryOperation) (*url.URL, bool) {
	if operation.kind == registryUploadKind && operation.uploadID != "" && !p.authorizeUploadRequest(endpoint, operation, r.Method) {
		http.Error(w, "registry upload session is unknown or expired", http.StatusForbidden)
		return nil, false
	}
	if operation.kind == registryUploadInitKind && endpoint.RawQuery != "" {
		cleaned, err := stripCrossRepositoryMount(endpoint)
		if err != nil {
			http.Error(w, "cross-repository mount request is invalid", http.StatusForbidden)
			return nil, false
		}
		endpoint = cleaned
	}
	if operation.kind == registryUploadInitKind && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
		http.Error(w, "monolithic registry uploads are unsupported", http.StatusForbidden)
		return nil, false
	}
	return endpoint, true
}

func (p *PullProxy) authorizeGuestOperation(w http.ResponseWriter, r *http.Request, operation registryOperation, token string) bool {
	if len(r.Header.Values("Authorization")) == 1 && strings.HasPrefix(token, "Bearer rheic-") &&
		p.authorizeToken(strings.TrimPrefix(token, "Bearer "), operation.repository, operation.action) {
		return true
	}
	http.Error(w, "registry authorization is invalid", http.StatusForbidden)
	return false
}

func (p *PullProxy) forwardRegistryOperation(w http.ResponseWriter, r *http.Request, endpoint *url.URL, operation registryOperation) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if !p.limiter.acquire(ctx) {
		if r.Context().Err() != nil {
			return
		}
		writeRegistryBusy(w)
		return
	}
	defer p.limiter.release()
	upstreamToken, err := p.exchangeOperationToken(ctx, operation)
	if err != nil {
		http.Error(w, "registry authorization failed", http.StatusBadGateway)
		return
	}
	defer clear([]byte(upstreamToken))
	transport, err := p.registryTransportFor(ctx)
	if err != nil {
		http.Error(w, "registry transport unavailable", http.StatusBadGateway)
		return
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL = endpoint
	out.Host = endpoint.Host
	out.Header = r.Header.Clone()
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Authorization")
	out.Header.Set("Authorization", "Bearer "+upstreamToken)
	out.Header.Set("Accept-Encoding", "identity")
	if operation.kind == registryUploadInitKind {
		out.Body = http.NoBody
		out.ContentLength = 0
		out.TransferEncoding = nil
	} else {
		out.Body = http.MaxBytesReader(w, r.Body, maxRegistryRequestBody)
	}
	response, err := client.Do(out)
	if err != nil {
		http.Error(w, "registry request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	p.finishRegistryResponse(w, r.Method, endpoint, operation, response)
}

func (p *PullProxy) writeRegistryChallenge(w http.ResponseWriter, operation registryOperation) {
	if operation.repository == "" || (operation.action != registryActionPull && operation.action != registryActionPush) {
		http.Error(w, "registry authorization is required", http.StatusUnauthorized)
		return
	}
	scope := "repository:" + operation.repository + ":" + operation.action
	if operation.action == registryActionPush {
		scope = "repository:" + operation.repository + ":pull,push"
	}
	realm := p.realms[0]
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service=%q,scope=%q`, "https://"+realm.Host+realm.Path, p.service, scope))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
}

func (p *PullProxy) exchangeOperationToken(ctx context.Context, operation registryOperation) (string, error) {
	transport, err := p.tokenTransportFor(ctx, p.realms[0])
	if err != nil {
		return "", err
	}
	scope := "repository:" + operation.repository + ":" + operation.action
	if operation.action == registryActionPush {
		// OCI upload workflows may need to query existing blobs before writing.
		// Keep this action grant explicit and never request delete.
		scope = "repository:" + operation.repository + ":pull,push"
	}
	return p.store.ExchangeScopedToken(ctx, transport, p.registry, p.credentialScope, p.sandboxName, p.service, scope, p.realms)
}

func parseRegistryOperation(method string, endpoint *url.URL, expectedHost string) (registryOperation, error) {
	if endpoint == nil || endpoint.Scheme != registryHTTPScheme || !strings.EqualFold(endpoint.Host, expectedHost) || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" {
		return registryOperation{}, errors.New("invalid registry request URL")
	}
	if endpoint.Path == registryV2Path && (method == http.MethodGet || method == http.MethodHead) {
		return registryOperation{kind: "probe"}, nil
	}
	parts := strings.Split(endpoint.Path, "/")
	if len(parts) < 5 || parts[0] != "" || parts[1] != "v2" {
		return registryOperation{}, errors.New("invalid registry path")
	}
	if operation, matched, err := parseManifestOperation(method, endpoint, parts); matched {
		return operation, err
	}
	if operation, matched, err := parseBlobOperation(method, endpoint, parts); matched {
		return operation, err
	}
	return parseUploadOperation(method, parts)
}

func parseManifestOperation(method string, endpoint *url.URL, parts []string) (registryOperation, bool, error) {
	if parts[len(parts)-2] != registryManifestsPath {
		return registryOperation{}, false, nil
	}
	repository, ok := registryRepository(parts[2 : len(parts)-2])
	if !ok || !validReference(parts[len(parts)-1]) || endpoint.RawQuery != "" {
		return registryOperation{}, true, errors.New("invalid manifest path")
	}
	switch method {
	case http.MethodGet, http.MethodHead:
		return registryOperation{repository: repository, action: registryActionPull, kind: registryManifestsPath}, true, nil
	case http.MethodPut:
		return registryOperation{repository: repository, action: registryActionPush, kind: registryManifestsPath}, true, nil
	default:
		return registryOperation{}, true, errors.New("unsupported manifest method")
	}
}

func parseBlobOperation(method string, endpoint *url.URL, parts []string) (registryOperation, bool, error) {
	if parts[len(parts)-2] != registryBlobPath {
		return registryOperation{}, false, nil
	}
	repository, ok := registryRepository(parts[2 : len(parts)-2])
	if !ok || !validReference(parts[len(parts)-1]) || endpoint.RawQuery != "" {
		return registryOperation{}, true, errors.New("invalid blob path")
	}
	if method != http.MethodGet && method != http.MethodHead {
		return registryOperation{}, true, errors.New("unsupported blob method")
	}
	return registryOperation{repository: repository, action: registryActionPull, kind: registryBlobPath}, true, nil
}

func parseUploadOperation(method string, parts []string) (registryOperation, error) {
	if len(parts) >= 6 && parts[len(parts)-3] == registryBlobPath && parts[len(parts)-2] == registryUploadsPath && parts[len(parts)-1] == "" && method == http.MethodPost {
		repository, ok := registryRepository(parts[2 : len(parts)-3])
		if !ok {
			return registryOperation{}, errors.New("invalid upload repository")
		}
		return registryOperation{repository: repository, action: registryActionPush, kind: registryUploadInitKind}, nil
	}
	if len(parts) < 6 || parts[len(parts)-3] != registryBlobPath || parts[len(parts)-2] != registryUploadsPath || !validUploadID(parts[len(parts)-1]) {
		return registryOperation{}, errors.New("invalid upload session path")
	}
	if !uploadSessionMethod(method) {
		return registryOperation{}, errors.New("unsupported upload method")
	}
	repository, ok := registryRepository(parts[2 : len(parts)-3])
	if !ok {
		return registryOperation{}, errors.New("invalid upload repository")
	}
	return registryOperation{repository: repository, action: registryActionPush, kind: registryUploadKind, uploadID: parts[len(parts)-1]}, nil
}

func uploadSessionMethod(method string) bool {
	switch method {
	case http.MethodPatch, http.MethodPut, http.MethodDelete, http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func registryRepository(parts []string) (string, bool) {
	if len(parts) == 0 {
		return "", false
	}
	repository := strings.Join(parts, "/")
	if len(repository) > 255 {
		return "", false
	}
	for _, component := range parts {
		if !validRepoComponent(component) {
			return "", false
		}
	}
	return repository, true
}

func validUploadID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for i := range value {
		if !isUploadIDCharacter(value[i]) {
			return false
		}
	}
	return true
}

func isUploadIDCharacter(c byte) bool {
	return isASCIIAlphaNumeric(c) || c == '-' || c == '_'
}

func validReference(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for i := range value {
		if !isReferenceCharacter(value[i]) {
			return false
		}
	}
	return true
}

func isReferenceCharacter(c byte) bool {
	return isASCIIAlphaNumeric(c) || c == '.' || c == '_' || c == '-' || c == ':'
}

func isASCIIAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func stripCrossRepositoryMount(endpoint *url.URL) (*url.URL, error) {
	values, err := url.ParseQuery(endpoint.RawQuery)
	if err != nil {
		return nil, err
	}
	for key := range values {
		if key != "mount" && key != "from" {
			return nil, errors.New("unsupported upload initialization query")
		}
	}
	if (len(values["mount"]) == 0) != (len(values["from"]) == 0) || len(values["mount"]) > 1 || len(values["from"]) > 1 {
		return nil, errors.New("incomplete cross-repository mount")
	}
	copyURL := *endpoint
	copyURL.RawQuery = ""
	copyURL.ForceQuery = false
	return &copyURL, nil
}

func (p *PullProxy) authorizeUploadRequest(endpoint *url.URL, operation registryOperation, method string) bool {
	key := operation.repository + "/" + operation.uploadID
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	now := time.Now()
	for current, session := range p.uploads {
		if !session.expiresAt.After(now) {
			delete(p.uploads, current)
		}
	}
	session, ok := p.uploads[key]
	if !ok || session.registryHost != endpoint.Host || session.repository != operation.repository || session.id != operation.uploadID {
		return false
	}
	return sameUploadURL(session.location, endpoint, method)
}

func sameUploadURL(stored, incoming *url.URL, method string) bool {
	if stored == nil || incoming == nil || !strings.EqualFold(stored.Host, incoming.Host) || stored.Path != incoming.Path || stored.Scheme != incoming.Scheme {
		return false
	}
	storedValues, err := url.ParseQuery(stored.RawQuery)
	if err != nil {
		return false
	}
	incomingValues, err := url.ParseQuery(incoming.RawQuery)
	if err != nil {
		return false
	}
	if method == http.MethodPut {
		digests := incomingValues["digest"]
		if len(digests) != 1 || !validDigest(digests[0]) {
			return false
		}
		incomingValues.Del("digest")
	}
	return storedValues.Encode() == incomingValues.Encode()
}

func validDigest(value string) bool {
	algorithm, hexValue, ok := strings.Cut(value, ":")
	if !ok || (algorithm != "sha256" && algorithm != "sha512") {
		return false
	}
	want := 64
	if algorithm == "sha512" {
		want = 128
	}
	if len(hexValue) != want {
		return false
	}
	for i := range hexValue {
		if !isLowerHexCharacter(hexValue[i]) {
			return false
		}
	}
	return true
}

func isLowerHexCharacter(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

func (p *PullProxy) finishRegistryResponse(w http.ResponseWriter, method string, endpoint *url.URL, operation registryOperation, response *http.Response) {
	if isPullRedirectStatus(response.StatusCode) {
		p.finishRegistryRedirect(w, method, endpoint, response)
		return
	}
	validatedLocation, ok := p.recordUploadLocation(w, method, endpoint, operation, response)
	if !ok {
		return
	}
	if uploadCompleted(method, operation, response.StatusCode) {
		p.removeUpload(operation.repository, operation.uploadID)
	}
	p.writeForwardRegistryResponse(w, method, response, validatedLocation)
}

func (p *PullProxy) finishRegistryRedirect(w http.ResponseWriter, method string, endpoint *url.URL, response *http.Response) {
	if len(response.Header.Values("Location")) != 1 {
		_ = response.Body.Close()
		http.Error(w, "registry redirect is invalid", http.StatusBadGateway)
		return
	}
	if method != http.MethodGet && method != http.MethodHead {
		_ = response.Body.Close()
		http.Error(w, "registry write redirect is unsupported", http.StatusBadGateway)
		return
	}
	redirect, err := p.validatePullRedirect(endpoint, response.Header.Get("Location"))
	if err != nil {
		_ = response.Body.Close()
		http.Error(w, "registry redirect is untrusted", http.StatusBadGateway)
		return
	}
	if !strings.EqualFold(redirect.Host, p.authority) {
		if err := p.recordBlobRedirect(redirect); err != nil {
			_ = response.Body.Close()
			http.Error(w, "registry redirect capacity reached", http.StatusServiceUnavailable)
			return
		}
	}
	copyForwardHeaders(w.Header(), response.Header, true)
	w.WriteHeader(response.StatusCode)
}

func (p *PullProxy) recordUploadLocation(w http.ResponseWriter, method string, endpoint *url.URL, operation registryOperation, response *http.Response) (bool, bool) {
	if !uploadLocationResponse(method, operation, response.StatusCode) {
		return false, true
	}
	if len(response.Header.Values("Location")) != 1 {
		_ = response.Body.Close()
		http.Error(w, "registry returned an invalid upload location", http.StatusBadGateway)
		return false, false
	}
	resolved, id, err := p.validateUploadLocation(endpoint, response.Header.Get("Location"), operation.repository)
	if err != nil || (operation.kind == registryUploadKind && id != operation.uploadID) {
		_ = response.Body.Close()
		http.Error(w, "registry returned an invalid upload location", http.StatusBadGateway)
		return false, false
	}
	if err := p.storeUpload(operation.repository, id, resolved); err != nil {
		_ = response.Body.Close()
		http.Error(w, "registry upload session capacity reached", http.StatusServiceUnavailable)
		return false, false
	}
	return true, true
}

func uploadLocationResponse(method string, operation registryOperation, status int) bool {
	if status != http.StatusAccepted {
		return false
	}
	if operation.kind == registryUploadInitKind {
		return true
	}
	return operation.kind == registryUploadKind && (method == http.MethodPatch || method == http.MethodGet || method == http.MethodHead)
}

func uploadCompleted(method string, operation registryOperation, status int) bool {
	if operation.kind != registryUploadKind {
		return false
	}
	return method == http.MethodPut && status >= 200 && status < 300 ||
		method == http.MethodDelete && (status == http.StatusNoContent || status == http.StatusAccepted)
}

func (p *PullProxy) writeForwardRegistryResponse(w http.ResponseWriter, method string, response *http.Response, validatedLocation bool) {
	if !validRegistryResponseStatus(response.StatusCode) {
		_ = response.Body.Close()
		http.Error(w, "registry returned an unsupported response", http.StatusBadGateway)
		return
	}
	if !validForwardBodyLength(p.maxBytes, method, response) {
		_ = response.Body.Close()
		http.Error(w, "registry response has unknown or excessive length", http.StatusBadGateway)
		return
	}
	copyForwardHeaders(w.Header(), response.Header, validatedLocation)
	if response.ContentLength >= 0 && method != http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	}
	w.WriteHeader(response.StatusCode)
	if responseBodyNotAllowed(method, response.StatusCode) {
		return
	}
	_, _ = io.CopyN(w, response.Body, response.ContentLength)
}

func validForwardBodyLength(maxBytes int64, method string, response *http.Response) bool {
	maxBody := maxRegistryErrorBody
	if response.StatusCode >= 200 && response.StatusCode < 300 && (method == http.MethodGet || method == http.MethodHead) {
		maxBody = maxBytes
	}
	return method == http.MethodHead || response.ContentLength >= 0 && response.ContentLength <= maxBody
}

func responseBodyNotAllowed(method string, status int) bool {
	return method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified
}

func validRegistryResponseStatus(status int) bool {
	return status >= 200 && status <= 599 && (status < 300 || status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusConflict || status == http.StatusRequestEntityTooLarge || status == http.StatusTooManyRequests || status >= 500)
}

func copyForwardHeaders(dst, src http.Header, redirect bool) {
	allowed := []string{"Content-Type", "Content-Encoding", "Content-Length", "Content-Range", "Docker-Content-Digest", "Docker-Distribution-Api-Version", "Docker-Upload-UUID", "ETag", "Last-Modified", "Range", "Retry-After"}
	if redirect {
		allowed = append(allowed, "Location")
	}
	for _, key := range allowed {
		for _, value := range src.Values(key) {
			dst.Add(key, value)
		}
	}
}

func (p *PullProxy) validateUploadLocation(current *url.URL, location, repository string) (*url.URL, string, error) {
	if strings.TrimSpace(location) == "" {
		return nil, "", errors.New("upload location is missing")
	}
	next, err := current.Parse(location)
	if err != nil || !validUploadLocationAuthority(next, p.authority) {
		return nil, "", errors.New("upload location authority is invalid")
	}
	id, ok := uploadIDFromLocationPath(next.Path, repository)
	if !ok {
		return nil, "", errors.New("upload location path is invalid")
	}
	if _, err := url.ParseQuery(next.RawQuery); err != nil {
		return nil, "", errors.New("upload location query is invalid")
	}
	return next, id, nil
}

func validUploadLocationAuthority(next *url.URL, authority string) bool {
	return next != nil && next.Scheme == registryHTTPScheme && next.User == nil && next.Fragment == "" &&
		next.Opaque == "" && strings.EqualFold(next.Host, authority) && next.RawPath == ""
}

func uploadIDFromLocationPath(path, repository string) (string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 6 || parts[0] != "" || parts[1] != "v2" || parts[len(parts)-3] != registryBlobPath ||
		parts[len(parts)-2] != registryUploadsPath || !validUploadID(parts[len(parts)-1]) {
		return "", false
	}
	if strings.Join(parts[2:len(parts)-3], "/") != repository {
		return "", false
	}
	return parts[len(parts)-1], true
}

func (p *PullProxy) storeUpload(repository, id string, location *url.URL) error {
	key := repository + "/" + id
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	now := time.Now()
	for current, session := range p.uploads {
		if !session.expiresAt.After(now) {
			delete(p.uploads, current)
		}
	}
	if _, exists := p.uploads[key]; !exists && len(p.uploads) >= maxUploadSessions {
		return errors.New("upload session cache is full")
	}
	copyURL := *location
	p.uploads[key] = uploadSession{registryHost: location.Host, repository: repository, id: id, location: &copyURL, expiresAt: now.Add(time.Hour)}
	return nil
}

func (p *PullProxy) removeUpload(repository, id string) {
	p.stateMu.Lock()
	delete(p.uploads, repository+"/"+id)
	p.stateMu.Unlock()
}

func (p *PullProxy) serveBlobRedirectRequest(w http.ResponseWriter, r *http.Request, host string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "blob redirect method is unsupported", http.StatusForbidden)
		return
	}
	if r.URL == nil || r.URL.Path == "" || r.URL.Opaque != "" || r.URL.Fragment != "" || r.URL.User != nil {
		http.Error(w, "invalid blob redirect URL", http.StatusBadRequest)
		return
	}
	endpoint := &url.URL{Scheme: registryHTTPScheme, Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	if !p.consumeBlobRedirect(endpoint) {
		http.Error(w, "blob redirect was not authorized by the registry", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if !p.limiter.acquire(ctx) {
		if r.Context().Err() != nil {
			return
		}
		writeRegistryBusy(w)
		return
	}
	defer p.limiter.release()
	response, err := p.fetchBlobRedirect(ctx, r, host)
	if err != nil {
		http.Error(w, "blob redirect request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	p.writeBlobRedirect(w, r.Method, response)
}

func (p *PullProxy) recordBlobRedirect(endpoint *url.URL) error {
	if endpoint == nil || !strings.EqualFold(endpoint.Scheme, registryHTTPScheme) || endpoint.User != nil || endpoint.Fragment != "" {
		return errors.New("invalid blob redirect session")
	}
	host, ok := normalizedRedirectHost(endpoint.Host)
	if !ok || !p.isRedirectHost(host) {
		return errors.New("invalid blob redirect session")
	}
	canonical := *endpoint
	canonical.Host = host
	key := canonical.String()
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.blobRedirects == nil {
		p.blobRedirects = make(map[string]blobRedirectSession)
	}
	now := time.Now()
	for current, session := range p.blobRedirects {
		if !session.expiresAt.After(now) || session.usesLeft <= 0 {
			delete(p.blobRedirects, current)
		}
	}
	if _, exists := p.blobRedirects[key]; !exists && len(p.blobRedirects) >= maxBlobRedirectSessions {
		return errors.New("blob redirect session cache is full")
	}
	p.blobRedirects[key] = blobRedirectSession{usesLeft: blobRedirectUses, expiresAt: now.Add(blobRedirectLifetime)}
	return nil
}

func (p *PullProxy) consumeBlobRedirect(endpoint *url.URL) bool {
	if endpoint == nil || !strings.EqualFold(endpoint.Scheme, registryHTTPScheme) || endpoint.User != nil || endpoint.Fragment != "" {
		return false
	}
	host, ok := normalizedRedirectHost(endpoint.Host)
	if !ok || !p.isRedirectHost(host) {
		return false
	}
	canonical := *endpoint
	canonical.Host = host
	key := canonical.String()
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	session, ok := p.blobRedirects[key]
	if !ok || !session.expiresAt.After(time.Now()) || session.usesLeft <= 0 {
		delete(p.blobRedirects, key)
		return false
	}
	session.usesLeft--
	if session.usesLeft == 0 {
		delete(p.blobRedirects, key)
	} else {
		p.blobRedirects[key] = session
	}
	return true
}

func (p *PullProxy) fetchBlobRedirect(ctx context.Context, r *http.Request, host string) (*http.Response, error) {
	if p.transportFactory == nil {
		return nil, errors.New("blob redirect transport factory is unavailable")
	}
	transport, err := p.transportFactory.Redirect(ctx, host)
	if err != nil {
		return nil, err
	}
	endpoint := &url.URL{Scheme: registryHTTPScheme, Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	request, err := http.NewRequestWithContext(ctx, r.Method, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client.Do(request) // #nosec G704 -- factory enforces configured host allowlisting with policy-checked DNS pins.
}

func (p *PullProxy) writeBlobRedirect(w http.ResponseWriter, method string, response *http.Response) {
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent && response.StatusCode != http.StatusNotFound {
		http.Error(w, "blob redirect response is unsupported", http.StatusBadGateway)
		return
	}
	if response.ContentLength < 0 || response.ContentLength > p.maxBytes {
		http.Error(w, "blob response exceeds supported limits", http.StatusBadGateway)
		return
	}
	copyForwardHeaders(w.Header(), response.Header, false)
	w.Header().Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	w.WriteHeader(response.StatusCode)
	if method == http.MethodGet {
		_, _ = io.CopyN(w, response.Body, response.ContentLength)
	}
}
