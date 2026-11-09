// Package mcpmanager owns the daemon's local stdio MCP registry and one-use
// approval challenges. Challenges are memory-only and never survive restart.
package mcpmanager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	core "github.com/rheic/sandboxes-core"

	"github.com/rheic/sandboxes-daemon/internal/mcpprocess"
	"github.com/rheic/sandboxes-daemon/internal/version"
)

const (
	maxArguments          = 1 << 20
	maxResult             = 4 << 20
	maxServers            = 128
	maxPending            = 128
	maxRegistryBytes      = 2 << 20
	maxExecutableBytes    = 256 << 20
	challengeTTL          = 2 * time.Minute
	callTimeout           = 30 * time.Second
	challengeRegistration = "register"
	challengeToolCall     = "call"

	registrySettingKey       = "mcp_stdio_servers_v1"
	registrySchemaSettingKey = "mcp_registry_schema_version"
	registrySchemaLegacy     = 1
	registrySchemaCurrent    = 3

	// ApprovalHeaderStatic marks a header whose configured value is stored as
	// non-secret static configuration.
	ApprovalHeaderStatic = "static"
	// ApprovalHeaderHostVault marks a header template resolved from the host
	// vault at request time.
	ApprovalHeaderHostVault = "host-vault"
)

// RegistrySettingKey names the persisted MCP registry setting.
const RegistrySettingKey = registrySettingKey

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// State persists only host command metadata. It must be backed by the daemon's
// private state database; no approvals or call arguments are persisted.
type State interface {
	GetSetting(context.Context, string) (string, error)
	SetSetting(context.Context, string, string) error
}

type registryMigrationFinalizer interface {
	FinalizeMCPRegistryMigration(context.Context) error
	CheckpointTruncate(context.Context) error
}

// ApprovalProvider obtains consent through a daemon-trusted host UI or OS
// authorization service. An RPC field, challenge ID, CLI prompt, or caller
// identity alone must never implement this interface.
type ApprovalProvider interface {
	Approve(context.Context, ApprovalRequest) error
}

type ApprovalRequest struct {
	Action     string
	ServerName string
	Command    string
	// URL is the normalized remote destination. It is empty for stdio servers.
	URL string
	// Headers describes remote header names and value classes without values.
	// References contains only host-vault placeholder identifiers.
	Headers           []ApprovalHeader
	ArgumentCount     int
	Directory         string
	SandboxID         string
	ToolName          string
	ToolArgumentKeys  []string
	ToolArgumentBytes int
}

// ApprovalHeader is value-free scope metadata for one remote MCP header.
// Static headers carry no references; host-vault headers list the vault
// placeholder identifiers that will be resolved after approval.
type ApprovalHeader struct {
	Name       string
	ValueClass string
	References []string
}
type Server struct {
	Name             string   `json:"name"`
	Transport        string   `json:"transport,omitempty"`
	Command          string   `json:"command,omitempty"`
	Arguments        []string `json:"arguments,omitempty"`
	Directory        string   `json:"directory,omitempty"`
	ExecutableSHA256 string   `json:"executable_sha256,omitempty"`
	URL              string   `json:"url,omitempty"`
	// Headers is a legacy persisted field retained only for forward migration.
	// New registrations reject static header values.
	Headers map[string]string `json:"headers,omitempty"`
	// SecretHeaders contains only vault placeholder templates, never values.
	SecretHeaders map[string]string `json:"secret_headers,omitempty"`
}
type Summary struct {
	Name      string
	Transport string
	Loaded    bool
	Usable    bool
}
type challenge struct {
	kind          string
	expires       time.Time
	server        Server
	sandbox, tool string
	arguments     json.RawMessage
}
type Manager struct {
	state    State
	approver ApprovalProvider
	now      func() time.Time
	mu       sync.Mutex
	servers  map[string]Server
	pending  map[string]challenge
	sessions map[string]*managedSession
	starting map[string]chan struct{}
	closed   bool
	// remoteHosts is the exact allowlist of host names for remote MCP
	// servers; empty disables the transport (fail closed).
	remoteHosts map[string]struct{}
	// remoteTLSConfig overrides the TLS root store for remote MCP dials;
	// nil selects the system trust store. Intended for controlled tests.
	remoteTLSConfig *tls.Config
	remoteLookup    func(context.Context, string, string) ([]netip.Addr, error)
	remoteDial      func(context.Context, string, string) (net.Conn, error)
	remoteSecrets   RemoteSecretResolver
}

// RemoteSecretResolver resolves one MCP header placeholder from the host vault.
// Implementations must return only the requested secret and redact errors.
type RemoteSecretResolver func(context.Context, string, string) ([]byte, error)

// SetRemoteSecretResolver configures host-side lookup for remote MCP headers.
func (m *Manager) SetRemoteSecretResolver(resolver RemoteSecretResolver) {
	m.mu.Lock()
	m.remoteSecrets = resolver
	m.mu.Unlock()
}

func (m *Manager) SetApprovalProvider(provider ApprovalProvider) {
	m.mu.Lock()
	m.approver = provider
	m.mu.Unlock()
}

type managedSession struct {
	mu      sync.Mutex
	process *mcpprocess.Process
	session *mcp.ClientSession
	broken  bool
}

func New(ctx context.Context, state State) (*Manager, error) {
	m := &Manager{state: state, now: time.Now, servers: make(map[string]Server), pending: make(map[string]challenge), sessions: make(map[string]*managedSession), starting: make(map[string]chan struct{})}
	items, err := loadRegistry(ctx, state)
	if err != nil {
		return nil, err
	}
	if len(items) > maxServers {
		return nil, errors.New("MCP registry exceeds the server limit")
	}
	for i := range items {
		if validateStoredServer(items[i]) != nil {
			return nil, errors.New("MCP registry entry is invalid")
		}
		if _, duplicate := m.servers[items[i].Name]; duplicate {
			return nil, errors.New("MCP registry has duplicate server names")
		}
		m.servers[items[i].Name] = items[i]
	}
	return m, nil
}

// loadRegistry applies the forward-only registry schema migration before any
// RPC is served. All remote records lose static Headers because the daemon
// cannot determine whether a value is a credential. All other record fields
// and settings are preserved. The sanitized registry is written before the
// schema marker; failure aborts startup (fail closed).
func loadRegistry(ctx context.Context, state State) ([]Server, error) {
	raw, items, err := readRegistrySetting(ctx, state)
	if err != nil {
		return nil, err
	}
	schema, err := registrySchemaVersion(ctx, state)
	if err != nil {
		return nil, err
	}
	if schema > registrySchemaCurrent {
		return nil, errors.New("MCP registry schema is newer than this daemon supports")
	}
	if schema == registrySchemaCurrent {
		if err := checkpointRegistryMigration(ctx, state); err != nil {
			return nil, err
		}
		return items, nil
	}
	if migrateLegacyRemoteHeaders(items) && raw != "" {
		sanitized, err := json.Marshal(items)
		if err != nil {
			return nil, errors.New("MCP registry migration failed")
		}
		if err := state.SetSetting(ctx, registrySettingKey, string(sanitized)); err != nil {
			return nil, errors.New("MCP registry migration could not be persisted")
		}
	}
	if err := finalizeRegistryMigration(ctx, state); err != nil {
		return nil, err
	}
	if err := state.SetSetting(ctx, registrySchemaSettingKey, strconv.Itoa(registrySchemaCurrent)); err != nil {
		return nil, errors.New("MCP registry schema could not be persisted")
	}
	if err := checkpointRegistryMigration(ctx, state); err != nil {
		return nil, err
	}
	return items, nil
}

func readRegistrySetting(ctx context.Context, state State) (string, []Server, error) {
	raw, err := state.GetSetting(ctx, registrySettingKey)
	if errors.Is(err, core.ErrNotFound) {
		err = nil
		raw = ""
	}
	if err != nil {
		return "", nil, err
	}
	if len(raw) > maxRegistryBytes {
		return "", nil, errors.New("MCP registry exceeds the storage limit")
	}
	var items []Server
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &items); err != nil {
			return "", nil, errors.New("MCP registry state is invalid")
		}
	}
	return raw, items, nil
}

func finalizeRegistryMigration(ctx context.Context, state State) error {
	finalizer, ok := state.(registryMigrationFinalizer)
	if !ok {
		return nil
	}
	if err := finalizer.FinalizeMCPRegistryMigration(ctx); err != nil {
		return errors.New("MCP registry migration could not securely finalize storage")
	}
	return nil
}

func checkpointRegistryMigration(ctx context.Context, state State) error {
	finalizer, ok := state.(registryMigrationFinalizer)
	if !ok {
		return nil
	}
	if err := finalizer.CheckpointTruncate(ctx); err != nil {
		return errors.New("MCP registry WAL checkpoint failed")
	}
	return nil
}

func registrySchemaVersion(ctx context.Context, state State) (int, error) {
	raw, err := state.GetSetting(ctx, registrySchemaSettingKey)
	if errors.Is(err, core.ErrNotFound) {
		return registrySchemaLegacy, nil
	}
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(raw) == "" {
		return registrySchemaLegacy, nil
	}
	schemaVersion, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || schemaVersion < registrySchemaLegacy {
		return 0, errors.New("MCP registry schema is invalid")
	}
	return schemaVersion, nil
}

// migrateLegacyRemoteHeaders removes every legacy static header map from
// remote records. Header names and values are deliberately not logged.
func migrateLegacyRemoteHeaders(items []Server) bool {
	changed := false
	for index := range items {
		if items[index].Transport != transportRemote || len(items[index].Headers) == 0 {
			continue
		}
		items[index].Headers = nil
		changed = true
	}
	return changed
}

// SanitizeRegistrySetting removes legacy remote static Headers from a
// serialized registry value. It is used for pre-upgrade database backups,
// never logs or returns header names/values, and leaves already-sanitized data
// byte-identical.
func SanitizeRegistrySetting(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return raw, nil
	}
	var items []Server
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return "", errors.New("MCP registry backup state is invalid")
	}
	if !migrateLegacyRemoteHeaders(items) {
		return raw, nil
	}
	sanitized, err := json.Marshal(items)
	if err != nil {
		return "", errors.New("MCP registry backup migration failed")
	}
	return string(sanitized), nil
}

func (m *Manager) Register(ctx context.Context, name, command string, args []string, dir string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	server, err := prepareServer(name, command, args, dir)
	if err != nil {
		return "", err
	}
	return m.registerPrepared(ctx, server)
}

func (m *Manager) registerPrepared(ctx context.Context, server Server) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", errors.New("MCP manager is closed")
	}
	m.expireLocked()
	if len(m.pending) >= maxPending || len(m.servers) >= maxServers {
		return "", errors.New("MCP registry is at capacity")
	}
	if _, ok := m.servers[server.Name]; ok {
		return "", errors.New("MCP server name already exists")
	}
	for pendingID := range m.pending {
		candidate := m.pending[pendingID]
		if candidate.kind == challengeRegistration && candidate.server.Name == server.Name {
			return "", errors.New("MCP server name already has a pending registration")
		}
	}
	id, err := token()
	if err != nil {
		return "", err
	}
	m.pending[id] = challenge{kind: challengeRegistration, expires: m.now().Add(challengeTTL), server: cloneServer(server)}
	return id, nil
}
func (m *Manager) ApproveRegistration(ctx context.Context, id string) (*Summary, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("MCP manager is closed")
	}
	p, ok := m.pending[id]
	if !ok || p.kind != challengeRegistration {
		m.mu.Unlock()
		return nil, errors.New("MCP approval challenge is invalid or expired")
	}
	delete(m.pending, id)
	m.mu.Unlock()
	if !m.now().Before(p.expires) {
		return nil, errors.New("MCP approval challenge expired")
	}
	m.mu.Lock()
	approver := m.approver
	m.mu.Unlock()
	if approver == nil {
		return nil, errors.New("trusted MCP host approval provider is unavailable")
	}
	destination, headers, err := approvalScope(p.server)
	if err != nil {
		return nil, err
	}
	if err := approver.Approve(ctx, ApprovalRequest{Action: "register", ServerName: p.server.Name, Command: p.server.Command, URL: destination, Headers: headers, ArgumentCount: len(p.server.Arguments), Directory: p.server.Directory}); err != nil {
		return nil, errors.New("MCP registration was denied or trusted approval failed")
	}
	if err := m.verifyServer(p.server); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("MCP manager is closed")
	}
	if _, exists := m.servers[p.server.Name]; exists {
		return nil, errors.New("MCP server name already exists")
	}
	if len(m.servers) >= maxServers {
		return nil, errors.New("MCP registry is at capacity")
	}
	m.servers[p.server.Name] = cloneServer(p.server)
	if err := m.persist(ctx); err != nil {
		delete(m.servers, p.server.Name)
		return nil, err
	}
	return &Summary{Name: p.server.Name}, nil
}
func (m *Manager) List() []Summary {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Summary, 0, len(m.servers))
	for name := range m.servers {
		server := m.servers[name]
		_, loaded := m.sessions[name]
		result = append(result, Summary{Name: name, Transport: serverTransport(server), Loaded: loaded, Usable: m.serverUsableLocked(server)})
	}
	slicesSort(result)
	return result
}
func (m *Manager) Remove(ctx context.Context, name string) (bool, error) {
	m.mu.Lock()
	if _, ok := m.servers[name]; !ok {
		m.mu.Unlock()
		return false, nil
	}
	deleted := m.servers[name]
	delete(m.servers, name)
	if err := m.persist(ctx); err != nil {
		m.servers[name] = deleted
		m.mu.Unlock()
		return false, err
	}
	session := m.sessions[name]
	delete(m.sessions, name)
	m.mu.Unlock()
	if session != nil {
		if err := session.close(); err != nil {
			return false, err
		}
	}
	return true, nil
}
func (m *Manager) RequestCall(sandbox, server, tool string, raw json.RawMessage) (string, error) {
	if sandbox == "" || server == "" || tool == "" {
		return "", errors.New("sandbox, server, and tool are required")
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > maxArguments {
		return "", errors.New("MCP arguments exceed 1 MiB")
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil || args == nil {
		return "", errors.New("MCP arguments must be a JSON object")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", errors.New("MCP manager is closed")
	}
	m.expireLocked()
	cfg, ok := m.servers[server]
	if !ok {
		return "", errors.New("MCP server is not registered")
	}
	if len(m.pending) >= maxPending {
		return "", errors.New("MCP approvals are at capacity")
	}
	id, err := token()
	if err != nil {
		return "", err
	}
	m.pending[id] = challenge{kind: challengeToolCall, expires: m.now().Add(challengeTTL), server: cloneServer(cfg), sandbox: sandbox, tool: tool, arguments: append(json.RawMessage(nil), raw...)}
	return id, nil
}
func (m *Manager) ApproveCall(ctx context.Context, id string, validateSandbox func(context.Context, string) error) (json.RawMessage, error) {
	m.mu.Lock()
	p, ok := m.pending[id]
	if ok {
		delete(m.pending, id)
	}
	registered, registeredOK := m.servers[p.server.Name]
	m.mu.Unlock()
	if !ok || p.kind != challengeToolCall {
		return nil, errors.New("MCP approval challenge is invalid or expired")
	}
	if !registeredOK || !sameServer(registered, p.server) {
		return nil, errors.New("MCP server registration changed after approval was requested")
	}
	if !m.now().Before(p.expires) {
		return nil, errors.New("MCP approval challenge expired")
	}
	if validateSandbox == nil {
		return nil, errors.New("MCP sandbox validation is unavailable")
	}
	if err := validateSandbox(ctx, p.sandbox); err != nil {
		return nil, errors.New("sandbox is no longer available for MCP")
	}
	m.mu.Lock()
	approver := m.approver
	m.mu.Unlock()
	if approver == nil {
		return nil, errors.New("trusted MCP host approval provider is unavailable")
	}
	if err := m.approveCallScope(ctx, p, approver); err != nil {
		return nil, err
	}
	if err := validateSandbox(ctx, p.sandbox); err != nil {
		return nil, errors.New("sandbox is no longer available for MCP")
	}
	return m.execute(ctx, p.server, p.tool, p.arguments)
}

// approveCallScope presents the exact call scope to the trusted provider and
// revalidates it after the provider returns. The check binds approval to the
// destination and header configuration captured at challenge creation.
func (m *Manager) approveCallScope(ctx context.Context, p challenge, approver ApprovalProvider) error {
	argumentKeys, err := jsonObjectKeys(p.arguments)
	if err != nil {
		return errors.New("MCP tool arguments are invalid")
	}
	destination, headers, err := approvalScope(p.server)
	if err != nil {
		return err
	}
	if err := approver.Approve(ctx, ApprovalRequest{
		Action: "call", ServerName: p.server.Name, Command: p.server.Command,
		URL: destination, Headers: headers,
		ArgumentCount: len(p.server.Arguments), Directory: p.server.Directory,
		SandboxID: p.sandbox, ToolName: p.tool, ToolArgumentKeys: argumentKeys,
		ToolArgumentBytes: len(p.arguments),
	}); err != nil {
		return errors.New("MCP tool call was denied or trusted approval failed")
	}
	if m.serverRegistrationChanged(p.server) {
		return errors.New("MCP server registration changed after approval")
	}
	return m.verifyServer(p.server)
}

func (m *Manager) serverRegistrationChanged(server Server) bool {
	m.mu.Lock()
	current, registered := m.servers[server.Name]
	m.mu.Unlock()
	return !registered || !sameServer(current, server)
}

func jsonObjectKeys(raw json.RawMessage) ([]string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("MCP arguments must be a JSON object")
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys, nil
}

// Close terminates and reaps every host stdio process owned by this manager.
func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	starts := make([]chan struct{}, 0, len(m.starting))
	for _, started := range m.starting {
		starts = append(starts, started)
	}
	m.mu.Unlock()
	for _, started := range starts {
		<-started
	}
	m.mu.Lock()
	sessions := make([]*managedSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[string]*managedSession)
	m.mu.Unlock()
	var result error
	for _, session := range sessions {
		result = errors.Join(result, session.close())
	}
	return result
}

func sameServer(left, right Server) bool {
	return left.Name == right.Name && left.Transport == right.Transport && left.Command == right.Command && left.Directory == right.Directory &&
		left.ExecutableSHA256 == right.ExecutableSHA256 && left.URL == right.URL &&
		slices.Equal(left.Arguments, right.Arguments) && maps.Equal(left.Headers, right.Headers) && maps.Equal(left.SecretHeaders, right.SecretHeaders)
}

// cloneServer takes a deep snapshot of mutable server fields so a pending
// challenge cannot alias the live registry through a shared map or slice.
func cloneServer(server Server) Server {
	server.Arguments = slices.Clone(server.Arguments)
	server.Headers = maps.Clone(server.Headers)
	server.SecretHeaders = maps.Clone(server.SecretHeaders)
	return server
}
func (m *Manager) expireLocked() {
	now := m.now()
	for id := range m.pending {
		if !now.Before(m.pending[id].expires) {
			delete(m.pending, id)
		}
	}
}
func (m *Manager) persist(ctx context.Context) error {
	items := make([]Server, 0, len(m.servers))
	for name := range m.servers {
		items = append(items, m.servers[name])
	}
	slicesSortServers(items)
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return m.state.SetSetting(ctx, "mcp_stdio_servers_v1", string(raw))
}
func prepareServer(name, command string, args []string, dir string) (Server, error) {
	if err := validateRegistrationInput(name, command, args, dir); err != nil {
		return Server{}, err
	}
	resolved, hash, err := resolveExecutable(command)
	if err != nil {
		return Server{}, err
	}
	resolvedDir, err := resolveWorkingDirectory(dir)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name, Command: resolved, Arguments: append([]string(nil), args...), Directory: resolvedDir, ExecutableSHA256: hash}, nil
}

func validateRegistrationInput(name, command string, args []string, dir string) error {
	if !namePattern.MatchString(name) {
		return errors.New("invalid MCP server name")
	}
	if !filepath.IsAbs(command) || !filepath.IsAbs(dir) {
		return errors.New("MCP executable and working directory must be absolute paths")
	}
	if len(args) > 64 {
		return errors.New("MCP server allows at most 64 arguments")
	}
	total := len(name) + len(command) + len(dir)
	for _, arg := range args {
		total += len(arg)
		key, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		key = strings.ToLower(key)
		if credentialOption(key) {
			return errors.New("MCP command arguments cannot contain credential options; MCP credential injection is not implemented")
		}
	}
	if total > 16<<10 {
		return errors.New("MCP registration exceeds 16 KiB")
	}
	return nil
}

func resolveExecutable(command string) (string, string, error) {
	resolved, err := filepath.EvalSymlinks(command)
	if err != nil {
		return "", "", errors.New("MCP executable cannot be resolved")
	}
	info, err := os.Stat(resolved)
	if err != nil || !isMCPExecutable(resolved, info) || info.Size() <= 0 || info.Size() > maxExecutableBytes {
		return "", "", errors.New("MCP executable must be a regular executable file")
	}
	hash, err := fileHash(resolved)
	if err != nil {
		return "", "", errors.New("MCP executable identity could not be read")
	}
	return resolved, hash, nil
}

func resolveWorkingDirectory(dir string) (string, error) {
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", errors.New("MCP working directory cannot be resolved")
	}
	dinfo, err := os.Stat(resolvedDir)
	if err != nil || !dinfo.IsDir() {
		return "", errors.New("MCP working directory is not a directory")
	}
	return resolvedDir, nil
}
func verifyExecutable(s Server) error {
	info, err := os.Lstat(s.Command)
	if err != nil || !isMCPExecutable(s.Command, info) {
		return errors.New("registered MCP executable is unavailable or no longer a regular file")
	}
	hash, err := fileHash(s.Command)
	if err != nil || hash != s.ExecutableSHA256 {
		return errors.New("registered MCP executable changed after approval")
	}
	dir, err := os.Stat(s.Directory)
	if err != nil || !dir.IsDir() {
		return errors.New("registered MCP working directory is unavailable")
	}
	return nil
}

func executableAvailable(s Server) bool {
	info, err := os.Lstat(s.Command)
	if err != nil || !isMCPExecutable(s.Command, info) {
		return false
	}
	dir, err := os.Lstat(s.Directory)
	return err == nil && dir.IsDir()
}

func validateStoredServer(s Server) error {
	if !namePattern.MatchString(s.Name) || len(s.Arguments) > 64 {
		return errors.New("invalid MCP registry entry")
	}
	switch s.Transport {
	case transportRemote:
		return validateStoredRemoteServer(s)
	case "":
		return validateStoredStdioServer(s)
	default:
		return errors.New("invalid MCP registry entry")
	}
}

func validateStoredRemoteServer(s Server) error {
	if s.Command != "" || s.URL == "" || s.ExecutableSHA256 != "" {
		return errors.New("invalid remote MCP registry entry")
	}
	if _, err := copiedRemoteHeaders(s.Headers, s.SecretHeaders); err != nil {
		return errors.New("invalid remote MCP registry entry")
	}
	return nil
}

func validateStoredStdioServer(s Server) error {
	if !filepath.IsAbs(s.Command) || !filepath.IsAbs(s.Directory) {
		return errors.New("invalid MCP registry entry")
	}
	if len(s.ExecutableSHA256) != sha256.Size*2 {
		return errors.New("invalid MCP executable identity")
	}
	if _, err := hex.DecodeString(s.ExecutableSHA256); err != nil {
		return errors.New("invalid MCP executable identity")
	}
	total := len(s.Name) + len(s.Command) + len(s.Directory)
	for _, arg := range s.Arguments {
		total += len(arg)
		key, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if credentialOption(strings.ToLower(key)) {
			return errors.New("MCP registry contains credential-bearing arguments")
		}
	}
	if total > 16<<10 {
		return errors.New("MCP registry entry exceeds limit")
	}
	return nil
}

func credentialOption(key string) bool {
	for _, sensitive := range []string{"token", "secret", "password", "credential", "api-key", "apikey", "authorization"} {
		if strings.Contains(key, sensitive) {
			return true
		}
	}
	return false
}

func fileHash(path string) (digest string, resultErr error) {
	// #nosec G304 -- caller passes the canonical host executable recorded for an approved MCP server.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxExecutableBytes {
		return "", errors.New("MCP executable is outside the allowed size range")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func token() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (m *Manager) execute(ctx context.Context, s Server, tool string, raw json.RawMessage) (json.RawMessage, error) {
	if err := m.verifyServer(s); err != nil {
		return nil, err
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil || args == nil {
		return nil, errors.New("MCP arguments are invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	managed, err := m.sessionForCall(ctx, s)
	if err != nil {
		return nil, err
	}
	result, err := managed.session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		managed.broken = true
	}
	managed.mu.Unlock()
	if err != nil {
		cleanupErr := m.dropSession(s.Name, managed)
		return nil, errors.Join(fmt.Errorf("MCP tool call failed: %w", err), cleanupErr)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, errors.New("MCP result is not valid JSON")
	}
	if len(encoded) > maxResult {
		return nil, errors.New("MCP tool result exceeds 4 MiB")
	}
	return encoded, nil
}

// sessionForCall returns a connected, serialized MCP session with its mutex
// held. It does not hold the registry lock during process startup or IO.
func (m *Manager) sessionForCall(ctx context.Context, server Server) (*managedSession, error) {
	for {
		session, waiting, starting, err := m.findSession(server)
		if err != nil {
			return nil, err
		}
		if session != nil {
			return session, nil
		}
		if waiting != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-waiting:
				continue
			}
		}
		if starting != nil {
			return m.startAndPublish(ctx, server, starting)
		}
	}
}

func (m *Manager) findSession(server Server) (*managedSession, <-chan struct{}, chan struct{}, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, nil, nil, errors.New("MCP manager is closed")
	}
	current, registered := m.servers[server.Name]
	if !registered || !sameServer(current, server) {
		m.mu.Unlock()
		return nil, nil, nil, errors.New("MCP server registration changed before process start")
	}
	if session := m.sessions[server.Name]; session != nil {
		session.mu.Lock()
		m.mu.Unlock()
		if !session.broken {
			return session, nil, nil, nil
		}
		session.mu.Unlock()
		if err := m.dropSession(server.Name, session); err != nil {
			return nil, nil, nil, errors.New("MCP process cleanup failed")
		}
		return nil, nil, nil, nil
	}
	if waiting := m.starting[server.Name]; waiting != nil {
		m.mu.Unlock()
		return nil, waiting, nil, nil
	}
	starting := make(chan struct{})
	m.starting[server.Name] = starting
	m.mu.Unlock()
	return nil, nil, starting, nil
}

func (m *Manager) startAndPublish(ctx context.Context, server Server, starting chan struct{}) (*managedSession, error) {
	session, startErr := m.startSession(ctx, server)
	m.mu.Lock()
	delete(m.starting, server.Name)
	current, registered := m.servers[server.Name]
	if startErr == nil && !m.closed && registered && sameServer(current, server) {
		m.sessions[server.Name] = session
		session.mu.Lock()
		close(starting)
		m.mu.Unlock()
		return session, nil
	}
	m.mu.Unlock()
	var closeErr error
	if session != nil {
		closeErr = session.close()
	}
	m.mu.Lock()
	close(starting)
	m.mu.Unlock()
	if startErr != nil {
		return nil, errors.New("MCP server initialization failed")
	}
	if closeErr != nil {
		return nil, errors.New("MCP process cleanup failed")
	}
	return nil, errors.New("MCP server registration changed during startup")
}

func (m *Manager) startSession(ctx context.Context, server Server) (*managedSession, error) {
	if err := m.verifyServer(server); err != nil {
		return nil, err
	}
	if server.Transport == transportRemote {
		return m.startRemoteSession(ctx, server)
	}
	process, err := mcpprocess.Start(server.Command, server.Arguments, server.Directory, restrictedEnvironment())
	if err != nil {
		return nil, errors.New("MCP server could not be started")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "rheic-daemon", Version: version.Version}, nil)
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: process.Stdout, Writer: process.Stdin, MaxLineLength: 5 << 20}, nil)
	if err != nil {
		_ = process.Close()
		return nil, err
	}
	return &managedSession{process: process, session: session}, nil
}

func (s *managedSession) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var result error
	if s.session != nil {
		if err := s.session.Close(); err != nil {
			result = errors.Join(result, errors.New("MCP session cleanup failed"))
		}
		s.session = nil
	}
	if s.process != nil {
		if err := s.process.Close(); err != nil {
			result = errors.Join(result, errors.New("MCP process cleanup failed"))
		}
		s.process = nil
	}
	return result
}

func (m *Manager) dropSession(name string, session *managedSession) error {
	m.mu.Lock()
	if m.sessions[name] == session {
		delete(m.sessions, name)
	}
	m.mu.Unlock()
	return session.close()
}
func restrictedEnvironment() []string {
	if os.PathSeparator == '\\' {
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		temporary := os.TempDir()
		return []string{"SystemRoot=" + systemRoot, "PATH=" + filepath.Join(systemRoot, "System32"), "TEMP=" + temporary, "TMP=" + temporary}
	}
	return []string{"PATH=/usr/bin:/bin", "HOME=" + os.TempDir()}
}
func slicesSort(items []Summary) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Name < items[j-1].Name; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
func slicesSortServers(items []Server) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Name < items[j-1].Name; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// verifyServer applies the transport-specific registration checks: executable
// integrity for local stdio servers, host-allowlist policy for remote servers.
func (m *Manager) verifyServer(s Server) error {
	if s.Transport == transportRemote {
		return m.verifyRemoteServer(s)
	}
	return verifyExecutable(s)
}

// serverTransport reports the user-facing transport name for a registration.
func serverTransport(s Server) string {
	if s.Transport == transportRemote {
		return "remote"
	}
	return "stdio"
}

// serverUsableLocked reports whether a session can currently be established.
func (m *Manager) serverUsableLocked(s Server) bool {
	if s.Transport == transportRemote {
		host, err := remoteServerHost(s.URL)
		return err == nil && m.remoteHostAllowedLocked(host)
	}
	return executableAvailable(s)
}
