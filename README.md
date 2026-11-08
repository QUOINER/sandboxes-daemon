# sandboxes-daemon

## Import path migration

The canonical Go module path is now `github.com/rheic/sandboxes-daemon` (previously `github.com/quoiner/sandboxes-daemon`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

Policy updates use atomic single-rule mutations. The legacy whole-policy
replacement RPC is rejected to prevent stale clients from restoring revoked
rules; clients must upgrade with the coordinated API and SDK release.

Status: pre-alpha.

Local control plane. Owns the operation journal, reconciliation, SQLite store,
local API, and supervision of runtime and gateway processes.

## Boundaries

- secrets are not stored in plaintext;
- SQL transactions are not held across VM or network I/O;
- partial failures never report success.
- registry and service secrets use the host OS credential vault and are never written to SQLite;
- domain egress rules are resolved through the configured upstream and fail closed.

## Run

```sh
go run ./cmd/sandboxesd \
  --state "$HOME/.sandboxes" \
  --socket "$HOME/.sandboxes/sandboxesd.sock"
```

The daemon owns `sandboxes.db` and exposes a local gRPC socket with `0600`
permissions. It refuses to start when the socket path already exists; stale
paths are not removed automatically because their ownership is unverified.
The daemon also holds a state-directory lock while running; a second cooperating
daemon using that state directory fails to start. The lock file is retained.

Runtime mode is explicit:

```sh
# state-only default
sandboxesd --state "$HOME/.sandboxes"

# containerd/nerdbox backend
sandboxesd --state "$HOME/.sandboxes" \
  --containerd "$HOME/.sandboxes/containerd/containerd.sock" \
  --gvproxy "$HOME/.sandboxes/bin/gvproxy-policy-v2" \
  --dns-upstream 1.1.1.1:53 \
  --image docker.io/library/alpine:3.22
```

`--settings` defaults to `~/.config/rheic/settings.toml`. Supported overrides
are `dns_upstream`, `default_policy_profile`, `default_cpus`,
`default_memory_mib`, `docker_volume_size` and `mcp_remote_allowed_hosts`. The
last is a comma-separated exact DNS host allowlist for remote MCP, for example
`mcp_remote_allowed_hosts = "mcp.example.com,api.example.com"`; wildcards and
IP literals are rejected, and an empty value disables remote MCP. The file is
strict, mode-checked and never contains secrets. Settings need a daemon restart
to take effect; new sandboxes use the policy profile and resource defaults.

Service proxy references require the matching static guest helper artifact.
Build it with `make build-proxy-helper` and pass
`--proxy-helper ./bin/rheic-proxy-helper-linux-arm64` to `sandboxesd`. The
daemon accepts only a static Linux ARM64 ELF helper. If the helper is absent,
`${proxy:service}` fails closed. Proxy-enabled sandboxes currently support one
service per sandbox.

Empty `--containerd` keeps the state-only control plane. With a runtime backend,
create/start/stop/delete call the runtime adapter. With `--gvproxy`, the daemon
also starts a default-deny gateway and attaches nerdbox network annotations;
exec/PTY still remain unsupported.

`RegistryCredentialService` stores registry login entries in macOS Keychain,
Windows Credential Manager, or Linux Secret Service. It fails closed when the
native vault is unavailable and has no plaintext fallback. Credential scopes
are persisted separately. Saving a credential does not verify it with the
registry. A scoped host broker routes private Docker Hub pulls and pushes from
guest Docker through a per-sandbox TLS forward proxy; host-only entries are
excluded. The guest receives only a synthetic, repository/action-scoped token.
The real registry token is acquired by the host for each request and is never
forwarded to the guest. Upload cancellation is allowed only for a session
created through that proxy; manifest/blob deletion and cross-host upload
locations are denied. Other registries and live VM pull/push acceptance remain
unsupported or unverified.

`SecretService` stores service API keys (`openai`, `anthropic`, `github`, ...)
in the host vault, scoped globally or to one sandbox. Values are held in memory
only for the RPC and are never returned by `List`. A non-secret SQLite index
supports listing and sandbox-scoped cleanup; the value itself never enters the
database, logs, argv or sandbox snapshots. Guest-visible
`${secret:service}` references are rejected: environment values are readable
by guest processes and do not preserve the host credential boundary. Use a
supported host proxy reference instead. Existing scripts using
`${secret:service}` must migrate before upgrading; the daemon fails closed and
does not pass the reference or credential to the guest. The
`${proxy:service}` Create/Start/exec path is implemented on the current feature
branches and remains **unreleased and pending verification**. It requires
`--proxy-helper` and a supported provider credential variable; the guest image
does not need `/bin/sh`. The guest gets a placeholder and provider base URL; the host broker reads
the real value from the vault and checks sandbox network policy on each request.
The broker refuses to replace an existing socket path and requires a private
parent directory owned by the daemon user. The value is not written to SQLite
or sandbox metadata.

Service records can also hold a fixed `op://` or AWS Secrets Manager reference,
or an explicitly supplied host-shell command. The daemon resolves these sources
only when the proxy needs a credential, caches successful values according to
the source refresh policy, and keeps source text and resolved values out of
SQLite and guest state. Host commands run as the daemon user and are not
confined from host files; use only trusted commands and keep their helpers and
the temporary directory outside writable sandbox mounts. The implementation
is on an unpublished feature branch and has not received provider/runtime or
independent security review.

Global network rules are stored as daemon settings, merged with each sandbox's
explicit rules at gateway start/update, and re-applied to running sandboxes on
mutation. Deny wins across scopes. Domain rules require `--dns-upstream` and a
pinned gvproxy build; the gateway rejects domain rules without it.

The account RPC runs trusted daemon-configured OAuth only. On Docker Hub device
login it exchanges the returned access token for a Hub PAT, stores access and
refresh tokens in the native vault, stores the PAT under separate host-only and
all-sandboxes registry scopes, and records a non-authenticating fingerprint so
logout removes only credentials created by that account flow. Existing registry
entries are not overwritten. Docker account login uses the Docker public
device-flow client ID embedded in Docker CLI and the installed Docker
Sandboxes `sbx` binary. No Rheic OAuth registration is needed. Browser launch
is supported on macOS; other platforms return unsupported.

## Policy sync client (internal preview)

`internal/policysync` contains a daemon-internal client for the self-hosted
control plane. It fetches `GET /v1/orgs/{org}/policy` over TLS with a bearer
credential and a pinned Ed25519 public key, re-verifies the canonical bundle
signature locally (server-side verification is not trusted), rejects expired
bundles and revision rollbacks, and stores only verified bundles in the
`org_policy_bundles` SQLite table. The schema migration is forward-only and
creates a pre-upgrade backup; network, TLS, signature, expiry and revision
failures fail closed and leave the previous bundle intact.

The client is not wired into the CLI, local API or SDK yet; that product wiring
is a separate slice. Multi-tenancy, applying synced policy to sandboxes,
offline last-known-good behavior and audit SIEM export remain out of scope for
this preview. The table stores policy metadata and signatures only, never
sandbox secrets.
