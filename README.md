# sandboxes-daemon

![Rheic blue shark logo](docs/assets/rheic-shark.png)


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

# daemon-owned containerd/nerdbox backend
sandboxesd --state "$HOME/.sandboxes" \
  --containerd "/absolute/path/to/containerd" \
  --ctr "/absolute/path/to/ctr" \
  --runtime-dir "/absolute/path/to/runtime/bin" \
  --runtime-assets "/absolute/path/to/runtime/assets" \
  --gvproxy "$HOME/.sandboxes/bin/gvproxy-policy-v2" \
  --dns-upstream 1.1.1.1:53 \
  --image docker.io/library/alpine:3.22
```

`--settings` defaults to `~/.config/rheic/settings.toml`. Supported overrides
are `dns_upstream`, `default_policy_profile`, `default_cpus`,
`default_memory_mib`, `docker_volume_size`, `mcp_remote_allowed_hosts`,
`org_policy.enforce`, `org_policy.org` and the optional `policy_sync.*` block
documented under [Policy sync](#policy-sync-opt-in-background-sync). The MCP
value is a comma-separated exact DNS host allowlist, for example
`mcp_remote_allowed_hosts = "mcp.example.com,api.example.com"`; wildcards and
IP literals are rejected, and an empty value disables remote MCP. The file is
strict, mode-checked and never contains secrets. Settings need a daemon restart
to take effect; new sandboxes use the policy profile and resource defaults.

All remote MCP headers must use host-vault placeholder templates. Static header
values are rejected because custom names cannot establish whether a value is a
credential. Only `${placeholder}` references are persisted and resolved at
request time. Remote hosts still require exact allowlist entries, and redirects
are refused.

Trusted registration and per-call approvals receive the normalized remote
destination and a value-free header scope: each header name and its host-vault
placeholder identifiers. Header values and resolved secrets are never passed
to the approval provider. A call approval is invalidated if the destination or
header configuration changes before execution.

### Remote MCP upgrade migration

v0.0.50 versions the persisted MCP registry and performs a one-way forward
migration during daemon startup, before any RPC is accepted. Every remote
server entry written by an older daemon loses its static `headers` map. The
daemon cannot tell a benign static value from a credential saved by an older
release, so it removes the whole legacy map rather than guessing. Server names,
URLs, transports, stdio entries, host-vault `secret_headers` placeholder
templates and all unrelated settings are preserved. The same legacy static
`headers` are scrubbed in place from existing pre-upgrade
`.pre-v<version>-*.bak` database backups beside the active database; backups are
never deleted and unrelated backup settings or rows are untouched. SQLite full
secure deletion overwrites removed header bytes in database pages. The one-time
upgrade vacuums stale SQLite free pages from earlier releases, then checkpoints
and truncates the active WAL after persisting the schema marker. Later starts
retry the checkpoint before RPC startup. The vacuum needs temporary disk space
proportional to database size; if migration or any backup write fails, startup
fails closed and retries on the next start. Re-register the server and move
required header values into the host vault. After an interrupted backup write,
SQLite recovery runs and startup retries sanitization before accepting RPCs.
Legacy values are not logged, displayed or recoverable after a successful
migration. The registry then uses schema v3, and every future remote header
must use a host-vault reference. See
[docs/MCP-MIGRATION.md](docs/MCP-MIGRATION.md).

Service proxy references require the matching static guest helper artifact.
Build it with `make build-proxy-helper` and pass
`--proxy-helper ./bin/rheic-proxy-helper-linux-arm64` to `sandboxesd`. The
daemon accepts only a static Linux ARM64 ELF helper. If the helper is absent,
`${proxy:service}` fails closed. Proxy-enabled sandboxes currently support one
service per sandbox.

Empty `--containerd` keeps the state-only control plane. Runtime mode requires
the exact containerd and `ctr` v2.4.2 binaries plus the explicit shim and runtime
asset paths. The daemon owns containerd: it creates its root, state, config and
state beneath `<state>/containerd`, verifies any existing config against the
generated values. Linux Unix sockets use a private per-user directory at
`/tmp/.rsbx-<uid>` with a stable state-hash endpoint, keeping socket paths below
the kernel's Unix-domain length limit even when the state path is long. On Linux
a state-owned keeper preserves the private mount
namespace across daemon restarts and supervises containerd in that namespace.
Daemon shutdown detaches from the Linux keeper. There is no user-facing keeper
stop command yet: an empty-task query races same-UID `ctr` clients that can
create tasks concurrently. Each Linux containerd child receives a fresh
socket/config generation. The stable `containerd.sock` endpoint is an atomic
symlink to the active generation, and prior socket paths are left untouched;
the keeper can therefore restart after a child SIGKILL without unlinking a
possibly substituted path. An unexpected file or symlink at the stable endpoint
fails closed. A dead keeper marker also fails closed rather than starting a new
namespace over potentially live shim mounts. Restart the daemon with the same
state and runtime paths to reattach to a live keeper. After a host reboot the
old namespace cannot survive, so the marker is cleared only after the read-only
mount precheck. No supported manual cleanup procedure for a dead same-boot
keeper is provided yet. On Linux the launcher requires permission to create a
private mount namespace and fails closed if it cannot.
On macOS the launcher supervises containerd and terminates it when the daemon
exits. Runtime asset digest and
provenance verification remains a separate release gate. With a runtime
backend, create/start/stop/delete call the runtime adapter. With `--gvproxy`,
the daemon also starts a default-deny gateway and attaches nerdbox network
annotations; exec/PTY still remain unsupported.

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

## Policy sync (opt-in background sync)

`internal/policysync` pulls signed organization policy bundles from the
self-hosted control plane. It fetches `GET /v1/orgs/{org}/policy` over TLS with
a bearer credential and a pinned Ed25519 public key, re-verifies the canonical
bundle signature locally (server-side verification is not trusted), rejects
expired bundles and revision rollbacks, and stores only verified bundles in the
`org_policy_bundles` SQLite table. The schema migration is forward-only and
creates a pre-upgrade backup; network, TLS, signature, expiry and revision
failures fail closed and leave the previous bundle intact.

The daemon runs the client only when the settings block is present. It is off by
default, and the four required values are all-or-none: a partial configuration
is a startup error.

```toml
policy_sync.url = "https://control.example.test:8443"
policy_sync.org = "acme"
policy_sync.public_key_file = "/home/operator/.config/rheic/policy.public"
policy_sync.token_file = "/home/operator/.config/rheic/policy.token"
policy_sync.interval = "5m" # optional, 30s..24h, default 5m
```

- `policy_sync.url` must be an absolute HTTPS URL with no path, query, fragment
  or userinfo. Redirects are refused and the normal system trust store is used;
  there is no insecure or custom-CA flag.
- `policy_sync.org` must be a valid organization ID and must match the bundle's
  `orgId`.
- `policy_sync.public_key_file` contains the base64 Ed25519 public key. It must
  be a bounded (4 KiB) regular file and not a symlink.
- `policy_sync.token_file` contains the bearer token. It must be a bounded
  (4 KiB) regular file, mode `0600`, and not a symlink. The token is never
  accepted as a command-line flag (process list exposure), is read only at
  startup, and is never logged or included in errors.
- `policy_sync.interval` is optional. Values outside 30 seconds to 24 hours are
  rejected. The loop adds up to 20% random jitter so replicas do not poll in
  lockstep.

On startup the daemon performs one attempt and then repeats it on the configured
interval. Attempts are sequential (single-flight), and daemon shutdown cancels
an in-flight request promptly. A failed attempt logs a redacted error and leaves
the previously stored bundle untouched; it never crashes the daemon. If
`org_policy.enforce` is on and there is no usable bundle, sandbox operations
still fail closed through `internal/orgpolicy`; there is no permissive fallback.

### End-to-end recipe

This uses synthetic keys and a controlled local control plane. Keep the private
key offline.

```sh
# 1. Generate the policy-signing key pair (policy-key.private is 0600).
rheic-server keygen --prefix ./policy-key

# 2. Create an unsigned payload. revision must increase on every rollout and
#    expiresAt should be comfortably in the future.
cat > ./policy-payload.json <<'EOF'
{
  "schemaVersion": 1,
  "orgId": "acme",
  "revision": 1,
  "issuedAt": "2026-11-08T00:00:00Z",
  "expiresAt": "2026-12-08T00:00:00Z",
  "rules": [
    {"resource": "network:blocked.example.test:443", "action": "deny", "ruleId": "deny-1"}
  ]
}
EOF

# 3. Sign locally with the canonical policy encoding.
rheic-server sign-policy \
  --input ./policy-payload.json \
  --private-key ./policy-key.private \
  --output ./signed-policy.json

# 4. Publish with an admin credential from the server's credentials file.
export RHEIC_ADMIN_TOKEN="$(jq -r '.credentials[] | select(.role == "admin") | .token' ./credentials.json)"
curl --fail --cacert ./tls/ca.crt \
  -H "Authorization: Bearer $RHEIC_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @./signed-policy.json \
  -X PUT https://control.example.test:8443/v1/orgs/acme/policy

# 5. Install the daemon-side settings and protected files.
install -d -m 700 "$HOME/.config/rheic"
cat > "$HOME/.config/rheic/settings.toml" <<EOF
policy_sync.url = "https://control.example.test:8443"
policy_sync.org = "acme"
policy_sync.public_key_file = "$HOME/.config/rheic/policy.public"
policy_sync.token_file = "$HOME/.config/rheic/policy.token"
policy_sync.interval = "5m"
EOF
chmod 600 "$HOME/.config/rheic/settings.toml"
install -m 644 ./policy-key.public "$HOME/.config/rheic/policy.public"

# Use a reader or admin token. Write it without putting it on a command line.
(umask 077; jq -r '.credentials[] | select(.role == "reader") | .token' ./credentials.json \
  > "$HOME/.config/rheic/policy.token")

# 6. Start the daemon. With org_policy.enforce also set, the synced deny rules
#    apply to new sandbox operations.
sandboxesd --state "$HOME/.sandboxes" \
  --socket "$HOME/.sandboxes/sandboxesd.sock"

# 7. Observe the attempt and the stored revision.
#    Log line: level=INFO msg="policy bundle synced" org=acme revision=1 ...
sqlite3 "$HOME/.sandboxes/sandboxes.db" \
  'SELECT org_id, revision, datetime(expires_at/1000000000, "unixepoch") FROM org_policy_bundles;'
```

The daemon does not expose policy-sync state through the CLI, local API or SDK
yet. A subsequent slice can add an operation/status surface, offline
last-known-good reporting and secret-vault token storage instead of a file.

## Organization policy enforcement (ADR-0003 slice)

`org_policy.enforce = true` plus `org_policy.org = "<org>"` applies the stored,
locally verified bundle for that organization to sandbox network policy. The
setting defaults to off. When it is on, every create, start, policy mutation,
policy refresh and policy-check path first loads the bundle from SQLite (never
from the network). A missing, expired, cross-organization, malformed or
metadata-inconsistent bundle returns a typed `core.ErrConflict` error and the
operation fails closed; there is no permissive fallback.

What is enforced:

- only `network` deny resources of the form
  `network:<domain-or-cidr>:<port>`, where the port is mandatory and non-zero;
- every mapped deny expands to both TCP and UDP on the same destination/port,
  so the restriction cannot be bypassed by choosing another transport;
- organization deny is prepended to the effective deny list and keeps its signed
  rule ID for audit and gateway decisions; gateway deny precedence therefore
  beats local allow rules;
- if the gateway cannot enforce the resulting combination (for example a
  domain deny overlapping a direct IP allow), create/start/mutation fails with
  `orgpolicy.ErrPolicyConflict` instead of dropping the organization deny.

Resource parsing decisions:

- a bare IP literal is treated as a `/32` or `/128` CIDR; a destination with a
  slash must parse as a CIDR; any other destination is a domain rule;
- a malformed `network:` deny fails the whole operation (fail closed) because
  ignoring it would silently weaken a signed restriction;
- organization `allow` rules are advisory and ignored in this slice, and
  malformed allow resources are ignored with them;
- `filesystem`, `mcp` and `secret` deny resources are outside this slice and are
  ignored; they are documented as not enforced;
- an IPv6 organization rule requires the existing IPv6 capability and otherwise
  fails closed through the same normalizer as local rules;
- a domain deny requires `--quic-experimental` and a patched gvproxy with the
  QUIC classifier. Without it the gateway rejects UDP domain policy, so the
  operation fails closed rather than granting TCP-only enforcement.

Not enforced by this slice: filesystem, MCP and secret resources; organization
allow rules; offline last-known-good beyond the stored bundle's expiry;
multi-tenancy; and apply-time signature re-verification (the signature is
verified by the policy sync client before the bundle is stored, and the local
SQLite store is trusted daemon state). The daemon does not contact the control
plane in the create/start/policy hot path.
