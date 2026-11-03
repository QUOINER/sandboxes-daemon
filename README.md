# sandboxes-daemon

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

`--settings` defaults to `~/.config/klorq/settings.toml`. Supported overrides
are `dns_upstream`, `default_policy_profile`, `default_cpus`,
`default_memory_mib` and `docker_volume_size`. The file is strict, mode-checked
and never contains secrets. DNS and existing gateways need a daemon restart;
new sandboxes use the policy profile and resource defaults.

Service proxy references require the matching static guest helper artifact.
Build it with `make build-proxy-helper` and pass
`--proxy-helper ./bin/klorq-proxy-helper-linux-arm64` to `sandboxesd`. The
daemon accepts only a static Linux ARM64 ELF helper. If the helper is absent,
`${proxy:service}` fails closed. Proxy-enabled sandboxes currently support one
service per sandbox and require an image with `/bin/sh`.

Empty `--containerd` keeps the state-only control plane. With a runtime backend,
create/start/stop/delete call the runtime adapter. With `--gvproxy`, the daemon
also starts a default-deny gateway and attaches nerdbox network annotations;
exec/PTY still remain unsupported.

`RegistryCredentialService` stores registry login entries in macOS Keychain,
Windows Credential Manager, or Linux Secret Service. It fails closed when the
native vault is unavailable and has no plaintext fallback. Credential scopes
are persisted separately. Authentication verification and use by guest image
pulls are not wired yet.

`SecretService` stores service API keys (`openai`, `anthropic`, `github`, ...)
in the host vault, scoped globally or to one sandbox. Values are held in memory
only for the RPC and are never returned by `List`. A non-secret SQLite index
supports listing and sandbox-scoped cleanup; the value itself never enters the
database, logs, argv or sandbox snapshots. At exec time a whole-value
`${secret:service}` environment reference is resolved from the host vault and
passed only to that process; sandbox scope wins over global. The
`${proxy:service}` Create/Start/exec path is implemented on the current feature
branches and remains **unreleased and pending verification**. It requires
`--proxy-helper`, a supported provider credential variable, and `/bin/sh` in the
image. The guest gets a placeholder and provider base URL; the host broker reads
the real value from the vault and checks sandbox network policy on each request.
The broker refuses to replace an existing socket path and requires a private
parent directory owned by the daemon user. The value is not written to SQLite
or sandbox metadata.

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
Sandboxes `sbx` binary. No Klorq OAuth registration is needed. Browser launch
is supported on macOS; other platforms return unsupported.
