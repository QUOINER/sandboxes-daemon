# Remote MCP registry migration (v0.0.49)

v0.0.49 introduces a versioned MCP registry. The daemon applies a one-way
forward migration at startup, before it accepts any RPC. This is an intentional
alpha compatibility break.

## What changes

- The settings key `mcp_stdio_servers_v1` keeps the server records, but remote
  records written by an older daemon lose their static `headers` map.
- The same legacy static `headers` are scrubbed in place from existing
  `.pre-v<version>-*.bak` database backups beside the active database. Backups
  are not deleted, and unrelated backup settings, rows and files are preserved.
- SQLite full secure deletion is enabled on each backup connection before the
  registry row is updated, so removed header bytes are overwritten in the
  database pages instead of remaining in SQLite freeblocks.
- The active store also enables SQLite full secure deletion for updates and
  runs a one-time `VACUUM` during the registry schema upgrade to remove older
  freelist pages left by previous releases. It then checkpoints/truncates the
  WAL after persisting the schema marker; current-schema startups also retry a
  WAL checkpoint before RPC startup in case an earlier startup was interrupted.
- The one-time `VACUUM` may require temporary disk space roughly proportional
  to the database size. If it or the final checkpoint cannot complete, daemon
  startup fails closed and retries on the next start.
- If the process or host stops during a backup transaction, SQLite may recover
  the original row from its rollback journal on the next open. That startup
  re-runs backup sanitization and still refuses RPC service until it completes.
  The removal guarantee applies after a successful startup; filesystem
  snapshots and storage-device remanence are outside this migration's scope.
- The settings key `mcp_registry_schema_version` records the current schema
  version (`2`).
- Server names, URLs, transports, stdio records, host-vault `secret_headers`
  placeholder templates and all unrelated settings are preserved.

## Why values are removed

Older releases accepted literal values for custom header names in the static
`headers` map, including names that could hold credentials. The daemon cannot
reliably classify a stored value as a secret from its name or contents. Keeping
the map would allow an upgraded daemon to transmit a persisted credential after
a trusted call approval. Guessing which entries are safe is not an acceptable
security boundary, so the migration removes the entire legacy static map.

## Failure and idempotence

- The sanitized registry is written before the schema marker.
- Each relevant pre-upgrade backup is updated in place. If any read or write
  fails, daemon startup aborts and no RPC is served.
- If the current database was already sanitized before a backup write failed, a
  later startup retries the backups only. Re-running the migration is safe.
- Once the schema marker is present, later startups do not strip static headers
  from the active registry again. Backup scrubbing remains idempotent.

## User action

Legacy static header values are not logged, displayed or recoverable. Register
the server again to recreate any static headers that are still required. For
credential-bearing headers, use host-vault `secret_headers` with
`${placeholder}` references instead of static values.

## Approval scope

Trusted registration and per-call approvals receive:

- the normalized remote destination;
- each remote header name;
- the header value class (`static` or `host-vault`);
- the host-vault placeholder identifiers for `host-vault` headers.

Header values and resolved secrets are never included. If the destination or
header configuration changes after a call challenge is created, the pending
approval is rejected before any network access or vault resolution.
