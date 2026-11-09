# Changelog

## v0.0.50 — 2026-11-09

- Reject all static remote MCP headers and require host-vault placeholders for every header value.
- Migrate schema-v2 registry rows and managed backups to schema v3, removing static values before serving RPC.
- Update the sandboxes-api module dependency to v0.0.24.
- Bind vault header injection to the approved HTTPS host and port; validate stored remote URL syntax before serving.
- Enforce private Unix daemon state-directory permissions before opening SQLite.

## v0.0.49 — 2026-11-08
- Bind M7 release and image publication approval to the exact reviewed commit.
- Add typed host-vault-backed remote MCP headers, validate and persist only placeholder references, and resolve values at request time.
- Version the persisted MCP registry and run a forward migration at daemon startup. Legacy remote static `headers` are removed before any RPC is served because an old value may be a persisted credential; server records, destinations, vault placeholder templates, stdio entries and unrelated settings are preserved. The same legacy static `headers` are scrubbed in place from pre-upgrade `.pre-v<version>-*.bak` database backups beside the active database, without deleting the backups. SQLite secure deletion overwrites removed bytes; a one-time active-database vacuum removes old freelist remnants, then startup checkpoints/truncates the WAL before serving RPCs. The vacuum may require temporary space proportional to the database size. Migration or backup-sanitization failure aborts startup and is retried on restart. The change is an intentional alpha compatibility break and old static header values cannot be restored automatically.
- Include the normalized remote destination and value-free header scope (name and host-vault placeholder identifiers) in trusted MCP registration and call approvals. Header values and resolved secrets are never exposed to the approval provider; pending calls are invalidated if the destination or header configuration changes during approval.
- Align API, gateway and runtime dependencies with the latest released modules, including the IPv6 RA refresh fix in runtime v0.0.29.
- Update host keyring and SQLite dependencies to their latest compatible releases.
- Update golang.org/x/sys from v0.49.0 to v0.50.0.
