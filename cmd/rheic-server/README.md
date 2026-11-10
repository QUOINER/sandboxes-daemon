# Self-hosted control-plane preview

![Rheic blue shark logo](../../docs/assets/rheic-shark.png)

`rheic-server` serves signed organization policy and accepts structured audit
events over HTTPS. It is a single-operator preview; applying synced policy to
sandbox operations, audit search/SIEM export, PostgreSQL HA and deployment
packaging are not implemented yet. The daemon can pull policy as an opt-in
background sync (see the daemon README). Bounded JSON audit export is available.
Static bearer credentials are role scoped: `admin` may publish policy and ingest
audit, `reader` may only read policy.

The API contract is in `sandboxes-api/openapi/cloud/v1.yaml`.

## Prepare keys and TLS

Generate the offline Ed25519 policy key pair. Keep the private key away from
the server host:

```sh
rheic-server keygen --prefix ./policy-key
```

`policy-key.private` has mode `0600`; `policy-key.public` is base64 encoded and
can be copied to the server.

Create a protected credentials file with mode `0600` (a regular file owned by
the server user, not a symlink). It is strict JSON with one entry per named
bearer credential:

```json
{
  "credentials": [
    {"name": "ops-admin", "role": "admin", "token": "<random value, at least 32 bytes>"},
    {"name": "audit-reader", "role": "reader", "token": "<different random value, at least 32 bytes>"}
  ]
}
```

Generate each token separately, for example with `openssl rand -base64 48`, and
never reuse a token between entries or roles. The server refuses to start on an
empty file, an unknown role, a token shorter than 32 bytes, duplicate names or
tokens, unknown fields, invalid JSON, or a file readable by group or others.
Comparison is constant time over SHA-256 digests. Token values are never logged.

| Operation | admin | reader |
| --- | --- | --- |
| `GET /v1/orgs/{org}/policy` | yes | yes |
| `PUT /v1/orgs/{org}/policy` | yes | no (403) |
| `POST /v1/orgs/{org}/audit` | yes | no (403) |

Export a token from the file into the environment for the examples below; do
not put it on a command line or in shell history:

```sh
export RHEIC_ADMIN_TOKEN="$(jq -r '.credentials[] | select(.role == "admin") | .token' ./credentials.json)"
```

Static credentials are installation wide: they are not scoped to an org. Each
org path is still isolated in storage, but a credential holder may use any org
ID handled by this server. Per-org authorization is an OIDC/follow-up gate.

Provide a certificate and an owner-only regular key file (mode `0600`) for the
server's DNS name. Clients verify TLS normally; there is no insecure mode. The
default listener is loopback. Set
`--listen` to a reachable interface only behind the intended firewall and
network policy.

## Start the server

```sh
rheic-server \
  --listen 127.0.0.1:8443 \
  --db ./state/rheic-server.db \
  --credentials-file ./credentials.json \
  --policy-public-key ./policy-key.public \
  --tls-cert ./tls/server.crt \
  --tls-key ./tls/server.key
```

The database and its directory are restricted to the current user. The server
uses SQLite WAL mode, rejects a newer schema, and creates a private snapshot
before applying a migration to a non-empty database. Without `--db`, it stores
the database under the operating system's user config directory in `rheic/`.

## Optional OIDC bearer validation

Set all three flags together to accept OIDC JWT bearer tokens in addition to
static credentials:

```sh
rheic-server \
  --credentials-file ./credentials.json \
  --oidc-issuer https://idp.example.test \
  --oidc-audience rheic-control-plane \
  --oidc-jwks-url https://idp.example.test/.well-known/jwks.json \
  ... # database, policy key and TLS flags as above
```

Only `RS256` and `EdDSA` signatures are accepted. Tokens using `none`, HMAC or
any other algorithm are rejected before verification. The validator enforces:

- exact `iss` match against `--oidc-issuer`;
- the configured audience in `aud` (string or array);
- required `exp` and optional `nbf`, with 60 seconds of clock leeway;
- a non-empty `kid` that resolves to a usable key in the JWKS;
- an `org` claim matching the org path, and a `role` claim of `admin` or
  `reader`. A token scoped to one org gets `403` on another org, and a reader
  token cannot publish or ingest.

The JWKS is fetched over HTTPS, cached, refreshed every 5 minutes, and must be
refreshed successfully before it is 15 minutes old. An unknown `kid` triggers
at most one rate-limited refresh (not more than once every 30 seconds), so a
stream of random key IDs cannot force unbounded fetches. If a refresh fails
while the cache is stale, validation fails closed. JWKS and JWT payloads are
size bounded, duplicate JSON members are rejected, RSA keys below 2048 bits
and non-Ed25519 OKP keys are ignored.

This is bearer-token validation, not a full OIDC client: there is no browser
login, authorization-code flow, token issuance/refresh, discovery endpoint, or
token introspection/revocation. Treat it as a documented gap rather than an
implicit feature. Tokens, signatures and authorization headers are never
logged.

## Sign and publish a policy

The signer receives a JSON `PolicyPayload` matching the OpenAPI schema. The
JSON representation is only the transport format; it is not signed directly.
Both signer and server sign/verify the following version-1 canonical byte
format, using Ed25519:

1. Domain separator: the UTF-8 bytes `rheic-policy-payload\0v1\0`.
2. `schemaVersion`: unsigned 32-bit big-endian integer.
3. `orgId`: unsigned 32-bit big-endian UTF-8 byte length, then the exact UTF-8
   bytes (no Unicode normalization).
4. `revision`: unsigned 64-bit big-endian integer.
5. `issuedAt`, then `expiresAt`: each is signed 64-bit big-endian Unix seconds
   followed by unsigned 32-bit big-endian nanoseconds. RFC 3339 timestamps may
   use an explicit offset; they are interpreted as instants and encoded in
   UTC. Precision finer than one nanosecond is rejected. The signer emits UTC
   timestamps ending in `Z`.
6. `rules`: unsigned 32-bit big-endian rule count, followed in array order by
   each rule's `resource`, `action`, and `ruleId`; each string uses the same
   32-bit byte-length prefix and exact UTF-8 encoding as `orgId`.

Rules must already be in strictly increasing bytewise UTF-8 `ruleId` order;
duplicate IDs and unsorted arrays are rejected, not silently reordered. JSON
with duplicate object members, invalid UTF-8, or unpaired Unicode surrogate
escapes is rejected. The bundle's
`signature` is standard padded Base64 of the 64-byte Ed25519 signature over the
canonical bytes above. The server accepts strictly increasing revisions and
rejects expired, malformed, cross-organization or incorrectly signed bundles.
Legacy signatures over `json.Marshal(payload)` are not accepted. Reissue an
existing policy with a higher revision using this format. Signing is local and
does not contact the server:

```sh
rheic-server sign-policy \
  --input ./policy-payload.json \
  --private-key ./policy-key.private \
  --output ./signed-policy.json

curl --fail --cacert ./tls/ca.crt \
  -H "Authorization: Bearer $RHEIC_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @./signed-policy.json \
  -X PUT https://control.example.test:8443/v1/orgs/acme/policy
```

Audit ingestion is newline-delimited JSON. It only accepts bounded metadata
fields and rejects unknown fields, including payload/detail fields. Do not put
secrets, user paths or request bodies into audit values.

## Export audit events

`GET /v1/orgs/{org}/audit` returns one bounded JSON object, not NDJSON:

```json
{"events":[{"id":42,"occurredAt":"2026-11-08T00:00:00Z","sandboxId":"sbx_1","operationId":"op_1","action":"network.connect","resource":"network","decision":"allow"}],"nextCursor":"42"}
```

- `limit` is optional; it defaults to 100 and must be between 1 and 500.
- `after` is optional and is an exclusive event ID cursor. Omit it for the
  first page. IDs are assigned monotonically, and events are always ordered by
  ascending ID, so a cursor does not replay or skip already exported events
  when new events arrive.
- `nextCursor` is empty on the last page; otherwise pass it as `after` on the
  next request.
- Invalid `limit` or `after` values return `400` with `invalid_limit` or
  `invalid_cursor`.
- `admin` and `reader` may export. Each response is restricted to the org in
  the path.

```sh
curl --fail --cacert ./tls/ca.crt \
  -H "Authorization: Bearer $RHEIC_READER_TOKEN" \
  'https://control.example.test:8443/v1/orgs/acme/audit?limit=100&after=0'
```

An admin bearer grants access to every org handled by this server; a reader
bearer reads every org. Do not expose this preview endpoint to untrusted
clients. OIDC and per-org authorization are explicit follow-up gates, not
implied by the HTTPS listener. The credential file is read once at startup;
restart the server after rotating a token.
