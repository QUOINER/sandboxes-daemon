# Self-hosted control-plane preview

`rheic-server` serves signed organization policy and accepts structured audit
events over HTTPS. It is a single-operator preview; daemon synchronization,
OIDC, multi-operator roles, policy application, audit search/export, PostgreSQL
HA and deployment packaging are not implemented yet.

The API contract is in `sandboxes-api/openapi/cloud/v1.yaml`.

## Prepare keys and TLS

Generate the offline Ed25519 policy key pair. Keep the private key away from
the server host:

```sh
rheic-server keygen --prefix ./policy-key
```

`policy-key.private` has mode `0600`; `policy-key.public` is base64 encoded and
can be copied to the server. Generate an admin token and protect its file:

```sh
umask 077
openssl rand -base64 48 > ./admin-token
chmod 600 ./admin-token
```

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
  --admin-token-file ./admin-token \
  --policy-public-key ./policy-key.public \
  --tls-cert ./tls/server.crt \
  --tls-key ./tls/server.key
```

The database and its directory are restricted to the current user. The server
uses SQLite WAL mode, rejects a newer schema, and creates a private snapshot
before applying a migration to a non-empty database. Without `--db`, it stores
the database under the operating system's user config directory in `rheic/`.

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
  -H "Authorization: Bearer $(cat ./admin-token)" \
  -H 'Content-Type: application/json' \
  --data-binary @./signed-policy.json \
  -X PUT https://control.example.test:8443/v1/orgs/acme/policy
```

Audit ingestion is newline-delimited JSON. It only accepts bounded metadata
fields and rejects unknown fields, including payload/detail fields. Do not put
secrets, user paths or request bodies into audit values.

The admin bearer currently grants access to every org handled by this server.
Do not expose this preview endpoint to untrusted clients. OIDC and per-org
authorization are explicit follow-up gates, not implied by the HTTPS listener.
