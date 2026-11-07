# Self-hosted control-plane MVP

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
before applying a migration to a non-empty database.

## Sign and publish a policy

The signer receives a JSON `PolicyPayload` matching the OpenAPI schema. The
server accepts strictly increasing revisions and rejects expired, malformed,
cross-organization or incorrectly signed bundles. Signing is local and does
not contact the server:

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
