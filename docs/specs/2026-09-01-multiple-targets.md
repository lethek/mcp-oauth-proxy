# Multiple upstream MCP servers

Status: draft, for review
Date: 2026-09-01

## Problem

One proxy fronts one MCP server. Serving both Forgejo and Plane means two
deployments, two databases, two encryption keys, two OAuth clients registered at
the provider, and two hostnames. Per-user credentials would mean two enrolment
pages as well.

This proposes one proxy serving several targets, each with its own upstream URL
and its own way of authenticating to that upstream.

## The part that is not plumbing

The single-resource assumption is deliberate and is baked into the schema, not
just the routing. `store.go` drops the `resource` column from both `flows` and
`auth_codes`, with the comment that it "was collected and never used" because it
is "validated at /authorize against the one resource this proxy serves".
`oauth.go:245` rejects any `resource` parameter naming anything else, and
`access_tokens` carries a `client_id` but no audience.

So "which service is this token for?" currently has exactly one possible answer,
and the code was simplified to match.

Serving several targets means a token must be bound to the one it was issued for
and rejected at the others. Without that, a token minted for Forgejo works
against Plane, which would create a privilege path between two services that are
today isolated by being separate deployments. **This is the substance of the
change. The routing is the easy part.**

## Design

### Routing and identity

Path-based, under a single origin: `PUBLIC_URL/<target>/mcp`.

One `PUBLIC_URL`, so one issuer and one authorization server, serving several
resources. That matches the OAuth model directly: `resource` per RFC 8707
distinguishes them, and each gets its own RFC 9728 document at
`/.well-known/oauth-protected-resource/<target>/mcp`.

Hostname-based routing was considered, because it would preserve existing client
URLs. It was rejected: it puts several issuers in one process, and every token
would then need binding to an issuer as well as a resource, which is strictly
more of the thing that makes this change risky.

The migration cost is therefore that clients re-add their connector at a new URL.
For MCP clients that is a re-run of dynamic registration and consent, not a
manual credential move.

### Configuration

Per-target variables with a name prefix, rather than JSON in an environment
variable. Secrets stay in their own variables, so each maps to one Vault key and
nothing has to log or parse a blob containing a credential:

```
TARGETS=forgejo,plane

TARGET_FORGEJO_UPSTREAM_MCP_URL=http://forgejo-mcp.default.svc.cluster.local:8080
TARGET_FORGEJO_CREDENTIAL_MODE=provider_token

TARGET_PLANE_UPSTREAM_MCP_URL=http://plane-mcp-api.default.svc.cluster.local:8211/http/api-key
TARGET_PLANE_CREDENTIAL_MODE=static
TARGET_PLANE_STATIC_HEADERS=Authorization: Bearer ...\nx-workspace-slug: xmmx
```

`CREDENTIAL_MODE` is `provider_token` (today's default: forward the provider's
token) or `static` (v0.3.0's fixed headers). A third, `per_user`, arrives with
the per-user credentials work.

Target names must match `[a-z0-9-]+`, because they appear in URLs.

The upstream OAuth settings stay global. One provider authenticates people, and
that is orthogonal to which MCP server they then reach.

### Backwards compatibility

The existing flat `UPSTREAM_MCP_URL` and `UPSTREAM_STATIC_HEADERS` continue to
work and describe a single unnamed target served at `/mcp`, exactly as today.
Setting both `TARGETS` and the flat variables is a boot-time error.

This matters: it means the running `git-mcp` deployment needs no change and no
client reconfiguration until you choose to migrate it.

### Audience binding

Restore what was removed, and enforce it:

- `resource` returns as a column on `flows` and `auth_codes`, and is added to
  `access_tokens`.
- `/authorize` validates `resource` against the configured targets. **When more
  than one target is configured, `resource` is required**, because there is no
  sensible default and guessing would hand out a token for the wrong service. A
  single-target deployment keeps today's lenient behaviour.
- `/mcp` under a target compares the presented token's stored resource against
  that target's resource URI.

A mismatch answers **401 with a `WWW-Authenticate` challenge naming that target's
resource metadata**, not 403. The token is valid but has the wrong audience, and
a challenge pointing at the right metadata lets a well-behaved client discover
the correct resource and obtain a usable token by itself. A 403 would be a dead
end requiring human intervention.

### Per-user credentials

This changes the design in the companion spec before it is built. Credentials
become per `(subject, target)`:

```sql
CREATE TABLE IF NOT EXISTS user_credentials (
    subject        TEXT NOT NULL,
    target         TEXT NOT NULL,
    sealed_headers BYTEA NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, target)
);
```

`/settings` then lists every target in `per_user` mode, one section each. Doing
this now is the whole reason for the chosen ordering: building it keyed on
`subject` alone would mean later migrating rows of encrypted secrets, which is
the migration least worth getting wrong.

## Risks

- **One deployment now fails as a unit.** A bad config takes every target down,
  where today a broken Plane config cannot affect Forgejo. This is the main thing
  being traded away, and it is why config validation must fail at boot rather
  than at first request.
- **`ENCRYPTION_KEY` rotation** already invalidates every session; it now does so
  for every service at once.
- **Audience enforcement is the security boundary.** If it is wrong, the change
  is worse than useless: it converts deployment isolation into a bug. The tests
  below exist mainly for this.

## Testing

- Config: target name validation, unknown mode, missing per-target URL, `TARGETS`
  together with the legacy flat variables, and a single-target legacy config
  still producing today's behaviour and URLs.
- Metadata: one authorization-server document, one protected-resource document
  per target, each naming its own resource.
- `/authorize`: `resource` required with several targets, optional with one,
  rejected when naming an unconfigured target.
- **Cross-target rejection**, against a real database: mint a token for target A,
  present it at target B, assert 401 with a challenge naming B's metadata, and
  assert no request reaches B's upstream. This is the test the change exists for,
  and it should fail loudly if audience checking is ever removed.
- Per-target credential modes: `provider_token` forwards the session's token,
  `static` injects fixed headers, and in both cases the caller's own
  `Authorization` never reaches the upstream.

## Out of scope

- Hostname-based routing.
- Per-target OAuth providers.
- Key versioning, still worth having on its own.
