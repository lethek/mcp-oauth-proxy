# Per-user upstream credentials

Status: draft, for review. Superseded in part by the multiple-targets spec.
Date: 2026-09-01

> **Ordering note.** This is now scheduled after multiple-targets. That changes
> two things here: `user_credentials` is keyed on `(subject, target)` rather than
> `subject` alone, and `/settings` lists every target in per-user mode rather
> than a single set of fields. The rest of this document stands. See
> `2026-09-01-multiple-targets.md`.

## Problem

`UPSTREAM_STATIC_HEADERS` (v0.3.0) sends one fixed credential to the MCP server
for every caller. The provider authenticates each person properly, and then the
proxy discards that distinction at the last hop.

The cost is attribution. Plane records every action against the owner of the one
personal access token, so its audit trail cannot say who did what. Revoking one
person's access means rotating the shared credential and disrupting everyone.

This proposes keeping the fixed-credential mode and adding a per-user mode, where
each authenticated subject supplies their own credential through a self-service
page.

## What already exists

Most of the identity work is done:

- `sessions.subject` is populated at callback time from `upstream.Subject()`,
  which asks the provider's userinfo endpoint who the token belongs to
  (`oauth.go:376`). Every session already knows which human is behind it.
- `sealer` in `crypto.go` does AES-256-GCM and already protects upstream tokens
  at rest. Storing another secret needs no new cryptography.
- `prepareUpstreamHeaders` takes a `map[string]string`. Per-user is a different
  source for that argument, not a different code path.

## Design

### Storage

One new table, sealed with the existing key:

```sql
CREATE TABLE IF NOT EXISTS user_credentials (
    subject        TEXT PRIMARY KEY,
    sealed_headers BYTEA NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The plaintext is the JSON encoding of the same `map[string]string` that static
mode uses. Storing the whole header set, rather than just a token, means users in
different workspaces can carry different `x-workspace-slug` values without the
proxy needing a template language.

There is no foreign key to `sessions`. A credential outlives any individual
session, and should survive a user re-authorising.

### Configuration

A new variable declares which headers a user supplies and how to present them.
JSON, to avoid inventing a delimiter format:

```
UPSTREAM_USER_HEADERS=[
  {"header":"Authorization","label":"Plane personal access token","prefix":"Bearer "},
  {"header":"x-workspace-slug","label":"Workspace slug"}
]
```

`prefix` is applied when the header is built, so a user pastes a bare token
rather than having to type `Bearer ` themselves.

**`UPSTREAM_USER_HEADERS` and `UPSTREAM_STATIC_HEADERS` are mutually exclusive,
and setting both is a boot-time error.** The tempting alternative — fall back to
the shared credential for users who have not enrolled — would silently undo the
attribution this exists to provide, and would do so exactly when someone forgot
to enrol. Failing loudly at boot is better than a config that quietly degrades.

### Request path

`handleMCP` gains one lookup before injection:

1. `LookupAccessToken` resolves the caller's token to a session, as today.
2. A new `Store.UserHeaders(ctx, sessionID)` joins `sessions` to
   `user_credentials` in a single query and returns the sealed blob.
3. On a hit, unseal, and pass the map to `prepareUpstreamHeaders`.
4. On a miss, return 403 (see below) without contacting the upstream.

One query rather than fetching the subject and then the credential, to avoid a
second round trip on every request. No existing signature changes.

### Enrolment

`/settings` is an authenticated catalogue. It lists every configured target in
`per_user` mode, shows whether the signed-in subject has enrolled in each, and
offers a form per target to set or replace that credential.

**Targets themselves stay operator-defined, in configuration under version
control. Users supply credentials, never upstream URLs.** A user-supplied
upstream URL would let anyone who can log in aim the proxy at any address it can
reach and have it attach credentials to the request: Vault, Postgres, the
Kubernetes API. The usual defence of refusing private address ranges is
unavailable, because the legitimate upstreams are themselves internal cluster
services and are indistinguishable from those by address. An operator allowlist
would be the only real control, and maintaining one is the same work as defining
the targets.

The form fields for each target come from that target's `UPSTREAM_USER_HEADERS`.

It needs its own browser session, which the proxy does not currently have. The
existing consent page is bound to an in-flight authorization via `flows` and
`browser_hash`; there is no standing notion of "this browser is this person".

So `/settings` performs its own authorization-code round trip against the
provider and, on return, sets a signed, short-lived cookie carrying the subject.
That cookie authorises reads and writes of that subject's row and nothing else.

The rejected alternative was to fold enrolment into the existing consent page,
which would have reused `flows` and `browser_hash` and added no new session
concept. It was rejected because it couples credential management to an MCP
client's authorization flow: a user wanting to rotate a leaked token would have
to trigger an authorize flow from a client to reach the form. Credential
management should not require a third party to start it.

A follow-up worth considering, but out of scope here: when consent runs and the
subject has no credential stored, show a notice linking to `/settings`.

### Failure surfaces

**Not enrolled.** 403 with a JSON body naming the enrolment URL. Deliberately not
a 401 challenge: the caller authenticated correctly, so re-authenticating will
not help, and a challenge would send well-behaved clients into a retry loop.

**Credential rejected upstream.** A revoked PAT makes the MCP server answer 401,
which today would surface to the client as an opaque upstream failure. The proxy
should translate an upstream 401 in per-user mode into its own 403 naming the
enrolment URL, so the message says "your stored credential is no longer valid"
rather than "unauthorized".

This is more error-path work than happy-path work, and is the main reason this
change is larger than it first appears.

## Security

- Credentials are sealed with the existing `ENCRYPTION_KEY`. **Rotating that key
  already invalidates every session; it would now also destroy every stored
  credential, forcing all users to re-enrol.** `crypto.go` supports one key with
  no versioning, so rotation is a hard cutover with no re-encryption path. If
  per-user credentials land, key versioning becomes worth having on its own.
- The enrolment form needs CSRF protection consistent with the existing consent
  page, including its `form-action` handling.
- Credential values must never be logged, including in error paths. Log the
  subject and the header names only.
- A subject may read and write only its own row. The cookie carries the subject;
  nothing in the request body may select it.

## Testing

- `UPSTREAM_USER_HEADERS` parsing: valid, malformed JSON, empty header name,
  missing label, and mutual exclusion with `UPSTREAM_STATIC_HEADERS`.
- Store round trip against the real Postgres CI service: seal, read back,
  replace, and confirm the stored bytes are not the plaintext.
- `handleMCP` in per-user mode: injects that subject's headers; an unenrolled
  subject gets 403 and no upstream request is made; and the existing guarantee
  that the caller's own `Authorization` never reaches the upstream still holds.
- Enrolment: unauthenticated `GET /settings` redirects; the catalogue lists only
  targets in `per_user` mode; `POST` stores against the cookie's subject; and
  both a forged subject and an unconfigured target name in the body are ignored.

## Out of scope

- Key versioning and re-encryption, though this change strengthens the case.
- Admin-side seeding or listing of other users' credentials.
- Per-user upstream credentials for anything other than header injection.
