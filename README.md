# mcp-oauth-proxy

Puts an OAuth 2.1 authorization surface in front of an MCP server that has none,
and delegates the actual authentication to an OAuth provider you already run.

Built to connect [forgejo-mcp](https://git.b4mad.industries/agentic-forges/forgejo-mcp)
to Claude Code on the web, but nothing here is Forgejo-specific beyond the
defaults.

## Why it exists

MCP clients discover how to authenticate by fetching protected resource metadata
from the server, then registering themselves with whatever authorization server
that metadata names. Two things usually stop that working:

- Most MCP servers serve no metadata and never return a `401`, so discovery has
  nothing to go on.
- Most OAuth providers have no dynamic client registration, so a client that
  wants to register itself has nowhere to do it.

This proxy answers both. It serves the metadata, presents a registration
endpoint, and behind that uses one application you registered by hand with the
provider. Clients get tokens this proxy issued; the provider's token stays here.

## How a request flows

```
client                 proxy                        provider        MCP server
  |  POST /mcp           |                              |               |
  |--------------------->|  401 + WWW-Authenticate      |               |
  |<---------------------|                              |               |
  |  GET metadata        |                              |               |
  |--------------------->|                              |               |
  |  POST /register      |                              |               |
  |--------------------->|                              |               |
  |  GET /authorize      |                              |               |
  |--------------------->|  consent page: who is asking |               |
  |                      |                              |               |
  |  POST /consent       |                              |               |
  |--------------------->|  302 to provider ----------->|               |
  |                      |         (user signs in)      |               |
  |                      |<-- 302 /callback + code -----|               |
  |                      |  exchange code for token --->|               |
  |<-- 302 + our code ---|  (token stored encrypted)    |               |
  |  POST /token         |                              |               |
  |--------------------->|  our access + refresh token  |               |
  |<---------------------|                              |               |
  |  POST /mcp + Bearer  |                              |               |
  |--------------------->|  swap in provider token ---------------->    |
  |<------------------------------------------------------------------ |
```

## Configuration

All configuration is environment variables. Everything below is required except
where a default is shown.

| Variable | Meaning |
| --- | --- |
| `PUBLIC_URL` | The origin clients dial, e.g. `https://git-mcp.example.com`. Used as the OAuth issuer and as the base of every advertised URL, so it must match reality. Must be `https` unless it is loopback. No trailing slash. Spelling out a default port is fine; it is normalised before being compared against a browser's `Origin`. |
| `UPSTREAM_MCP_URL` | The MCP server to forward to once a request is authorized. Plain `http` is accepted here for private-network deployments, and warned about at boot when it is not loopback. Required unless `TARGETS` is set. |
| `TARGETS` | Comma-separated names, to serve several MCP servers from one proxy. See below. |
| `UPSTREAM_ISSUER` | The OAuth provider's origin. Discovery is read from `/.well-known/openid-configuration`, falling back to `/.well-known/oauth-authorization-server`. |
| `UPSTREAM_CLIENT_ID` | Client id of the application you registered with the provider. |
| `UPSTREAM_CLIENT_SECRET` | Its secret. |
| `UPSTREAM_SCOPES` | Space-separated. Default `openid profile email`. |
| `UPSTREAM_STATIC_HEADERS` | Optional. Newline-separated `Name: Value` pairs, sent to the MCP server in place of the provider's token. See below. |
| `DATABASE_URL` | PostgreSQL connection string. The schema is created on boot. |
| `ENCRYPTION_KEY` | Base64 of exactly 32 bytes. Encrypts provider tokens at rest with AES-256-GCM. Changing it invalidates every stored session. |
| `REFRESH_TOKEN_TTL` | How long a refresh token stays usable. Rotation issues a new one, so this acts as an idle timeout. Go duration, default `720h` (30 days). |
| `SESSION_TTL` | Absolute cap on one authorization, however actively it is refreshed. Reaching it sends the user back through the provider. Go duration, default `2160h` (90 days). Must not be shorter than `REFRESH_TOKEN_TTL`. |
| `LISTEN_ADDR` | Default `:8080`. |

Generate a key with:

```bash
openssl rand -base64 32
```

The application you register with the provider must use
`PUBLIC_URL` + `/callback` as its redirect URI.

### Several MCP servers behind one proxy

`TARGETS` names them. Each is then configured by its own variables, where the
prefix is the name uppercased with hyphens turned into underscores, so `git-mcp`
reads `TARGET_GIT_MCP_*`:

```
TARGETS=forgejo,plane

TARGET_FORGEJO_UPSTREAM_MCP_URL=http://forgejo-mcp:8080
TARGET_FORGEJO_CREDENTIAL_MODE=provider_token

TARGET_PLANE_UPSTREAM_MCP_URL=http://plane-mcp-api:8211/http/api-key
TARGET_PLANE_CREDENTIAL_MODE=static
TARGET_PLANE_STATIC_HEADERS=Authorization: Bearer plane_api_xxx
```

`CREDENTIAL_MODE` is one of:

- `provider_token`, the default, which forwards the provider's own token.
- `static`, which sends the fixed `..._STATIC_HEADERS` instead.
- `per_user`, which sends the credential each user stored for themselves. See
  below.

Each target is served at `PUBLIC_URL/<name>/mcp` and is a distinct OAuth
resource, with its own RFC 9728 document at
`/.well-known/oauth-protected-resource/<name>/mcp`. There is still one issuer and
one authorization server.

**A token is bound to the target it was issued for.** Presenting it at another
gets a 401 whose challenge names that target's metadata, so a client can discover
the right resource and fetch a usable token by itself. Because of that, the
`resource` parameter is **required** at `/authorize` when several targets are
configured: there is no sensible default and guessing would mint a token for the
wrong service.

`TARGETS` cannot be combined with `UPSTREAM_MCP_URL` or `UPSTREAM_STATIC_HEADERS`;
setting both is refused at boot rather than resolved by precedence. Leaving
`TARGETS` unset keeps the single-target behaviour exactly as it was, serving
`/mcp` with `resource` optional, so an existing deployment needs no change.

### Per-user credentials

`static` sends one credential for everybody, so the MCP server records every
action against whoever owns that credential and cannot tell callers apart.
`per_user` fixes that: each person stores their own, and the server sees who is
actually asking.

`..._USER_HEADERS` declares what they are asked for, as JSON:

```
TARGET_PLANE_CREDENTIAL_MODE=per_user
TARGET_PLANE_USER_HEADERS=[
  {"header":"Authorization","label":"Plane personal access token","prefix":"Bearer "},
  {"header":"x-workspace-slug","label":"Workspace slug"}
]
```

`prefix` is applied when the header is built, so a user pastes a bare token
rather than typing `Bearer ` themselves.

Users then visit **`PUBLIC_URL/settings`**, which lists every `per_user` target,
shows which they have configured, and takes a value per field. The page runs its
own sign-in against the provider, so **its redirect URI,
`PUBLIC_URL/settings/callback`, must be registered with the provider alongside
`PUBLIC_URL/callback`.**

Credentials are stored encrypted with `ENCRYPTION_KEY`, keyed on the provider's
subject and the target, and never logged.

Someone who has not enrolled gets **403** naming the settings page, and their
request never reaches the MCP server. It is deliberately not a 401 challenge:
they authenticated correctly, so re-authenticating would succeed and change
nothing, leaving a well-behaved client looping. An upstream 401, which is what a
revoked credential looks like, is rewritten the same way rather than passed
through as an unexplained "unauthorized" about a credential the client has never
seen.

**Targets are configured here, never by users.** A user-supplied upstream URL
would let anyone who can sign in point the proxy at any address it can reach and
have it attach credentials to the request. Refusing private address ranges is no
defence when the legitimate upstreams are themselves internal.

Note also that rotating `ENCRYPTION_KEY` already invalidates every session; with
per-user credentials stored it also destroys those, and everyone must enrol
again.

### Static upstream credentials

By default the proxy forwards the provider's own token to the MCP server. Some
MCP servers do not accept it, and authenticate with a fixed credential instead.
Plane's api-key endpoint is one: it wants a personal access token and a
workspace header.

`UPSTREAM_STATIC_HEADERS` covers that case:

```yaml
UPSTREAM_STATIC_HEADERS: |
  Authorization: Bearer plane_api_xxxxxxxx
  x-workspace-slug: acme
```

Newlines separate the pairs, because header values routinely contain commas.

The provider still authenticates every user, and the proxy still issues and
validates its own tokens, so an unauthenticated caller gets nowhere. What
changes is only the credential the MCP server sees. The session's provider token
is not loaded at all in this mode, so a provider that issues no refresh token
cannot break forwarding.

Note what this means: everyone the provider lets in shares one upstream
credential, and the MCP server cannot tell them apart. Scope that credential to
the least it needs.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource` | RFC 9728 metadata. Also served at `/mcp` suffix. |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata. |
| `/register` | RFC 7591 dynamic client registration. |
| `/authorize`, `/consent` | Authorization request, then the consent screen. Nothing reaches the provider until the user approves. |
| `/callback`, `/token` | Provider redirect and token issuance. Authorization code flow with PKCE. |
| `/revoke` | RFC 7009. Presenting either token ends the whole session. |
| `/mcp` | Authenticated pass-through to the upstream MCP server. |
| `/healthz` | Liveness. Reports only on this process. |

## Security notes

### Consent is the thing that makes registration safe

Registration is anonymous, so anyone can obtain a `client_id` pointing at an
address they control. That is inherent in dynamic client registration and cannot
be validated away.

What contains it is the consent screen. `/authorize` renders a page naming the
client and the address that will receive the authorization, and contacts the
provider only after the user approves. The provider's own consent cannot stand
in for this: it names the single application this proxy registered, says nothing
about which client is asking, and is usually skipped entirely once the user has
approved that application once.

Without the screen, a crafted `/authorize` link is enough to take over an
account. The victim opens it, the provider recognises an already-approved
application and redirects straight back, and the authorization code lands on the
attacker's address. The consent page is what turns that into a question the
victim can answer.

The flow id is **not** a CSRF defence, and treating it as one leaves the hole
half open. Anyone may call `/authorize` and read a valid flow id straight out of
the page they get back, so an attacker can create their own flow and then have a
victim's browser submit that id from a page they control. A plain HTML form POST
is not blocked by CORS, so the approval would succeed in the victim's session.

What actually binds the decision is a `SameSite=Lax` HttpOnly cookie set at
`/authorize`. Lax rather than Strict on purpose: both refuse the cross-site POST
that is the attack, but Strict would also withhold the cookie on the ordinary
cross-site navigation that reaches `/authorize`, minting a fresh secret every
time and letting a second client started mid-flow invalidate the first one's
consent page. The flow records a hash of it, and `/consent` approves only when
the submitting browser presents the matching value. A cross-site POST does not
carry the cookie, so it has nothing to prove itself with. The binding check is
part of the same SQL update that marks the flow approved, so it cannot be
skipped by a future caller.

`Origin` and `Sec-Fetch-Site` are checked as well, for anything that does not
honour `SameSite`, but neither is required. A browser whose referrer policy
withholds the origin sends the literal `null`, which describes a policy rather
than a sender, so the check defers to the cookie instead of failing shut. For
the same reason the consent page sets `Referrer-Policy: same-origin` rather than
`no-referrer`: under `no-referrer` the browser sends `Origin: null` on the
page's own form, so the page would refuse every submission it produced.

A flow that was never approved cannot be redeemed at `/callback` at all.

One caveat: the binding cookie is reused across concurrent authorizations in the
same browser, so opening two clients at once works. That means an attacker who
can already write cookies for this origin, typically from a compromised
subdomain, could fix the value. The `Origin` check is what covers that case.

### Credentials

- **Tokens the proxy issues are opaque**, stored as SHA-256 hashes. A database
  disclosure yields no usable credentials.
- **Provider tokens are encrypted at rest** with AES-256-GCM and never leave the
  process. Clients cannot use them directly against the provider's own API.
- **PKCE with S256 is mandatory.** Authorization requests without it are refused.
- **Authorization codes are single use**, deleted on read in the same statement
  that returns them.
- **Refresh tokens rotate, and reuse is acted on.** A rotated token is kept and
  marked used rather than deleted. Presenting it again means either the client
  replayed it or someone else holds a copy, and only one of those is survivable,
  so the session is revoked.
- **Sessions expire.** A refresh token dies after `REFRESH_TOKEN_TTL` since it
  was issued, and the session behind it after `SESSION_TTL` whatever happens.
  `/revoke` ends one immediately.
- **Revocation beats an in-flight refresh.** A request that loaded an expired
  provider token can be parked on the per-session refresh lock while another
  request revokes the session. It re-reads under the lock and aborts if the
  session has gone, and a write against a missing session reports that rather
  than passing silently, so a revoked session cannot refresh or forward.
- **Redirect URIs are checked on registration and matched exactly on use.**
  https anywhere, http only on loopback, and private-use schemes for native
  clients. No fragments.

### Deployment

- **TLS is assumed for anything a browser touches.** `PUBLIC_URL` and
  `UPSTREAM_ISSUER` are refused at boot if they use `http` against a
  non-loopback host, rather than silently downgrading every exchange.
  `UPSTREAM_MCP_URL` is deliberately held to a weaker rule, because the ordinary
  deployment puts the MCP server next to this proxy on a private network where
  plain `http` is normal. That hop still carries the provider's token, so it is
  logged as a warning at boot when it is neither TLS nor loopback.
- **Unauthenticated endpoints are rate limited** per peer address, in
  `routes()` rather than inside each handler, so the whole list is visible in
  one place. The caps differ by what an endpoint can be made to do:
  `/register` and `/authorize` create rows for a caller holding nothing, so
  they are capped tightly; `/consent`, `/callback`, `/token` and `/revoke` all
  demand a high-entropy credential first, so they share a much looser backstop.
  A tight cap there would buy little and would break a hosted MCP client whose
  users all refresh from one egress address. `X-Forwarded-For` is deliberately
  ignored, because honouring a client-supplied header would let an attacker
  pick a fresh bucket per request; behind a load balancer these are therefore
  caps on total rate, not per-caller ones.

### What this does not fix

**The proxy inherits whatever the provider grants.** If the provider cannot
issue scoped tokens — Forgejo currently cannot, its OAuth2 scopes are not
implemented — then the credential this proxy holds carries the authorizing
user's full rights. The proxy changes who holds the token, not how much it can
do. This is why the consent screen says the client can do anything the account
can.

## Development

```bash
go build ./...
go vet ./...
go test ./...
docker build -t mcp-oauth-proxy:dev .
```

The authorization tests exercise single use, rotation and reuse detection
against real SQL, so they need a database. They skip unless `TEST_DATABASE_URL`
is set, which keeps `go test ./...` working on a machine with no Postgres:

```bash
docker run -d --name mcp-oauth-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=proxytest -p 55432:5432 postgres:17-alpine
```

```bash
TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:55432/proxytest?sslmode=disable" go test ./...
```

The tests stand up a stub provider that redirects straight back from
`/authorize` and returns a known token, so the whole flow runs without a
browser.

Running the proxy for real needs a PostgreSQL instance and an OAuth provider.
