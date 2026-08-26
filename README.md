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
| `PUBLIC_URL` | The origin clients dial, e.g. `https://git-mcp.example.com`. Used as the OAuth issuer and as the base of every advertised URL, so it must match reality. No trailing slash. |
| `UPSTREAM_MCP_URL` | The MCP server to forward to once a request is authorized. |
| `UPSTREAM_ISSUER` | The OAuth provider's origin. Discovery is read from `/.well-known/openid-configuration`, falling back to `/.well-known/oauth-authorization-server`. |
| `UPSTREAM_CLIENT_ID` | Client id of the application you registered with the provider. |
| `UPSTREAM_CLIENT_SECRET` | Its secret. |
| `UPSTREAM_SCOPES` | Space-separated. Default `openid profile email`. |
| `DATABASE_URL` | PostgreSQL connection string. The schema is created on boot. |
| `ENCRYPTION_KEY` | Base64 of exactly 32 bytes. Encrypts provider tokens at rest with AES-256-GCM. Changing it invalidates every stored session. |
| `LISTEN_ADDR` | Default `:8080`. |

Generate a key with:

```bash
openssl rand -base64 32
```

The application you register with the provider must use
`PUBLIC_URL` + `/callback` as its redirect URI.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource` | RFC 9728 metadata. Also served at `/mcp` suffix. |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata. |
| `/register` | RFC 7591 dynamic client registration. |
| `/authorize`, `/callback`, `/token` | Authorization code flow with PKCE. |
| `/mcp` | Authenticated pass-through to the upstream MCP server. |
| `/healthz` | Liveness. Reports only on this process. |

## Security notes

- **Tokens the proxy issues are opaque**, stored as SHA-256 hashes. A database
  disclosure yields no usable credentials.
- **Provider tokens are encrypted at rest** with AES-256-GCM and never leave the
  process. Clients cannot use them directly against the provider's own API.
- **PKCE with S256 is mandatory.** Authorization requests without it are refused.
- **Authorization codes and refresh tokens are single use**, deleted on read in
  the same statement that returns them.
- **Redirect URIs must match** one registered by that client, exactly.
- **The proxy inherits whatever the provider grants.** If the provider cannot
  issue scoped tokens — Forgejo currently cannot, its OAuth2 scopes are not
  implemented — then the credential this proxy holds carries the authorizing
  user's full rights. The proxy changes who holds the token, not how much it
  can do.

## Development

```bash
go build ./...
go vet ./...
docker build -t mcp-oauth-proxy:dev .
```

Running it needs a PostgreSQL instance and an OAuth provider. For an end-to-end
run without a browser, point `UPSTREAM_ISSUER` at a stub provider that redirects
straight back from `/authorize` and returns a known token from its token
endpoint.
