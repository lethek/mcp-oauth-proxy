# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

CI (`.github/workflows/build.yaml`) runs these, in this order:

```bash
gofmt -l .          # must print nothing
go vet ./...
go test -race ./...
go build ./...
```

The database-backed tests skip unless `TEST_DATABASE_URL` is set. Under CI they fail instead of skipping. CI uses `postgres:17-alpine`:

```bash
docker run -d --name mcp-oauth-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=proxytest -p 55432:5432 postgres:17-alpine
TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:55432/proxytest?sslmode=disable" go test -race ./...
```

Run a single test with `go test -run TestName ./...`. `newTestStore` in `store_test.go` clears the tables before each test, so point it at a throwaway database.

## Architecture

The repo is one Go package (`main`) at the root, built into one binary. Files are split by concern, and tests sit beside them. HTML templates in `templates/` are embedded by `ui.go`. Styles are inlined into the pages because the page CSP blocks linked stylesheets.

The proxy adds an OAuth 2.1 authorization server in front of MCP servers that have none. It delegates sign-in to an upstream provider. It issues its own tokens to MCP clients and keeps the provider's token encrypted in Postgres. The README's "How a request flows" diagram shows the sequence.

- `config.go` reads and validates all environment variables once in `LoadConfig`. Bad config fails at boot rather than falling back to a default.
- `main.go` holds `routes()`, which is the full route table. Every route gets its rate limit there, never inside a handler. It also runs the background sweep.
- `oauth.go` serves registration, `/authorize`, `/callback`, `/token`, `/revoke` and the metadata documents. `consent.go` renders the consent page that every flow must pass before it reaches the provider.
- `proxy.go` serves `handleMCP`. It checks the bearer token, refreshes the provider token if needed, swaps in the target's credential and reverse-proxies to the MCP server.
- `settings.go` serves `/settings`, where users enrol their own credentials for `per_user` targets. It runs its own login, separate from the consent flow.
- `store.go` holds all SQL. The schema is one idempotent `CREATE TABLE IF NOT EXISTS` / `ALTER` block that runs on every boot, with no migration framework. Single-use codes and refresh rotation with reuse detection are enforced in SQL.
- `crypto.go` holds the `sealer` (AES-256-GCM). It authenticates a purpose string, which is bound to a target stamp with `boundPurpose`.
- `cimd.go` fetches Client ID Metadata Documents. It blocks private addresses at dial time, refuses redirects and caps the response size.

### Targets and credential modes

A `Target` is one upstream MCP server. A single-target deployment has an unnamed target served at `/mcp`. `TARGETS=a,b` serves `/a/mcp` and `/b/mcp`, configured through `TARGET_<NAME>_*` variables. Each target has a credential mode: `provider_token` forwards the user's provider token, `static` sends fixed headers, and `per_user` sends headers each user enrolled at `/settings`.

### Target stamps

`Target.Stamp()` in `stamp.go` hashes everything that decides where a credential is sent: the name, the upstream URL, the mode, and the user header names and prefixes. Flows, sessions and stored credentials carry the stamp. A process refuses rows stamped for a different definition, so replicas mid-rollout cannot use each other's credentials. Changing what `Stamp()` hashes signs everyone out. The sweep records served stamps in `stamp_seen`, then deletes credentials that are unsaved and unserved for 7 days. If recording fails, the stray sweep is skipped.

### Naming

"Upstream" means the OAuth provider in `upstream.go` and in `Upstream*` config fields. It means the MCP server in `proxy.go` and in `UpstreamMCP`.

## Tests

`oauth_test.go` has the `harness` (`newHarness`, `newHarnessWith`). It starts a stub provider that redirects straight back from `/authorize`, plus a stub MCP server, so full flows run without a browser. Regression tests are named after the behaviour they protect. Several files group tests by the review that produced them, such as `reviewfindings_test.go` and `planefindings_test.go`.

## Conventions

- Commit subjects use Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`). Branches use `feat/`, `fix/` or `refactor/` prefixes, and PRs target `main`.
- Comments explain why, often citing the RFC. Match that density.
- Text files are LF only (`.gitattributes`), so the CI format check passes on Windows checkouts.
- Config or behaviour changes need matching updates to `README.md`, which documents every environment variable and endpoint.
