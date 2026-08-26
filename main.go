// Command mcp-oauth-proxy fronts an MCP server that has no OAuth support with
// the authorization surface the MCP specification requires, delegating the
// actual authentication to an upstream OAuth provider.
//
// It exists because MCP clients expect to register themselves dynamically,
// while most providers — Forgejo among them — only offer applications you
// register by hand. The proxy bridges that: it presents registration, issues
// its own short-lived tokens, and keeps the provider's token to itself.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is stamped at build time via -ldflags.
var version = "dev"

type Server struct {
	cfg      *Config
	store    *Store
	upstream *Upstream
	sealer   *sealer
	proxy    http.Handler

	// The caps differ by what each endpoint can be made to do, not by how
	// sensitive it sounds.
	//
	// registerLimit and flowLimit guard the two endpoints that create rows for a
	// caller holding nothing at all, so they are the only real resource cap.
	// credentialLimit covers endpoints that need a high-entropy credential
	// before they do anything, where a tight per-address cap would buy very
	// little and would punish a hosted client whose users share one egress
	// address. It is a brute-force backstop, not a resource cap.
	registerLimit   *limiter
	flowLimit       *limiter
	credentialLimit *limiter
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	upstreamURL, err := url.Parse(cfg.UpstreamMCP)
	if err != nil {
		return err
	}

	seal, err := newSealer(cfg.EncryptionKey)
	if err != nil {
		return err
	}

	if cfg.IsPlaintextUpstream() {
		slog.Warn("the MCP server is reached over plain http; the provider's token crosses that hop in the clear",
			"upstream_mcp", cfg.UpstreamMCP)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := NewStore(ctx, cfg.DatabaseURL, cfg.RefreshTokenTTL, cfg.SessionTTL)
	if err != nil {
		return err
	}
	defer store.Close()

	s := &Server{
		cfg:             cfg,
		store:           store,
		upstream:        NewUpstream(cfg),
		sealer:          seal,
		proxy:           newReverseProxy(upstreamURL),
		registerLimit:   newLimiter(20, time.Minute),
		flowLimit:       newLimiter(120, time.Minute),
		credentialLimit: newLimiter(600, time.Minute),
	}

	// Confirm the provider is discoverable at boot. This is a warning rather
	// than a failure: the provider may simply be starting up alongside us, and
	// discovery is retried on the first request that needs it.
	if _, err := s.upstream.Meta(ctx); err != nil {
		slog.Warn("upstream discovery is not answering yet", "issuer", cfg.UpstreamIssuer, "err", err)
	} else {
		slog.Info("upstream provider discovered", "issuer", cfg.UpstreamIssuer)
	}

	go s.sweep(ctx)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 15 * time.Second,
		// No WriteTimeout: streamable HTTP responses are long-lived by design.
		IdleTimeout: 120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening",
			"version", version,
			"addr", cfg.ListenAddr,
			"public_url", cfg.PublicURL,
			"upstream_mcp", cfg.UpstreamMCP,
			"resource", cfg.ResourceURI())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// RFC 9728 requires the bare path; MCP clients may also probe the
	// resource-specific form, so both are served.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/mcp", s.handleAuthorizationServerMetadata)

	// Every unauthenticated endpoint is capped here rather than inside its
	// handler, so this list is the whole story and adding a route without a limit
	// is a visible omission rather than a forgotten line.
	mux.HandleFunc("POST /register", limited(s.registerLimit, s.handleRegister))
	mux.HandleFunc("GET /authorize", limited(s.flowLimit, s.handleAuthorize))
	// The consent screen stands between /authorize and the provider. Without it
	// an anonymous registration could be used to collect someone else's
	// credentials, so nothing may reach /callback that did not pass through here.
	// The rest each demand a credential the caller must already hold, so they
	// share the looser backstop. /token in particular is dialled by the MCP
	// client rather than a browser, and a hosted client refreshes for every one
	// of its users from a single address.
	mux.HandleFunc("POST /consent", limited(s.credentialLimit, s.handleConsent))
	mux.HandleFunc("GET /callback", limited(s.credentialLimit, s.handleCallback))
	mux.HandleFunc("POST /token", limited(s.credentialLimit, s.handleToken))
	mux.HandleFunc("POST /revoke", limited(s.credentialLimit, s.handleRevoke))

	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/mcp/", s.handleMCP)

	// Liveness only. It says this process is up, not that the provider or the
	// MCP server behind it are, so it can never take the pod down for their sake.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	return mux
}

// sweepInterval is how often expired rows are cleared. The first pass runs at
// startup rather than after the first tick: a process that restarts more often
// than this would otherwise never sweep at all, and under a rollout or a crash
// loop that is exactly what happens. The sweep is what makes an expired
// session's provider token stop existing rather than merely stop being
// reachable, so skipping it is not only a question of table size.
const sweepInterval = 30 * time.Minute

func (s *Server) sweep(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		if err := s.store.Sweep(ctx); err != nil {
			slog.Warn("sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
