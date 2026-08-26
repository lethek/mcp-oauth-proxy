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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := NewStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	s := &Server{
		cfg:      cfg,
		store:    store,
		upstream: NewUpstream(cfg),
		sealer:   seal,
		proxy:    newReverseProxy(upstreamURL),
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

	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /callback", s.handleCallback)
	mux.HandleFunc("POST /token", s.handleToken)

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

func (s *Server) sweep(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.store.Sweep(ctx); err != nil {
				slog.Warn("sweep failed", "err", err)
			}
		}
	}
}
