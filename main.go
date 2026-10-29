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
	"fmt"
	"log/slog"
	"net/http"
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

	// reg holds the targets being served. A request loads its snapshot once and
	// uses it throughout.
	reg *registry

	// cimd resolves https client ids to their metadata documents.
	cimd *cimdClient

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

	// mcpLimit is separate from credentialLimit on purpose. MCP is by far the
	// busiest route, and sharing a bucket let one chatty session exhaust it and
	// then refuse /token, /callback, /consent and /settings for everyone. A
	// backstop on the proxied path must not be able to take the authorization
	// surface down with it.
	mcpLimit *limiter
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

	seal, err := newSealer(cfg.EncryptionKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := NewStore(ctx, cfg.DatabaseURL, cfg.RefreshTokenTTL, cfg.SessionTTL)
	if err != nil {
		return err
	}
	defer store.Close()

	var reg *registry
	if cfg.AdminEnabled() {
		store.EnableAdminTargets(seal, cfg.AllowedUpstreamHosts, cfg.AllowedUpstreamNetworks)
		reg = newAdminRegistry(ctx, cfg, store)
		// Failing here rather than serving config targets alone: a replica that
		// cannot read the table would answer 503 for every admin target's session
		// anyway, and starting without it hides the fault.
		if err := reg.Rebuild(ctx); err != nil {
			return fmt.Errorf("loading admin targets: %w", err)
		}
		go reg.Poll(ctx, pollInterval)
	} else {
		snap, err := newSnapshot(cfg.Targets, cfg, nil)
		if err != nil {
			return err
		}
		reg = &registry{}
		reg.Store(snap)
	}
	for _, e := range reg.Load().entries {
		if isPlaintextURL(e.Target.UpstreamMCP) {
			slog.Warn("the MCP server is reached over plain http; the credential crosses that hop in the clear",
				"target", e.Target.Name, "upstream_mcp", e.Target.UpstreamMCP)
		}
	}

	s := &Server{
		cfg:             cfg,
		store:           store,
		upstream:        NewUpstream(cfg),
		sealer:          seal,
		reg:             reg,
		cimd:            newCIMDClient(),
		registerLimit:   newLimiter(20, time.Minute),
		flowLimit:       newLimiter(120, time.Minute),
		credentialLimit: newLimiter(600, time.Minute),
		mcpLimit:        newLimiter(6000, time.Minute),
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
		// ReadTimeout bounds the body as well as the headers. Without it a slow
		// body holds a goroutine indefinitely, and the rate limiter counts
		// requests rather than open connections so it does not help. Generous,
		// because an MCP request body can be large; it only has to be finite.
		ReadTimeout: 2 * time.Minute,
		// No WriteTimeout: streamable HTTP responses are long-lived by design.
		IdleTimeout: 120 * time.Second,
		// The default is 1 MB across all headers, which is more than any of these
		// endpoints needs and is where an oversized state or client_id would
		// otherwise arrive.
		MaxHeaderBytes: 64 << 10,
	}

	served := reg.Load()
	errCh := make(chan error, 1)
	go func() {
		// Targets are logged individually. A single line cannot describe several
		// of them, and the old one printed an empty upstream and only the first
		// target's resource, which read as a misconfiguration rather than a
		// summary.
		// Includes admin targets, as loaded at boot.
		for _, e := range served.entries {
			t := e.Target
			slog.Info("serving target",
				"target", t.Name,
				"source", orDefault(t.Source, SourceConfig),
				"path", t.MCPPath(),
				"resource", t.Resource,
				"credential_mode", t.Mode,
				"upstream_mcp", t.UpstreamMCP)
		}
		slog.Info("listening",
			"version", version,
			"addr", cfg.ListenAddr,
			"public_url", cfg.PublicURL,
			"targets", len(served.entries),
			"cimd_enabled", cfg.CIMDEnabled)
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

	// RFC 9728 derives a resource's metadata path from the resource's own path,
	// so each target gets its own document. The bare path is only meaningful when
	// there is a single resource to mean; with several it says so rather than
	// naming one of them arbitrarily.
	//
	// Read once: the single or multi route shape is fixed at boot. Admin targets
	// will require named mode, so it cannot change while the process runs.
	multi := s.reg.Load().MultiTarget()
	if multi {
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleAmbiguousResourceMetadata)
		mux.HandleFunc("GET /.well-known/oauth-protected-resource/{target}/mcp", s.handleProtectedResourceMetadata)
	} else {
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
		mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.handleProtectedResourceMetadata)
	}
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/mcp", s.handleAuthorizationServerMetadata)

	// Every unauthenticated endpoint is capped here rather than inside its
	// handler, so this list is the whole story and adding a route without a limit
	// is a visible omission rather than a forgotten line.
	mux.HandleFunc("POST /register", limited(s.registerLimit, s.cfg, s.handleRegister))
	mux.HandleFunc("GET /authorize", limited(s.flowLimit, s.cfg, s.handleAuthorize))
	// The consent screen stands between /authorize and the provider. Without it
	// an anonymous registration could be used to collect someone else's
	// credentials, so nothing may reach /callback that did not pass through here.
	// The rest each demand a credential the caller must already hold, so they
	// share the looser backstop. /token in particular is dialled by the MCP
	// client rather than a browser, and a hosted client refreshes for every one
	// of its users from a single address.
	mux.HandleFunc("POST /consent", limited(s.credentialLimit, s.cfg, s.handleConsent))
	mux.HandleFunc("GET /callback", limited(s.credentialLimit, s.cfg, s.handleCallback))
	mux.HandleFunc("POST /token", limited(s.credentialLimit, s.cfg, s.handleToken))
	mux.HandleFunc("POST /revoke", limited(s.credentialLimit, s.cfg, s.handleRevoke))

	// The MCP endpoints are capped on their own bucket. They demand a credential
	// and are the busiest route, so a shared cap would let ordinary traffic here
	// refuse the authorization endpoints; an unauthenticated request still costs
	// a database round trip, so leaving them uncapped is not right either.
	//
	// Named targets are looked up per request, so the table does not have to be
	// rebuilt when the set of targets changes. An unknown name answers 404 in the
	// handler.
	mcp := limited(s.mcpLimit, s.cfg, s.handleMCP)
	if multi {
		mux.HandleFunc("/{target}/mcp", mcp)
		mux.HandleFunc("/{target}/mcp/{rest...}", mcp)
	} else {
		mux.HandleFunc("/mcp", mcp)
		mux.HandleFunc("/mcp/", mcp)
	}

	// The enrolment page is always served, because whether any target wants a
	// credential of the user's own can change while the process runs. It runs its
	// own login rather than sharing the consent flow, which is bound to one MCP
	// client's authorization and cannot answer "who is this browser" outside it.
	mux.HandleFunc("GET /settings", limited(s.flowLimit, s.cfg, s.handleSettings))
	mux.HandleFunc("POST /settings/logout", limited(s.credentialLimit, s.cfg, s.handleSettingsLogout))
	mux.HandleFunc("GET /settings/callback", limited(s.credentialLimit, s.cfg, s.handleSettingsCallback))
	mux.HandleFunc("POST /settings", limited(s.credentialLimit, s.cfg, s.handleSettingsSave))

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
		s.sweepOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) sweepOnce(ctx context.Context) {
	// Record what this process serves before anything is deleted on the
	// strength of it. A failure here skips the stray credential sweep, which
	// would otherwise judge this process's own definitions unserved, but it
	// does not stop the expiry sweep.
	snap := s.reg.Load()
	served := make([]StampedName, 0, len(snap.entries))
	for _, e := range snap.entries {
		served = append(served, StampedName{e.Target.Name, e.Stamp})
	}
	recorded := true
	if err := s.store.RecordServedStamps(ctx, served); err != nil {
		recorded = false
		slog.Warn("recording served stamps failed; skipping the stray credential sweep", "err", err)
	}
	if err := s.store.Sweep(ctx); err != nil {
		slog.Warn("sweep failed", "err", err)
	}
	if !recorded {
		return
	}
	if err := s.store.SweepStrayCredentials(ctx); err != nil {
		slog.Warn("stray credential sweep failed", "err", err)
	}
}
