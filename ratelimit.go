package main

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// limiter is a fixed-window counter keyed by client address. Several of these
// exist, one per class of endpoint; routes() decides which endpoint draws on
// which.
//
// It deliberately ignores X-Forwarded-For: the proxy has no way to know which
// hop it can trust, and honouring a client-supplied header would let an
// attacker pick a fresh key per request. Behind a load balancer every caller
// therefore shares one bucket, which makes these caps on total rate rather than
// per-user ones.
type limiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	count int
	reset time.Time
}

// maxTrackedKeys bounds the limiter's own memory, so it cannot become the
// exhaustion vector it exists to prevent.
const maxTrackedKeys = 10000

func newLimiter(limit int, w time.Duration) *limiter {
	return &limiter{limit: limit, window: w, windows: make(map[string]*window)}
}

func (l *limiter) allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// An already-tracked caller is answered from its own window. Checking the
	// cap first would refuse established callers during a flood, which punishes
	// exactly the wrong people: serving them does not grow the map.
	if w, ok := l.windows[key]; ok && !now.After(w.reset) {
		if w.count >= l.limit {
			return false
		}
		w.count++
		return true
	}

	// Past here the key is new or its window has lapsed, so this inserts.
	if len(l.windows) >= maxTrackedKeys {
		for k, v := range l.windows {
			if now.After(v.reset) {
				delete(l.windows, k)
			}
		}
		// Still full: every tracked key is inside its window, so we are under a
		// distributed flood. Refuse rather than grow.
		if len(l.windows) >= maxTrackedKeys {
			return false
		}
	}

	l.windows[key] = &window{count: 1, reset: now.Add(l.window)}
	return true
}

// clientKey is the remote address without its port, so a caller cannot get a
// fresh bucket per connection.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limited caps an endpoint by caller address. Applying this at the routing
// table rather than inside each handler means the limits for every endpoint are
// visible in one list, and a new endpoint cannot quietly ship without one.
func limited(l *limiter, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientKey(r)) {
			slog.Warn("rate limited", "peer", clientKey(r), "path", r.URL.Path)
			w.Header().Set("Retry-After", "60")
			oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many requests from this address")
			return
		}
		h(w, r)
	}
}
