package main

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is a fixed-window counter keyed by client address. Several of these
// exist, one per class of endpoint; routes() decides which endpoint draws on
// which.
//
// The key comes from the peer address, or from X-Forwarded-For when the
// deployment declares how many proxies sit in front (TRUSTED_PROXY_HOPS).
//
// Ignoring the header entirely was the previous behaviour and is worse than it
// sounds: behind an ingress every caller shares one bucket, so a single
// anonymous client exceeding the cap locks out registration and authorization
// for everyone. A total cap in a shared bucket is a remote kill switch rather
// than a defence. Honouring the header blindly would be the opposite mistake,
// letting a caller pick a fresh key per request, so the number of hops has to
// be stated rather than guessed.
//
// IPv6 keys are reduced to their /64. A single host is routinely given one, so
// keying on the full address hands out an effectively unlimited supply of fresh
// buckets.
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

// clientKey identifies the caller for rate-limiting purposes.
//
// trustedHops is how many reverse proxies sit in front of this process. With
// none, the peer address is used and X-Forwarded-For is ignored, because it is
// then entirely caller-supplied. With one or more, that many entries are walked
// back from the RIGHT of the header: each hop appends the address it saw, so the
// rightmost entries are the ones our own infrastructure wrote and the caller
// cannot forge. Anything further left is attacker-controlled and never read.
func clientKey(r *http.Request, trustedHops int) string {
	peer := hostOnly(r.RemoteAddr)
	if trustedHops <= 0 {
		return aggregate(peer)
	}

	forwarded := r.Header.Values("X-Forwarded-For")
	var chain []string
	for _, v := range forwarded {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				chain = append(chain, p)
			}
		}
	}
	// The peer is the last hop and is not in the header, so one trusted hop
	// means the peer itself, two means the final header entry, and so on.
	idx := len(chain) - (trustedHops - 1)
	if trustedHops == 1 || idx < 0 || idx >= len(chain) {
		return aggregate(peer)
	}
	return aggregate(hostOnly(chain[idx]))
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// aggregate reduces an IPv6 address to its /64. A host is routinely allocated a
// whole /64, so keying on the full address would let one caller rotate through
// more buckets than the limiter can hold, which both evades the limit and fills
// the table that refuses new keys when full.
func aggregate(host string) string {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return host
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// limited caps an endpoint by caller address. Applying this at the routing
// table rather than inside each handler means the limits for every endpoint are
// visible in one list, and a new endpoint cannot quietly ship without one.
func limited(l *limiter, trustedHops int, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := clientKey(r, trustedHops)
		if !l.allow(key) {
			slog.Warn("rate limited", "peer", key, "path", r.URL.Path)
			w.Header().Set("Retry-After", "60")
			oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many requests from this address")
			return
		}
		h(w, r)
	}
}
