// edge-guard is a real-world xngin agent: IP allow/deny ACLs plus a
// per-client token-bucket rate limiter (per IPv4 address, per IPv6 /64).
// It demonstrates the xngin-go SDK.
//
// Flags:
//
//	-listen unix:/run/xngin/edge-guard.sock   (or tcp:127.0.0.1:7777)
//	-allow 10.0.0.0/8,192.168.0.0/16          (optional allowlist CIDRs)
//	-deny  203.0.113.0/24                     (denylist CIDRs)
//	-rate  50                                 (requests/sec per IPv4 or IPv6 /64, 0=off)
//	-burst 20                                 (bucket size)
//	-max-buckets 100000                       (rate-limit table cap)
//	-ttl   5                                  (verdict cache-ttl seconds)
package main

import (
	"container/list"
	"context"
	"flag"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xngin/xngin-go/xngin"
)

const defaultMaxBuckets = 100000

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

type guard struct {
	allow []*net.IPNet
	deny  []*net.IPNet
	rate  float64
	burst float64
	ttl   uint32

	// maxBuckets caps the rate-limit table; the least recently used
	// bucket is evicted when a new key would exceed it.
	maxBuckets int
	now        func() time.Time

	mu      sync.Mutex
	buckets map[string]*list.Element // values are *bucket
	lru     list.List                // front = most recently used
}

func newGuard() *guard {
	return &guard{
		buckets:    map[string]*list.Element{},
		maxBuckets: defaultMaxBuckets,
		now:        time.Now,
	}
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func contains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// rateKey returns the rate-limit bucket key for ip. IPv6 clients are
// grouped by /64 since a single subscriber typically controls a whole
// /64 and could otherwise mint a fresh bucket per address.
func rateKey(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return "unknown"
}

// idleWindow is how long a bucket takes to refill from empty; an entry
// idle at least that long is full again, so dropping it loses no state.
func (g *guard) idleWindow() time.Duration {
	if g.rate <= 0 {
		return 0
	}
	return time.Duration(g.burst / g.rate * float64(time.Second))
}

// evictLocked drops idle buckets from the LRU tail, then the oldest
// buckets until there is room for one more entry. Callers hold g.mu.
func (g *guard) evictLocked(now time.Time) {
	idle := g.idleWindow()
	for e := g.lru.Back(); e != nil; e = g.lru.Back() {
		b := e.Value.(*bucket)
		if now.Sub(b.last) < idle && (g.maxBuckets <= 0 || g.lru.Len() < g.maxBuckets) {
			return
		}
		g.lru.Remove(e)
		delete(g.buckets, b.key)
	}
}

// takeToken returns true when a request for key is within its rate budget.
func (g *guard) takeToken(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	var b *bucket
	if e := g.buckets[key]; e != nil {
		b = e.Value.(*bucket)
		g.lru.MoveToFront(e)
	} else {
		g.evictLocked(now)
		b = &bucket{key: key, tokens: g.burst, last: now}
		g.buckets[key] = g.lru.PushFront(b)
	}
	b.tokens += now.Sub(b.last).Seconds() * g.rate
	if b.tokens > g.burst {
		b.tokens = g.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (g *guard) Handle(_ context.Context, r *xngin.Request) (*xngin.Verdict, error) {
	src := r.GetIP("src-ip")
	key := rateKey(src)

	v := xngin.Allow()
	if g.ttl > 0 {
		v.CacheTTL = g.ttl
	}

	if g.deny != nil && src != nil && contains(g.deny, src) {
		return &xngin.Verdict{
			Action: "deny", Status: 403,
			Reason: "denylist hit", Score: 100,
			CacheTTL: g.ttl,
			Vars:     map[string]string{"guard": "denylist"},
		}, nil
	}

	if len(g.allow) > 0 && (src == nil || !contains(g.allow, src)) {
		return &xngin.Verdict{
			Action: "deny", Status: 403,
			Reason: "not in allowlist", Score: 80,
			Vars: map[string]string{"guard": "allowlist-miss"},
		}, nil
	}

	if g.rate > 0 && !g.takeToken(key) {
		return &xngin.Verdict{
			Action: "deny", Status: 429,
			Reason: "rate limit exceeded", Score: 60,
			Vars: map[string]string{"guard": "ratelimit"},
			SetHeaders: map[string]string{
				"retry-after": "1",
			},
		}, nil
	}

	v.Vars = map[string]string{"guard": "pass"}
	return v, nil
}

func main() {
	var (
		listen = flag.String("listen", "unix:/tmp/xngin-edge-guard.sock",
			"unix:/path or tcp:host:port")
		allow = flag.String("allow", "", "comma-separated allowlist CIDRs")
		deny  = flag.String("deny", "", "comma-separated denylist CIDRs")
		rate  = flag.Float64("rate", 0, "requests/sec per client IPv4 address or IPv6 /64 (0=off)")
		burst = flag.Float64("burst", 20, "token bucket size")
		ttl   = flag.Uint("ttl", 0, "verdict cache-ttl seconds")
		maxB  = flag.Int("max-buckets", defaultMaxBuckets,
			"max tracked rate-limit buckets (LRU-evicted)")
	)
	flag.Parse()

	if *maxB < 1 {
		log.Fatalf("bad -max-buckets: must be >= 1")
	}
	g := newGuard()
	g.ttl, g.maxBuckets = uint32(*ttl), *maxB
	var err error
	if *allow != "" {
		if g.allow, err = parseCIDRs(*allow); err != nil {
			log.Fatalf("bad -allow: %v", err)
		}
	}
	if *deny != "" {
		if g.deny, err = parseCIDRs(*deny); err != nil {
			log.Fatalf("bad -deny: %v", err)
		}
	}
	g.rate, g.burst = *rate, *burst

	srv := &xngin.Server{
		Handler: g,
		AgentID: "edge-guard/1.0",
		Logger:  log.Default(),
	}
	log.Printf("edge-guard listening on %s (rate=%v/s burst=%v)", *listen, *rate, *burst)
	log.Fatal(srv.ListenAndServe(*listen))
}
