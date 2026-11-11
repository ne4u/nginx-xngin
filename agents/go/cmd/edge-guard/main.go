// edge-guard is a real-world xngin agent: IP allow/deny ACLs plus a
// per-IP token-bucket rate limiter. It demonstrates the xngin-go SDK.
//
// Flags:
//
//	-listen unix:/run/xngin/edge-guard.sock   (or tcp:127.0.0.1:7777)
//	-allow 10.0.0.0/8,192.168.0.0/16          (optional allowlist CIDRs)
//	-deny  203.0.113.0/24                     (denylist CIDRs)
//	-rate  50                                 (requests/sec per IP, 0=off)
//	-burst 20                                 (bucket size)
//	-ttl   5                                  (verdict cache-ttl seconds)
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xngin/xngin-go/xngin"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type guard struct {
	allow []*net.IPNet
	deny  []*net.IPNet
	rate  float64
	burst float64
	ttl   uint32

	mu      sync.Mutex
	buckets map[string]*bucket
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

// takeToken returns true when a request from ip is within its rate budget.
func (g *guard) takeToken(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	b := g.buckets[key]
	now := time.Now()
	if b == nil {
		b = &bucket{tokens: g.burst, last: now}
		g.buckets[key] = b
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
	key := src.String()
	if key == "<nil>" || key == "" {
		key = "unknown"
	}

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
		rate  = flag.Float64("rate", 0, "requests/sec per client IP (0=off)")
		burst = flag.Float64("burst", 20, "token bucket size")
		ttl   = flag.Uint("ttl", 0, "verdict cache-ttl seconds")
	)
	flag.Parse()

	g := &guard{buckets: map[string]*bucket{}, ttl: uint32(*ttl)}
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
