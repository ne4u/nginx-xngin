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
//	-tls-cert /path/agent.pem                 (enable TLS; engine is client)
//	-tls-key  /path/agent.key
//	-tls-client-ca /path/ca.pem               (verify engine certs -> mTLS)
package main

import (
	"container/list"
	"context"
	"flag"
	"log"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/xngin/xngin-go/xngin"
)

const defaultMaxBuckets = 100000

// numShards spreads the bucket table over independent locks so hot
// clients can't serialize every request through one mutex.
const numShards = 64

type bucket struct {
	key    netip.Addr
	tokens float64
	last   time.Time
}

type shard struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*list.Element // values are *bucket
	lru     list.List                    // front = most recently used
}

type guard struct {
	allow []*net.IPNet
	deny  []*net.IPNet
	rate  float64
	burst float64
	ttl   uint32

	// maxBuckets caps the rate-limit table; the least recently used
	// bucket is evicted when a new key would exceed it. The cap is
	// per-shard (maxBuckets/numShards, min 1), so the global bound is
	// approximate.
	maxBuckets int
	now        func() time.Time

	shards [numShards]shard
}

func newGuard() *guard {
	g := &guard{
		maxBuckets: defaultMaxBuckets,
		now:        time.Now,
	}
	for i := range g.shards {
		g.shards[i].buckets = map[netip.Addr]*list.Element{}
	}
	return g
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

// rateKey returns the rate-limit bucket key for ip as raw address
// bytes (no string formatting on the hot path). IPv6 clients are
// grouped by /64 since a single subscriber typically controls a whole
// /64 and could otherwise mint a fresh bucket per address.
func rateKey(ip net.IP) netip.Addr {
	if ip == nil {
		return netip.Addr{}
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	a = a.Unmap()
	if a.Is6() {
		a = netip.PrefixFrom(a, 64).Masked().Addr()
	}
	return a
}

// shardOf maps a key to its shard with inline FNV-1a over the raw
// address bytes — no hashing allocation per request.
func (g *guard) shardOf(k netip.Addr) *shard {
	b := k.As16()
	h := uint64(14695981039346656037)
	for _, x := range b {
		h ^= uint64(x)
		h *= 1099511628211
	}
	return &g.shards[h&(numShards-1)]
}

// idleWindow is how long a bucket takes to refill from empty; an entry
// idle at least that long is full again, so dropping it loses no state.
func (g *guard) idleWindow() time.Duration {
	if g.rate <= 0 {
		return 0
	}
	return time.Duration(g.burst / g.rate * float64(time.Second))
}

// denyTTL is the cache-ttl attached to deny verdicts. It is clamped
// into the bucket refill window so a cached deny can never outlive the
// limiter's own memory of the client: once the window passes the agent
// is consulted again and the client may be allowed.
func (g *guard) denyTTL() uint32 {
	if g.ttl == 0 {
		return 0
	}
	if g.rate <= 0 {
		return g.ttl
	}
	win := uint32(math.Ceil(g.burst / g.rate))
	if win == 0 {
		return 0
	}
	if g.ttl < win {
		return g.ttl
	}
	return win
}

func (g *guard) perShardMax() int {
	m := g.maxBuckets / numShards
	if m < 1 {
		m = 1
	}
	return m
}

// evictLocked drops idle buckets from the LRU tail, then the oldest
// buckets until there is room for one more entry. Callers hold s.mu.
func (s *shard) evictLocked(now time.Time, idle time.Duration, max int) {
	for e := s.lru.Back(); e != nil; e = s.lru.Back() {
		b := e.Value.(*bucket)
		if now.Sub(b.last) < idle && s.lru.Len() < max {
			return
		}
		s.lru.Remove(e)
		delete(s.buckets, b.key)
	}
}

// takeToken returns true when a request for key is within its rate budget.
func (g *guard) takeToken(key netip.Addr) bool {
	s := g.shardOf(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := g.now()
	var b *bucket
	if e := s.buckets[key]; e != nil {
		b = e.Value.(*bucket)
		s.lru.MoveToFront(e)
	} else {
		s.evictLocked(now, g.idleWindow(), g.perShardMax())
		b = &bucket{key: key, tokens: g.burst, last: now}
		s.buckets[key] = s.lru.PushFront(b)
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

// sweep evicts idle/over-cap buckets in every shard; tests use it to
// force a global pass deterministically.
func (g *guard) sweep(now time.Time) {
	idle := g.idleWindow()
	max := g.perShardMax()
	for i := range g.shards {
		s := &g.shards[i]
		s.mu.Lock()
		s.evictLocked(now, idle, max)
		s.mu.Unlock()
	}
}

func (g *guard) Handle(_ context.Context, r *xngin.Request) (*xngin.Verdict, error) {
	src := r.GetIP("src-ip")
	key := rateKey(src)
	ttl := g.denyTTL()

	// vars/hdr-set mark a verdict uncacheable and are not replayed on
	// cache hits (until the cache entry learns to store them) — attach
	// them only when the deny is not being cached anyway.
	extras := ttl == 0

	if g.deny != nil && src != nil && contains(g.deny, src) {
		v := &xngin.Verdict{
			Action: "deny", Status: 403,
			Reason: "denylist hit", Score: 100, CacheTTL: ttl,
		}
		if extras {
			v.Vars = map[string]string{"guard": "denylist"}
		}
		return v, nil
	}

	if len(g.allow) > 0 && (src == nil || !contains(g.allow, src)) {
		v := &xngin.Verdict{
			Action: "deny", Status: 403,
			Reason: "not in allowlist", Score: 80, CacheTTL: ttl,
		}
		if extras {
			v.Vars = map[string]string{"guard": "allowlist-miss"}
		}
		return v, nil
	}

	if g.rate > 0 && !g.takeToken(key) {
		v := &xngin.Verdict{
			Action: "deny", Status: 429,
			Reason: "rate limit exceeded", Score: 60, CacheTTL: ttl,
		}
		if extras {
			v.Vars = map[string]string{"guard": "ratelimit"}
			v.SetHeaders = map[string]string{"retry-after": "1"}
		}
		return v, nil
	}

	// allows stay uncached: every request still takes a token.
	v := xngin.Allow()
	v.Vars = map[string]string{"guard": "pass"}
	return v, nil
}

func main() {
	var (
		listen = flag.String("listen", "unix:/tmp/xngin-edge-guard.sock",
			"unix:/path or tcp:host:port")
		allow   = flag.String("allow", "", "comma-separated allowlist CIDRs")
		deny    = flag.String("deny", "", "comma-separated denylist CIDRs")
		rate    = flag.Float64("rate", 0, "requests/sec per client IPv4 address or IPv6 /64 (0=off)")
		burst   = flag.Float64("burst", 20, "token bucket size")
		ttl     = flag.Uint("ttl", 0, "verdict cache-ttl seconds (deny verdicts only)")
		maxB    = flag.Int("max-buckets", defaultMaxBuckets,
			"max tracked rate-limit buckets (LRU-evicted)")
		tlsCert = flag.String("tls-cert", "", "agent TLS certificate (PEM)")
		tlsKey  = flag.String("tls-key", "", "agent TLS private key (PEM)")
		tlsCA   = flag.String("tls-client-ca", "",
			"CA verifying engine client certs (enables mTLS)")
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

	if *tlsCert != "" {
		cfg, err := xngin.TLSConfig(*tlsCert, *tlsKey, *tlsCA)
		if err != nil {
			log.Fatalf("bad tls config: %v", err)
		}
		srv.TLSConfig = cfg
	} else if *tlsKey != "" || *tlsCA != "" {
		log.Fatal("-tls-key/-tls-client-ca require -tls-cert")
	}

	log.Printf("edge-guard listening on %s (rate=%v/s burst=%v)", *listen, *rate, *burst)
	log.Fatal(srv.ListenAndServe(*listen))
}
