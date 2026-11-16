package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xngin/xngin-go/xngin"
)

func reqFrom(ip net.IP) *xngin.Request {
	return &xngin.Request{Msg: "http-request", Fields: map[string]xngin.Value{"src-ip": ip}}
}

func testGuard(rate, burst float64, maxBuckets int) (*guard, *time.Time) {
	g := newGuard()
	g.rate, g.burst, g.maxBuckets = rate, burst, maxBuckets
	clock := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return clock }
	return g, &clock
}

func (g *guard) size(t *testing.T) int {
	t.Helper()
	total := 0
	for i := range g.shards {
		s := &g.shards[i]
		s.mu.Lock()
		if len(s.buckets) != s.lru.Len() {
			t.Fatalf("shard %d map/lru out of sync: %d vs %d",
				i, len(s.buckets), s.lru.Len())
		}
		total += len(s.buckets)
		s.mu.Unlock()
	}
	return total
}

func TestRateKey(t *testing.T) {
	cases := map[string]netip.Addr{
		"192.0.2.7":            netip.MustParseAddr("192.0.2.7"),
		"::ffff:192.0.2.7":     netip.MustParseAddr("192.0.2.7"),
		"2001:db8:1:2:3:4:5:6": netip.MustParseAddr("2001:db8:1:2::"),
		"2001:db8:1:2:ffff::1": netip.MustParseAddr("2001:db8:1:2::"),
		"2001:db8:1:3::1":      netip.MustParseAddr("2001:db8:1:3::"),
	}
	for in, want := range cases {
		if got := rateKey(net.ParseIP(in)); got != want {
			t.Errorf("rateKey(%s) = %v, want %v", in, got, want)
		}
	}
	if got := rateKey(nil); got.IsValid() {
		t.Errorf("rateKey(nil) = %v, want invalid", got)
	}
}

func TestSameSlash64SharesBucket(t *testing.T) {
	g, _ := testGuard(50, 20, 1000)
	ctx := context.Background()
	denied := 0
	for i := 0; i < 100_000; i++ {
		ip := net.ParseIP("2001:db8:aa:bb::").To16()
		binary.BigEndian.PutUint64(ip[8:], uint64(i)+1)
		v, err := g.Handle(ctx, reqFrom(ip))
		if err != nil {
			t.Fatal(err)
		}
		if v.Status == 429 {
			denied++
		}
	}
	if n := g.size(t); n != 1 {
		t.Fatalf("buckets = %d, want 1 for a single /64", n)
	}
	if denied != 100_000-20 {
		t.Fatalf("denied = %d, want %d", denied, 100_000-20)
	}
}

func TestDistinctPrefixesStayUnderCap(t *testing.T) {
	const max = 1000
	g, _ := testGuard(50, 20, max)
	ctx := context.Background()
	for i := 0; i < 100_000; i++ {
		ip := make(net.IP, net.IPv6len)
		ip[0], ip[1] = 0x20, 0x01
		binary.BigEndian.PutUint32(ip[4:], uint32(i))
		ip[15] = byte(i)
		if _, err := g.Handle(ctx, reqFrom(ip)); err != nil {
			t.Fatal(err)
		}
		if n := g.size(t); n > max {
			t.Fatalf("after %d addrs buckets = %d > cap %d", i+1, n, max)
		}
	}
}

func TestIdleBucketsEvicted(t *testing.T) {
	g, clock := testGuard(10, 20, 1000) // idle window = 2s
	for i := 0; i < 500; i++ {
		ip := net.IPv4(10, 0, byte(i>>8), byte(i))
		g.takeToken(rateKey(ip))
	}
	if n := g.size(t); n != 500 {
		t.Fatalf("buckets = %d, want 500", n)
	}
	*clock = clock.Add(g.idleWindow())
	g.sweep(*clock)
	if n := g.size(t); n != 0 {
		t.Fatalf("buckets after idle sweep = %d, want 0", n)
	}
}

func TestEvictionKeepsActiveLimit(t *testing.T) {
	g, clock := testGuard(1, 3, 1000)
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	for i := 0; i < 3; i++ {
		if !g.takeToken(a) {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	*clock = clock.Add(500 * time.Millisecond)
	g.takeToken(b) // triggers a sweep in b's shard; "a" is not idle yet
	if g.takeToken(a) {
		t.Fatal("drained bucket was reset by eviction")
	}
}

func TestDenyTTLClampedToWindow(t *testing.T) {
	// rate=50 burst=20 -> window = ceil(0.4) = 1s
	g, _ := testGuard(50, 20, 1000)
	g.ttl = 60
	if got := g.denyTTL(); got != 1 {
		t.Fatalf("denyTTL = %d, want clamp to 1", got)
	}
	g.ttl = 0
	if got := g.denyTTL(); got != 0 {
		t.Fatalf("denyTTL = %d, want 0 for ttl=0", got)
	}
	// no limiter -> ttl passes through for ACL denies
	g, _ = testGuard(0, 20, 1000)
	g.ttl = 30
	if got := g.denyTTL(); got != 30 {
		t.Fatalf("denyTTL = %d, want 30", got)
	}
}

func TestAllowNeverCached(t *testing.T) {
	g, _ := testGuard(50, 20, 1000)
	g.ttl = 60
	v, err := g.Handle(context.Background(), reqFrom(net.ParseIP("192.0.2.9")))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != "allow" {
		t.Fatalf("action = %q, want allow", v.Action)
	}
	if v.CacheTTL != 0 {
		t.Fatalf("allow CacheTTL = %d, want 0 (every request takes a token)", v.CacheTTL)
	}
}

func TestCacheableDenyDropsExtras(t *testing.T) {
	g, _ := testGuard(1, 1, 1000) // burst=1, window=1s
	g.ttl = 60                    // clamps to 1 -> cacheable
	ctx := context.Background()
	// burn the single token
	if _, err := g.Handle(ctx, reqFrom(net.ParseIP("192.0.2.1"))); err != nil {
		t.Fatal(err)
	}
	v, err := g.Handle(ctx, reqFrom(net.ParseIP("192.0.2.1")))
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != 429 {
		t.Fatalf("status = %d, want 429", v.Status)
	}
	if v.CacheTTL == 0 {
		t.Fatal("429 verdict should carry the clamped cache-ttl")
	}
	if len(v.SetHeaders) != 0 || len(v.Vars) != 0 {
		t.Fatalf("cacheable deny keeps hdr-set/vars: %+v", v)
	}
}

func TestUncachedDenyKeepsExtras(t *testing.T) {
	g, _ := testGuard(1, 1, 1000)
	// ttl unset -> deny is not cacheable, extras stay for observability
	ctx := context.Background()
	if _, err := g.Handle(ctx, reqFrom(net.ParseIP("192.0.2.1"))); err != nil {
		t.Fatal(err)
	}
	v, err := g.Handle(ctx, reqFrom(net.ParseIP("192.0.2.1")))
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != 429 || v.CacheTTL != 0 {
		t.Fatalf("verdict = %+v, want 429 uncached", v)
	}
	if v.Vars["guard"] != "ratelimit" || v.SetHeaders["retry-after"] != "1" {
		t.Fatalf("uncached deny lost vars/hdr-set: %+v", v)
	}
}
