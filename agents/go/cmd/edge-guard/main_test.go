package main

import (
	"context"
	"encoding/binary"
	"net"
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
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.buckets) != g.lru.Len() {
		t.Fatalf("map/lru out of sync: %d vs %d", len(g.buckets), g.lru.Len())
	}
	return len(g.buckets)
}

func TestRateKey(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
	}
	for in, want := range cases {
		if got := rateKey(net.ParseIP(in)); got != want {
			t.Errorf("rateKey(%s) = %q, want %q", in, got, want)
		}
	}
	if got := rateKey(nil); got != "unknown" {
		t.Errorf("rateKey(nil) = %q", got)
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
		g.takeToken(net.IPv4(10, 0, byte(i>>8), byte(i)).String())
	}
	if n := g.size(t); n != 500 {
		t.Fatalf("buckets = %d, want 500", n)
	}
	*clock = clock.Add(g.idleWindow())
	g.takeToken("192.0.2.1")
	if n := g.size(t); n != 1 {
		t.Fatalf("buckets after idle sweep = %d, want 1", n)
	}
}

func TestEvictionKeepsActiveLimit(t *testing.T) {
	g, clock := testGuard(1, 3, 1000)
	for i := 0; i < 3; i++ {
		if !g.takeToken("a") {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	*clock = clock.Add(500 * time.Millisecond)
	g.takeToken("b") // triggers a sweep; "a" is not idle yet
	if g.takeToken("a") {
		t.Fatal("drained bucket was reset by eviction")
	}
}
