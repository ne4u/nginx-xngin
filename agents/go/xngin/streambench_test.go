package xngin_test

// Concurrency regression tests for the XNAP server. They drive the
// wire protocol from an "engine" side over a real TCP conn and are
// self-contained (no test helpers from package xngin) so the same
// file can be dropped into a pre-concurrency checkout to measure the
// head-of-line blocking it fixes.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/xngin/xngin-go/xngin"
)

func encVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func notifyFrame(sid uint64, uri string) []byte {
	var p []byte
	msg := "http-request"
	p = encVarint(p, uint64(len(msg)))
	p = append(p, msg...)
	p = append(p, xngin.KVPairs(
		xngin.Pair{Name: "method", Value: "GET"},
		xngin.Pair{Name: "uri", Value: uri},
	)...)
	return (&xngin.Frame{Type: xngin.FrameNotify, Flags: xngin.FlagFin,
		SID: sid, Payload: p}).Marshal()
}

// connect starts srv on a loopback listener, performs the HELLO
// handshake, and returns the engine-side conn.
func connect(t *testing.T, srv *xngin.Server) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write((&xngin.Frame{Type: xngin.FrameEngineHello,
		Payload: xngin.KVPairs(
			xngin.Pair{Name: "version", Value: uint32(1)})}).Marshal())
	readFrames(t, c, 1) // drain AGENT_HELLO
	return c
}

// readFrames reads until at least n complete frames have been parsed.
func readFrames(t *testing.T, c net.Conn, n int) []xngin.Frame {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	var fs []xngin.Frame
	tmp := make([]byte, 8192)
	for len(fs) < n {
		m, err := c.Read(tmp)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		buf = append(buf, tmp[:m]...)
		frames, rest, err := xngin.ParseFrames(buf)
		if err != nil {
			t.Fatal(err)
		}
		buf = rest
		fs = append(fs, frames...)
	}
	return fs
}

// readVerdicts reads frames until every sid in want has a VERDICT.
// Returns sid -> latency since start.
func readVerdicts(t *testing.T, c net.Conn, want map[uint64]bool,
	start time.Time) map[uint64]time.Duration {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	got := map[uint64]time.Duration{}
	var buf []byte
	tmp := make([]byte, 8192)
	for len(got) < len(want) {
		n, err := c.Read(tmp)
		if err != nil {
			t.Fatalf("read: %v (got %v)", err, got)
		}
		buf = append(buf, tmp[:n]...)
		frames, rest, err := xngin.ParseFrames(buf)
		if err != nil {
			t.Fatal(err)
		}
		buf = rest
		for _, f := range frames {
			if f.Type == xngin.FrameVerdict && want[f.SID] {
				got[f.SID] = time.Since(start)
			}
		}
	}
	return got
}

// One 30ms stream plus a burst of fast streams on a single conn. With
// per-stream tasks the fast verdicts return immediately; a read loop
// that invokes the handler inline parks every stream behind the slow
// one (~30ms floor on every fast verdict).
func TestSlowStreamDoesNotBlockFastStreams(t *testing.T) {
	const (
		delay = 30 * time.Millisecond
		nFast = 24
	)
	srv := &xngin.Server{Handler: xngin.HandlerFunc(
		func(_ context.Context, r *xngin.Request) (*xngin.Verdict, error) {
			if r.Get("uri") == "/slow" {
				time.Sleep(delay)
			}
			return xngin.Allow(), nil
		})}
	c := connect(t, srv)

	start := time.Now()
	var out []byte
	out = append(out, notifyFrame(1, "/slow")...)
	want := map[uint64]bool{1: true}
	for i := 0; i < nFast; i++ {
		sid := uint64(3 + 2*i)
		want[sid] = true
		out = append(out, notifyFrame(sid, fmt.Sprintf("/f%d", i))...)
	}
	if _, err := c.Write(out); err != nil {
		t.Fatal(err)
	}
	lat := readVerdicts(t, c, want, start)

	fast := make([]time.Duration, 0, nFast)
	for sid, d := range lat {
		if sid != 1 {
			fast = append(fast, d)
		}
	}
	sort.Slice(fast, func(i, j int) bool { return fast[i] < fast[j] })
	p50, max := fast[len(fast)/2], fast[len(fast)-1]
	t.Logf("slow verdict at %v; fast p50 %v, max %v", lat[1], p50, max)
	if max >= delay {
		t.Fatalf("fast streams blocked behind slow handler "+
			"(head-of-line): max %v >= delay %v", max, delay)
	}
}

// All streams slow: parallel per-stream tasks finish them in ~one
// delay; a serialized read loop costs N*delay.
func TestConcurrentSlowStreamsWallTime(t *testing.T) {
	const (
		delay = 20 * time.Millisecond
		n     = 16
	)
	srv := &xngin.Server{Handler: xngin.HandlerFunc(
		func(_ context.Context, _ *xngin.Request) (*xngin.Verdict, error) {
			time.Sleep(delay)
			return xngin.Allow(), nil
		})}
	c := connect(t, srv)

	start := time.Now()
	var out []byte
	want := map[uint64]bool{}
	for i := 0; i < n; i++ {
		sid := uint64(1 + 2*i)
		want[sid] = true
		out = append(out, notifyFrame(sid, "/slow")...)
	}
	if _, err := c.Write(out); err != nil {
		t.Fatal(err)
	}
	lat := readVerdicts(t, c, want, start)
	wall := time.Since(start)

	var max time.Duration
	for _, d := range lat {
		if d > max {
			max = d
		}
	}
	t.Logf("%d x %v handlers completed in wall %v (max stream %v)",
		n, delay, wall, max)
	if wall > time.Duration(n)*delay/2 {
		t.Fatalf("streams serialized: wall %v >= %v (N*delay/2)",
			wall, time.Duration(n)*delay/2)
	}
}
