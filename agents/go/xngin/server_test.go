package xngin

import (
	"context"
	"net"
	"testing"
	"time"
)

func notifyPayload(msg string, kvs ...Pair) []byte {
	var p []byte
	p = appendVarint(p, uint64(len(msg)))
	p = append(p, msg...)
	return append(p, KVPairs(kvs...)...)
}

// readThrough reads frames until one of type typ arrives; it returns
// every frame seen (the caller inspects ordering, e.g. "no VERDICT
// preceded this PONG").
func readThrough(t *testing.T, a net.Conn, typ byte) []Frame {
	t.Helper()
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf []byte
	tmp := make([]byte, 4096)
	var out []Frame
	for {
		n, err := a.Read(tmp)
		if err != nil {
			t.Fatalf("no frame type %x: %v (saw %d)", typ, err, len(out))
		}
		buf = append(buf, tmp[:n]...)
		frames, rest, err := ParseFrames(buf)
		if err != nil {
			t.Fatal(err)
		}
		buf = rest
		for _, f := range frames {
			out = append(out, f)
			if f.Type == typ {
				return out
			}
		}
	}
}

type earlyHandler struct{}

func (earlyHandler) Handle(_ context.Context, _ *Request) (*Verdict, error) {
	return &Verdict{Action: "deny", Status: 500, Reason: "should not run"}, nil
}

func (earlyHandler) EarlyVerdict(_ context.Context, r *Request) (*Verdict, error) {
	if len(r.Body) != 0 {
		return Deny(500, "body visible in early callback"), nil
	}
	return &Verdict{Action: "allow", Reason: "early"}, nil
}

func TestEarlyVerdictBeforeBody(t *testing.T) {
	srv := &Server{Handler: earlyHandler{}}
	a, b := net.Pipe()
	defer a.Close()
	go srv.serveConn(b)
	handshake(t, a)

	go a.Write((&Frame{Type: FrameNotify, Flags: FlagNotifyHasBody,
		SID: 1,
		Payload: notifyPayload("http-request",
			Pair{"method", "GET"}, Pair{"uri", "/"})}).Marshal())

	f := readThrough(t, a, FrameVerdict)[0]
	pairs, err := ParseKV(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := PairsGet(pairs, "action"); got != "allow" {
		t.Fatalf("early verdict action = %v", got)
	}
	if got, _ := PairsGet(pairs, "reason"); got != "early" {
		t.Fatalf("early verdict reason = %v", got)
	}

	// BODY arriving after the verdict is ignored; the conn must keep
	// serving — a PONG proves the read loop got past the dead frames.
	go func() {
		a.Write((&Frame{Type: FrameBody, Flags: FlagBodyLast,
			SID: 1, Payload: []byte("late body")}).Marshal())
		a.Write((&Frame{Type: FramePing, Payload: []byte("x")}).Marshal())
	}()
	for _, f := range readThrough(t, a, FramePong) {
		if f.Type == FrameVerdict {
			t.Fatal("second verdict for an already-decided stream")
		}
	}
}

type bodyHandler struct {
	got chan []byte
}

func (h bodyHandler) Handle(_ context.Context, r *Request) (*Verdict, error) {
	h.got <- append([]byte(nil), r.Body...)
	return Allow(), nil
}

func BenchmarkRoundTrip(b *testing.B) {
	srv := &Server{Handler: HandlerFunc(
		func(_ context.Context, _ *Request) (*Verdict, error) {
			return Allow(), nil
		})}
	a, c := net.Pipe()
	defer a.Close()
	go srv.serveConn(c)

	notify := (&Frame{Type: FrameNotify, SID: 1,
		Payload: notifyPayload("http-request",
			Pair{"method", "GET"}, Pair{"uri", "/"},
			Pair{"scheme", "http"}, Pair{"host", "x"},
			Pair{"http-version", "1.1"},
			Pair{"src-ip", net.ParseIP("192.0.2.1").To4()},
			Pair{"src-port", uint32(12345)},
			Pair{"headers", KVMap(map[string]Value{
				"user-agent":   "bench/1",
				"accept":       "*/*",
				"x-request-id": "r1",
			})})}).Marshal()

	go a.Write((&Frame{Type: FrameEngineHello,
		Payload: KVPairs(Pair{"version", uint32(Version)})}).Marshal())
	readThroughB(b, a, FrameAgentHello)

	b.ReportAllocs()
	b.ResetTimer()
	var buf []byte
	tmp := make([]byte, 8192)
	for i := 0; i < b.N; i++ {
		if _, err := a.Write(notify); err != nil {
			b.Fatal(err)
		}
		for {
			n, err := a.Read(tmp)
			if err != nil {
				b.Fatal(err)
			}
			buf = append(buf, tmp[:n]...)
			frames, rest, _ := ParseFrames(buf)
			buf = rest
			done := false
			for _, f := range frames {
				if f.Type == FrameVerdict {
					done = true
				}
			}
			if done {
				break
			}
		}
	}
}

func readThroughB(b *testing.B, a net.Conn, typ byte) {
	b.Helper()
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := a.Read(tmp)
		if err != nil {
			b.Fatalf("no frame type %x: %v", typ, err)
		}
		buf = append(buf, tmp[:n]...)
		frames, rest, err := ParseFrames(buf)
		if err != nil {
			b.Fatal(err)
		}
		buf = rest
		for _, f := range frames {
			if f.Type == typ {
				a.SetReadDeadline(time.Time{})
				return
			}
		}
	}
}

func TestNoEarlyHandlerWaitsForLast(t *testing.T) {
	h := bodyHandler{got: make(chan []byte, 1)}
	srv := &Server{Handler: h}
	a, b := net.Pipe()
	defer a.Close()
	go srv.serveConn(b)
	handshake(t, a)

	// NOTIFY + PING: the conn answers the PONG before any BODY, so a
	// verdict must not precede it.
	go func() {
		a.Write((&Frame{Type: FrameNotify, Flags: FlagNotifyHasBody,
			SID: 1,
			Payload: notifyPayload("http-request",
				Pair{"method", "POST"})}).Marshal())
		a.Write((&Frame{Type: FramePing, Payload: []byte("x")}).Marshal())
	}()
	for _, f := range readThrough(t, a, FramePong) {
		if f.Type == FrameVerdict {
			t.Fatal("verdict emitted before body LAST without EarlyHandler")
		}
	}

	go func() {
		a.Write((&Frame{Type: FrameBody, SID: 1,
			Payload: []byte("hello ")}).Marshal())
		a.Write((&Frame{Type: FrameBody, Flags: FlagBodyLast,
			SID: 1, Payload: []byte("world")}).Marshal())
	}()

	select {
	case body := <-h.got:
		if string(body) != "hello world" {
			t.Fatalf("body = %q", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never ran at LAST")
	}
	readThrough(t, a, FrameVerdict)
}
