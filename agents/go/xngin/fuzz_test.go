// Go codec fuzz: go test -fuzz=FuzzFrames -fuzztime=30s ./xngin
package xngin

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// hugeLen is a varint encoding of 2^64-1.
var hugeLen = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}

// frameWith wraps payload in a well-formed NOTIFY frame.
func frameWith(payload []byte) []byte {
	return (&Frame{Type: FrameNotify, Payload: payload}).Marshal()
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// malformedLengths are inputs with attacker-controlled huge lengths in
// frame, string, name and STRLIST positions.
var malformedLengths = map[string][]byte{
	"frame-len":     cat(hugeLen, []byte{0x08, 0, 0, 0, 0, 0, 0}),
	"frame-len-big": cat(appendVarint(nil, DefaultMaxFrame+1), []byte{0x08}),
	"overlong":      {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80},
	"hdr-varint":    {0x06, 0x08, 0, 0, 0, 0, 0x80},
	"name-len":      frameWith(cat(hugeLen, []byte("x"))),
	"str-len":       frameWith(cat([]byte{1, 'a', VTStr}, hugeLen, []byte("x"))),
	"bin-len":       frameWith(cat([]byte{1, 'a', VTBin}, hugeLen, []byte("x"))),
	"kvl-len":       frameWith(cat([]byte{1, 'a', VTKVL}, hugeLen, []byte("x"))),
	"strlist-count": frameWith(cat([]byte{1, 'a', VTStrList}, hugeLen, []byte{1, 'x'})),
	"strlist-elem":  frameWith(cat([]byte{1, 'a', VTStrList, 1}, hugeLen, []byte("x"))),
	"strlist-2^62":  frameWith(cat([]byte{1, 'a', VTStrList}, appendVarint(nil, 1<<62))),
}

func parseAll(data []byte) error {
	frames, _, err := ParseFrames(data)
	if err != nil {
		return err
	}
	for _, fr := range frames {
		if _, err := ParseKV(fr.Payload); err != nil {
			return err
		}
	}
	return nil
}

func TestMalformedLengthsRejected(t *testing.T) {
	for name, data := range malformedLengths {
		t.Run(name, func(t *testing.T) {
			if err := parseAll(data); !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v want ErrProtocol", err)
			}
		})
	}
}

func TestParseFramesMax(t *testing.T) {
	wire := frameWith(make([]byte, 100))
	if _, _, err := ParseFramesMax(wire, 64); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversize frame err=%v want ErrProtocol", err)
	}
	// oversize is rejected from the header alone, before buffering
	if _, _, err := ParseFramesMax(wire[:3], 64); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversize partial err=%v want ErrProtocol", err)
	}
	frames, rest, err := ParseFramesMax(wire, 128)
	if err != nil || len(frames) != 1 || len(rest) != 0 {
		t.Fatalf("frames=%d rest=%d err=%v", len(frames), len(rest), err)
	}
}

func FuzzFrames(f *testing.F) {
	f.Add([]byte{0x0a, 0x08, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	for _, data := range malformedLengths {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		frames, _, err := ParseFrames(data)
		if err != nil {
			return
		}
		for _, fr := range frames {
			_, _ = ParseKV(fr.Payload)
			_, _, _, _ = parseNotify(fr.Payload)
			// decoded frames must re-marshal without panic
			_ = fr.Marshal()
		}
	})
}

// frameLevel are malformedLengths entries that break framing itself;
// the rest are well-framed with a malformed NOTIFY payload.
var frameLevel = map[string]bool{
	"frame-len": true, "frame-len-big": true, "overlong": true, "hdr-varint": true,
}

func testServer() *Server {
	return &Server{Handler: HandlerFunc(func(context.Context, *Request) (*Verdict, error) {
		return Allow(), nil
	})}
}

// handshake sends ENGINE_HELLO on a and waits for AGENT_HELLO.
func handshake(t *testing.T, a net.Conn) {
	t.Helper()
	go a.Write((&Frame{Type: FrameEngineHello,
		Payload: KVPairs(Pair{"version", uint32(Version)})}).Marshal())
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf []byte
	rbuf := make([]byte, 4096)
	for {
		n, err := a.Read(rbuf)
		if err != nil {
			t.Fatalf("no AGENT_HELLO: %v", err)
		}
		buf = append(buf, rbuf[:n]...)
		var frames []Frame
		frames, buf, err = ParseFrames(buf)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frames {
			if f.Type == FrameAgentHello {
				return
			}
		}
	}
}

func TestServeConnSurvivesMalformedInput(t *testing.T) {
	srv := testServer()
	for name, data := range malformedLengths {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			done := make(chan struct{})
			go func() { srv.serveConn(b); close(done) }()
			go a.Write(data)
			if frameLevel[name] {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("connection not closed")
				}
				return
			}
			// payload errors are not fatal; the connection keeps serving
			handshake(t, a)
		})
	}
	// a fresh connection still works after the bad ones
	a, b := net.Pipe()
	defer a.Close()
	go srv.serveConn(b)
	handshake(t, a)
}
