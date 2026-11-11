package xngin

import (
	"net"
	"testing"
)

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 300, 16384, 1 << 32, ^uint64(0)} {
		var buf []byte
		buf = appendVarint(buf, v)
		d := &decoder{buf: buf}
		got, err := d.varint()
		if err != nil || got != v {
			t.Fatalf("varint %d -> %d (err=%v)", v, got, err)
		}
	}
}

func TestSvarintRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, -1, 42, -300, 1 << 40, -(1 << 40)} {
		var buf []byte
		buf = appendSvarint(buf, v)
		d := &decoder{buf: buf}
		got, err := d.svarint()
		if err != nil || got != v {
			t.Fatalf("svarint %d -> %d (err=%v)", v, got, err)
		}
	}
}

func TestValueRoundTrip(t *testing.T) {
	cases := []Value{
		nil, true, false,
		int64(-42), uint64(300),
		"hello", []byte{1, 2, 3},
		net.ParseIP("10.0.0.7"),
		[]string{"a", "b", "c"},
		[]Pair{{"k1", "v1"}, {"k2", int64(7)}},
	}
	for _, c := range cases {
		buf, err := appendValue(nil, c)
		if err != nil {
			t.Fatalf("encode %v: %v", c, err)
		}
		d := &decoder{buf: buf}
		got, err := d.value()
		if err != nil {
			t.Fatalf("decode %v: %v", c, err)
		}
		switch want := c.(type) {
		case net.IP:
			if got.(net.IP).String() != want.String() {
				t.Fatalf("ip %v -> %v", want, got)
			}
		case []Pair:
			gp := got.([]Pair)
			if len(gp) != len(want) || gp[0].Name != want[0].Name {
				t.Fatalf("kvl %v -> %v", want, gp)
			}
		case []string:
			gs := got.([]string)
			if len(gs) != len(want) || gs[0] != want[0] {
				t.Fatalf("strlist %v -> %v", want, gs)
			}
		case []byte:
			if string(got.([]byte)) != string(want) {
				t.Fatalf("bin %v -> %v", want, got)
			}
		default:
			if got != c {
				t.Fatalf("%T %v -> %v", c, c, got)
			}
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	payload := KVPairs(Pair{"action", "allow"}, Pair{"score", int64(7)})
	f := &Frame{Type: FrameVerdict, Flags: FlagFin, SID: 41, FID: 2,
		Payload: payload}
	wire := f.Marshal()

	frames, rest, err := ParseFrames(wire)
	if err != nil || len(rest) != 0 || len(frames) != 1 {
		t.Fatalf("parse: frames=%d rest=%d err=%v", len(frames), len(rest), err)
	}
	g := frames[0]
	if g.Type != FrameVerdict || g.SID != 41 || g.FID != 2 {
		t.Fatalf("bad header %+v", g)
	}
	pairs, err := ParseKV(g.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := PairsGet(pairs, "action"); v != "allow" {
		t.Fatalf("action=%v", v)
	}
	if v, _ := PairsGet(pairs, "score"); v != int64(7) {
		t.Fatalf("score=%v", v)
	}
}

func TestParseFramesPartial(t *testing.T) {
	f := (&Frame{Type: FramePing, SID: 1, Payload: []byte("ab")}).Marshal()
	for cut := 1; cut < len(f); cut++ {
		frames, rest, _ := ParseFrames(f[:cut])
		if len(frames) != 0 || len(rest) != cut {
			t.Fatalf("cut=%d frames=%d rest=%d", cut, len(frames), len(rest))
		}
	}
}

func TestKVLNested(t *testing.T) {
	inner := []Pair{{"host", "x"}, {"ua", "y"}}
	payload := KVPairs(Pair{"headers", inner})
	pairs, _ := ParseKV(payload)
	v, ok := PairsGet(pairs, "headers")
	if !ok {
		t.Fatal("no headers")
	}
	ps := v.([]Pair)
	if len(ps) != 2 || ps[0].Value != "x" {
		t.Fatalf("nested kvl: %v", ps)
	}
}
