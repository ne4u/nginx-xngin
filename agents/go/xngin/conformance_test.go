package xngin

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Type     string          `json:"type"`
	Value    int64           `json:"value"`
	Expect   json.RawMessage `json:"expect"`
	ExpectKV [][2]any        `json:"expect_kv"`
	KName    string          `json:"kname"`
	FType    byte            `json:"ftype"`
	Flags    uint32          `json:"flags"`
	Sid      uint64          `json:"sid"`
	Fid      uint64          `json:"fid"`
	Hex      string          `json:"hex"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	p := filepath.Join("..", "..", "..", "test", "conformance",
		"vectors.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Vectors
}

// decodeExpect converts the JSON 'expect' shape to the Go Value produced
// by our decoder.
func decodeExpect(t *testing.T, raw json.RawMessage) Value {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return normExpect(t, v)
}

func normExpect(t *testing.T, v any) Value {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return x
	case float64:
		return int64(x)
	case string:
		return x
	case []any:
		return normList(t, x)
	case map[string]any:
		if h, ok := x["$bytes"]; ok {
			b, err := hex.DecodeString(h.(string))
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		if ps, ok := x["$pairs"]; ok {
			arr := ps.([]any)
			out := make([]Pair, 0, len(arr))
			for _, e := range arr {
				kv := e.([]any)
				out = append(out, Pair{kv[0].(string),
					normExpect(t, kv[1])})
			}
			return out
		}
	}
	t.Fatalf("bad expect: %v", v)
	return nil
}

func normList(t *testing.T, x []any) Value {
	// $pairs handled by caller via map; plain list of strings here
	out := make([]string, 0, len(x))
	for _, e := range x {
		out = append(out, e.(string))
	}
	return out
}

// normGot converts decoded Go values to canonical form for comparison.
func normGot(t *testing.T, v Value) Value {
	switch x := v.(type) {
	case net.IP:
		return x.String()
	case uint64:
		return int64(x) // vectors use small ints; int64 compare is enough
	case []Pair:
		return x
	case []byte:
		return x
	default:
		return x
	}
}

func eqExpect(t *testing.T, got Value, want json.RawMessage) {
	t.Helper()
	exp := decodeExpect(t, want)
	got = normGot(t, got)

	switch e := exp.(type) {
	case []Pair:
		gp, ok := got.([]Pair)
		if !ok || len(gp) != len(e) {
			t.Fatalf("kvl: got %v want %v", got, e)
		}
		for i := range e {
			if gp[i].Name != e[i].Name {
				t.Fatalf("kvl name: %v vs %v", gp[i], e[i])
			}
			eqExpect(t, gp[i].Value, mustJSON(e[i].Value))
		}
	case []string:
		gs, ok := got.([]string)
		if !ok || len(gs) != len(e) {
			t.Fatalf("strlist: got %v want %v", got, e)
		}
		for i := range e {
			if gs[i] != e[i] {
				t.Fatalf("strlist[%d]: %v vs %v", i, gs[i], e[i])
			}
		}
	case []byte:
		gb, ok := got.([]byte)
		if !ok || string(gb) != string(e) {
			t.Fatalf("bin: got %v want %v", got, e)
		}
	default:
		if got != exp {
			t.Fatalf("got %#v want %#v", got, exp)
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestConformance(t *testing.T) {
	for _, vec := range loadVectors(t) {
		t.Run(vec.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(vec.Hex)
			if err != nil {
				t.Fatal(err)
			}
			switch vec.Kind {
			case "varint":
				d := &decoder{buf: wire}
				v, err := d.varint()
				if err != nil || v != uint64(vec.Value) {
					t.Fatalf("got %d want %d", v, vec.Value)
				}
				out := appendVarint(nil, uint64(vec.Value))
				if string(out) != string(wire) {
					t.Fatalf("encode mismatch")
				}
			case "svarint":
				d := &decoder{buf: wire}
				v, err := d.svarint()
				if err != nil || v != vec.Value {
					t.Fatalf("got %d want %d", v, vec.Value)
				}
				out := appendSvarint(nil, vec.Value)
				if string(out) != string(wire) {
					t.Fatalf("encode mismatch")
				}
			case "value":
				d := &decoder{buf: wire}
				v, err := d.value()
				if err != nil {
					t.Fatal(err)
				}
				eqExpect(t, v, vec.Expect)
			case "kv":
				d := &decoder{buf: wire}
				name, v, err := d.kv()
				if err != nil {
					t.Fatal(err)
				}
				if name != vec.KName {
					t.Fatalf("name %q want %q", name, vec.KName)
				}
				eqExpect(t, v, vec.Expect)
			case "frame":
				frames, rest, err := ParseFrames(wire)
				if err != nil || len(rest) != 0 || len(frames) != 1 {
					t.Fatalf("frames=%d rest=%d err=%v",
						len(frames), len(rest), err)
				}
				f := frames[0]
				if f.Type != vec.FType || f.Flags != vec.Flags ||
					f.SID != vec.Sid || f.FID != vec.Fid {
					t.Fatalf("hdr %+v", f)
				}
				pairs, err := ParseKV(f.Payload)
				if err != nil {
					t.Fatal(err)
				}
				if len(pairs) != len(vec.ExpectKV) {
					t.Fatalf("kv count %d want %d",
						len(pairs), len(vec.ExpectKV))
				}
				for i, ekv := range vec.ExpectKV {
					if pairs[i].Name != ekv[0] {
						t.Fatalf("kv[%d] name %q want %q",
							i, pairs[i].Name, ekv[0])
					}
					eqExpect(t, pairs[i].Value,
						mustJSON(ekv[1]))
				}
			}
		})
	}
}
