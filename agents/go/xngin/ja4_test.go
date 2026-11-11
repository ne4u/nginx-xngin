package xngin

import (
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"testing"
)

var ja4Re = regexp.MustCompile(`^t[0-9a-z]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}` +
	`_[0-9a-f]{12}_[0-9a-f]{12}$`)

// buildCH assembles a synthetic ClientHello handshake message
// (4-byte handshake header + body) for tests.
func buildCH(ciphers []uint16, exts map[uint16][]byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, 0x0303) // legacy_version
	b = append(b, make([]byte, 32)...)           // random
	b = append(b, 0)                             // session_id len
	b = binary.BigEndian.AppendUint16(b, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		b = binary.BigEndian.AppendUint16(b, c)
	}
	b = append(b, 1, 0) // compression: 1 method, null

	var eb []byte
	for et, data := range exts {
		eb = binary.BigEndian.AppendUint16(eb, et)
		eb = binary.BigEndian.AppendUint16(eb, uint16(len(data)))
		eb = append(eb, data...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(eb)))
	b = append(b, eb...)

	msg := []byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(msg, b...)
}

func u16s(vals ...uint16) []byte {
	var out []byte
	for _, v := range vals {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

func TestComputeJA4(t *testing.T) {
	// supported_versions: list len 4 + {0x0304, 0x0303}
	sv := append([]byte{4}, u16s(0x0304, 0x0303)...)
	// ALPN: list len 3 + len-prefixed "h2"
	alpn := append(u16s(3), 2, 'h', '2')
	// signature_algorithms: list len 4 + {0x0403, 0x0804}
	sig := append(u16s(4), u16s(0x0403, 0x0804)...)
	// server_name with a hostname
	sni := []byte{0, 5, 0, 0, 2, 'h', 'i'}

	ch := buildCH(
		[]uint16{0x1301, 0x1302, 0x1303, 0xc02f, 0x0a0a}, // last is GREASE
		map[uint16][]byte{
			0x0000: sni,
			0x0010: alpn,
			0x000d: sig,
			0x002b: sv,
			0x0017: nil,
		},
	)

	ja4, ja4r, err := ComputeJA4(ch)
	if err != nil {
		t.Fatalf("ComputeJA4: %v", err)
	}
	if !ja4Re.MatchString(ja4) {
		t.Fatalf("ja4 format: %q", ja4)
	}

	// a-part: tls1.3, sni present, 4 ciphers (GREASE dropped),
	// 5 exts (GREASE none here; SNI+ALPN counted), alpn h2
	if got := ja4[:10]; got != "t13d0405h2" {
		t.Fatalf("ja4_a = %q (ja4 %q)", got, ja4)
	}
	if got := ja4r[:10]; got != "t13d0405h2" {
		t.Fatalf("ja4r_a = %q", got)
	}
}

func TestComputeJA4_NoExt(t *testing.T) {
	ch := buildCH([]uint16{0x1301}, nil) // no extensions at all

	ja4, ja4r, err := ComputeJA4(ch)
	if err != nil {
		t.Fatalf("ComputeJA4: %v", err)
	}
	if got := ja4[:10]; got != "t12i010000" {
		t.Fatalf("ja4_a = %q (ja4 %q)", got, ja4)
	}
	// empty ext list → the 000000000000 quirk, matching the module
	if ja4[len(ja4)-12:] != "000000000000" {
		t.Fatalf("expected zero-hash tail, got %q", ja4)
	}
	_ = ja4r
}

func TestComputeJA4_Bad(t *testing.T) {
	if _, _, err := ComputeJA4(nil); err == nil {
		t.Fatal("nil should error")
	}
	if _, _, err := ComputeJA4([]byte{0x02, 0, 0, 0}); err == nil {
		t.Fatal("non-CH msg should error")
	}
	if _, _, err := ComputeJA4([]byte{0x01, 0, 0, 9, 3, 3}); err == nil {
		t.Fatal("truncated should error")
	}
}

// TestComputeJA4_Golden checks parity with the engine's own JA4 for a
// captured ClientHello. The hex + expected value come from a live
// xngin_tls_inspect run (stub stats ch_raw_hex + ja4); left empty here so
// unit tests stay self-contained — the integration suite asserts
// ja4_match == "1" end-to-end instead.
func TestComputeJA4_Golden(t *testing.T) {
	const chHex, engineJA4 = "", ""
	if chHex == "" {
		t.Skip("no captured golden vector")
	}
	raw, err := hex.DecodeString(chHex)
	if err != nil {
		t.Fatal(err)
	}
	ja4, _, err := ComputeJA4(raw)
	if err != nil {
		t.Fatalf("ComputeJA4: %v", err)
	}
	if ja4 != engineJA4 {
		t.Fatalf("ja4 %q != engine %q", ja4, engineJA4)
	}
}
