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

// TestComputeJA4_Versions covers the version map + supported_versions
// overrides: GREASE filtered, max wins, legacy_version fallback.
func TestComputeJA4_Versions(t *testing.T) {
	svOf := func(vs ...uint16) []byte {
		return append([]byte{byte(len(vs) * 2)}, u16s(vs...)...)
	}
	for _, tc := range []struct {
		name string
		exts map[uint16][]byte
		want string // ja4_a[:3]
	}{
		{"sv-11", map[uint16][]byte{0x002b: svOf(0x0302)}, "t11"},
		{"sv-10", map[uint16][]byte{0x002b: svOf(0x0301)}, "t10"},
		{"sv-s3", map[uint16][]byte{0x002b: svOf(0x0300)}, "ts3"},
		{"sv-unknown", map[uint16][]byte{0x002b: svOf(0x7777)}, "t00"},
		{"sv-max-wins", map[uint16][]byte{0x002b: svOf(0x0303, 0x0304)}, "t13"},
		// GREASE in supported_versions is filtered, not picked as max
		{"sv-grease", map[uint16][]byte{0x002b: svOf(0x0a0a, 0x0304, 0xfafa)}, "t13"},
		{"legacy-fallback", nil, "t12"}, // no ext block → 0x0303 → 12
	} {
		ch := buildCH([]uint16{0x1301}, tc.exts)
		ja4, _, err := ComputeJA4(ch)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ja4[:3] != tc.want {
			t.Fatalf("%s: ja4_a %q want %q", tc.name, ja4[:10], tc.want)
		}
	}
}

// TestComputeJA4_CountCaps: cipher/extension counts saturate at 99.
func TestComputeJA4_CountCaps(t *testing.T) {
	ciphers := make([]uint16, 120) // 0x0100..0x0177, none GREASE
	for i := range ciphers {
		ciphers[i] = uint16(0x0100 + i)
	}
	exts := make(map[uint16][]byte, 120)
	for i := 0; i < 120; i++ {
		exts[uint16(0x1000+i)] = nil // 0x1000..0x1077, none GREASE
	}
	ja4, _, err := ComputeJA4(buildCH(ciphers, exts))
	if err != nil {
		t.Fatal(err)
	}
	if ja4[:10] != "t12i9999"+"00" {
		t.Fatalf("ja4_a %q", ja4[:10])
	}
}

// TestComputeJA4_ALPN covers ALPN edge paths: first proto only,
// 2-byte GREASE protos skipped, non-alnum → hex nibbles.
func TestComputeJA4_ALPN(t *testing.T) {
	list := func(protos ...[]byte) []byte {
		var l []byte
		for _, p := range protos {
			l = append(l, byte(len(p)))
			l = append(l, p...)
		}
		return append(u16s(uint16(len(l))), l...)
	}
	for _, tc := range []struct {
		name  string
		list  []byte
		want  string // last 2 chars of ja4_a
	}{
		{"first-only", list([]byte("h2"), []byte("http/1.1")), "h2"},
		{"grease-skip", list([]byte{0x1a, 0x1a}, []byte("h2")), "h2"},
		{"non-alnum", list([]byte{0xff, 0x80}), "f0"},
		{"empty-list", nil, "00"},
	} {
		exts := map[uint16][]byte{}
		if tc.list != nil {
			exts[0x0010] = tc.list
		}
		ja4, _, err := ComputeJA4(buildCH([]uint16{0x1301}, exts))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ja4[8:10] != tc.want {
			t.Fatalf("%s: alpn %q want %q (ja4 %q)",
				tc.name, ja4[8:10], tc.want, ja4)
		}
	}
}

// TestComputeJA4_EmptySNI: server_name present but with no data still
// counts as an extension but flags 'i' (no SNI sent).
func TestComputeJA4_EmptySNI(t *testing.T) {
	exts := map[uint16][]byte{
		0x0000: {},                         // empty SNI
		0x002b: {2, 0x03, 0x04},            // supported_versions: 1.3
	}
	ja4, _, err := ComputeJA4(buildCH([]uint16{0x1301}, exts))
	if err != nil {
		t.Fatal(err)
	}
	if ja4[:10] != "t13i0102"+"00" {
		t.Fatalf("ja4_a %q", ja4[:10])
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
	// real ClientHello captured from a live xngin_tls_inspect stack run
	// (python-urllib3 → OpenSSL 3.x); engineJA4 is the C module's own
	// output — this is the engine↔SDK parity gate. Also cross-checked
	// by the Python oracle in test/harness/test_ja4.py (same bytes).
	const chHex = "010005d10303db016a12ae89d83e215cfc6facf4df54ecd9f48fe7bb70a4ce2f4e72d1fcfd2e204237074c32d679bcc6" +
	"6608909b25f7fcc30b5e36dc6a9b639ac3a7e94778b5aa0022130213031301c02cc030c02bc02fcca9cca8c024c028c0" +
	"23c027009f009e006b006701000566ff01000100000b000403000102000a0012001011ec001d0017001e001800190100" +
	"0101002300000016000000170000000d0036003409050906090404030503060308070808081a081b081c0809080a080b" +
	"080408050806040105010601030303010302040205020602002b00050403040303002d00020101003304ea04e811ec04" +
	"c077669c22708d84c2037143be902102ea286f60409a2d4b4728f47531c1773d10a820e346de52ba1a5985d0e4c7f2a5" +
	"9e434088407334bb843eb5ba5a36f4a319f49cec04abd51226a1f69f42378f0a923547d00464ac6b778331f1f9b192e3" +
	"a6e75c6d7b7747dff318910448a9f129516038c5922f0cf3c18de633b9a4828e750a1313890414452f6137af089af573" +
	"17aac0665fb94fd9f7859ce1a368613bb7554bc7d2931107b2f9194d6141573ab4c9d2ec3f8acbc16949b8995150a320" +
	"55654567fe9ba884cb5ffebacf7620caa6e395d69b519eb8548dd5aca4e525131919f8c758cca40712036a56d0301480" +
	"7e1d61ba5bd027ca7794616a9c17689589d28a404b72b9f7baa3ec1b63b95b115021bd2c543f8285f96acdadeb49db61" +
	"9f81d252ac333cd298704707bb1ec5bcdc0c22c83ab4af59cc450b0f14c1c10af56aa7796d2acba46f77a34674b35b2c" +
	"aca30c6a71f945ede22c879b93fe7a5b1d3343153772b7029549391c97067522c719e73790c2dc21ae474d1b7c12fab1" +
	"6aa8439c0dd55e78e31fe4505f079ac883417526f59419dc2358e398404930458c9df3b82672460c937568e88cbe6875" +
	"43c8573f779c1a392bbb8e2aa003725fe892bdc2226704c9012c020aaa3bbd9d5aad3b4c0bd877b077b0bec9456eba31" +
	"1a4a621b6e0c8672484c10c7cff7203ad1406454d391ac6024fafc3eb1a619dbd4b580c0a137207f9c375847d457f514" +
	"c3789a343f5b8aeaeb3cd3d260dcc79f0032aec68b17cf3b440b2a99b9b310cafac8a9e35a7a50a3ccc8be2e217d1112" +
	"cb76e17ad1f81004f18e7b310d48bb673f5b236e488f58cb7f3f5c38f4c45b3d93491629c0cc25ccfee3676bd056ec5b" +
	"242ffbbe47ab6a21bb424106bc44219925659b246b0c66758de107b877c411a5d1ce63222fd79c074037357d8c1ccbb3" +
	"c4fad41bbb442351127f28f4b481e62b08cbacb6c561f4d0446b620ea341315ad86e10824b04908c8b5a8e8f5629dedc" +
	"948363a48520cd027b3e8944948f933396c389347b1dcb13c226605dff715954062c55f67313a124cf5576069421f174" +
	"4139fca04e779b071289e53aa8a5337e78a2c02ae512b61a9d5db33f63c313eeb119dfaa61c6586ac1596f852b7d2fc6" +
	"56fb9b13f657bf4ae0c25af20af0421e17ebcf57882d3974cc6be41fbc695644dc32e5f0247343c773b504c8626028c0" +
	"896cab44384057ee57078be27f42994d1b733fde16038294c1ddc92f8d898d026b87de79b14207288f71777ce1a81018" +
	"af71dc3c7b435256f658a6e8378cf807bd34a81b389151f575b2c858f0a06460a0ab8cb42bd1c12680251472f33fadf2" +
	"4c7c39b4a41674dd361f76bc370c393a2f9896f0083ceef04589b3808a2b25f11ba788c8c913a75e54f72e6014ace98b" +
	"a03199387038a5aedb7ce00b07271c78d829ca735ab295255823f354036951ae960966a33fc72a12a413c7339927ea5a" +
	"80c44632ea08a6a87caa19c78ae1bb027cd377947b06019812f61618c2b70ef4192a3b5bc01bec00849843aeaa5b9b09" +
	"9808994cd2252ebb195004b497ee4c6e02da65afdb64794289e066121a98b62b2017325cb15f774fe6cb1bb64ba3a618" +
	"426da6f7d6298809c6e694ae73d3950fe243d43b824b9d04d5d29e14b1f58b40d035d9e1a61e8035d89a7583e9c215f6" +
	"ade241b8005d211dd961f793bc83de1e68001d00207937257f5743fedfcee50ec183188f4ef154489bdb17591e8cc2d8" +
	"022dd44b05"
	const engineJA4 = "t13i171000_ab0a1bf427ad_8e6e362c5eac"
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
