"""JA4 oracle: synthetic-ClientHello vectors + live-capture golden."""

import re
import struct

import pytest

import ja4

JA4_RE = re.compile(r"^t[0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}"
                    r"_[0-9a-f]{12}_[0-9a-f]{12}$")


def build_ch(ciphers, exts):
    """Assemble a synthetic ClientHello handshake message
    (4-byte handshake header + body), same wire format the engine
    captures via SSL_CTX_set_msg_callback."""
    b = bytearray()
    b += struct.pack(">H", 0x0303)      # legacy_version
    b += bytes(32)                      # random
    b.append(0)                         # session_id len
    b += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        b += struct.pack(">H", c)
    b += bytes([1, 0])                  # compression: null only
    eb = bytearray()
    for et, data in exts.items():
        eb += struct.pack(">H", et) + struct.pack(">H", len(data)) + data
    b += struct.pack(">H", len(eb)) + eb
    return bytes([0x01]) + len(b).to_bytes(3, "big") + bytes(b)


def u16s(*vals):
    return b"".join(struct.pack(">H", v) for v in vals)


def test_ja4_full():
    """SNI+ALPN+sigalgs+supported_versions CH → known ja4_a layout."""
    sv = bytes([4]) + u16s(0x0304, 0x0303)
    alpn = u16s(3) + bytes([2]) + b"h2"
    sig = u16s(4) + u16s(0x0403, 0x0804)
    sni = bytes([0, 5, 0, 0, 2]) + b"hi"

    ch = build_ch([0x1301, 0x1302, 0x1303, 0xc02f, 0x0a0a],
                  {0x0000: sni, 0x0010: alpn, 0x000d: sig,
                   0x002b: sv, 0x0017: b""})

    j, jr = ja4.compute_ja4(ch)
    assert JA4_RE.match(j)
    # TLS1.3 via supported_versions, SNI, 4 ciphers (GREASE dropped),
    # 5 exts, ALPN h2 — same vector the Go unit test asserts
    assert j[:10] == "t13d0405h2"
    assert jr[:10] == "t13d0405h2"
    # ja4_r carries the raw sorted lists: GREASE cipher gone, SNI+ALPN
    # counted in _a but absent from the hashed ext list
    assert "0a0a" not in jr
    _, b_raw, c_raw = jr.split("_", 2)
    assert b_raw == "1301,1302,1303,c02f"        # sorted, GREASE dropped
    ext_part, sig_part = c_raw.split("_")
    assert ext_part == "000d,0017,002b"          # SNI/ALPN excluded
    assert sig_part == "0403,0804"               # sig algs in wire order


def test_ja4_grease_shuffle_stable():
    """JA4 sorts: permuted extension/cipher order → same fingerprint."""
    exts = {0x002b: bytes([2]) + u16s(0x0304), 0x000d: u16s(2) + u16s(0x0403),
            0x0017: b""}
    c1, c2 = [0x1301, 0xc02f, 0x1302], [0x1302, 0x1301, 0xc02f]
    j1 = ja4.compute_ja4(build_ch(c1, exts))[0]
    # same ext set, different dict-insertion order → different wire order
    exts2 = {0x0017: b"", 0x000d: u16s(2) + u16s(0x0403),
             0x002b: bytes([2]) + u16s(0x0304)}
    j2 = ja4.compute_ja4(build_ch(c2, exts2))[0]
    assert j1 == j2


def test_ja4_no_ext():
    """No extension block: '00' fields + zero-hash tails."""
    j, jr = ja4.compute_ja4(build_ch([0x1301], {}))
    assert j[:10] == "t12i010000"               # legacy ver, no SNI/ALPN
    assert j.endswith("_000000000000")          # empty ext+sig list quirk
    assert jr == "t12i010000_1301_"             # raw mirrors the same


def test_ja4_versions():
    """Version map + supported_versions override + GREASE filtering."""
    sv = lambda *vs: bytes([len(vs) * 2]) + u16s(*vs)
    cases = [
        ({0x002b: sv(0x0302)}, "t11"),
        ({0x002b: sv(0x0301)}, "t10"),
        ({0x002b: sv(0x0300)}, "ts3"),
        ({0x002b: sv(0x7777)}, "t00"),
        ({0x002b: sv(0x0303, 0x0304)}, "t13"),          # max wins
        ({0x002b: sv(0x0a0a, 0x0304, 0xfafa)}, "t13"),  # GREASE filtered
        ({}, "t12"),                                   # legacy fallback
    ]
    for exts, want in cases:
        j, _ = ja4.compute_ja4(build_ch([0x1301], exts))
        assert j[:3] == want, f"{exts}: {j[:10]}"


def test_ja4_count_caps():
    """cipher/extension counts saturate at 99."""
    ciphers = [0x0100 + i for i in range(120)]
    exts = {0x1000 + i: b"" for i in range(120)}
    j, _ = ja4.compute_ja4(build_ch(ciphers, exts))
    assert j[:10] == "t12i999900"


def test_ja4_alpn_edges():
    """first proto only; 2-byte GREASE skipped; non-alnum → hex nibbles."""
    def alpn_list(*protos):
        l = b"".join(bytes([len(p)]) + p for p in protos)
        return u16s(len(l)) + l

    cases = [
        (alpn_list(b"h2", b"http/1.1"), "h2"),   # first only
        (alpn_list(b"\x1a\x1a", b"h2"), "h2"),   # GREASE skipped
        (alpn_list(b"\xff\x80"), "f0"),          # hex nibbles
        (None, "00"),                            # no ALPN ext
    ]
    for al, want in cases:
        exts = {0x0010: al} if al is not None else {}
        j, _ = ja4.compute_ja4(build_ch([0x1301], exts))
        assert j[8:10] == want, f"{al}: {j[:10]}"


def test_ja4_empty_sni():
    """server_name present-but-empty: counts as ext, flags 'i'."""
    exts = {0x0000: b"", 0x002b: bytes([2]) + u16s(0x0304)}
    j, _ = ja4.compute_ja4(build_ch([0x1301], exts))
    assert j[:10] == "t13i010200"


def test_ja4_bad():
    for bad in (b"", None, b"\x02\x00\x00\x00", b"\x01\x00\x00\x09\x03\x03"):
        with pytest.raises(ValueError):
            ja4.compute_ja4(bad)


# Real ClientHello captured from a live xngin_tls_inspect stack run
# (python-urllib3 → OpenSSL 3.x). ja4 is the engine's own output —
# this is the three-way parity gate: C engine, Go SDK, this oracle.
GOLDEN_CH_HEX = (
    "010005d10303db016a12ae89d83e215cfc6facf4df54ecd9f48fe7bb70a4ce2f4e72d1fcfd2e204237074c32d679bcc6"
    "6608909b25f7fcc30b5e36dc6a9b639ac3a7e94778b5aa0022130213031301c02cc030c02bc02fcca9cca8c024c028c0"
    "23c027009f009e006b006701000566ff01000100000b000403000102000a0012001011ec001d0017001e001800190100"
    "0101002300000016000000170000000d0036003409050906090404030503060308070808081a081b081c0809080a080b"
    "080408050806040105010601030303010302040205020602002b00050403040303002d00020101003304ea04e811ec04"
    "c077669c22708d84c2037143be902102ea286f60409a2d4b4728f47531c1773d10a820e346de52ba1a5985d0e4c7f2a5"
    "9e434088407334bb843eb5ba5a36f4a319f49cec04abd51226a1f69f42378f0a923547d00464ac6b778331f1f9b192e3"
    "a6e75c6d7b7747dff318910448a9f129516038c5922f0cf3c18de633b9a4828e750a1313890414452f6137af089af573"
    "17aac0665fb94fd9f7859ce1a368613bb7554bc7d2931107b2f9194d6141573ab4c9d2ec3f8acbc16949b8995150a320"
    "55654567fe9ba884cb5ffebacf7620caa6e395d69b519eb8548dd5aca4e525131919f8c758cca40712036a56d0301480"
    "7e1d61ba5bd027ca7794616a9c17689589d28a404b72b9f7baa3ec1b63b95b115021bd2c543f8285f96acdadeb49db61"
    "9f81d252ac333cd298704707bb1ec5bcdc0c22c83ab4af59cc450b0f14c1c10af56aa7796d2acba46f77a34674b35b2c"
    "aca30c6a71f945ede22c879b93fe7a5b1d3343153772b7029549391c97067522c719e73790c2dc21ae474d1b7c12fab1"
    "6aa8439c0dd55e78e31fe4505f079ac883417526f59419dc2358e398404930458c9df3b82672460c937568e88cbe6875"
    "43c8573f779c1a392bbb8e2aa003725fe892bdc2226704c9012c020aaa3bbd9d5aad3b4c0bd877b077b0bec9456eba31"
    "1a4a621b6e0c8672484c10c7cff7203ad1406454d391ac6024fafc3eb1a619dbd4b580c0a137207f9c375847d457f514"
    "c3789a343f5b8aeaeb3cd3d260dcc79f0032aec68b17cf3b440b2a99b9b310cafac8a9e35a7a50a3ccc8be2e217d1112"
    "cb76e17ad1f81004f18e7b310d48bb673f5b236e488f58cb7f3f5c38f4c45b3d93491629c0cc25ccfee3676bd056ec5b"
    "242ffbbe47ab6a21bb424106bc44219925659b246b0c66758de107b877c411a5d1ce63222fd79c074037357d8c1ccbb3"
    "c4fad41bbb442351127f28f4b481e62b08cbacb6c561f4d0446b620ea341315ad86e10824b04908c8b5a8e8f5629dedc"
    "948363a48520cd027b3e8944948f933396c389347b1dcb13c226605dff715954062c55f67313a124cf5576069421f174"
    "4139fca04e779b071289e53aa8a5337e78a2c02ae512b61a9d5db33f63c313eeb119dfaa61c6586ac1596f852b7d2fc6"
    "56fb9b13f657bf4ae0c25af20af0421e17ebcf57882d3974cc6be41fbc695644dc32e5f0247343c773b504c8626028c0"
    "896cab44384057ee57078be27f42994d1b733fde16038294c1ddc92f8d898d026b87de79b14207288f71777ce1a81018"
    "af71dc3c7b435256f658a6e8378cf807bd34a81b389151f575b2c858f0a06460a0ab8cb42bd1c12680251472f33fadf2"
    "4c7c39b4a41674dd361f76bc370c393a2f9896f0083ceef04589b3808a2b25f11ba788c8c913a75e54f72e6014ace98b"
    "a03199387038a5aedb7ce00b07271c78d829ca735ab295255823f354036951ae960966a33fc72a12a413c7339927ea5a"
    "80c44632ea08a6a87caa19c78ae1bb027cd377947b06019812f61618c2b70ef4192a3b5bc01bec00849843aeaa5b9b09"
    "9808994cd2252ebb195004b497ee4c6e02da65afdb64794289e066121a98b62b2017325cb15f774fe6cb1bb64ba3a618"
    "426da6f7d6298809c6e694ae73d3950fe243d43b824b9d04d5d29e14b1f58b40d035d9e1a61e8035d89a7583e9c215f6"
    "ade241b8005d211dd961f793bc83de1e68001d00207937257f5743fedfcee50ec183188f4ef154489bdb17591e8cc2d8"
    "022dd44b05"
)
GOLDEN_JA4 = "t13i171000_ab0a1bf427ad_8e6e362c5eac"


def test_ja4_golden():
    j, _ = ja4.compute_ja4(bytes.fromhex(GOLDEN_CH_HEX))
    assert j == GOLDEN_JA4
