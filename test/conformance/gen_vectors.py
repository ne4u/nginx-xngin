#!/usr/bin/env python3
"""Generate conformance vectors from the Python reference codec.

Each vector is {name, kind, ...input, "hex": wire-bytes}. Every SDK's
conformance test asserts decode(hex) == input and encode(input) == hex.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "harness"))
import xnap  # noqa: E402

V = []


def decode_expect(wire):
    """Decode an encoded value back to its semantic form, then render as
       JSON-friendly 'expect'."""
    r = xnap.Reader(wire)
    return expect_repr(r.val())


def value(name, typ, pyval):
    wire = xnap.enc_val(pyval)
    V.append({
        "name": name,
        "kind": "value",
        "type": typ,
        "expect": decode_expect(wire),
        "hex": wire.hex(),
    })


def expect_repr(v):
    import ipaddress
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, bytes):
        return {"$bytes": v.hex()}
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(v)
    if isinstance(v, (list, tuple)):
        # decoded KVL arrives as list of (name, value) pairs; decoded
        # STRLIST as list of str — distinguish by element shape
        if all(isinstance(e, tuple) for e in v):
            return {"$pairs": [[k, expect_repr(x)] for k, x in v]}
        return [expect_repr(e) for e in v]
    raise TypeError(f"no repr for {type(v)}")


def kv(name, key, val):
    wire = xnap.enc_kv(key, val)
    V.append({
        "name": name,
        "kind": "kv",
        "kname": key,
        "expect": decode_expect(wire[len(xnap.enc_varint(len(key.encode()))) + len(key.encode()):]),
        "hex": wire.hex(),
    })


def frame(name, ftype, flags, sid, fid, payload_kv):
    payload = b"".join(xnap.enc_kv(k, v) for k, v in payload_kv)
    wire = xnap.enc_frame(ftype, flags, sid, fid, payload)
    # decode each value to get its semantic 'expect'
    r = xnap.Reader(payload)
    expect_kv = [(k, expect_repr(v)) for k, v in r.kv_iter()]
    V.append({
        "name": name,
        "kind": "frame",
        "ftype": ftype,
        "flags": flags,
        "sid": sid,
        "fid": fid,
        "expect_kv": expect_kv,
        "hex": wire.hex(),
    })


def varint(name, v):
    V.append({"name": name, "kind": "varint", "value": v,
              "hex": xnap.enc_varint(v).hex()})


def svarint(name, v):
    V.append({"name": name, "kind": "svarint", "value": v,
              "hex": xnap.enc_svarint(v).hex()})


varint("uvarint-0", 0)
varint("uvarint-1", 1)
varint("uvarint-127", 127)
varint("uvarint-128", 128)
varint("uvarint-300", 300)
varint("uvarint-16384", 16384)
varint("uvarint-1M", 1048576)
varint("uvarint-2^32", 4294967296)

svarint("svarint-0", 0)
svarint("svarint--1", -1)
svarint("svarint-42", 42)
svarint("svarint--300", -300)
svarint("svarint-big", 1 << 40)
svarint("svarint-neg-big", -(1 << 40))

value("null", "null", None)
value("true", "bool", True)
value("false", "bool", False)
value("int-neg", "int64", -42)
value("int-pos", "int64", 1337)
value("str-empty", "str", "")
value("str-ascii", "str", "hello xngin")
value("str-utf8", "str", "héllo→wörld")
value("bin", "bin", b"\x00\x01\x02\xff")
import ipaddress
value("ipv4", "ipv4", ipaddress.IPv4Address("10.20.30.40"))
value("ipv6", "ipv6", ipaddress.IPv6Address("::1"))
value("strlist", "strlist", xnap.StrList(["a", "bc", "def"]))
value("kvl-headers", "kvl", [("host", "example.com"),
                             ("user-agent", "curl/8"),
                             ("x-a", "1"), ("x-a", "2")])

kv("kv-action", "action", "allow")
kv("kv-score", "score", xnap.Raw(xnap.VT_INT32, xnap.enc_svarint(90)))
kv("kv-uri", "uri", "/admin?x=1")
kv("kv-ttl", "cache-ttl", xnap.Raw(xnap.VT_UINT32, xnap.enc_varint(30)))

frame("verdict-allow", xnap.FT_VERDICT, xnap.FL_FIN, 41, 0,
      [("action", "allow"),
       ("score", xnap.Raw(xnap.VT_INT32, xnap.enc_svarint(0))),
       ("reason", "clean")])

frame("verdict-deny", xnap.FT_VERDICT, xnap.FL_FIN, 7, 0,
      [("action", "deny"),
       ("status", xnap.Raw(xnap.VT_INT32, xnap.enc_svarint(403))),
       ("reason", "denylist hit"),
       ("body", b"forbidden")])

frame("verdict-redirect", xnap.FT_VERDICT, xnap.FL_FIN, 9, 0,
      [("action", "redirect"),
       ("status", xnap.Raw(xnap.VT_INT32, xnap.enc_svarint(302))),
       ("location", "https://example.com/")])

frame("ping", xnap.FT_PING, 0, 0, 3, [])

frame("verdict-mutations", xnap.FT_VERDICT, xnap.FL_FIN, 13, 0,
      [("action", "allow"),
       ("hdr-set", [("x-added", "1"), ("x-tag", "yes")]),
       ("hdr-unset", xnap.StrList(["x-secret"])),
       ("vars", [("rule", "acl-pass"), ("level", "3")]),
       ("cache-ttl", xnap.Raw(xnap.VT_UINT32, xnap.enc_varint(60)))])

frame("verdict-res-mutations", xnap.FT_VERDICT, xnap.FL_FIN, 15, 0,
      [("action", "allow"),
       ("req-body", b"REWRITTEN"),
       ("res-hdr-set", [("x-agent", "on"), ("x-ja4", "t13d0000h0_0_0")]),
       ("res-hdr-unset", xnap.StrList(["x-powered-by", "server"])),
       ("res-body", b"REPLACED")])

frame("verdict-response", xnap.FT_VERDICT, xnap.FL_FIN, 21, 0,
      [("action", "allow"),
       ("res-hdr-set", [("x-filtered", "yes")]),
       ("res-body", b"masked"),
       ("vars", [("res_rule", "pii-redact")])])

out = os.path.join(os.path.dirname(__file__), "vectors.json")
with open(out, "w") as f:
    json.dump({"protocol": "XNAP", "version": 1, "vectors": V}, f, indent=2)
print(f"wrote {len(V)} vectors -> {out}")
