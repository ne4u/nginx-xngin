"""Python codec conformance vs shared vectors.json."""

import ipaddress
import json
import os

import pytest

import xnap

VECTORS = os.path.join(os.path.dirname(__file__), "..",
                       "conformance", "vectors.json")


def load_vectors():
    with open(VECTORS) as f:
        return json.load(f)["vectors"]


def norm(v):
    """Normalize a decoded value to the JSON-native 'expect' shape."""
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(v)
    if isinstance(v, bytes):
        return {"$bytes": v.hex()}
    if isinstance(v, tuple):
        return norm(list(v))
    if isinstance(v, list):
        if all(isinstance(e, (list, tuple)) and len(e) == 2
               and isinstance(e[0], str) for e in v):
            return {"$pairs": [[k, norm(x)] for k, x in v]}
        return [norm(e) for e in v]
    return v


@pytest.mark.parametrize("vec", load_vectors(),
                         ids=lambda v: v["name"])
def test_vector(vec):
    wire = bytes.fromhex(vec["hex"])
    kind = vec["kind"]

    if kind == "varint":
        r = xnap.Reader(wire)
        assert r.varint() == vec["value"]
        assert xnap.enc_varint(vec["value"]) == wire

    elif kind == "svarint":
        r = xnap.Reader(wire)
        assert r.svarint() == vec["value"]
        assert xnap.enc_svarint(vec["value"]) == wire

    elif kind == "value":
        r = xnap.Reader(wire)
        assert r.pos < r.end
        dec = r.val()
        assert norm(dec) == vec["expect"]

    elif kind == "kv":
        r = xnap.Reader(wire)
        name, dec = r.kv()
        assert name == vec["kname"]
        assert norm(dec) == vec["expect"]

    elif kind == "frame":
        frames, rest = xnap.feed(wire)
        assert rest == b""
        assert len(frames) == 1
        f = frames[0]
        assert f.type == vec["ftype"]
        assert f.flags == vec["flags"]
        assert f.sid == vec["sid"]
        assert f.fid == vec["fid"]
        kvs = [(k, norm(v)) for k, v in f.kvs()]
        exp = [(k, e) for k, e in vec["expect_kv"]]
        assert kvs == exp
