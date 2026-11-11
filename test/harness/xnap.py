"""XNAP (xngin Agent Protocol) reference implementation.

Minimal, dependency-free codec + frame IO used by the test stub agent and
the conformance test suite. Implements SPEC.md version 1.
"""

import ipaddress
import struct

VERSION = 1

# frame types
FT_ENGINE_HELLO = 0x01
FT_AGENT_HELLO = 0x02
FT_DISCON = 0x03
FT_NOTIFY = 0x04
FT_VERDICT = 0x05
FT_BODY = 0x06
FT_ABORT = 0x07
FT_PING = 0x08
FT_PONG = 0x09

# value types
VT_NULL = 0x00
VT_TRUE = 0x01
VT_FALSE = 0x02
VT_INT32 = 0x03
VT_INT64 = 0x04
VT_UINT32 = 0x05
VT_UINT64 = 0x06
VT_IPV4 = 0x07
VT_IPV6 = 0x08
VT_STR = 0x09
VT_BIN = 0x0A
VT_KVL = 0x0B
VT_STRLIST = 0x0C

# stream flags
FL_FIN = 0x01
FL_ABORT = 0x02
FL_NOTIFY_HAS_BODY = 1 << 8
FL_NOTIFY_ASYNC = 1 << 9
FL_BODY_LAST = 1 << 8
FL_BODY_TRUNCATED = 1 << 9

CAP_BODY = 0x01
CAP_ASYNC = 0x02
CAP_VCACHE = 0x04
CAP_RESP = 0x08


class ProtoError(Exception):
    pass


# ---------- encoding ----------

def enc_varint(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def enc_svarint(v: int) -> bytes:
    return enc_varint((v << 1) ^ (v >> 63))


def enc_val(val) -> bytes:
    """Encode a typed value from a Python object:
       None->NULL, bool->TRUE/FALSE, int->INT64,
       str->STR, bytes->BIN, ipaddress->IPV4/6,
       list of (k,v) pairs->KVL, StrList(list of str)->STRLIST,
       ("type", raw) via Raw(tag, bytes)."""
    if val is None:
        return bytes([VT_NULL])
    if val is True:
        return bytes([VT_TRUE])
    if val is False:
        return bytes([VT_FALSE])
    if isinstance(val, Raw):
        return bytes([val.tag]) + val.data
    if isinstance(val, int):
        return bytes([VT_INT64]) + enc_svarint(val)
    if isinstance(val, str):
        b = val.encode()
        return bytes([VT_STR]) + enc_varint(len(b)) + b
    if isinstance(val, bytes):
        return bytes([VT_BIN]) + enc_varint(len(val)) + val
    if isinstance(val, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        t = VT_IPV4 if isinstance(val, ipaddress.IPv4Address) else VT_IPV6
        return bytes([t]) + val.packed
    if isinstance(val, StrList):
        out = bytearray([VT_STRLIST])
        out += enc_varint(len(val.items))
        for s in val.items:
            b = s.encode() if isinstance(s, str) else s
            out += enc_varint(len(b)) + b
        return bytes(out)
    if isinstance(val, (list, tuple)):
        # KVL: sequence of (name, value) pairs
        inner = bytearray()
        for k, v in val:
            inner += enc_kv(k, v)
        return bytes([VT_KVL]) + enc_varint(len(inner)) + bytes(inner)
    raise TypeError(f"cannot encode {type(val)}")


class Raw:
    def __init__(self, tag, data):
        self.tag = tag
        self.data = data


class StrList:
    def __init__(self, items):
        self.items = list(items)


def enc_kv(name, val) -> bytes:
    nb = name.encode() if isinstance(name, str) else name
    return enc_varint(len(nb)) + nb + enc_val(val)


def enc_frame(ftype, flags, sid, fid, payload=b"") -> bytes:
    body = bytes([ftype]) + struct.pack(">I", flags) \
        + enc_varint(sid) + enc_varint(fid) + payload
    return enc_varint(len(body)) + body


# ---------- decoding ----------

class Reader:
    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos
        self.end = len(data)

    def varint(self):
        v = 0
        shift = 0
        while True:
            if self.pos >= self.end:
                raise ProtoError("truncated varint")
            b = self.data[self.pos]
            self.pos += 1
            v |= (b & 0x7F) << shift
            if not (b & 0x80):
                return v
            shift += 7
            if shift >= 70:
                raise ProtoError("overlong varint")

    def svarint(self):
        v = self.varint()
        return (v >> 1) ^ -(v & 1)

    def need(self, n):
        if self.end - self.pos < n:
            raise ProtoError("truncated")

    def val(self):
        self.need(1)
        t = self.data[self.pos]
        self.pos += 1
        if t == VT_NULL:
            return None
        if t == VT_TRUE:
            return True
        if t == VT_FALSE:
            return False
        if t in (VT_INT32, VT_INT64):
            return self.svarint()
        if t in (VT_UINT32, VT_UINT64):
            return self.varint()
        if t == VT_IPV4:
            self.need(4)
            a = ipaddress.IPv4Address(self.data[self.pos:self.pos + 4])
            self.pos += 4
            return a
        if t == VT_IPV6:
            self.need(16)
            a = ipaddress.IPv6Address(self.data[self.pos:self.pos + 16])
            self.pos += 16
            return a
        if t in (VT_STR, VT_BIN):
            n = self.varint()
            self.need(n)
            b = self.data[self.pos:self.pos + n]
            self.pos += n
            return b.decode() if t == VT_STR else bytes(b)
        if t == VT_KVL:
            n = self.varint()
            self.need(n)
            sub = Reader(self.data[self.pos:self.pos + n])
            self.pos += n
            return list(sub.kv_iter())
        if t == VT_STRLIST:
            n = self.varint()
            out = []
            for _ in range(n):
                ln = self.varint()
                self.need(ln)
                out.append(self.data[self.pos:self.pos + ln].decode())
                self.pos += ln
            return out
        raise ProtoError(f"unknown value type {t:#x}")

    def kv(self):
        """next (name, value) or None at end"""
        if self.pos >= self.end:
            return None
        n = self.varint()
        self.need(n)
        name = self.data[self.pos:self.pos + n].decode()
        self.pos += n
        return name, self.val()

    def kv_iter(self):
        while True:
            kv = self.kv()
            if kv is None:
                return
            yield kv


class Frame:
    __slots__ = ("type", "flags", "sid", "fid", "payload")

    def __init__(self, ftype, flags, sid, fid, payload):
        self.type = ftype
        self.flags = flags
        self.sid = sid
        self.fid = fid
        self.payload = payload

    def kvs(self):
        return list(Reader(self.payload).kv_iter())

    def kvs_dict(self):
        return dict(self.kvs())

    def notify_msg(self):
        """(msg-name, [(k,v), ...])"""
        r = Reader(self.payload)
        n = r.varint()
        r.need(n)
        msg = r.data[r.pos:r.pos + n].decode()
        r.pos += n
        return msg, list(r.kv_iter())


def feed(buf: bytes):
    """(frames, leftover) — parse complete frames from buf."""
    frames = []
    pos = 0
    end = len(buf)
    while True:
        start = pos
        # frame-len varint
        flen = 0
        shift = 0
        done = False
        while pos < end and shift < 70:
            b = buf[pos]
            pos += 1
            flen |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                done = True
                break
        if not done:
            if pos - start >= 10:
                raise ProtoError("overlong length varint")
            return frames, buf[start:]
        if flen < 6:
            raise ProtoError(f"bad frame len {flen}")
        if end - pos < flen:
            return frames, buf[start:]
        p = pos
        ftype = buf[p]
        p += 1
        flags = struct.unpack(">I", buf[p:p + 4])[0]
        p += 4
        r = Reader(buf, p)
        sid = r.varint()
        fid = r.varint()
        payload = buf[r.pos:pos + flen]
        frames.append(Frame(ftype, flags, sid, fid, payload))
        pos += flen


def kvs_to_dict(kvs):
    return dict(kvs)


def headers_dict(kvs):
    """extract 'headers' KVL -> {name: [values]}"""
    out = {}
    for k, v in kvs:
        if k == "headers" and isinstance(v, list):
            for hk, hv in v:
                out.setdefault(hk, []).append(hv)
    return out
