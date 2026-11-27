"""HTTP/2 fingerprint oracle + raw frame client.

Builds the canonical Akamai-format string
    settings|window_update|priorities|pseudo_header_order
and a minimal raw-frames h2 client that exercises the engine's
recv tee (custom SETTINGS order, WINDOW_UPDATE, PRIORITY, and
pseudo-header order).
"""

import socket
import ssl as _ssl
import struct

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# frame types
DATA, HEADERS, PRIORITY, RST, SETTINGS = 0x0, 0x1, 0x2, 0x3, 0x4
PUSH, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0x5, 0x6, 0x7, 0x8, 0x9

# setting ids (RFC 7540 §6.5.2)
S_TABLE, S_PUSH, S_STREAMS, S_WINDOW, S_FRAME, S_HDR_LIST = range(1, 7)


def akamai_fp(settings, window_update, priorities, order):
    """Canonical fingerprint from the frames a client sent."""
    s = ",".join(f"{i}:{v}" for i, v in settings)
    p = ",".join(f"{sid}:{int(ex)}:{dep}:{w}"
                 for sid, ex, dep, w in priorities) or "0"
    letters = order.split(",") if isinstance(order, str) else order
    return f"{s}|{window_update}|{p}|{','.join(letters)}"


def frame(ftype, flags, sid, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + payload)


def settings_frame(pairs, ack=False):
    if ack:
        return frame(SETTINGS, 0x1, 0)
    body = b"".join(struct.pack(">HI", i, v) for i, v in pairs)
    return frame(SETTINGS, 0, 0, body)


def window_update(sid, inc):
    return frame(WINDOW_UPDATE, 0, sid, struct.pack(">I", inc & 0x7FFFFFFF))


def priority_frame(sid, exclusive, depends, weight):
    dep = (depends & 0x7FFFFFFF) | (0x80000000 if exclusive else 0)
    return frame(PRIORITY, 0, sid, struct.pack(">I", dep)
                 + bytes([weight - 1]))


def idx(i):
    """HPACK static-table indexed field (i < 128)."""
    return bytes([0x80 | i])


def lit_name_ref(name_idx, value):
    """HPACK literal-with-incremental-indexing, indexed name."""
    return bytes([0x40 | name_idx, len(value)]) + value.encode()


def lit_name(name, value):
    """HPACK literal-with-incremental-indexing, literal name."""
    return bytes([0x40, len(name)]) + name.encode() \
        + bytes([len(value)]) + value.encode()


# static-table indices for the pseudo headers
IDX_AUTHORITY, IDX_METHOD_GET, IDX_PATH, IDX_SCHEME = 1, 2, 4, 6

PSEUDO_FIELD = {
    "a": lambda scheme, auth: lit_name_ref(IDX_AUTHORITY, auth),
    "m": lambda scheme, auth: idx(IDX_METHOD_GET),
    "p": lambda scheme, auth: idx(IDX_PATH),
    "s": lambda scheme, auth: idx(IDX_SCHEME + (1 if scheme == "https" else 0)),
}


def headers_block(order, scheme="https", authority="127.0.0.1",
                  path="/"):
    """HPACK block emitting pseudo headers in the given letter order."""
    order = order.replace(",", "")
    out = []
    for ch in order:
        if ch == "p" and path != "/":
            out.append(lit_name_ref(IDX_PATH, path))
        else:
            out.append(PSEUDO_FIELD[ch](scheme, authority))
    return b"".join(out)


def h2_handshake(sock, settings, window_inc, priorities,
                 order="m,a,s,p", scheme="https",
                 authority="127.0.0.1", sid=3, path_idx=IDX_PATH):
    """Send preface + frames + one GET request; return bytes read back."""
    parts = [PREFACE, settings_frame(settings)]
    if window_inc:
        parts.append(window_update(0, window_inc))
    for psid, ex, dep, w in priorities:
        parts.append(priority_frame(psid, ex, dep, w))
    block = headers_block(order, scheme=scheme, authority=authority)
    parts.append(frame(HEADERS, 0x1 | 0x4, sid, block))  # END_STREAM|END_HEADERS
    sock.sendall(b"".join(parts))

    out = b""
    sock.settimeout(5)
    try:
        while True:
            chunk = sock.recv(65535)
            if not chunk:
                break
            out += chunk
            if b"\x00\x00\x00\x01" in out:      # some HEADERS back
                break
    except socket.timeout:
        pass
    return out


def connect(host, port, use_ssl=True):
    s = socket.create_connection((host, port), timeout=5)
    if not use_ssl:
        return s
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    return ctx.wrap_socket(s, server_hostname="localhost")
