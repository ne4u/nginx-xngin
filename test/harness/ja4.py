"""JA4 TLS client fingerprint — independent reference implementation.

Pure byte-level parser (no ssl module) written straight from the JA4
spec, used as a third-party oracle against the C engine's ja4 field
and the Go SDK's ComputeJA4. Input is a handshake message: 4-byte
handshake header + ClientHello body (what the engine captures via
SSL_CTX_set_msg_callback and ships as the "ch-raw" NOTIFY field).

Returns (ja4, ja4_r) matching the engine's wire format:

    ja4   = ja4_a "_" sha256[:12](sorted cipher list)
                "_" sha256[:12](sorted ext list "_" sig-alg list)
    ja4_r = ja4_a "_" cipher list "_" ext list "_" sig-alg list
"""

import hashlib

EXT_SNI, EXT_SIGALGS, EXT_ALPN, EXT_SUPVERS = 0x0000, 0x000d, 0x0010, 0x002b

_VERSION_MAP = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                0x0300: "s3", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}


def _is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


def _hash12(s):
    # engine quirk: empty input maps to all-zero hash, not sha256("")
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "0" * 12


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def parse_ch(raw):
    """Parse ClientHello body fields needed for JA4. Raises ValueError."""
    if not raw or len(raw) < 4 or raw[0] != 0x01:
        raise ValueError("not a client_hello handshake message")
    body = raw[4:]
    if int.from_bytes(raw[1:4], "big") != len(body):
        raise ValueError("handshake length mismatch")
    if len(body) < 38:
        raise ValueError("truncated client_hello")

    pos = 0
    legacy_ver = _u16(body, pos)
    pos += 2 + 32                                  # version + random
    sid_len = body[pos]
    pos += 1 + sid_len                             # session_id
    clen = _u16(body, pos)
    pos += 2
    ciphers = [_u16(body, i) for i in range(pos, pos + clen, 2)]
    pos += clen
    ncomp = body[pos]
    pos += 1 + ncomp                               # compression methods

    exts = {}
    if pos < len(body):                            # ext block is optional
        elen = _u16(body, pos)
        pos += 2
        end = pos + elen
        while pos + 4 <= end:
            et, edl = _u16(body, pos), _u16(body, pos + 2)
            exts[et] = body[pos + 4:pos + 4 + edl]
            pos += 4 + edl

    return {"ver": legacy_ver, "ciphers": ciphers, "exts": exts}


def compute_ja4(raw):
    """Compute (ja4, ja4_r) from a raw client_hello handshake message."""
    ch = parse_ch(raw)
    exts = ch["exts"]

    ciphers = sorted(c for c in ch["ciphers"] if not _is_grease(c))
    ext_types = sorted(e for e in exts
                       if not _is_grease(e) and e not in (EXT_SNI, EXT_ALPN))
    ext_total = sum(1 for e in exts if not _is_grease(e))

    highest = ch["ver"]
    sv = exts.get(EXT_SUPVERS)
    if sv and len(sv) >= 3:
        n = sv[0]
        vals = [_u16(sv, i) for i in range(1, min(1 + n, len(sv) - 1), 2)]
        cand = max((v for v in vals if not _is_grease(v)), default=0)
        if cand:
            highest = cand
    ver = _VERSION_MAP.get(highest, "00")

    sni = "d" if exts.get(EXT_SNI) else "i"

    alpn = "00"
    adata = exts.get(EXT_ALPN)
    if adata and len(adata) >= 3:
        end = 2 + _u16(adata, 0)
        pos = 2
        while pos < len(adata) and pos < end:
            plen = adata[pos]
            pos += 1
            if plen and pos + plen <= len(adata):
                p = adata[pos:pos + plen]
                if plen == 2 and _is_grease(_u16(p, 0)):
                    pos += plen
                    continue
                f, l = p[0], p[-1]
                if chr(f).isalnum() and chr(l).isalnum():
                    alpn = chr(f) + chr(l)
                else:
                    alpn = f"{f >> 4:x}{l & 0x0f:x}"
                break
            pos += plen

    sigs = []
    sdata = exts.get(EXT_SIGALGS)
    if sdata and len(sdata) >= 2:
        n = _u16(sdata, 0)
        sigs = [_u16(sdata, i) for i in range(2, min(2 + n, len(sdata) - 1), 2)
                if not _is_grease(_u16(sdata, i))]

    ja4_a = (f"t{ver}{sni}{min(len(ciphers), 99):02d}"
             f"{min(ext_total, 99):02d}{alpn}")

    b_raw = ",".join(f"{c:04x}" for c in ciphers)
    c_raw = ",".join(f"{e:04x}" for e in ext_types)
    if sigs:
        if ext_types:
            c_raw += "_"
        c_raw += ",".join(f"{s:04x}" for s in sigs)

    return (f"{ja4_a}_{_hash12(b_raw)}_{_hash12(c_raw)}",
            f"{ja4_a}_{b_raw}_{c_raw}")
