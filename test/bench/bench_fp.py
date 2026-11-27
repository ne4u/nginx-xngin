#!/usr/bin/env python3
"""Connection-level fingerprinting overhead benchmark.

The h2/h3 tee parses only the first few KB of each connection, so the
cost lands on connection setup — per-request cost on a warm conn is
~zero (the tee restores c->recv after the first HEADERS frame). This
bench measures exactly that: one nginx, two server blocks on separate
port pairs — one plain, one `xngin_h2_inspect on` — both `http2 on`
and QUIC-enabled, `empty_gif` content (no upstream/agent noise).

Lanes (off vs on, same proto):
  h1c   cleartext HTTP/1.1     (tee installed, preface scan only)
  h1s   TLS HTTP/1.1           (tee after Finished, h1 bytes -> BAD)
  h2c   cleartext h2 prior-knowledge
  h2s   TLS h2 (ALPN)
  h3    QUIC/HTTP3 (aioquic client)

Per lane: median conn-setup (tcp+TLS/QUIC handshake), first-request
(preface+frames -> response HEADERS), and warm-request times.

Usage: python3 test/bench/bench_fp.py [--conns 60] [--reqs 10]
Env: XNGIN_NGINX_BIN, XNGIN_MODULE_SO (defaults per stacklib).
"""

import argparse
import asyncio
import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "harness"))
import stacklib                                   # noqa: E402
import h2fp                                       # noqa: E402

CONF = """\
load_module {module_so};
error_log {root}/logs/error.log warn;
pid {root}/nginx.pid;
worker_processes 1;
daemon on;
master_process on;

events {{ worker_connections 2048; }}

http {{
    access_log off;

    server {{
        listen {p_off};
        listen {ps_off} ssl;
        listen {ps_off} quic;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        http2 on;
        location /baseline {{ empty_gif; }}
    }}

    server {{
        listen {p_on};
        listen {ps_on} ssl;
        listen {ps_on} quic;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        http2 on;
        xngin_h2_inspect on;
        location /baseline {{ empty_gif; }}
    }}
}}
"""

# Chrome-like preamble: ordered SETTINGS, conn WINDOW_UPDATE, PRIORITY
SETTINGS = [(h2fp.S_TABLE, 65536), (h2fp.S_STREAMS, 1000),
            (h2fp.S_WINDOW, 6291456), (h2fp.S_FRAME, 16384)]
WINDOW = 15663105
PRIOS = [(5, True, 0, 200), (3, False, 0, 150)]
ORDER = "m,a,s,p"


def med(v):
    return statistics.median(v) if v else 0.0


# ---------- h1 ----------

def h1_once(port, use_ssl, reqs):
    t0 = time.perf_counter_ns()
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    if use_ssl:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname="localhost")
    t_conn = (time.perf_counter_ns() - t0) / 1e3

    def one():
        t = time.perf_counter_ns()
        s.sendall(b"GET /baseline/x HTTP/1.1\r\nHost: x\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise EOFError("conn closed mid-headers")
            buf += chunk
        head, _, buf = buf.partition(b"\r\n\r\n")
        assert b" 200 " in head.split(b"\r\n", 1)[0], head[:64]
        clen = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":")[1])
        while len(buf) < clen:
            chunk = s.recv(65536)
            if not chunk:
                raise EOFError("conn closed mid-body")
            buf += chunk
        return (time.perf_counter_ns() - t) / 1e3

    t_first = one()
    warm = [one() for _ in range(reqs)]
    s.close()
    return t_conn, t_first, warm


# ---------- h2 ----------

def _read_frame(s, buf):
    """return (buf_remainder, type, flags, sid, payload)"""
    while len(buf) < 9:
        chunk = s.recv(65536)
        if not chunk:
            raise EOFError("conn closed mid-frame")
        buf += chunk
    n = int.from_bytes(buf[:3], "big")
    while len(buf) < 9 + n:
        chunk = s.recv(65536)
        if not chunk:
            raise EOFError("conn closed mid-frame")
        buf += chunk
    return buf[9 + n:], buf[3], buf[4], \
        int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF, buf[9:9 + n]


def _h2_request(s, buf, sid, scheme):
    block = h2fp.headers_block(ORDER, scheme=scheme,
                               authority="127.0.0.1", path="/baseline/x")
    s.sendall(h2fp.frame(h2fp.HEADERS, 0x1 | 0x4, sid, block))
    while True:
        buf, ft, fl, fsid, _ = _read_frame(s, buf)
        if ft == h2fp.HEADERS and fsid == sid:
            return buf


def h2_once(port, use_ssl, reqs):
    t0 = time.perf_counter_ns()
    s = h2fp.connect("127.0.0.1", port, use_ssl=use_ssl)
    t_conn = (time.perf_counter_ns() - t0) / 1e3

    # preface + SETTINGS + WINDOW_UPDATE + PRIORITY, then first HEADERS
    parts = [h2fp.PREFACE, h2fp.settings_frame(SETTINGS),
             h2fp.window_update(0, WINDOW)]
    for psid, ex, dep, w in PRIOS:
        parts.append(h2fp.priority_frame(psid, ex, dep, w))
    block = h2fp.headers_block(
        ORDER, scheme="https" if use_ssl else "http",
        authority="127.0.0.1", path="/baseline/x")
    parts.append(h2fp.frame(h2fp.HEADERS, 0x1 | 0x4, 3, block))
    s.sendall(b"".join(parts))

    t = time.perf_counter_ns()
    buf = b""
    while True:
        buf, ft, fl, fsid, _ = _read_frame(s, buf)
        if ft == h2fp.HEADERS and fsid == 3:
            break
    t_first = (time.perf_counter_ns() - t) / 1e3

    # ack server settings once, then warm requests on the same conn
    s.sendall(h2fp.settings_frame([], ack=True))
    warm = []
    sid = 5
    for _ in range(reqs):
        t = time.perf_counter_ns()
        buf = _h2_request(s, buf, sid,
                          "https" if use_ssl else "http")
        warm.append((time.perf_counter_ns() - t) / 1e3)
        sid += 2
    s.close()
    return t_conn, t_first, warm


# ---------- h3 ----------

try:
    from aioquic.asyncio import connect as aquic_connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    HAVE_AIOQUIC = True
except ImportError:
    HAVE_AIOQUIC = False


if HAVE_AIOQUIC:
    class H3Client(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.h3 = None
            self.events = asyncio.Queue()

        def quic_event_received(self, event):
            if self.h3 is not None:
                for ev in self.h3.handle_event(event):
                    self.events.put_nowait(ev)

    async def h3_once(port, reqs):
        cfg = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN,
            verify_mode=ssl.CERT_NONE)
        t0 = time.perf_counter_ns()
        async with aquic_connect("127.0.0.1", port, configuration=cfg,
                                 create_protocol=H3Client) as proto:
            t_conn = (time.perf_counter_ns() - t0) / 1e3
            proto.h3 = H3Connection(proto._quic)
            proto.transmit()

            async def one(sid):
                t = time.perf_counter_ns()
                proto.h3.send_headers(
                    sid,
                    [(b":method", b"GET"), (b":scheme", b"https"),
                     (b":authority", b"127.0.0.1"),
                     (b":path", b"/baseline/x"),
                     (b"user-agent", b"bench-fp")],
                    end_stream=True)
                proto.transmit()
                while True:
                    ev = await asyncio.wait_for(proto.events.get(), 10)
                    if isinstance(ev, HeadersReceived) \
                            and ev.stream_id == sid:
                        break
                return (time.perf_counter_ns() - t) / 1e3

            t_first = await one(
                proto._quic.get_next_available_stream_id())
            warm = []
            for _ in range(reqs):
                sid = proto._quic.get_next_available_stream_id()
                warm.append(await one(sid))
        return t_conn, t_first, warm


async def h3_timed(port, reqs):
    return await asyncio.wait_for(h3_once(port, reqs), 15)


def q(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p))] if s else 0.0


def summarize(conn, first, warm):
    return {"conn_us": med(conn), "first_us": med(first),
            "req_us": med(warm),
            "conn_p25": q(conn, .25), "conn_p75": q(conn, .75),
            "n": len(conn)}


def run_pair(sample, ports, conns):
    """Interleave off/on samples (alternating which goes first) so
    drift — GC, CPU frequency, client warm-up — hits both sides
    equally.  sample(port) -> (conn_us, first_us, warm_us[])."""
    acc = [([], [], []), ([], [], [])]
    for i in range(conns):
        order = (0, 1) if i % 2 == 0 else (1, 0)
        for side in order:
            c, f, w = sample(ports[side])
            acc[side][0].append(c)
            acc[side][1].append(f)
            acc[side][2].extend(w)
    return summarize(*acc[0]), summarize(*acc[1])


def h3_sample(port, reqs):
    for attempt in (1, 2):
        try:
            return asyncio.run(h3_timed(port, reqs))
        except Exception:
            if attempt == 2:
                raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conns", type=int, default=60)
    ap.add_argument("--reqs", type=int, default=10,
                    help="warm requests per connection")
    ap.add_argument("--only", default="",
                    help="comma list of lanes (h1c,h1s,h2c,h2s,h3)")
    args = ap.parse_args()
    only = set(filter(None, args.only.split(",")))

    if not stacklib.HAVE_H2:
        sys.exit("nginx built without http_v2 — bench_fp needs "
                 "`http2 on`; see stacklib.HAVE_H2")
    have_h3 = HAVE_AIOQUIC and stacklib.HAVE_H3

    root = subprocess.run(["mktemp", "-d", "/tmp/xngin-fpbench-XXXX"],
                          capture_output=True, text=True).stdout.strip()
    os.makedirs(os.path.join(root, "logs"), exist_ok=True)

    cert, key = os.path.join(root, "cert.pem"), os.path.join(root, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1",
         "-subj", "/CN=localhost"], check=True, capture_output=True)

    ports = {k: stacklib.free_port()
             for k in ("p_off", "ps_off", "p_on", "ps_on")}
    conf = CONF.format(module_so=stacklib.MODULE_SO, root=root,
                       cert=cert, key=key, **ports)
    conf_path = os.path.join(root, "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(conf)

    proc = subprocess.Popen([stacklib.NGINX_BIN, "-c", conf_path,
                             "-p", root],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                probe = socket.create_connection(
                    ("127.0.0.1", ports["p_off"]), 0.2)
                probe.close()
                break
            except OSError:
                time.sleep(0.05)
        # functional check: h2s + h3 must actually work before timing
        c, f, w = h2_once(ports["ps_on"], True, 2)
        if have_h3:
            h3_sample(ports["ps_on"], 1)

        lanes = [
            ("h1c", h1_once, "p_off", "p_on", False),
            ("h1s", h1_once, "ps_off", "ps_on", True),
            ("h2c", h2_once, "p_off", "p_on", False),
            ("h2s", h2_once, "ps_off", "ps_on", True),
        ]
        rows = []

        def report(name, off, on):
            rows.append((name, off, on))
            print(f"{name:5s} conn {off['conn_us']:7.0f} -> "
                  f"{on['conn_us']:7.0f}us "
                  f"(iqr {off['conn_p25']:.0f}-{off['conn_p75']:.0f} / "
                  f"{on['conn_p25']:.0f}-{on['conn_p75']:.0f})  "
                  f"first {off['first_us']:6.0f} -> {on['first_us']:6.0f}us "
                  f" warm {off['req_us']:5.0f} -> {on['req_us']:5.0f}us",
                  flush=True)

        for name, fn, kp_off, kp_on, use_ssl in lanes:
            if only and name not in only:
                continue
            off, on = run_pair(
                lambda p, fn=fn, u=use_ssl: fn(p, u, args.reqs),
                (ports[kp_off], ports[kp_on]), args.conns)
            report(name, off, on)

        if only and "h3" not in only:
            pass
        elif have_h3:
            # A/A: off vs off — the noise floor for the h3 deltas
            off, on = run_pair(lambda p: h3_sample(p, args.reqs),
                               (ports["ps_off"], ports["ps_off"]),
                               args.conns)
            report("h3-aa", off, on)
            off, on = run_pair(lambda p: h3_sample(p, args.reqs),
                               (ports["ps_off"], ports["ps_on"]),
                               args.conns)
            report("h3", off, on)
        else:
            print("note: no aioquic or no http_v3 in nginx, "
                  "skipping h3 lane", flush=True)

        print("\n=== added fingerprint cost (inspect on - off) ===")
        for name, off, on in rows:
            dc = on["conn_us"] - off["conn_us"]
            df = on["first_us"] - off["first_us"]
            dw = on["req_us"] - off["req_us"]
            print(f"{name:5s} conn {dc:+7.0f}us  first {df:+7.0f}us  "
                  f"warm {dw:+5.0f}us")

        out = os.path.join(root, "bench_fp.json")
        with open(out, "w") as f:
            json.dump({n: {"off": o, "on": x} for n, o, x in rows},
                      f, indent=2)
        print(f"\nresults: {out}")
    finally:
        proc.terminate()
        pidfile = os.path.join(root, "nginx.pid")
        if os.path.exists(pidfile):
            import signal
            try:
                os.kill(int(open(pidfile).read().strip()), 15)
            except OSError:
                pass


if __name__ == "__main__":
    main()
