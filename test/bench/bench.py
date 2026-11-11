#!/usr/bin/env python3
"""xngin latency/throughput benchmark.

Lanes on one nginx port; content handler is empty_gif (C-speed, no
upstream dependency — POST gets 405 but xngin's access-phase work
still runs):
  /baseline  no offload
  /          blocking verdict, UDS agent
  /async     fire-and-forget offload
  /cache     blocking + xngin_cache_key (repeat keys = cache hit)
  /body      blocking + xngin_body_inspect (POST 1k)
  /resp      blocking + xngin_response (second round-trip)
  /deny      agent denies 403 (no content handler)
  /tcpblock  blocking verdict, loopback-TCP agent

Measures:
  * serial keep-alive prober -> per-request p50/p95/p99 (us)
  * ab -k -c 50 -n 5000    -> throughput + mean latency
  * $xngin_agent_rtt_us    -> engine-side agent RTT (access log)

Usage:
  python3 test/bench/bench.py [--serial-n 300] [--ab-n 5000] [--ab-c 50]

Env: XNGIN_NGINX_BIN, XNGIN_MODULE_SO (defaults per stacklib).
"""

import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "harness"))
import stacklib                                   # noqa: E402

POST_BODY = b"x" * 1024

CONF = """\
load_module {module_so};
error_log {root}/logs/error.log warn;
pid {root}/nginx.pid;
worker_processes 4;
daemon on;
master_process on;

events {{ worker_connections 2048; }}

http {{
    log_format xnginlog 'uri=$uri st=$status rtt=$xngin_agent_rtt_us '
                        'cache=$xngin_cache err=$xngin_error';
    access_log {root}/logs/access.log xnginlog;

    xngin_agent_group uds {{
        server unix:{uds_sock};
        keepalive 4;
        ping_interval 60s;
    }}
    xngin_agent_group net {{
        server 127.0.0.1:{tcp_port};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_cache_zone verdicts:8m;

    server {{
        listen {listen_port};

        location /baseline {{ empty_gif; }}

        location / {{
            xngin_enable on; xngin_group uds;
            xngin_timeout 200ms; xngin_fail close;
            empty_gif;
        }}
        location /async {{
            xngin_enable on; xngin_group uds;
            xngin_mode async;
            empty_gif;
        }}
        location /cache {{
            xngin_enable on; xngin_group uds;
            xngin_cache_key $uri;
            empty_gif;
        }}
        location /body {{
            xngin_enable on; xngin_group uds;
            xngin_body_inspect on; xngin_body_max 8k;
            empty_gif;
        }}
        location /resp {{
            xngin_enable on; xngin_group uds;
            xngin_response on;
            empty_gif;
        }}
        location /deny {{
            xngin_enable on; xngin_group uds;
            empty_gif;
        }}
        location /tcpblock {{
            xngin_enable on; xngin_group net;
            empty_gif;
        }}
    }}
}}
"""

RULES = {
    "default": {"action": "allow", "cache_ttl": 60},
    "rules": [
        {"match": {"uri_contains": "/deny"},
         "verdict": {"action": "deny", "status": 403, "body": "denied"}},
    ],
    "res_default": {"action": "allow"},
}

# name, path, method, body, expected status
LANES = [
    ("baseline",  "/baseline/x",  "GET",  None,      200),
    ("blocking",  "/x",           "GET",  None,      200),
    ("async",     "/async/x",     "GET",  None,      200),
    ("cache-hit", "/cache/x",     "GET",  None,      200),
    ("body-1k",   "/body/x",      "POST", POST_BODY, 405),
    ("resp-insp", "/resp/x",      "GET",  None,      200),
    ("deny-403",  "/deny/x",      "GET",  None,      403),
    ("tcp-block", "/tcpblock/x",  "GET",  None,      200),
]


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p / 100))]


class KeepAlive:
    """One keep-alive HTTP/1.1 connection; per-request wall time in us."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port))
        self.sock.settimeout(10)
        self.buf = b""

    def close(self):
        self.sock.close()

    def _readline(self):
        while b"\r\n" not in self.buf:
            self.buf += self.sock.recv(65536)
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _readn(self, n):
        while len(self.buf) < n:
            self.buf += self.sock.recv(65536)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def request(self, path, method="GET", body=None):
        req = (f"{method} {path} HTTP/1.1\r\nHost: bench\r\n"
               f"Content-Length: {len(body) if body else 0}\r\n\r\n"
               ).encode() + (body or b"")
        t0 = time.perf_counter_ns()
        self.sock.sendall(req)
        line = self._readline()
        status = int(line.split()[1])
        clen = None
        chunked = False
        while True:
            h = self._readline()
            if not h:
                break
            h = h.lower()
            if h.startswith(b"content-length:"):
                clen = int(h.split(b":")[1])
            elif h.startswith(b"transfer-encoding:"):
                chunked = b"chunked" in h
        if chunked:
            while True:
                n = int(self._readline().split(b";")[0], 16)
                if n == 0:
                    self._readline()          # trailing CRLF
                    break
                self._readn(n + 2)            # data + CRLF
        elif clen:
            self._readn(clen)
        return status, (time.perf_counter_ns() - t0) / 1e3


def serial_bench(port, path, method, body, want, n):
    ka = KeepAlive(port)
    bad = 0
    try:
        for _ in range(20):                    # warmup
            ka.request(path, method, body)
        ts = []
        for _ in range(n):
            st, us = ka.request(path, method, body)
            bad += (st != want)
            ts.append(us)
        return ts, bad
    finally:
        ka.close()


def ab_bench(port, path, method, body, n, c, tmpdir):
    argv = ["ab", "-k", "-c", str(c), "-n", str(n), "-q"]
    if body:
        f = os.path.join(tmpdir, "post.bin")
        with open(f, "wb") as fh:
            fh.write(body)
        argv += ["-p", f, "-T", "application/octet-stream"]
    argv.append(f"http://127.0.0.1:{port}{path}")
    out = subprocess.run(argv, capture_output=True, text=True).stdout
    rps = re.search(r"Requests per second:\s+([\d.]+)", out)
    lat = re.search(r"Time per request:\s+([\d.]+) \[ms\] \(mean, across",
                    out)
    fails = re.search(r"Failed requests:\s+(\d+)", out)
    return (float(rps.group(1)) if rps else 0.0,
            float(lat.group(1)) * 1e3 if lat else 0.0,
            int(fails.group(1)) if fails else -1)


def log_rtts(access_log, uri):
    """$xngin_agent_rtt_us values for a lane from the access log."""
    out = []
    pat = re.compile(rf"uri={re.escape(uri)} .*rtt=(\d+)")
    try:
        with open(access_log) as f:
            for line in f:
                m = pat.search(line)
                if m:
                    out.append(int(m.group(1)))
    except OSError:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial-n", type=int, default=300)
    ap.add_argument("--ab-n", type=int, default=5000)
    ap.add_argument("--ab-c", type=int, default=50)
    args = ap.parse_args()

    root = subprocess.run(["mktemp", "-d", "/tmp/xngin-bench-XXXX"],
                          capture_output=True, text=True).stdout.strip()
    os.makedirs(os.path.join(root, "logs"), exist_ok=True)

    uds_agent = stacklib.Agent(root, 0, RULES)
    tcp_agent = stacklib.Agent(root, 1, RULES, tcp=True)

    conf = CONF.format(
        module_so=stacklib.MODULE_SO, root=root,
        uds_sock=uds_agent.sock, tcp_port=tcp_agent.port,
        listen_port=stacklib.free_port())
    conf_path = os.path.join(root, "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(conf)

    port = int(re.search(r"listen (\d+);", conf).group(1))
    procs = []
    try:
        uds_agent.start(root)
        tcp_agent.start(root)
        procs.append(subprocess.Popen(
            [stacklib.NGINX_BIN, "-c", conf_path, "-p", root],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/baseline/x",
                                       timeout=1)
                break
            except Exception:
                time.sleep(0.1)

        # wait for the agent group to be ready too: fail-close would 503
        # until conns complete the XNAP handshake
        for _ in range(100):
            try:
                st = urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/x", timeout=1).status
                if st == 200:
                    break
            except urllib.error.HTTPError:
                time.sleep(0.05)
            except Exception:
                time.sleep(0.05)

        # global warmup: nginx workers, upstream conn pools and agent
        # keepalives all start cold — prime every lane before measuring
        for name, path, method, body, want in LANES:
            ka = KeepAlive(port)
            try:
                for _ in range(50):
                    ka.request(path, method, body)
            finally:
                ka.close()

        rows = []
        for name, path, method, body, want in LANES:
            ts, bad = serial_bench(port, path, method, body, want,
                                   args.serial_n)
            rps, lat_us, fails = ab_bench(port, path, method, body,
                                          args.ab_n, args.ab_c, root)
            rtts = log_rtts(os.path.join(root, "logs", "access.log"), path)
            rows.append({
                "lane": name, "n": len(ts), "bad_status": bad,
                "p50": pct(ts, 50), "p95": pct(ts, 95), "p99": pct(ts, 99),
                "mean": statistics.fmean(ts),
                "ab_rps": rps, "ab_lat_us": lat_us, "ab_fails": fails,
                "rtt_p50": pct(rtts, 50) if rtts else None,
                "rtt_p99": pct(rtts, 99) if rtts else None,
            })
            print(f"{name:10s} p50={rows[-1]['p50']:7.0f}us "
                  f"p99={rows[-1]['p99']:7.0f}us "
                  f"ab={rps:8.0f}rps rtt_p50={rows[-1]['rtt_p50']}"
                  + (f"  !! {bad} bad-status" if bad else ""),
                  flush=True)

        out = os.path.join(root, "bench.json")
        with open(out, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"\nresults: {out}")

        base = rows[0]["mean"]
        print("\n=== summary (mean serial latency delta vs baseline) ===")
        for r in rows:
            print(f"{r['lane']:10s} +{r['mean'] - base:7.0f}us  "
                  f"(mean {r['mean']:.0f}us, ab {r['ab_rps']:.0f} rps)")

    finally:
        for p in procs:
            p.terminate()
        for a in (uds_agent, tcp_agent):
            if a.proc:
                a.proc.terminate()
        pidfile = os.path.join(root, "nginx.pid")
        if os.path.exists(pidfile):
            import signal
            try:
                os.kill(int(open(pidfile).read().strip()), 15)
            except OSError:
                pass


if __name__ == "__main__":
    main()
