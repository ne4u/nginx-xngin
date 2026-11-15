#!/usr/bin/env python3
"""xngin latency/throughput benchmark.

Lanes on one nginx port; content handler is empty_gif (C-speed, no
upstream dependency — POST gets 405 but xngin's access-phase work
still runs):
  /baseline  no offload
  /          blocking verdict, UDS agent
  /async     fire-and-forget offload
  /cache     blocking + xngin_cache_key (repeat keys = cache hit)
  /body      blocking + xngin_body_inspect (POST 1k / 64k)
  /resp      blocking + xngin_response (second round-trip)
  /deny      agent denies 403 (no content handler)
  /tcpblock  blocking verdict, loopback-TCP agent
  /goblock   blocking verdict, Go edge-guard agent (rate=0, UDS)
  /cecho     blocking verdict, C echo agent (fixed allow, UDS)
  /mtlsblock blocking verdict, Python stub agent over mTLS (agent-bound)
  /gomtls    blocking verdict, Go edge-guard agent over mTLS

Measures:
  * serial keep-alive prober -> per-request p50/p95/p99 (us)
  * ab -k -c 50 -n 5000    -> throughput + mean latency
  * $xngin_agent_rtt_us    -> engine-side agent RTT (access log)
  * $xngin_encode_us / $xngin_syscall_us / $xngin_agent_us
    -> engine CPU vs socket I/O vs agent-side time (access log)
  * $xngin_agentus         -> c-echo agent's self-reported svc time

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
POST_BODY_64K = b"x" * 65536

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
                        'enc=$xngin_encode_us sys=$xngin_syscall_us '
                        'agt=$xngin_agent_us aus=$xngin_agentus '
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
    xngin_agent_group go {{
        server unix:{go_sock};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_agent_group cecho {{
        server unix:{c_sock};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_agent_group mtls {{
        server unix:{mtls_sock};
        ssl on;
        ssl_trusted_certificate {mtls_ca};
        ssl_certificate {mtls_eng_crt};
        ssl_certificate_key {mtls_eng_key};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_agent_group gomtls {{
        server unix:{go_mtls_sock};
        ssl on;
        ssl_trusted_certificate {mtls_ca};
        ssl_certificate {mtls_eng_crt};
        ssl_certificate_key {mtls_eng_key};
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
            xngin_body_inspect on; xngin_body_max 128k;
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
        location /goblock {{
            xngin_enable on; xngin_group go;
            empty_gif;
        }}
        location /cecho {{
            xngin_enable on; xngin_group cecho;
            empty_gif;
        }}
        location /mtlsblock {{
            xngin_enable on; xngin_group mtls;
            empty_gif;
        }}
        location /gomtls {{
            xngin_enable on; xngin_group gomtls;
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
    ("baseline",  "/baseline/x",  "GET",  None,          200),
    ("blocking",  "/x",           "GET",  None,          200),
    ("async",     "/async/x",     "GET",  None,          200),
    ("cache-hit", "/cache/x",     "GET",  None,          200),
    ("body-1k",   "/body/x",      "POST", POST_BODY,     405),
    ("body-64k",  "/body/x",      "POST", POST_BODY_64K, 405),
    ("resp-insp", "/resp/x",      "GET",  None,          200),
    ("deny-403",  "/deny/x",      "GET",  None,          403),
    ("tcp-block", "/tcpblock/x",  "GET",  None,          200),
    ("go-block",  "/goblock/x",   "GET",  None,          200),
    ("c-echo",    "/cecho/x",     "GET",  None,          200),
    ("mtls-block", "/mtlsblock/x", "GET", None,          200),
    ("go-mtls",   "/gomtls/x",    "GET",  None,          200),
]

REPO = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))


def build_go_agent(root):
    """Build edge-guard for the go lanes; None when go is missing."""
    dst = os.path.join(root, "edge-guard")
    r = subprocess.run(
        ["go", "build", "-o", dst, "./cmd/edge-guard"],
        cwd=os.path.join(REPO, "agents", "go"),
        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"note: go build failed, skipping go lanes\n{r.stderr}",
              flush=True)
        return None
    return dst


def build_c_agent(root):
    """Compile the C echo agent for the c-echo lane; None on failure."""
    dst = os.path.join(root, "xnap-echo")
    r = subprocess.run(
        ["cc", "-O2", "-pthread", "-o", dst,
         os.path.join(REPO, "test", "bench", "echo_agent.c")],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"note: cc failed, skipping c-echo lane\n{r.stderr}",
              flush=True)
        return None
    return dst


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


METRIC_KEYS = ("rtt", "enc", "sys", "agt", "aus")


def log_metrics(access_log, uri, start=None, end=None):
    """per-request engine-side timings for a lane from the access log.
    start/end are byte offsets delimiting the serial-bench window —
    rtt/enc/sys/agt blend queue-wait under `ab -c 50`, so only the
    serial slice gives honest per-request numbers."""
    out = {k: [] for k in METRIC_KEYS}
    pat = re.compile(
        rf"uri={re.escape(uri)} .*"
        r"rtt=(\d+|-).*enc=(\d+|-).*sys=(\d+|-).*agt=(\d+|-).*aus=(\d+|-)")
    try:
        with open(access_log) as f:
            if start:
                f.seek(start)
            if end is None:
                lines = f.read().splitlines()
            else:
                lines = f.read(end - f.tell()).splitlines()
            for line in lines:
                m = pat.search(line)
                if not m:
                    continue
                for k, g in zip(METRIC_KEYS, m.groups()):
                    if g != "-":
                        out[k].append(int(g))
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
    certs = stacklib.gen_mtls_certs(root)
    mtls_agent = stacklib.Agent(
        root, 2, RULES,
        tls={"cert": certs["agent_cert"], "key": certs["agent_key"],
             "client_ca": certs["ca"]})

    go_sock = os.path.join(root, "edge-guard.sock")
    go_mtls_sock = os.path.join(root, "edge-guard-mtls.sock")
    c_sock = os.path.join(root, "xnap-echo.sock")
    go_bin = build_go_agent(root)
    c_bin = build_c_agent(root)
    lanes = LANES
    if not go_bin:
        lanes = [l for l in lanes if l[0] not in ("go-block", "go-mtls")]
    if not c_bin:
        lanes = [l for l in lanes if l[0] != "c-echo"]

    conf = CONF.format(
        module_so=stacklib.MODULE_SO, root=root,
        uds_sock=uds_agent.sock, tcp_port=tcp_agent.port,
        go_sock=go_sock, go_mtls_sock=go_mtls_sock,
        c_sock=c_sock,
        mtls_sock=mtls_agent.sock, mtls_ca=certs["ca"],
        mtls_eng_crt=certs["engine_cert"],
        mtls_eng_key=certs["engine_key"],
        listen_port=stacklib.free_port())
    conf_path = os.path.join(root, "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(conf)

    port = int(re.search(r"listen (\d+);", conf).group(1))
    procs = []
    go_proc = None
    go_mtls_proc = None
    c_proc = None
    try:
        uds_agent.start(root)
        tcp_agent.start(root)
        mtls_agent.start(root)
        if go_bin:
            go_proc = subprocess.Popen(
                [go_bin, "-listen", f"unix:{go_sock}", "-rate", "0"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            go_mtls_proc = subprocess.Popen(
                [go_bin, "-listen", f"unix:{go_mtls_sock}", "-rate", "0",
                 "-tls-cert", certs["agent_cert"],
                 "-tls-key", certs["agent_key"],
                 "-tls-client-ca", certs["ca"]],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if c_bin:
            c_proc = subprocess.Popen(
                [c_bin, "-listen", f"unix:{c_sock}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        for ready_path in ("/x", "/mtlsblock/x",
                           "/goblock/x" if go_bin else None,
                           "/gomtls/x" if go_bin else None,
                           "/cecho/x" if c_bin else None):
            if ready_path is None:
                continue
            for _ in range(100):
                try:
                    st = urllib.request.urlopen(
                        f"http://127.0.0.1:{port}{ready_path}",
                        timeout=1).status
                    if st == 200:
                        break
                except Exception:
                    time.sleep(0.05)

        # global warmup: nginx workers, upstream conn pools and agent
        # keepalives all start cold — prime every lane before measuring
        for name, path, method, body, want in lanes:
            ka = KeepAlive(port)
            try:
                for _ in range(50):
                    ka.request(path, method, body)
            finally:
                ka.close()

        log_path = os.path.join(root, "logs", "access.log")
        rows = []
        for name, path, method, body, want in lanes:
            log_off = os.path.getsize(log_path)
            ts, bad = serial_bench(port, path, method, body, want,
                                   args.serial_n)
            log_end = os.path.getsize(log_path)
            rps, lat_us, fails = ab_bench(port, path, method, body,
                                          args.ab_n, args.ab_c, root)
            met = log_metrics(log_path, path, log_off, log_end)
            rows.append({
                "lane": name, "n": len(ts), "bad_status": bad,
                "p50": pct(ts, 50), "p95": pct(ts, 95), "p99": pct(ts, 99),
                "mean": statistics.fmean(ts),
                "ab_rps": rps, "ab_lat_us": lat_us, "ab_fails": fails,
                "rtt_p50": pct(met["rtt"], 50) if met["rtt"] else None,
                "rtt_p99": pct(met["rtt"], 99) if met["rtt"] else None,
                "enc_p50": pct(met["enc"], 50) if met["enc"] else None,
                "sys_p50": pct(met["sys"], 50) if met["sys"] else None,
                "agt_p50": pct(met["agt"], 50) if met["agt"] else None,
                "aus_p50": pct(met["aus"], 50) if met["aus"] else None,
            })
            r = rows[-1]
            print(f"{name:10s} p50={r['p50']:7.0f}us "
                  f"p99={r['p99']:7.0f}us "
                  f"ab={rps:8.0f}rps rtt_p50={r['rtt_p50']} "
                  f"enc={r['enc_p50']} sys={r['sys_p50']} "
                  f"agt={r['agt_p50']}"
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

        print("\n=== offload breakdown (log p50, us) ===")
        print(f"{'lane':10s} {'enc':>6s} {'sys':>6s} {'agent':>6s} "
              f"{'rtt':>6s} {'agentus':>7s}")
        for r in rows:
            if r["enc_p50"] is None:
                continue
            aus = "-" if r["aus_p50"] is None else str(r["aus_p50"])
            print(f"{r['lane']:10s} {r['enc_p50']:6d} {r['sys_p50']:6d} "
                  f"{r['agt_p50'] or 0:6d} {r['rtt_p50'] or 0:6d} {aus:>7s}")

    finally:
        for p in procs:
            p.terminate()
        for p in (go_proc, go_mtls_proc, c_proc):
            if p:
                p.terminate()
        for a in (uds_agent, tcp_agent, mtls_agent):
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
