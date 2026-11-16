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
  /rustblock blocking verdict, Rust mini_waf agent (UDS)
  /rustasync fire-and-forget, Rust mini_waf
  /rustcache blocking + cache key, Rust mini_waf
  /rustbody  blocking + body inspect, Rust mini_waf (POST 1k / 64k)
  /rustresp  blocking + response inspect, Rust mini_waf
  /rustdeny  Rust mini_waf deny (threshold 80; /etc/passwd URI)
  /rusttcp   blocking verdict, Rust mini_waf on loopback TCP
  /rustmtls  blocking verdict, Rust mini_waf over mTLS
  /mtlsblock blocking verdict, Python stub agent over mTLS (agent-bound)
  /gomtls    blocking verdict, Go edge-guard agent over mTLS

Measures:
  * serial keep-alive prober -> per-request p50/p95/p99 (us)
  * k6 constant-VUS probes -> max RPS per lane (concurrency doubles
    until the achieved rate plateaus; falls back to `ab -k -c N -n M`
    when k6 is not installed)
  * $xngin_agent_rtt_us    -> engine-side agent RTT (access log)
  * $xngin_encode_us / $xngin_syscall_us / $xngin_agent_us
    -> engine CPU vs socket I/O vs agent-side time (access log)
  * $xngin_agentus         -> c-echo agent's self-reported svc time

Usage:
  python3 test/bench/bench.py [--serial-n 300] [--k6-dur 4s]
                              [--k6-cap 4096] [--lanes a,b,c]
                              [--ab-n 5000] [--ab-c 50]

Env: XNGIN_NGINX_BIN, XNGIN_MODULE_SO (defaults per stacklib).
"""

import argparse
import json
import os
import re
import shutil
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
    xngin_agent_group rust {{
        server unix:{rust_sock};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_agent_group rustdeny {{
        server unix:{rust_deny_sock};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_agent_group rusttcp {{
        server 127.0.0.1:{rust_tcp_port};
        keepalive 2;
        ping_interval 60s;
    }}
    xngin_agent_group rustmtls {{
        server unix:{rust_mtls_sock};
        ssl on;
        ssl_trusted_certificate {mtls_ca};
        ssl_certificate {mtls_eng_crt};
        ssl_certificate_key {mtls_eng_key};
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
        location /rustblock {{
            xngin_enable on; xngin_group rust;
            empty_gif;
        }}
        location /rustasync {{
            xngin_enable on; xngin_group rust; xngin_mode async;
            empty_gif;
        }}
        location /rustcache {{
            xngin_enable on; xngin_group rust;
            xngin_cache_key $uri;
            empty_gif;
        }}
        location /rustbody {{
            xngin_enable on; xngin_group rust;
            xngin_body_inspect on; xngin_body_max 128k;
            empty_gif;
        }}
        location /rustresp {{
            xngin_enable on; xngin_group rust; xngin_response on;
            empty_gif;
        }}
        location /rustdeny {{
            xngin_enable on; xngin_group rustdeny;
            empty_gif;
        }}
        location /rusttcp {{
            xngin_enable on; xngin_group rusttcp;
            empty_gif;
        }}
        location /rustmtls {{
            xngin_enable on; xngin_group rustmtls;
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
    ("rust-block", "/rustblock/x", "GET", None,          200),
    ("rust-async", "/rustasync/x", "GET", None,          200),
    ("rust-cache", "/rustcache/x", "GET", None,          200),
    ("rust-body-1k", "/rustbody/x", "POST", POST_BODY,   405),
    ("rust-body-64k", "/rustbody/x", "POST", POST_BODY_64K, 405),
    ("rust-resp",  "/rustresp/x",  "GET",  None,          200),
    ("rust-deny",  "/rustdeny/x/etc/passwd", "GET", None, 403),
    ("rust-tcp",   "/rusttcp/x",   "GET",  None,          200),
    ("rust-mtls",  "/rustmtls/x",  "GET",  None,          200),
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


def build_rust_agent():
    """Build mini_waf (release) for the rust-block lane; None on
    failure. The binary stays under target/ — no copy needed."""
    r = subprocess.run(
        ["cargo", "build", "--release", "--example", "mini_waf"],
        cwd=os.path.join(REPO, "agents", "rust"),
        capture_output=True, text=True)
    dst = os.path.join(REPO, "agents", "rust", "target", "release",
                       "examples", "mini_waf")
    if r.returncode != 0 or not os.path.exists(dst):
        print(f"note: cargo build failed, skipping rust-block lane\n"
              f"{r.stderr}", flush=True)
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


K6_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "k6_probe.js")


def k6_probe(port, path, method, body, want, vus, dur, tmpdir, tag):
    """One constant-VUS probe. Returns a metrics dict; `clean` is set
    when no requests failed the expected status."""
    export = os.path.join(tmpdir, f"k6-{tag}-v{vus}.json")
    env = dict(os.environ)
    env.update({
        "K6_URL": f"http://127.0.0.1:{port}{path}",
        "K6_METHOD": method,
        "K6_WANT": str(want),
    })
    if body:
        env["K6_BODY_LEN"] = str(len(body))
    subprocess.run(
        ["k6", "run", "--quiet", "--vus", str(vus), "--duration", dur,
         "--summary-export", export,
         "--summary-trend-stats=min,avg,med,p(90),p(95),p(99),max",
         K6_SCRIPT],
        env=env, capture_output=True, timeout=300)
    try:
        met = json.load(open(export))["metrics"]
    except (OSError, json.JSONDecodeError, KeyError):
        return {"rate": 0.0, "vus": vus, "clean": False}

    def vals(k):
        v = met.get(k) or {}
        return v.get("values", v)

    # k6 rate metrics export `value` (fraction of true samples); for
    # http_req_failed a true sample = a failed request.
    return {
        "rate": vals("http_reqs").get("rate", 0.0),
        "count": vals("http_reqs").get("count", 0),
        "vus": vus,
        "failed_rate": vals("http_req_failed").get(
            "value", vals("http_req_failed").get("rate", 1.0)),
        "lat_p99_us": vals("http_req_duration").get("p(99)", 0) * 1e3,
        "clean": vals("http_req_failed").get(
            "value", vals("http_req_failed").get("rate", 1.0)) == 0,
    }


def k6_max_rps(port, path, method, body, want, dur, cap, tmpdir, tag):
    """Scale VU concurrency until the achieved rate plateaus (<5% gain)
    or requests start failing — the closed-loop throughput ceiling."""
    best = {"rate": 0.0, "vus": 0, "lat_p99_us": 0, "clean": True}
    vus = 64
    for i in range(7):
        res = k6_probe(port, path, method, body, want, vus, dur,
                       tmpdir, f"{tag}-p{i}")
        if not res["clean"] or res["rate"] <= best["rate"] * 1.05:
            if not best["vus"]:
                best = res          # report even a failing first probe
            break
        best = res
        vus = min(vus * 2, cap)
    return best["rate"], best


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
    ap.add_argument("--k6-dur", default="4s",
                    help="duration of each k6 arrival-rate probe")
    ap.add_argument("--k6-cap", type=int, default=4096,
                    help="max VU concurrency for the max-rps search")
    ap.add_argument("--lanes", default=None,
                    help="comma-separated lane filter")
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
    rust_sock = os.path.join(root, "mini-waf.sock")
    rust_deny_sock = os.path.join(root, "mini-waf-deny.sock")
    rust_mtls_sock = os.path.join(root, "mini-waf-mtls.sock")
    rust_tcp_port = stacklib.free_port()
    go_bin = build_go_agent(root)
    c_bin = build_c_agent(root)
    rust_bin = build_rust_agent()
    lanes = LANES
    if not go_bin:
        lanes = [l for l in lanes if l[0] not in ("go-block", "go-mtls")]
    if not c_bin:
        lanes = [l for l in lanes if l[0] != "c-echo"]
    if not rust_bin:
        lanes = [l for l in lanes if not l[0].startswith("rust-")]
    if args.lanes:
        want = set(args.lanes.split(","))
        lanes = [l for l in lanes if l[0] in want]
    if not lanes:
        print("no lanes to run")
        return
    have_k6 = shutil.which("k6") is not None
    if not have_k6:
        print("note: k6 not found, falling back to ab for throughput",
              flush=True)

    conf = CONF.format(
        module_so=stacklib.MODULE_SO, root=root,
        uds_sock=uds_agent.sock, tcp_port=tcp_agent.port,
        go_sock=go_sock, go_mtls_sock=go_mtls_sock,
        c_sock=c_sock, rust_sock=rust_sock,
        rust_deny_sock=rust_deny_sock, rust_tcp_port=rust_tcp_port,
        rust_mtls_sock=rust_mtls_sock,
        mtls_sock=mtls_agent.sock, mtls_ca=certs["ca"],
        mtls_eng_crt=certs["engine_cert"],
        mtls_eng_key=certs["engine_key"],
        listen_port=stacklib.free_port())
    conf_path = os.path.join(root, "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(conf)

    port = int(re.search(r"listen (\d+);", conf).group(1))
    procs = []
    agent_procs = []
    try:
        uds_agent.start(root)
        tcp_agent.start(root)
        mtls_agent.start(root)
        if go_bin:
            agent_procs += [
                subprocess.Popen(
                    [go_bin, "-listen", f"unix:{go_sock}", "-rate", "0"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
                subprocess.Popen(
                    [go_bin, "-listen", f"unix:{go_mtls_sock}",
                     "-rate", "0",
                     "-tls-cert", certs["agent_cert"],
                     "-tls-key", certs["agent_key"],
                     "-tls-client-ca", certs["ca"]],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        if c_bin:
            agent_procs.append(subprocess.Popen(
                [c_bin, "-listen", f"unix:{c_sock}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        if rust_bin:
            rust_cmds = [
                [rust_bin, "--listen", f"unix:{rust_sock}"],
                # rust-deny: /etc/passwd hits proto-environ (85)
                [rust_bin, "--listen", f"unix:{rust_deny_sock}",
                 "--threshold", "80"],
                [rust_bin, "--listen",
                 f"tcp:127.0.0.1:{rust_tcp_port}"],
                [rust_bin, "--listen", f"unix:{rust_mtls_sock}",
                 "--tls-cert", certs["agent_cert"],
                 "--tls-key", certs["agent_key"],
                 "--tls-client-ca", certs["ca"]],
            ]
            agent_procs += [subprocess.Popen(
                c, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL) for c in rust_cmds]
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
                           "/cecho/x" if c_bin else None,
                           "/rustblock/x" if rust_bin else None,
                           "/rustdeny/x" if rust_bin else None,
                           "/rusttcp/x" if rust_bin else None,
                           "/rustmtls/x" if rust_bin else None):
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
            if have_k6:
                rps, kres = k6_max_rps(port, path, method, body, want,
                                       args.k6_dur, args.k6_cap, root,
                                       name)
                lat_us, fails = kres.get("lat_p99_us"), 0
            else:
                rps, lat_us, fails = ab_bench(port, path, method, body,
                                              args.ab_n, args.ab_c,
                                              root)
                kres = {}
            met = log_metrics(log_path, path, log_off, log_end)
            rows.append({
                "lane": name, "n": len(ts), "bad_status": bad,
                "p50": pct(ts, 50), "p95": pct(ts, 95), "p99": pct(ts, 99),
                "mean": statistics.fmean(ts),
                "k6_max_rps": rps if have_k6 else None,
                "k6_lat_p99_us": lat_us if have_k6 else None,
                "k6_probe": kres,
                "ab_rps": rps if not have_k6 else None,
                "ab_lat_us": lat_us if not have_k6 else None,
                "ab_fails": fails,
                "rtt_p50": pct(met["rtt"], 50) if met["rtt"] else None,
                "rtt_p99": pct(met["rtt"], 99) if met["rtt"] else None,
                "enc_p50": pct(met["enc"], 50) if met["enc"] else None,
                "sys_p50": pct(met["sys"], 50) if met["sys"] else None,
                "agt_p50": pct(met["agt"], 50) if met["agt"] else None,
                "aus_p50": pct(met["aus"], 50) if met["aus"] else None,
            })
            r = rows[-1]
            tool = "k6max" if have_k6 else "ab   "
            print(f"{name:10s} p50={r['p50']:7.0f}us "
                  f"p99={r['p99']:7.0f}us "
                  f"{tool}={rps:8.0f}rps rtt_p50={r['rtt_p50']} "
                  f"enc={r['enc_p50']} sys={r['sys_p50']} "
                  f"agt={r['agt_p50']}"
                  + (f"  !! {bad} bad-status" if bad else ""),
                  flush=True)

        out = os.path.join(root, "bench.json")
        with open(out, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"\nresults: {out}")

        base = rows[0]["mean"]
        thr = "k6_max_rps" if have_k6 else "ab_rps"
        print("\n=== summary (mean serial latency delta vs baseline) ===")
        for r in rows:
            print(f"{r['lane']:10s} +{r['mean'] - base:7.0f}us  "
                  f"(mean {r['mean']:.0f}us, {r[thr]:.0f} rps max)")

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
        for p in agent_procs:
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
