"""Integration test stack: stub agent(s) + echo backend + nginx.

Requires:
  XNGIN_NGINX_BIN  nginx binary (default /tmp/nginx-xngin-install/sbin/nginx)
  XNGIN_MODULE_SO  module .so    (default /tmp/nginx-1.31.8/objs/...so)
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

HARNESS = os.path.dirname(os.path.abspath(__file__))
NGINX_BIN = os.environ.get("XNGIN_NGINX_BIN",
                           "/tmp/nginx-xngin-install/sbin/nginx")
MODULE_SO = os.environ.get("XNGIN_MODULE_SO",
                           "/tmp/nginx-1.31.8/objs/ngx_http_xngin_module.so")

NGINX_CONF = """\
load_module {module_so};
error_log {root}/logs/error.log {loglevel};
pid {root}/nginx.pid;
worker_processes 1;
daemon on;
master_process on;

events {{ worker_connections 512; }}

http {{
    log_format xnginlog '$status act=$xngin_action score=$xngin_score '
                        'err=$xngin_error rtt=$xngin_agent_rtt_us '
                        'cache=$xngin_cache rule=$xngin_rule '
                        'ja4=$xngin_ja4 aja4=$xngin_agent_ja4 '
                        'aja4r=$xngin_agent_ja4_r jm=$xngin_ja4_match '
                        'res=$xngin_res_rule agent=$xngin_agent';
    access_log {root}/logs/access.log xnginlog;

    {main_extra}

    upstream backend {{ server 127.0.0.1:{backend_port}; }}

    server {{
        listen {listen_port}{listen_opts};
        {srv_extra}

        location / {{
            xngin_enable on;
            {loc_group}
            xngin_timeout {timeout};
            xngin_fail {fail};
            {loc_extra}
            proxy_pass http://backend;
        }}
        {loc_blocks}
    }}
    {server_blocks}
}}
"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Agent:
    def __init__(self, root, idx, rules, tcp=False, tls=None):
        self.idx = idx
        self.tcp = tcp
        self.tls = tls          # {cert, key, client_ca} or None
        if tcp:
            self.port = free_port()
            self.listen = f"tcp:{self.port}"
            self.addr = f"127.0.0.1:{self.port}"
        else:
            # keep under AF_UNIX sun_path limit (~104 bytes on macOS):
            # pytest tmp_path is too deep, so sockets live in /tmp
            self.sock = (f"/tmp/xngin-{os.getpid()}-{idx}-"
                         f"{free_port()}.sock")
            self.listen = f"unix:{self.sock}"
            self.addr = f"unix:{self.sock}"
        self.rules_file = os.path.join(root, f"rules{idx}.json")
        self.stats_file = os.path.join(root, f"stats{idx}.json")
        self.proc = None
        self.cmd = None            # non-stub agent command template
        with open(self.rules_file, "w") as f:
            json.dump(rules, f)

    def start(self, root):
        log = open(os.path.join(root, f"agent{self.idx}.log"), "w")
        if self.cmd:
            argv = [a.format(listen=self.listen) for a in self.cmd]
        else:
            argv = [sys.executable, os.path.join(HARNESS, "stub_agent.py"),
                    "--listen", self.listen,
                    "--rules", self.rules_file,
                    "--stats", self.stats_file]
            if self.tls:
                argv += ["--tls-cert", self.tls["cert"],
                         "--tls-key", self.tls["key"]]
                if self.tls.get("client_ca"):
                    argv += ["--tls-client-ca", self.tls["client_ca"]]
        self.proc = subprocess.Popen(argv, stdout=log, stderr=log)
        if self.cmd:
            # no stats file for a foreign agent: probe the listen addr
            for _ in range(100):
                if self.proc.poll() is not None:
                    raise RuntimeError(f"agent{self.idx} exited early")
                try:
                    if self.tcp:
                        socket.create_connection(
                            ("127.0.0.1", self.port), 0.2).close()
                        return
                    if os.path.exists(self.sock):
                        return
                except OSError:
                    pass
                time.sleep(0.05)
            raise RuntimeError("agent did not start")
        for _ in range(100):
            if os.path.exists(self.stats_file):
                return
            time.sleep(0.05)
        raise RuntimeError("agent did not start")

    def stats(self):
        for _ in range(20):
            try:
                with open(self.stats_file) as f:
                    return json.load(f)
            except Exception:
                time.sleep(0.05)
        return {}

    def kill(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait()


def gen_mtls_certs(root):
    """CA + agent server cert + engine client cert for agent mTLS."""
    def run(*a):
        subprocess.run(["openssl"] + list(a), check=True, capture_output=True)

    def sign(csr, ca, cakey, out, ext=None):
        a = ["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", cakey,
             "-CAcreateserial", "-out", out, "-days", "1"]
        if ext:
            a += ["-extfile", ext]
        run(*a)

    ca_key, ca = (os.path.join(root, "ca.key"),
                  os.path.join(root, "ca.pem"))
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", ca_key, "-out", ca, "-days", "1",
        "-subj", "/CN=xngin-test-ca")

    # agent (TLS server) cert with SAN localhost + 127.0.0.1
    a_key, a_csr, a_crt = (os.path.join(root, "agent.key"),
                           os.path.join(root, "agent.csr"),
                           os.path.join(root, "agent.pem"))
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", a_key,
        "-out", a_csr, "-subj", "/CN=localhost")
    ext = os.path.join(root, "san.ext")
    with open(ext, "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    sign(a_csr, ca, ca_key, a_crt, ext)

    # engine (TLS client) cert
    e_key, e_csr, e_crt = (os.path.join(root, "engine.key"),
                           os.path.join(root, "engine.csr"),
                           os.path.join(root, "engine.pem"))
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", e_key,
        "-out", e_csr, "-subj", "/CN=xngin-engine")
    sign(e_csr, ca, ca_key, e_crt)

    return {"ca": ca, "agent_cert": a_crt, "agent_key": a_key,
            "engine_cert": e_crt, "engine_key": e_key}


class Stack:
    def __init__(self, root, agents_rules, timeout="300ms", fail="close",
                 loc_extra="", main_extra="", tcp_agents=False,
                 loglevel="warn", ssl=False, srv_extra="",
                 http_ready=True, sub="", go_agent=None, mtls=False,
                 agent_tls=True, client_cert=True, wrong_ca=False,
                 loc_blocks="", server_hosts=None, server_suffix=None,
                 group_extra="", extra_groups=None,
                 loc_group="xngin_group waf;", server_blocks=None):
        if sub:
            root = os.path.join(root, sub)
        self.root = root
        self.ssl = ssl
        self.http_ready = http_ready
        self.listen_port = free_port()
        self.backend_port = free_port()
        os.makedirs(os.path.join(root, "logs"), exist_ok=True)

        listen_opts = ""
        if ssl:
            self.cert = os.path.join(root, "cert.pem")
            self.key = os.path.join(root, "key.pem")
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", self.key, "-out", self.cert, "-days", "1",
                 "-subj", "/CN=localhost"],
                check=True, capture_output=True)
            listen_opts = " ssl"
            srv_extra = (f"ssl_certificate {self.cert};\n        "
                         f"ssl_certificate_key {self.key};\n        "
                         + srv_extra)

        certs = gen_mtls_certs(root) if mtls else None
        agent_tls_cfg = ({"cert": certs["agent_cert"],
                          "key": certs["agent_key"],
                          "client_ca": certs["ca"]}
                         if certs and agent_tls else None)
        self.agents = [Agent(root, i, r, tcp=tcp_agents, tls=agent_tls_cfg)
                       for i, r in enumerate(agents_rules)]
        if go_agent:
            self.agents[0].cmd = go_agent
        lines = []
        for i, a in enumerate(self.agents):
            addr = a.addr
            if server_hosts and server_hosts[i] and a.tcp:
                addr = f"{server_hosts[i]}:{a.port}"
            sfx = server_suffix[i] if server_suffix else ""
            lines.append(f"server {addr}{sfx};")
        servers = "\n        ".join(lines)

        tls_conf = ""
        if mtls:
            trusted = certs["ca"]
            if wrong_ca:
                # engine trusts an unrelated CA -> agent cert rejected
                ca2 = os.path.join(root, "ca2")
                os.makedirs(ca2, exist_ok=True)
                trusted = gen_mtls_certs(ca2)["ca"]
            lines = ["ssl on;",
                     f"ssl_trusted_certificate {trusted};"]
            if client_cert:
                lines += [f"ssl_certificate {certs['engine_cert']};",
                          f"ssl_certificate_key {certs['engine_key']};"]
            tls_conf = "\n        ".join(lines)

        self.conf = os.path.join(root, "nginx.conf")
        # extra server{} blocks (e.g. SNI vhosts on the same listen):
        # a callable receives this half-built Stack (ports and cert/key
        # paths are already set) and returns raw nginx config
        sblocks = server_blocks(self) if callable(server_blocks) \
            else (server_blocks or "")
        groups = ""
        for gname, addrs in (extra_groups or {}).items():
            srvs = "\n        ".join(
                f"server {a if isinstance(a, str) else self.agents[a].addr};"
                for a in addrs)
            groups += (f"\n    xngin_agent_group {gname} {{\n"
                       f"        {srvs}\n        keepalive 1;\n    }}\n")

        main = f"""
    xngin_agent_group waf {{
        {servers}
        {group_extra}
        {tls_conf}
        keepalive 1;
        ping_interval 60s;
    }}
{groups}
{main_extra}"""
        with open(self.conf, "w") as f:
            f.write(NGINX_CONF.format(
                module_so=MODULE_SO, root=root, loglevel=loglevel,
                backend_port=self.backend_port,
                listen_port=self.listen_port, listen_opts=listen_opts,
                srv_extra=srv_extra,
                timeout=timeout, fail=fail,
                loc_extra=loc_extra, loc_blocks=loc_blocks,
                loc_group=loc_group, server_blocks=sblocks,
                main_extra=main))
        self.procs = []

    def url(self, path="/"):
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://127.0.0.1:{self.listen_port}{path}"

    def request(self, path="/", method="GET", headers=None, data=None):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None

        handlers = [NoRedirect]
        if self.ssl:
            import ssl as _ssl
            handlers.append(urllib.request.HTTPSHandler(
                context=_ssl._create_unverified_context()))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(self.url(path), method=method,
                                     data=data, headers=headers or {})
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def start(self):
        blog = open(os.path.join(self.root, "backend.log"), "w")
        self.procs.append(subprocess.Popen(
            [sys.executable, os.path.join(HARNESS, "backend.py"),
             str(self.backend_port)],
            stdout=blog, stderr=blog))
        for a in self.agents:
            a.start(self.root)
        for _ in range(3):
            self.procs.append(subprocess.Popen(
                [NGINX_BIN, "-c", self.conf, "-p", self.root],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            try:
                self.wait_ready()
                return self
            except RuntimeError:
                # free_port() race: the probe socket is closed before
                # nginx binds, so another process can grab the port —
                # retry on a fresh one when bind() was the failure
                try:
                    bind_failed = "could not bind" in self.error_log()
                except OSError:
                    bind_failed = False
                if not bind_failed:
                    raise
                old, self.listen_port = self.listen_port, free_port()
                with open(self.conf) as f:
                    conf = f.read()
                # port is always followed by ';' or ' ' (listen opts) —
                # the terminator keeps prefix ports safe
                conf = conf.replace(f"listen {old};",
                                    f"listen {self.listen_port};")
                conf = conf.replace(f"listen {old} ",
                                    f"listen {self.listen_port} ")
                with open(self.conf, "w") as f:
                    f.write(conf)
        return self

    def wait_ready(self):
        if not self.http_ready:
            # handshake-level tests can't complete an HTTP probe
            for _ in range(100):
                try:
                    socket.create_connection(
                        ("127.0.0.1", self.listen_port), 1).close()
                    return
                except OSError:
                    time.sleep(0.1)
            raise RuntimeError("nginx not listening; see "
                               + os.path.join(self.root, "logs", "error.log"))
        for _ in range(100):
            try:
                self.request("/")
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("nginx did not come up; see "
                           + os.path.join(self.root, "logs", "error.log"))

    def access_log(self):
        with open(os.path.join(self.root, "logs", "access.log")) as f:
            return f.read()

    def error_log(self):
        with open(os.path.join(self.root, "logs", "error.log")) as f:
            return f.read()

    def stop(self):
        try:
            pidfile = os.path.join(self.root, "nginx.pid")
            if os.path.exists(pidfile):
                with open(pidfile) as f:
                    os.kill(int(f.read().strip()), signal.SIGQUIT)
        except Exception:
            pass
        for a in self.agents:
            if a.proc:
                a.proc.terminate()
        for p in self.procs:
            p.terminate()
        for p in self.procs + [a.proc for a in self.agents if a.proc]:
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
