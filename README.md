# xngin

[![CI](https://github.com/ne4u/nginx-xngin/actions/workflows/ci.yml/badge.svg)](https://github.com/ne4u/nginx-xngin/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20Commons%20Clause-blue)](LICENSE)

SPOE/SPOA-style traffic-decision offload for nginx. An http module
(`ngx_http_xngin_module`) offloads request allow/deny/mutate decisions to
N external agents — local (Unix sockets) or remote (TCP) — over **XNAP**,
a custom low-latency multiplexed binary protocol. Use it for WAF, ACL,
rate limiting, bot detection, auth, fraud scoring, anything.

```
GET / ──► nginx ──NOTIFY──► agent ──VERDICT──► allow → upstream
```

## Features

- **Multiplexed persistent conns**: many requests share one conn per
  worker↔agent; stream-id demux; ~1 local RTT per decision
- **Scale to N agents**: `xngin_agent_group` of mixed UDS/TCP servers,
  weights, keepalive conns, PING/PONG health checks, automatic failover
  and stream replay
- **Blocking + async modes**: enforce on the request path, or observe
  (detect/monitor) with zero added latency
- **Full verdicts**: allow, deny (status + custom body), redirect,
  request header set/unset before upstream, request body replacement,
  response header set/unset and body replacement, `$xngin_*` variables
- **Two-stage response handling**: blind verdict-time `res-*` ops, or a
  held `http-response` round-trip where the agent inspects the real
  upstream response before it's released (`xngin_response`)
- **Verdict cache**: shm zone keyed by `xngin_cache_key`; agents opt in
  with `cache-ttl` — repeat traffic skips the wire entirely
- **Body inspection**: flag-gated, capped, streamed as BODY frames
- **TLS fingerprinting**: `xngin_tls_inspect` captures the ClientHello —
  raw `ch-raw` plus engine JA4 in the NOTIFY; the `ja4-fp` example agent
  recomputes JA4/JA4_r and returns them as headers and `$xngin_*` vars
- **No C dependencies**: pure nginx APIs

## Repo

| path | what |
|---|---|
| `SPEC.md` | XNAP wire protocol (v1) |
| `module/` | the nginx module (C) |
| `agents/go/` | `xngin-go` SDK + **edge-guard** (IP ACL + rate limit) and **ja4-fp** (JA4 fingerprint → headers + vars) agents |
| `agents/rust/` | `xngin-rs` SDK + **mini-waf** agent (regex rules + anomaly score) |
| `test/` | pytest harness, scriptable stub agent (3rd impl), conformance vectors, benches, fuzz targets |
| `docs/` | architecture, latency analysis, config reference, examples |

## Quick start

```sh
# build module against nginx source
./configure --add-dynamic-module=$PWD/module && make modules

# nginx.conf
load_module objs/ngx_http_xngin_module.so;
http {
    xngin_agent_group waf { server unix:/run/waf.sock; }
    server {
        location / {
            xngin_enable on; xngin_group waf;
            proxy_pass http://backend;
        }
    }
}

# run an agent
(cd agents/go   && go run ./cmd/edge-guard -listen unix:/run/waf.sock -rate 50)
(cd agents/rust && cargo run --example mini_waf -- --listen unix:/run/waf.sock)
```

See `AGENTS.md` for build/test commands and `docs/` for details.

## License

Apache-2.0 with the [Commons Clause](https://commonsclause.com/)
restriction — free to use, modify, and self-host; selling the software
or a hosted/managed service built on it requires a commercial license.
See `LICENSE`.
