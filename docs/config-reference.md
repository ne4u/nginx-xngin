# xngin config reference

## Main context

```nginx
xngin_agent_group waf {
    server unix:/run/xngin/waf.sock;
    server 10.0.0.5:7777 weight=2 max_streams=128;
    server 10.0.0.6:7777 backup;            # only used when primaries down
    server agent.svc.local:7777 resolve;    # re-resolved periodically
    keepalive 2;          # conns per worker per weight unit (default 2)
    ping_interval 10s;    # health/RTT probe (default 10s, min 1s)
    max_streams 256;      # default per-conn cap, min'd with agent's
    balance hash $binary_remote_addr;  # sticky pick by request key
    resolve_interval 30s;                  # DNS re-resolution period
    ssl on;                        # optional TLS to agents (engine = client)
    ssl_trusted_certificate ca.pem;    # CA verifying agent certs (required)
    ssl_certificate engine.pem;        # engine client cert -> mTLS
    ssl_certificate_key engine.key;
    ssl_server_name waf.internal;      # SNI + cert hostname check
}

xngin_cache_zone verdicts:8m;   # shm zone for verdict cache (name:size)
xngin_ban_zone bans:1m;         # shm zone for CONTROL-pushed bans;
                                # without it bans are per-worker
```

## Location / server context

| directive | default | notes |
|---|---|---|
| `xngin_enable on\|off` | off | enable offload for this location |
| `xngin_group name [timeout=] [fail=] [mode=]` | — | which `xngin_agent_group` to use. **Repeatable**: sequential decision chain — each step runs in order, `allow` advances, `deny`/`redirect` is terminal. Per-step `timeout=`, `fail=`, `mode=` override the location defaults |
| `xngin_response_group name` | — | group used for `http-response` streams (defaults to the request `xngin_group`) |
| `xngin_mode blocking\|async` | blocking | async = fire-and-forget, verdict logged only |
| `xngin_timeout 50ms` | 50ms | verdict wait bound |
| `xngin_fail open\|close` | close | timeout/down: open=proceed, close=503 |
| `xngin_body_inspect on\|off` | off | capture request body for agent |
| `xngin_body_max 64k` | 64k | capture cap; larger bodies → `body-truncated` flag. Also raises `client_body_buffer_size` so the body stays in memory |
| `xngin_body_replace on\|off` | on | contract that the agent may send `req-body`. `on` keeps the body in one contiguous buffer (`request_body_in_single_buf`) so it can be swapped; `off` skips that allocation and streams BODY frames as copies — a violating `req-body` is still applied, with a warning |
| `xngin_upload_drain on\|off` | on | `on` (default) reads the client upload to completion before answering a verdict, preserving keep-alive. `off` answers deny/redirect verdicts that arrive mid-upload immediately and closes the connection (keep-alive off + lingering close) |
| `xngin_cache_key $expr` | — | engine-side cache key template (complex value, e.g. `$binary_remote_addr`) |
| `xngin_response on\|off` | off | hold the upstream response and send a second `http-response` NOTIFY (status + headers + body) for agent inspection. Requires the agent to negotiate `CAP_RESP` — otherwise the response passes through |
| `xngin_res_body_max 64k` | 64k | response body capture cap for `http-response`; larger bodies bypass the round-trip entirely (never truncated) |
| `xngin_var <name> <complex>` | — | repeatable; evaluates an nginx variable/expression per request and ships it as `vars` in both NOTIFYs (e.g. `xngin_var tenant $ssl_client_s_dn;`) |
| `xngin_header_include <name> …` | — | header allowlist for NOTIFY `headers`/`req-headers` KVLs (repeatable; when set, only listed names are sent) |
| `xngin_header_exclude <name> …` | — | header blocklist (repeatable); use to strip `cookie`, `authorization`, etc. before they cross to remote agents |
| `xngin_internal on\|off` | on | `off` skips xngin on subrequests and internal redirects (`r->internal`) — prevents double-counting rate-limit decisions on `error_page`/`try_files` hops |
| `xngin_status on\|off` | off | location emits JSON: pool health, in-flight streams, cache counters, ban store sizes |

## Agent group directives

| directive | default | notes |
|---|---|---|
| `server <addr>` | — | `unix:/path` or `host:port`; `weight=`, `max_streams=`, `backup`, `resolve` params. `backup` conns are only used when no primary agent is ready. `resolve` re-resolves the hostname on `resolve_interval` via the nginx `resolver` |
| `balance hash <complex>` | — | pick the conn by hashing a per-request key (e.g. `balance hash $binary_remote_addr;`) — agents that keep per-client state see a client on the same replica |
| `resolve_interval <t>` | 30s | re-resolution period for `resolve` servers |
| `keepalive n` | 2 | conns per worker per weight unit |
| `ping_interval t` | 10s | health/RTT probe (min 1s) |
| `max_streams n` | 256 | per-conn cap, min'd with the agent's |
| `ssl on` | off | TLS transport to agents (§SPEC 1.1); engine connects as the TLS client |
| `ssl_trusted_certificate <path>` | — | CA bundle verifying agent certs. **Required** with `ssl on`; the handshake fails on unverifiable agent certs |
| `ssl_certificate <path>` | — | engine client certificate → mutual TLS. Requires `ssl_certificate_key` |
| `ssl_certificate_key <path>` | — | private key for `ssl_certificate` |
| `ssl_server_name <name>` | — | expected agent hostname: sent as SNI and verified against the cert SAN/CN. IP literals skip SNI |

`ssl` requires nginx built `--with-http_ssl_module`. TLS over Unix
sockets is legal but pointless for same-host deployments; it's meant
for TCP agents. For FIPS-validated crypto (FedRAMP), build nginx
against an OpenSSL FIPS provider.

## Server context (TLS)

Requires nginx built `--with-http_ssl_module` and OpenSSL >= 1.1.1.

| directive | default | notes |
|---|---|---|
| `xngin_tls_inspect on\|off` | off | capture the ClientHello on this server's SSL_CTX: raw bytes and a computed JA4 are stored per connection and forwarded in the NOTIFY (`ch-raw`, `ja4`). Set on the **default server** of each `listen` — the callback runs before SNI switching |
| `xngin_tls_deny <ja4>` | — | repeatable; aborts the TLS handshake (`illegal_parameter` alert) when the computed JA4 matches. Local/synchronous — no agent round-trip |

## Variables

| variable | value |
|---|---|
| `$xngin_action` | allow / deny / redirect |
| `$xngin_score` | agent score (int) |
| `$xngin_reason` | agent reason string |
| `$xngin_error` | timeout / down / proto (empty when clean) |
| `$xngin_agent_rtt_us` | engine↔agent round-trip, microseconds |
| `$xngin_encode_us` | engine CPU: NOTIFY/BODY encode + queue, microseconds |
| `$xngin_syscall_us` | time inside agent-conn send/recv calls (incl. TLS record I/O), microseconds |
| `$xngin_agent_us` | rtt minus attributed recv time ≈ agent-side wait (agent CPU + propagation + wakeup), microseconds |
| `$xngin_cache` | hit / miss / bypass / disabled |
| `$xngin_ja4` | JA4 fingerprint of the ClientHello, when `xngin_tls_inspect` is on |
| `$xngin_agent` | agent URL that served the last decision (failover-visible in access log) |
| `$xngin_<name>` | any key from verdict `vars` (e.g. vars `rule` → `$xngin_rule`); response-stream vars also land here |

## Verdict fields

| field | type | effect |
|---|---|---|
| `action` | STR | `allow` / `deny` / `redirect` (required) |
| `status` | INT32 | deny status (default 403); on response streams, status override |
| `body` | BIN/STR | deny body |
| `content-type` | STR | deny body type |
| `location` | STR | redirect target |
| `hdr-set` / `hdr-unset` | KVL / STRLIST | request headers set/stripped upstream |
| `req-body` | BIN/STR | replace upstream-bound request body (needs `xngin_body_inspect`) |
| `res-hdr-set` / `res-hdr-unset` | KVL / STRLIST | response headers set/stripped toward the client |
| `res-body` | BIN/STR | replace the response body (C-L/ETag cleared) |
| `vars` | KVL | exposed as `$xngin_<name>` |
| `cache-ttl` | UINT32 | verdict cache seconds |
| `body-stream` | UINT/TRUE | on `allow`: keep the decision stream open; the agent streams the replacement body back as BODY frames on the same sid ending with LAST (works on request and response streams; for payloads that don't fit one frame) |
| `reason` / `score` | STR / INT32 | `$xngin_reason` / `$xngin_score` |

On `http-response` streams the `res-*` fields, `vars`, `reason`, `score`
and `action deny`/`redirect` apply; `hdr-*`, `req-body` and `cache-ttl`
are ignored (the upstream exchange is already done).

## CONTROL ops (agent → engine)

When the engine advertises `CAP_PUSH` (it always does), agents may send
CONTROL frames on even sid 2 — no stream, no reply, local enforcement:

| op | fields | effect |
|---|---|---|
| `ban-ip` | `ip`, `ttl` (s, default 300) | POST_READ rejects the client with 403 |
| `ban-ja4` | `ja4`, `ttl` | TLS ClientHello carrying the JA4 is aborted |
| `cache-drop` | `key` | evicts the verdict-cache entry for the raw `xngin_cache_key` value |

Bans live in `xngin_ban_zone` when configured (cross-worker) or
per-worker otherwise; they expire at `ttl`.

## Example

```nginx
location /api {
    xngin_enable on;
    xngin_group waf;
    xngin_fail open;
    xngin_timeout 40ms;
    xngin_body_inspect on;
    xngin_body_max 32k;
    xngin_cache_key $binary_remote_addr;
    proxy_pass http://api;
}
```
