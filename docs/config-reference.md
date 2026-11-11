# xngin config reference

## Main context

```nginx
xngin_agent_group waf {
    server unix:/run/xngin/waf.sock;
    server 10.0.0.5:7777 weight=2 max_streams=128;
    keepalive 2;          # conns per worker per weight unit (default 2)
    ping_interval 10s;    # health/RTT probe (default 10s, min 1s)
    max_streams 256;      # default per-conn cap, min'd with agent's
}

xngin_cache_zone verdicts:8m;   # shm zone for verdict cache (name:size)
```

## Location / server context

| directive | default | notes |
|---|---|---|
| `xngin_enable on\|off` | off | enable offload for this location |
| `xngin_group name` | — | which `xngin_agent_group` to use |
| `xngin_mode blocking\|async` | blocking | async = fire-and-forget, verdict logged only |
| `xngin_timeout 50ms` | 50ms | verdict wait bound |
| `xngin_fail open\|close` | close | timeout/down: open=proceed, close=503 |
| `xngin_body_inspect on\|off` | off | capture request body for agent |
| `xngin_body_max 64k` | 64k | capture cap; larger bodies → `body-truncated` flag. Also raises `client_body_buffer_size` so the body stays in memory |
| `xngin_cache_key $expr` | — | engine-side cache key template (complex value, e.g. `$binary_remote_addr`) |
| `xngin_response on\|off` | off | hold the upstream response and send a second `http-response` NOTIFY (status + headers + body) for agent inspection. Requires the agent to negotiate `CAP_RESP` — otherwise the response passes through |
| `xngin_res_body_max 64k` | 64k | response body capture cap for `http-response`; larger bodies bypass the round-trip entirely (never truncated) |

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
| `$xngin_cache` | hit / miss / bypass / disabled |
| `$xngin_ja4` | JA4 fingerprint of the ClientHello, when `xngin_tls_inspect` is on |
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
| `reason` / `score` | STR / INT32 | `$xngin_reason` / `$xngin_score` |

On `http-response` streams the `res-*` fields, `vars`, `reason`, `score`
and `action deny`/`redirect` apply; `hdr-*`, `req-body` and `cache-ttl`
are ignored (the upstream exchange is already done).

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
