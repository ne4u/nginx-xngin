# xngin architecture

```
client ──► nginx worker ──► [access phase] ngx_http_xngin_module
                 │                    │
                 │              XNAP frames (multiplexed)
                 │                    ▼
                 │            ┌───────────────────────┐
                 │            │  agent conn pool      │
                 │            │  per worker, per group│
                 │            └───────────────────────┘
                 │              ▲ unix / TCP
                 ▼              │
            upstream ◄─── VERDICT: allow / deny / redirect /
                              hdr-set / hdr-unset / req-body /
                              res-hdr-* / res-body / vars / cache-ttl
                 │
                 │   (optional) xngin_response: response held,
                 │   second http-response NOTIFY → VERDICT → release
```

## Pieces

- **`ngx_http_xngin_module`** — dynamic http module. Registers an
  ACCESS_PHASE handler that suspends the request (`r->main->count++` +
  `NGX_DONE`), serializes request context into a `NOTIFY` frame, waits for
  a `VERDICT`, applies it, and re-enters `ngx_http_core_run_phases`.
  Async mode dispatches the same frame but returns immediately.
- **Conn pool** (`ngx_http_xngin_conn.c`) — per-worker persistent
  connections to every agent server in each `xngin_agent_group`. Frames
  for many requests are multiplexed on one connection; a stream-id keyed
  open-addressed table maps replies to request contexts. Nonblocking
  connect via `ngx_event_connect_peer`, kqueue/epoll driven.
- **Codec** (`ngx_http_xngin_proto.c`) — varint/typed-KV encoder and a
  frame parser over a per-conn 64 KB read buffer.
- **Response filters** (`ngx_http_xngin_resp.c`) — a top header/body
  filter pair. Verdict-time `res-hdr-*`/`res-body` ops rewrite
  `headers_out` and substitute the body inline. With
  `xngin_response on` the header filter instead *holds* the response:
  it returns `NGX_OK` without calling the next filter, sets our bit in
  `r->buffered` (so `ngx_http_finalize_request` diverts into
  `ngx_http_writer` and the request stays alive after upstream
  finishes), and pool-copies body bufs until `last_buf`. Then a second
  `http-response` NOTIFY (own stream, `CAP_RESP` conns only) carries
  status + headers + body to the agent; the VERDICT applies `res-*`
  ops/deny, the held chain is emitted, and the request re-finalizes.
  Bodies over `xngin_res_body_max` are passed through uninspected
  instead of truncated.
- **Verdict cache** (`ngx_http_xngin_cache.c`) — optional shm zone
  (`xngin_cache_zone`) rbtree + LRU queue keyed by an engine-side
  `xngin_cache_key` template; agents opt a verdict in with `cache-ttl`.
- **Agents** — any process speaking XNAP. Two SDKs provided: `xngin-go`
  and `xngin-rs`. A Python stub (`test/harness/stub_agent.py`) serves as
  the third reference implementation and the test double.
- **TLS capture** (`ngx_http_xngin_tls.c`, opt-in via
  `xngin_tls_inspect`) — in postconfiguration the module iterates
  `cmcf->servers` and, for each enabled server's `SSL_CTX`, installs an
  `SSL_CTX` msg_callback that copies the raw ClientHello into a
  per-connection struct (`SSL` ex_data, `c->pool`). On nginx >= 1.29.2
  the JA4/deny work hangs off nginx's own `ngx_ssl_client_hello_arg`
  ex_data slot (chained to the previous `servername` fn), so core SNI
  handling is preserved; on older nginx a `client_hello_cb` is set
  directly. At the access phase the NOTIFY gains `ch-raw`, `ja4`,
  `tls-version`, `sni`, `alpn`. `xngin_tls_deny <ja4>` aborts the
  handshake synchronously — agents cannot be consulted mid-handshake.

## Request lifecycle

1. Access phase: cache lookup (`xngin_cache_key`) → hit applies verdict.
2. Optional body read (flag-gated, capped) via
   `ngx_http_read_client_request_body`.
3. Pick ready conn (least in-flight / max-streams ratio), assign odd
   stream-id, send `NOTIFY` (+ `BODY` frames).
4. Blocking: suspend, arm `xngin_timeout`. Async: return DECLINED.
5. `VERDICT` → apply action: resume phases (allow), return status (deny),
   set `r->content_handler` for custom deny body, set `Location` + 3xx
   (redirect), mutate `r->headers_in` (hdr-set/unset), swap the captured
   request body (req-body), stash vars, and arm response mutations
   (res-hdr-*, res-body) for the output filters.
6. Optional second round-trip (`xngin_response`): response headers/body
   held → `http-response` NOTIFY + BODY frames → response VERDICT →
   emit mutated/denied/held response.
7. Failure paths: conn death → stream replay on another conn (once);
   timeout → `xngin_fail open|close`; agent `ABORT` → same as conn death.
   Request cleanup sends `ABORT` best-effort.

## Scaling

- `xngin_agent_group` lists N `server` entries (unix or host:port),
  `weight=` multiplies conn count, `keepalive` sets conns per worker per
  weight unit. Agents can be local (UDS, ~0.1 ms RTT) or remote (TCP).
- Streams cap (`max-streams`, negotiated) bounds per-conn concurrency;
  excess requests shed per fail policy after timeout.
- Every nginx worker has its own pool — no locks anywhere on the hot path.
