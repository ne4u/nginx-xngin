# xngin — build & test notes

## Layout
- `SPEC.md` — XNAP wire protocol spec (normative, read first)
- `module/` — ngx_http_xngin_module (C, no external deps)
- `agents/go/` — xngin-go SDK + `cmd/edge-guard` (ACL + rate-limit agent)
- `agents/rust/` — xngin-rs SDK + `examples/mini_waf.rs` (regex WAF
  agent) + `examples/crs_waf/` (OWASP CRS agent via zentinel-modsec;
  per-vhost rulesets selected by `xngin_var waf_profile`)
- `test/harness/` — Python ref codec (`xnap.py`), scriptable `stub_agent.py`,
  `stacklib.py` test stack, codec unit tests
- `test/conformance/` — shared `vectors.json` consumed by all three codecs;
  regenerate with `python3 test/conformance/gen_vectors.py`
- `test/cases/` — pytest integration suite
- `test/bench/` — `bench.py` lane harness + `echo_agent.c` (minimal C
  XNAP agent; bench.py cc-compiles it for the `c-echo` lane) +
  `bench_fp.py` (per-connection h2/h3 fingerprint cost)
- `test/fuzz/`, `docker-compose.yml`, `test/Dockerfile`

## Build the module (macOS/Linux)
Module links `-lz -lbrotlidec` — needs zlib + brotli dev packages
(macOS: `brew install brotli`; Debian/Ubuntu: `apt-get install zlib1g-dev libbrotli-dev`).
```sh
curl -sO https://nginx.org/download/nginx-<VER>.tar.gz && tar xzf nginx-<VER>.tar.gz
cd nginx-<VER>
./configure --add-dynamic-module=<repo>/module \
            --with-cc-opt="-I/opt/homebrew/include" \
            --with-ld-opt="-L/opt/homebrew/lib"   # macOS Homebrew pcre2
make modules && make                            # .so lands in objs/
```

## Tests
```sh
# codec + conformance (all three SDKs)
python3 -m pytest test/harness -q
(cd agents/go && go test ./...)
(cd agents/rust && cargo test)

# integration (needs NGINX_BIN + MODULE_SO env vars)
export XNGIN_NGINX_BIN=/path/to/nginx
export XNGIN_MODULE_SO=/path/to/objs/ngx_http_xngin_module.so
python3 -m pytest test/cases -q
```

## Agents
```sh
(cd agents/go && go run ./cmd/edge-guard -listen unix:/tmp/eg.sock -rate 50)
(cd agents/rust && cargo run --example mini_waf -- --listen unix:/tmp/waf.sock)
(cd agents/rust && cargo run --example crs_waf -- --profile default=/path/rules.conf)
```

## Gotchas learned
- Socket read/write events carry `ngx_connection_t*` in `ev->data`; get the
  app ptr via `nc->data`. Timer events carry your own `ev->data`.
- `ngx_http_read_client_request_body` returns NGX_OK on the fast path after
  calling post_handler inline — do NOT return NGX_DONE for it; continue.
  It returns NGX_AGAIN/NGX_DONE when reading is pending.
- Request body lands in `rb->bufs` chain; `rb->buf` only for single-buf mode.
- AF_UNIX sun_path is ~104 bytes on macOS — keep test socket paths in /tmp.
- `ngx_str_set` with a ternary doesn't compile; branch explicitly.
- Verdict cache uses engine-side `xngin_cache_key` — agent only supplies ttl.
- nginx >= 1.29.2 occupies `SSL_CTX_set_client_hello_cb` itself (SNI via
  `ngx_ssl_client_hello_callback` + `ngx_ssl_client_hello_arg` in ctx
  ex_data). Never overwrite the cb — swap the stored arg (first member =
  `servername` fn ptr) and chain to the saved arg. On older nginx a raw
  `client_hello_cb` is fine (slot unused).
- `SSL_ERROR_WANT_CLIENT_HELLO_CB` is unhandled by `ngx_ssl_handshake` —
  `SSL_CLIENT_HELLO_RETRY` kills the connection; no agent round-trips at
  hello time. Deny must be local/synchronous.
- `client_hello_cb` fires on the *default* server's ctx per listen socket,
  pre-SNI — `xngin_tls_inspect` only makes sense there.
- `SSL_CTX_set_msg_callback` gives the full raw handshake msg (4-byte
  header included); filter `write_p==0 && SSL3_RT_HANDSHAKE &&
  buf[0]==SSL3_MT_CLIENT_HELLO`. Keep the first CH (HRR sends two).
- A body filter cannot "hold" output by returning NGX_OK — upstream
  finalizes the request anyway (pool freed, conn closed). To hold a
  response: set our bit in `r->buffered` (0x08; sub/ssi/copy use the same
  mechanism). `ngx_http_finalize_request` then diverts into
  `ngx_http_set_write_handler` and the request stays alive; emit + clear
  the bit + `ngx_http_finalize_request(r, NGX_OK)` to complete.
- Upstream often sends `last_buf` as a standalone EMPTY buf. Dropping
  zero-size bufs loses the terminal flag → write filter postpones the
  chain (< postpone_output) → nothing ever reaches the client. Append a
  special empty buf carrying `last_buf`/`last_in_chain` instead. Zero-size
  NON-special bufs error the write filter outright — never emit them.
- `ngx_snprintf`: `%x`/`%u` are FLAGS, not conversions — `%uxc` sets hex
  then consumes `%c` (single char). Connection numbers use `%uA`
  (`ngx_atomic_uint_t`), like `$connection`.
- `proxy_pass` keeps the upstream `headers_out.status_line` verbatim —
  overriding `headers_out.status` is not enough; clear `status_line` too
  or the wire shows the upstream status.
- VERDICT is a single frame: fields (e.g. a large `req-body`) must fit
  the negotiated `max-frame-size` (16k default); big payload tests should
  route bodies through BODY frames/echo, not the verdict.
- stub_agent stats flush every 0.5s — poll `stats()` or sleep 0.7s+ in
  tests; don't assert on stats immediately after a request.
- `ngx_http_read_client_request_body` takes a `r->main->count` ref that
  stock callers release when the *content*-phase checker finalizes
  NGX_DONE. The *access*-phase checker does not finalize NGX_DONE —
  release the ref yourself (`r->main->count--`) before returning from
  the handler's first run, or the request ends with count 2, keepalive
  never re-arms, and the NEXT request on that connection stalls in
  test_reading. Symptom: first POST works, second POST on the same
  keep-alive conn hangs before reaching the handler.
- Agent mTLS (`ssl on` in the group) needs `--with-http_ssl_module`;
  the engine is the TLS CLIENT, the agent is the TLS server.
- `ngx_ssl_create_connection` allocates from `c->pool` — agent conns
  from `ngx_event_connect_peer` have NO pool → segfault in ngx_pcalloc.
  Create a small `nc->pool` first and `ngx_destroy_pool` it in
  conn_close (same as ngx_http_upstream does).
- During `ngx_ssl_handshake`, openssl hijacks `rev/wev->handler` with
  its own `ngx_ssl_handshake_handler` — restore `conn_read`/`conn_write`
  in `c->ssl->handler` before resuming normal I/O.
- TLS conns can't `writev` — drain the pkt queue via `nc->send`
  (= `ngx_ssl_send`) one pkt at a time when `c->ssl`.
- Config-time: `ssl on` requires `ssl_trusted_certificate` (engine
  verifies agent cert; VERIFY_PEER + explicit X509_V_OK check +
  optional `ngx_ssl_check_host` via `ssl_server_name` which doubles as
  SNI — IPs send no SNI).
- stacklib `gen_mtls_certs(root)` makes CA + agent + engine certs via
  openssl; `Stack(mtls=True)` wires `ssl on` + engine client cert into
  the group and `--tls-cert/--tls-key/--tls-client-ca` into the stub.
  Knobs: `agent_tls=False` (plaintext agent), `wrong_ca=True`,
  `client_cert=False` — all should yield fail-close 503.
- Re-running `./configure` for `make modules` MUST repeat the original
  args exactly (`--without-http_rewrite_module` etc.) or the .so
  signature mismatches: "module is not binary compatible".
- macOS: overwriting a dlopen'd .so in place invalidates its code
  signature — the process dies with `Killed: 9` ("Code Signature
  Invalid" in the .ips crash report). `rm` the old .so first, then cp.
- If the .so is built missing a source file (e.g. ./configure ran while
  sources were stashed), `load_module` fails on the undefined symbol —
  every stack() test errors "nginx didn't start"; check the error log
  for `dlopen`.
- `ngx_http_optimize_servers` runs AFTER http postconfig —
  `cycle->listening`, `ls->handler`, `ls->servers`, and per-addr
  `conf.default_server`/`conf.ssl`/`conf.quic` do NOT exist at
  postconfiguration. Listener swaps (`ls->handler`) belong in the
  module's `init_module` (ngx_module_t slot), which runs after
  ngx_open_listening_sockets. When sweeping `cycle->listening`, filter
  `ls->handler == ngx_http_init_connection` — stream{} listeners share
  the array with a different `ls->servers` port-struct type.
- TLS recv tee seam: `c->recv = ngx_ssl_recv` is only assigned inside
  ngx_ssl_handshake right before `c->ssl->handler(c)` — wrapping at
  ClientHello time gets overwritten. Swap `c->ssl->handler` at the
  client-Finished msg_cb instead.
- QUIC: `ls->handler` (ngx_http_init_connection) dispatches BOTH the
  session conn (c->quic==NULL) and stream conns (c->quic =
  ngx_quic_stream_t*, ->parent = session conn). Stream conns inherit
  `sc->ssl = c->ssl`, so a hello stored via SSL ex_data is reachable
  from r->connection on h3 requests.
- Hello field gating scope: capture flags (hello->tlsfp / ->h2fp) must
  come from the SSL_CTX owner (default server of the listen) — the ctx
  that installed the callback — NOT the request's routed/sni-picked
  xscf. Routed-server gating suppressed ja4 on a non-default vhost and
  broke ban-ja4 pushes (agent substitutes `$hello` from the notify).
- h2/h3 fingerprinting lives in module/ngx_http_xngin_h2fp.c: pool-
  cleanup conn ctx, recv tee, h2 frame parser + HPACK-lite (pseudo-
  header order only, no Huffman), QPACK-lite for h3 control-stream
  SETTINGS + first field section. `xngin_h2_inspect` srv flag.
  h2/h3 tests: `test/harness/h2fp.py` oracle + raw-frame client;
  `Stack(quic=True)` adds `listen <port> quic;` (needs ssl=True);
  h3 client = `curl --http3-only` (system curl has ngtcp2/nghttp3),
  aioquic is pip-installed too.
- The live build tree is `/tmp/nginx-src/nginx-1.31.8` (the
  `/tmp/nginx-1.31.8` dir is a stale partial copy — `make modules`
  fails there on missing src files). Use
  `XNGIN_MODULE_SO=/tmp/nginx-src/nginx-1.31.8/objs/ngx_http_xngin_module.so`,
  not the stacklib default.
- stub_agent serializes `handle()` per conn: a `delay_ms` verdict
  blocks every stream queued behind it on that conn — later verdicts
  land in notify order, not delay order. Use this to order same-key
  cache stores deterministically (e.g. deny with a longer delay
  replaces an allow sent earlier).
- The verdict cache rbtree keys on crc32 only — equal-hash nodes need
  a byte-compare walk of BOTH subtrees (rotations park them either
  side). `zlib.crc32 == ngx_crc32_long`, so test key pairs can be
  precomputed in Python (e.g. k29685295/k32060020 → 0x3973d855).
- FIPS crypto stack per side: engine → OpenSSL FIPS provider;
  Go SDK → stdlib `crypto/tls` with `GOFIPS140=v1.0.0` (Go 1.24+) or
  `GOEXPERIMENT=boringcrypto`; Rust SDK → rustls + aws-lc-rs
  (FIPS 140-3 validated); Python harness → `ssl` on FIPS OpenSSL.
- `r->reading_body` is only set for UNBUFFERED body reads
  (`request_body_no_buffering`) and v2/v3 — a buffered read-in-flight
  does NOT set it. To force "answer then close" on a pending buffered
  read, set `r->keepalive = 0; r->lingering_close = 1;` directly
  (ngx_http_finalize_connection derives the same pair from
  reading_body).
- Borrowed (zero-copy) pkts: `ngx_xnap_pkt_t.owner != NULL` means
  pos..last references pool memory; `cap == 0` keeps it off the
  freelist. `ngx_http_xngin_ctx_abort` (request cleanup, pool still
  valid) sweeps ALL group conns via `ngx_http_xngin_group_materialize`
  to convert still-queued borrowed pkts to owned copies.
- macOS loopback TCP input delivery is kernel-coalesced under moderate
  concurrent load: one-way send->recv latency inflates ~15us -> ~370us
  even between two bare Python processes. Every XNAP round-trip pays it
  twice, so `*-tcp` bench lanes cap ~27-38k rps vs ~46k UDS regardless
  of agent (stub and mini_waf direct-drive to the same ~60-75k
  ceiling; high in-flight escapes the coalescing entirely ~200k+).
  Not fixable in userspace: nodelay, keepalive counts, max_streams and
  runtime flavor all measured flat. Diagnose transport-vs-agent gaps
  with `cargo test --test direct_bench -- --ignored` (XNAP_ADDR/CONNS/
  INFLIGHT env) bypassing nginx.
- QUIC + `worker_processes >1` on loopback is flaky: datagrams landing
  on the wrong worker are forwarded via socketpairs with ms-level
  stalls and occasional client-visible timeouts (~40% of aioquic conns
  timed out at 4 workers; 1 worker is clean). bench_fp.py therefore
  uses a single worker.
- aioquic handshakes swing ±0.5ms+ run to run (pure-Python crypto):
  never run all "off" samples then all "on" — a sequential ordering
  once produced a phantom "+1ms h3 handshake cost". bench_fp.py
  interleaves off/on and reports an `h3-aa` (off vs off) noise floor.
  For sub-µs questions, time inside nginx with temporary
  `clock_gettime` + `ngx_log_error(WARN)` instead (servername hook
  measured 4µs TCP / 6µs QUIC).
- Each h3 request is a fresh QUIC *stream conn* through `ls->handler`;
  the h3 tee skips streams the session agg can't learn from
  (uni after `seen_settings`, bidi after `seen_headers`) and every
  stream restores `c->recv` on `XFPS_DONE`/`XFPS_BAD` — keep both or
  warm h3 requests regain a per-request buffer + tee.
- CI builds nginx with `--with-http_ssl_module --with-http_v2_module`
  only (ubuntu OpenSSL 3.0 has no QUIC API, so no v3). Any static
  function whose call sites are all `#if (NGX_QUIC)`-guarded MUST have
  its decl + definition guarded too — unused-function trips -Werror
  on the no-QUIC build (this broke CI on the h2fp PR). fp tests gate
  on `stacklib.HAVE_H2` / `HAVE_H3` / `HAVE_CURL_H3` (nginx -V +
  curl --version detection at harness import).
