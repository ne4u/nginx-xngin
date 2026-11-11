# xngin — build & test notes

## Layout
- `SPEC.md` — XNAP wire protocol spec (normative, read first)
- `module/` — ngx_http_xngin_module (C, no external deps)
- `agents/go/` — xngin-go SDK + `cmd/edge-guard` (ACL + rate-limit agent)
- `agents/rust/` — xngin-rs SDK + `examples/mini_waf.rs` (regex WAF agent)
- `test/harness/` — Python ref codec (`xnap.py`), scriptable `stub_agent.py`,
  `stacklib.py` test stack, codec unit tests
- `test/conformance/` — shared `vectors.json` consumed by all three codecs;
  regenerate with `python3 test/conformance/gen_vectors.py`
- `test/cases/` — pytest integration suite
- `test/bench/`, `test/fuzz/`, `docker-compose.yml`, `test/Dockerfile`

## Build the module (macOS/Linux)
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
