# Changelog

## [Unreleased]

### Added
- `xngin_h2_inspect on` (server context): connection-level HTTP/2 and
  HTTP/3 fingerprinting without nginx patches. The module tees
  connection bytes off `c->recv` (installed at client-Finished for TLS,
  via the `ls->handler` dispatch for cleartext h2c and QUIC streams) and
  parses the fingerprint itself: `h2-fp` (Akamai format —
  `settings|window_update|priorities|pseudo_header_order`, HPACK-lite
  for the pseudo order), `h3-fp` (`settings|pseudo_header_order` via
  QPACK-lite over the client control stream + first field section), and
  on QUIC `ja4` gains the `q` transport char plus `quic-tp`/`quic-tps`
  (raw + ordered ids of TLS ext `0x0039`). New nginx variables
  `$xngin_h2fp` / `$xngin_h3fp`. Independent of `xngin_tls_inspect` —
  gated fields carry their capture scope on the hello so they work for
  non-default SNI vhosts too. The h3 tee only touches the streams that
  can contribute (control SETTINGS + first request HEADERS, 2KB buffer
  with prefix parse for oversized blocks) and drops off each stream as
  soon as it's done, so later requests on a QUIC conn pay nothing
- Early verdicts before BODY `LAST` in both SDKs (SPEC §4.2): Go
  `EarlyHandler` interface (`EarlyVerdict` may return a verdict at
  NOTIFY time) and Rust `AgentHandler::early_verdict` (default `None`,
  opt-in by overriding). Handlers that need the body keep the
  wait-for-`LAST` behavior; the engine stops sending BODY after a
  verdict
- Zero-copy BODY frames: payloads that reference provably stable memory
  (the single-buffer request body, the pool-held response chain) are
  queued as borrowed packets instead of memcpy'd; request cleanup
  materializes any still-queued borrowed packets into owned copies
  before the request pool dies
- `xngin_body_replace off` (default on): opt out of
  `request_body_in_single_buf` when the agent never replaces the
  request body — streamed BODY frames fall back to copies. A `req-body`
  verdict that violates the contract is still applied, with a warning
- `xngin_upload_drain off` (default on): deny/redirect verdicts that
  land while the upload is in flight answer immediately and close the
  connection instead of draining the body to keep it alive
- Request mutation: `req-body` replacement (Content-Length fixup),
  `hdr-set`/`hdr-unset` upstream header ops
- Response mutation: `res-hdr-set`/`res-hdr-unset`/`res-body` applied
  at verdict time in output filters
- `xngin_response` staged round-trip: `http-response` NOTIFY carries
  status + headers + buffered body to `CAP_RESP` agents;
  `xngin_res_body_max` cap with pass-through bypass; deny/redirect/vars
  on response streams
- `CAP_RESP` capability bit (8) negotiated in ENGINE_HELLO
- `ja4-fp` Go example agent: JA4/JA4_r recomputed from `ch-raw` via new
  `xngin.ComputeJA4`, surfaced as request/response headers and
  `$xngin_*` variables
- `docs/examples.md`, verdict-field table in `docs/config-reference.md`
- Optional TLS/mTLS on engine↔agent links: `ssl on` in the agent group
  makes the engine a TLS client — verifies the agent cert against
  `ssl_trusted_certificate`, optional `ssl_server_name` SNI/SAN pinning,
  `ssl_certificate`/`ssl_certificate_key` presents an engine client
  cert for mutual auth. Matching `--tls-cert`/`--tls-key`/
  `--tls-client-ca` flags in `stub_agent.py`, edge-guard, and mini_waf.
  FIPS-capable stacks: engine OpenSSL FIPS provider, Go `crypto/tls`
  (boringcrypto/GOFIPS140), rustls + aws-lc-rs (Rust).
- GitHub release prep: LICENSE (Apache-2.0 + Commons Clause),
  SECURITY.md, CONTRIBUTING.md, CI workflow, issue/PR templates

### Changed
- Go SDK fast path: frame payloads are scanned, not copied (retained
  bytes copy once — decoded `net.IP` values are now owned), marshal
  buffers are pooled, and a per-conn writer batches frames through
  `net.Buffers` writev; handler ctx is cancelled on conn teardown
- Rust SDK fast path: `BytesMut` + `freeze` zero-copy dispatch replaces
  per-frame `to_vec` and per-read `drain`; decide runs in spawned tasks
  bounded by the negotiated `max-streams` semaphore instead of inline
  in the read loop (a slow handler no longer stalls other streams); a
  writer task batches frames and flushes once per batch
- mini_waf: rules match borrowed request bytes via `regex::bytes` (no
  `to_string`/`from_utf8_lossy` copies) and denies early when URI or
  header rules alone cross the threshold
- edge-guard: `-ttl` now applies to deny verdicts only (allow verdicts
  stay uncached so every request still takes a token), clamped to the
  rate-limit refill window; `hdr-set`/`vars` are sent only on uncached
  denies since both make a verdict uncacheable; rate buckets are keyed
  by raw `netip.Addr` bytes and sharded across 64 lock shards

### Fixed
- Rust SDK AGENT_HELLO advertised a hardcoded `max-streams` 256 instead
  of `Server::max_streams`; `-ttl` on edge-guard previously cached
  allow verdicts, silently disabling the rate limiter for repeat keys
- Response hold uses `r->buffered` so upstream completion no longer
  finalizes the request before the response verdict lands; zero-size
  `last_buf` sentinel buffers propagate correctly
- `request-id` corruption in `http-response` NOTIFY (`%uxc` → `%uA`
  format bug)
- Deny overrides now clear upstream `headers_out.status_line`
- Response-stream fail-close returns 503 (consistent with request side)
- BODY frames no longer exceed negotiated `max-frame-size`
