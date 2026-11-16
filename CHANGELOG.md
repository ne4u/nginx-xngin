# Changelog

## [Unreleased]

### Added
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

### Fixed
- Response hold uses `r->buffered` so upstream completion no longer
  finalizes the request before the response verdict lands; zero-size
  `last_buf` sentinel buffers propagate correctly
- `request-id` corruption in `http-response` NOTIFY (`%uxc` → `%uA`
  format bug)
- Deny overrides now clear upstream `headers_out.status_line`
- Response-stream fail-close returns 503 (consistent with request side)
- BODY frames no longer exceed negotiated `max-frame-size`
