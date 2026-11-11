# Changelog

## [Unreleased]

### Added
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
