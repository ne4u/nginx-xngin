# XNAP — xngin Agent Protocol

Version: **1**

XNAP is a framed, multiplexed binary protocol between an nginx worker (the
*engine*) and a traffic-decision agent (the *agent*), modelled on HAProxy SPOP.
One persistent connection carries many in-flight requests concurrently, so the
steady-state cost of a decision is one frame out and one frame back.

## 1. Transport

- Unix domain stream socket or TCP. `TCP_NODELAY` MUST be set on TCP.
- Byte order: integers are uvarints (§2); multi-byte fixed fields are big-endian.
- Either side may close the connection at any time. The engine treats an
  unexpected close as a connection failure (§7).

### 1.1 TLS transport (optional)

When `ssl on` is configured on the engine's agent group, the connection
runs standard TLS (1.2 or 1.3) underneath the XNAP framing. The engine
is the TLS **client** (it initiates the connection); the agent is the
TLS **server** and presents its certificate.

- The engine MUST verify the agent certificate against the configured
  `ssl_trusted_certificate` CA and MUST close on verify failure.
- `ssl_server_name` optionally pins the expected agent hostname: it is
  sent as SNI and checked against the certificate SAN/CN. IP literals
  send no SNI.
- `ssl_certificate` + `ssl_certificate_key` present an engine client
  certificate; agents that require one get mutual TLS. Without them the
  connection is server-authenticated TLS only.
- All XNAP frames are carried unchanged inside TLS records. The HELLO
  exchange happens after the handshake completes.
- A TLS failure (handshake error, bad or missing peer certificate)
  behaves like a dead agent: the connection drops and `xngin_fail`
  policy applies.

TLS on agent links is intended for deployments that need peer
authentication, key rotation, or compliance (PCI DSS, FedRAMP) on the
engine↔agent path. For FIPS module requirements, build against a
validated crypto library (OpenSSL FIPS provider on the engine,
aws-lc-rs on the Rust SDK, boringcrypto/GOFIPS140 on the Go SDK).

The handshake cost is amortized: connections are persistent and
pre-warmed at worker init, so steady-state cost is just the record
layer (~22 bytes/frame, AES-GCM/ChaCha20 hardware-accelerated).

## 2. Primitive encodings

### 2.1 varint

Unsigned LEB128: 7 payload bits per byte, low bits first, continuation bit 0x80.

```
0        → 00
300      → AC 02
```

Signed integers use zigzag: `u = (v << 1) ^ (v >> 63)` for INT64,
`u = (v << 1) ^ (v >> 31)` for INT32.

### 2.2 Typed values

Every value in a KV payload is: `type: u8` then the encoding below.

| tag  | name    | encoding                                   |
|------|---------|--------------------------------------------|
| 0x00 | NULL    | (none)                                     |
| 0x01 | TRUE    | (none)                                     |
| 0x02 | FALSE   | (none)                                     |
| 0x03 | INT32   | zigzag varint                              |
| 0x04 | INT64   | zigzag varint                              |
| 0x05 | UINT32  | varint                                     |
| 0x06 | UINT64  | varint                                     |
| 0x07 | IPV4    | 4 bytes, network order                     |
| 0x08 | IPV6    | 16 bytes, network order                    |
| 0x09 | STR     | varint byte-len + UTF-8 bytes              |
| 0x0A | BIN     | varint byte-len + opaque bytes             |
| 0x0B | KVL     | varint byte-len + nested KV entries (§3.2) |
| 0x0C | STRLIST | varint count + count × STR                 |

## 3. Frame layout

```
+-------------+--------+-----------+-----------+----------+==========+
| frame-len   | type   | flags     | stream-id | frame-id | payload  |
| varint      | u8     | u32 BE    | varint    | varint   |          |
+-------------+--------+-----------+-----------+----------+==========+
```

`frame-len` counts every byte after itself (type..payload inclusive).
Receivers MUST reject frames larger than the negotiated `max-frame-size`
(default 16384) and frames declaring `frame-len` < 6.

### 3.1 Frame types

| type | name        | sender  | purpose                              |
|------|-------------|---------|--------------------------------------|
| 0x01 | ENGINE_HELLO| engine  | connection handshake                 |
| 0x02 | AGENT_HELLO | agent   | handshake reply                      |
| 0x03 | DISCON      | both    | graceful disconnect                  |
| 0x04 | NOTIFY      | engine  | request context (§4.1)               |
| 0x05 | VERDICT     | agent   | decision (§4.2)                      |
| 0x06 | BODY        | both    | body chunk (§4.2)                    |
| 0x07 | ABORT       | both    | cancel one stream                    |
| 0x08 | PING        | both    | liveness + RTT probe                 |
| 0x09 | PONG        | both    | echo reply                           |
| 0x0A | CONTROL     | agent   | engine control op (§4.6)             |

### 3.2 KV payloads

A KV payload is a sequence of entries, terminated by end of frame:

```
name-len: varint | name: bytes | value: typed-value
```

Repeated names are legal (e.g. repeated headers inside a KVL). Order is
preserved. Unknown names MUST be ignored for forward compatibility.

### 3.3 Flags

Generic stream lifecycle flags (bits 0-1):

| bit | name  | meaning                                        |
|-----|-------|------------------------------------------------|
| 0   | FIN   | sender will send no more frames on this stream |
| 1   | ABORT | stream aborted (see also ABORT frame)          |

Frame-specific flags (bits 8+):

| frame  | bit | name         | meaning                                  |
|--------|-----|--------------|------------------------------------------|
| NOTIFY | 8   | HAS_BODY     | BODY frames follow                       |
| NOTIFY | 9   | ASYNC        | verdict must not block the request       |
| BODY   | 8   | LAST         | final body chunk                         |
| BODY   | 9   | TRUNCATED    | body exceeded capture cap; this is partial |

### 3.4 Stream and frame ids

`stream-id` is odd when allocated by the engine (engine sends on odd streams)
and even when allocated by the agent. Agent-allocated even sids carry
agent-initiated messages: CONTROL ops (§4.6) use sid 2. `frame-id` is a
per-stream sequence number starting at 0, incremented per frame sent by that
side; it enables pipelining and replay detection.

## 4. Message payloads

### 4.1 NOTIFY — `http-request`

Payload: `msg-name: STR` then a flat KV entry list. The only defined message in
v1 is `http-request`:

| name          | type         | notes                                     |
|---------------|--------------|-------------------------------------------|
| `method`      | STR          |                                           |
| `scheme`      | STR          | `http` or `https`                         |
| `host`        | STR          | Host header value, may be empty           |
| `uri`         | STR          | original request URI incl. args           |
| `http-version`| STR          | `1.0`, `1.1`, `2`                         |
| `headers`     | KVL          | lower-cased names; one entry per value    |
| `src-ip`      | IPV4 / IPV6  |                                           |
| `src-port`    | UINT32       |                                           |
| `dst-ip`      | IPV4 / IPV6  | local address, best effort                |
| `dst-port`    | UINT32       |                                           |
| `tls`         | TRUE / FALSE |                                           |
| `tls-version` | STR          | negotiated version, when `tls`            |
| `sni`         | STR          | client SNI, when `tls` and sent           |
| `alpn`        | STR          | negotiated ALPN, when `tls` and selected  |
| `ja4`         | STR          | JA4 fingerprint of the ClientHello; present when `xngin_tls_inspect` captured it. Agents MAY ignore it and fingerprint `ch-raw` with any scheme |
| `ch-raw`      | BIN          | raw ClientHello handshake message (incl. 4-byte handshake header); present when `xngin_tls_inspect` captured it — canonical material for arbitrary TLS fingerprinting |
| `request-id`  | STR          | engine request id, for log correlation    |
| `vars`        | KVL          | nginx variables captured via `xngin_var` (e.g. `$ssl_client_s_dn`, GeoIP, userid) |
| `body-len`    | UINT32       | declared Content-Length when known        |
| `body-truncated` | TRUE      | present when body exceeded capture cap    |

`headers` is filtered by `xngin_header_include` / `xngin_header_exclude`
when configured — sensitive values such as `cookie` and `authorization`
only cross the wire when the operator allows them.

### 4.2 BODY

Payload is raw body bytes. Chunks are arbitrary; `LAST` flag marks the end.
An agent MAY return a VERDICT before `LAST` (headers-only decision), in which
case the engine stops sending BODY frames for that stream.

In the agent→engine direction, BODY frames carry a streamed replacement
body after a `body-stream` VERDICT (§4.3): the stream stays open, the
agent streams the new body, and `LAST` applies it.

With `xngin_body_inspect on` the engine dispatches the `http-request`
NOTIFY as soon as the request headers are parsed — while the client
upload is still in flight — and forwards body bytes to the agent as
they arrive. Agents MUST NOT assume the upload is complete when the
NOTIFY lands; `body-len` is the declared Content-Length and BODY frames
simply trail the client upload until `LAST`.

### 4.3 VERDICT

KV payload:

| name        | type    | notes                                        |
|-------------|---------|----------------------------------------------|
| `action`    | STR     | `allow` / `deny` / `redirect` (required)     |
| `status`    | INT32   | HTTP status for `deny` (default 403)         |
| `body`      | BIN/STR | optional deny response body                  |
| `content-type` | STR  | for deny `body`                              |
| `location`  | STR     | URL for `redirect` (status 301/302/303/307)  |
| `hdr-set`   | KVL     | request headers added/replaced upstream      |
| `hdr-unset` | STRLIST | request headers removed upstream             |
| `req-body`  | BIN/STR | replace the request body forwarded upstream (see §6) |
| `res-hdr-set` | KVL   | response headers added/replaced toward the client |
| `res-hdr-unset` | STRLIST | response headers removed                 |
| `res-body`  | BIN/STR | replace the response body after upstream produces it |
| `vars`      | KVL     | exposed to nginx as `$xngin_<name>`          |
| `cache-key` | STR     | reserved (engine key is authoritative)       |
| `cache-ttl` | UINT32  | seconds; >0 lets engine cache this verdict   |
| `body-stream` | TRUE/UINT | on `allow`: keep the stream open; agent streams a replacement body back via BODY frames ending with LAST (§4.2) |
| `reason`    | STR     | logged via `$xngin_reason`                   |
| `score`     | INT32   | logged via `$xngin_score`                    |

A VERDICT with no `action` is a protocol error and MUST be treated as `deny 500`
in blocking mode (fail-closed semantics inside the agent decision itself).

### 4.4 HELLO / DISCON / PING

`ENGINE_HELLO` KV payload:

| name             | type   | notes                               |
|------------------|--------|-------------------------------------|
| `version`        | UINT32 | protocol version, currently 1       |
| `max-frame-size` | UINT32 | receiver cap, bytes                 |
| `max-streams`    | UINT32 | max concurrent streams on this conn |
| `engine-id`      | STR    | free-form, e.g. `nginx/1.27.2 w3`   |
| `capabilities`   | UINT32 | bitmask: 1=BODY 2=ASYNC 4=VCACHE 8=RESP 16=PUSH |

`AGENT_HELLO`: same fields (`agent-id` instead of `engine-id`), plus the
agent MAY set `capabilities` lower than offered — the engine must honour the
intersection. Version mismatch (agent cannot serve version 1) ⇒ DISCON.

`DISCON` KV: `code` UINT32 (0=normal, 1=protocol error, 2=overloaded),
`reason` STR.

`PING`/`PONG` KV: `data` BIN — echoed verbatim. Used for health and RTT.

`ABORT` KV: `reason` STR (optional).

### 4.6 CONTROL — agent-pushed ops

When the engine advertises PUSH (capability bit 16), an agent MAY send
CONTROL frames on its own even sid (sid 2). They take effect locally and
immediately — no stream is opened and no reply is sent.

KV payload:

| name    | type   | notes                                       |
|---------|--------|---------------------------------------------|
| `op`    | STR    | `ban-ip` / `ban-ja4` / `cache-drop`         |
| `ip`    | STR    | client address, for `ban-ip`                |
| `ja4`   | STR    | JA4 fingerprint, for `ban-ja4`              |
| `key`   | STR    | raw `xngin_cache_key` value, for `cache-drop` |
| `ttl`   | UINT32 | ban lifetime seconds (default 300, max 86400) |

CONTROL frames received before the conn's AGENT_HELLO completes are
ignored.

Semantics — every pushed state is scoped to the agent's own group:

- `ban-ip`: subsequent requests from `ip` are refused (403) in the
  ACCESS phase — only in locations whose `xngin_group` chain includes
  the pushing group.
- `ban-ja4`: subsequent ClientHellos carrying `ja4` are aborted during
  the handshake — the TLS equivalent of `xngin_tls_deny`, but dynamic —
  on servers with `xngin_tls_inspect` whose locations use the pushing
  group.
- `cache-drop`: evicts the verdict-cache entry whose key equals the
  raw `xngin_cache_key` value, but only when the entry was stored by a
  verdict from the pushing group.

Bans live in the shared `xngin_ban_zone` when configured (visible to all
workers) and otherwise in per-worker memory. Entries expire at `ttl`;
the effective lifetime is capped at 86400 seconds.
Unknown `op` values are logged and ignored.

### 4.5 NOTIFY — `http-response`

Second defined message (requires capability bit 8, `RESP`). When enabled
(`xngin_response on`), the engine holds the response headers and sends
an `http-response` NOTIFY as soon as they are available — before
anything reaches the client. Body bytes then stream to the agent as
BODY frames while the upstream download continues (the engine keeps a
buffered copy for release/deny). It is a separate stream and gets its
own VERDICT. Both upstream-proxied and nginx-generated (local) responses
are inspected; only the module's own decision pages (deny, redirect,
fail-close) are excluded. When the wire body is compressed
(`Content-Encoding: gzip`, `deflate`, or `br`), the held copy is
inflated and the agent receives plaintext BODY frames with a
`decompressed` field naming the wire encoding; the client still gets
the compressed bytes.

| name          | type    | notes                                        |
|---------------|---------|----------------------------------------------|
| `uri`         | STR     | original request URI                         |
| `method`      | STR     | original request method                      |
| `status`      | INT32   | upstream response status                     |
| `headers`     | KVL     | response headers, lower-cased names          |
| `req-headers` | KVL     | request headers (filtered), for correlation  |
| `ja4`         | STR     | client JA4, when `xngin_tls_inspect` ran     |
| `vars`        | KVL     | the same `xngin_var` set as the request      |
| `decompressed`| STR     | wire Content-Encoding when BODY frames carry the inflated body (`gzip`, `deflate`, `br`) |
| `body-len`    | UINT32  | declared Content-Length when known           |
| `request-id`  | STR     | same id as the matching `http-request`       |

Response BODY frames follow with `LAST` on the final chunk (or a lone
`body-len`-less NOTIFY when the response was empty). As with
`http-request`, an agent MAY verdict before `LAST`; the engine then
stops sending BODY frames.

A response whose declared Content-Length already exceeds
`xngin_res_body_max` is never inspected — no `http-response` stream is
sent at all. When the length is undeclared (e.g. chunked) and the body
grows past the cap mid-download, the engine sends `ABORT` for the
stream and releases the response uninspected rather than letting an
agent redact half a payload and leak the rest.

The response VERDICT uses the same fields as §4.3 with these differences:

- `action allow` (default): `res-hdr-set`/`res-hdr-unset`/`res-body`
  rewrite the held response; `vars` are recorded too late for headers
  already sent on the request pass but still reach the access log.
  `body-stream` on `allow` keeps the stream open so the agent can
  stream a replacement body back via BODY frames (§4.2).
- `action deny`: the held response is discarded; the engine emits
  `status` (default 403) + `body`/`content-type` exactly like a request
  deny. `redirect` behaves likewise.
- `hdr-set`/`hdr-unset`/`req-body`/`cache-ttl` are meaningless here —
  the upstream exchange is over — and are ignored.
- `reason`/`score` update `$xngin_reason`/`$xngin_score` for the log.

Timeout/error policy follows `xngin_fail`: `open` releases the buffered
response unmodified, `closed` emits 503 (headers haven't been sent yet,
so this is still possible — unlike mid-stream failures).

## 5. Connection state machine

```
engine connect → ENGINE_HELLO → AGENT_HELLO → READY
                                   │
     READY: engine may send NOTIFY (new stream-id). Agent replies VERDICT.
     Either side: PING→PONG, DISCON, ABORT, or socket close.
```

- The engine opens each connection and speaks first.
- Streams are independent; VERDICT frames may arrive out of order relative to
  request order.
- After AGENT_HELLO the negotiated `max-streams` and `max-frame-size` are the
  **minimum** of both advertised values.

## 6. Agent verdict semantics

- `allow`: request proceeds; `hdr-set`/`hdr-unset` applied to the upstream-bound
  request; `vars` visible for the rest of the request lifetime and access log.
- `req-body`: replaces the body forwarded upstream (Content-Length and
  Transfer-Encoding are rewritten to match). Honored only when the engine
  captured the request body (`xngin_body_inspect`); an unread body cannot be
  swapped and the field is ignored. Ignored in ASYNC mode — the request has
  already been proxied.
- `body-stream`: on an `allow` verdict the engine keeps the stream
  registered and the agent streams the replacement body back as BODY
  frames on the same sid; the frame carrying `LAST` completes the
  replacement. On the request stream it replaces the upstream-bound
  body (like `req-body`); on an `http-response` stream it replaces the
  held response (like `res-body`) — this is the path for payloads that
  do not fit a single frame.
- `res-hdr-set` / `res-hdr-unset`: applied to the downstream response headers
  before they reach the client (works in both blocking and ASYNC modes).
- `res-body`: the upstream request still runs; the response body is replaced
  with this value as it streams to the client (Content-Length/ETag cleared).
  For agent-driven *inspection* of the real response body, see `http-response`
  (§4.5).
- `deny`: engine emits `status` (default 403) + optional `body`/`content-type`.
- `redirect`: engine emits 3xx with `Location`.
- `cache-ttl`: the engine looks up a per-request key computed by its own
  `xngin_cache_key` config directive *before* dispatch. When a verdict carries
  `cache-ttl` > 0 (and no `hdr-set`, `hdr-unset`, `req-body`, `res-body`,
  `location`, `redirect` or `vars` — those verdicts are not cacheable),
  the engine MAY store the verdict in shared memory under that key —
  including the deny `status`, `body`/`content-type`, and
  `res-hdr-set`/`res-hdr-unset` response mutations, which replay without
  an agent round-trip. Verdict `cache-key` is accepted but ignored; the
  engine key is authoritative so lookups stay computable without an agent
  round-trip. A cached entry can be evicted with the `cache-drop` CONTROL
  op (§4.6).

## 7. Failure handling (engine side)

- Connect/write/read failure on a conn: conn marked down; in-flight streams are
  replayed on another ready conn in the same group (new stream-id, frame-id
  reset), at most once per stream. If no conn is ready, the location's
  `xngin_fail` policy applies to affected requests.
- Missed `xngin_ping_interval` PONGs (2 consecutive) ⇒ conn marked down and
  re-established.
- Version/handshake failure ⇒ conn permanently disabled until worker reload.
- Request cancelled by client ⇒ engine sends ABORT for the stream (best effort).
