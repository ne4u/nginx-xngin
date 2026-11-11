# xngin examples

Copy-pasteable recipes for every mutation the verdict language supports.
Each shows the nginx config, the agent-side verdict, and what you'll see.
Verdict fields are XNAP KV entries — see `SPEC.md` §4.3 for wire types.

All examples assume a group is configured:

```nginx
http {
    xngin_agent_group waf { server unix:/run/xngin/waf.sock; }
    server {
        location / {
            xngin_enable on;
            xngin_group waf;
            proxy_pass http://backend;
        }
    }
}
```

## 1. Request headers (hdr-set / hdr-unset)

Agent sets `x-tenant` and strips `x-secret` before the request reaches
upstream.

```go
// Go SDK
v := xngin.Allow()
v.SetHeaders  = map[string]string{"x-tenant": "acme"}
v.UnsetHeader = []string{"x-secret"}
```

```python
# stub agent rules
{"match": {}, "verdict": {"action": "allow",
                          "hdr_set": {"x-tenant": "acme"},
                          "hdr_unset": ["x-secret"]}}
```

Result: upstream receives `x-tenant: acme`, never sees `x-secret`.

## 2. Request body rewrite (req-body)

Replace the body forwarded upstream. Requires `xngin_body_inspect on`
(the engine must capture the original body to swap it); `Content-Length`
is fixed up automatically.

```nginx
location / {
    xngin_enable on; xngin_group waf;
    xngin_body_inspect on; xngin_body_max 64k;
    proxy_pass http://backend;
}
```

```python
{"match": {"uri_contains": "/preview"},
 "verdict": {"action": "allow", "req_body": "REWRITTEN-BY-AGENT"}}
```

Result: `POST /preview` with any payload reaches upstream as
`REWRITTEN-BY-AGENT` with a corrected `Content-Length`.

## 3. Response headers (res-hdr-set / res-hdr-unset)

Stamp headers on the downstream response, or strip leaky ones — no
second round-trip needed; the verdict-time fields apply in the response
header filter.

```python
{"match": {},
 "verdict": {"action": "allow",
             "res_hdr_set": {"x-waf": "clean"},
             "res_hdr_unset": ["x-powered-by", "server"]}}
```

Result: clients see `x-waf: clean`; `x-powered-by`/`server` are gone.

## 4. Blind response body rewrite (res-body)

Replace the response body at verdict time without inspecting it —
upstream still runs; the engine swaps the body on the way out and clears
`Content-Length`/`ETag`.

```python
{"match": {"uri_contains": "/preview"},
 "verdict": {"action": "allow", "res_body": "REPLACED-RESPONSE"}}
```

Result: any request to `/preview` returns exactly `REPLACED-RESPONSE`.
For *inspection* of the real body before rewriting, use `http-response`
below instead.

## 5. Response inspection (http-response round-trip)

`xngin_response` holds the upstream response — headers are not sent —
and sends the agent a second `http-response` NOTIFY with status,
headers, and buffered body. The second VERDICT applies `res-*` fields.

```nginx
location / {
    xngin_enable on; xngin_group waf;
    xngin_response on;          # second round-trip
    xngin_res_body_max 64k;     # body cap; over this → pass uninspected
    proxy_pass http://backend;
}
```

```python
{"res_rules": [
    {"match": {"body_contains": "SSN"},
     "verdict": {"action": "allow", "res_body": "masked",
                 "res_hdr_set": {"x-redacted": "1"},
                 "vars": {"res_rule": "pii-redact"}}}]}
```

Result: responses containing `SSN` become `masked` with
`x-redacted: 1`; `$xngin_res_rule` logs `pii-redact`.

Semantics:

- `action deny` on a response stream discards the held response and
  emits `status`/`body`/`content-type`, exactly like a request deny.
- Responses larger than `xngin_res_body_max` bypass inspection —
  never truncated-and-redacted.
- Timeout/agent-down follows `xngin_fail` (headers haven't been sent,
  so `close` still yields 503).
- Requires the agent to negotiate capability bit 8 (`CAP_RESP`); agents
  without it are skipped and responses pass through.

## 6. JA4 fingerprinting (ja4-fp agent)

`agents/go/cmd/ja4-fp` recomputes JA4 + JA4_r from the raw ClientHello
(`ch-raw`) via `xngin.ComputeJA4` and surfaces them upstream, to the
client, and as nginx variables.

```nginx
server {
    listen 443 ssl;
    ssl_certificate     cert.pem;
    ssl_certificate_key key.pem;
    xngin_tls_inspect on;               # capture ClientHello (default server)

    location / {
        xngin_enable on; xngin_group waf;
        add_header x-echo-ja4 $xngin_agent_ja4 always;
        proxy_pass http://backend;
    }
    access_log /var/log/nginx/ja4.log xnginlog;
}
```

```sh
(cd agents/go && go run ./cmd/ja4-fp -listen unix:/run/xngin/waf.sock)
```

Result:

- upstream gets `x-ja4` / `x-ja4-raw` request headers (`hdr-set`)
- client gets `x-ja4` / `x-ja4-raw` response headers (`res-hdr-set`)
- nginx vars: `$xngin_agent_ja4`, `$xngin_agent_ja4_r`, `$xngin_ja4_match`
  (1 = agent JA4 equals the engine's own `$xngin_ja4`)
- `$xngin_ja4` is the engine-computed fingerprint for the same hello

## 7. Deny / custom response (existing behavior)

```python
{"match": {"uri_contains": "/admin"},
 "verdict": {"action": "deny", "status": 451,
             "body": "unavailable for legal reasons",
             "content_type": "text/plain"}}
```

Result: `GET /admin` → `451` with the custom body; never reaches
upstream.
