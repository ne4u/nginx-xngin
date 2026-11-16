# Multi-vhost agent policies

Running one nginx instance with many virtual hosts against a shared
fleet of xngin agents, where each vhost gets its own rules/policy.
The config model splits cleanly along that line:

- **the fleet** is defined once at `http{}` (`xngin_agent_group`) —
  a named conn pool of agent servers, shared by every vhost that
  references it;
- **the policy wiring** is all location-conf — every `xngin_*`
  directive except the group/cache/ban-zone definitions is legal in
  `http{}`, `server{}`, and `location{}`, and inherits downward
  (http → server → location), so each vhost picks its own group,
  timeouts, fail mode, body handling, cache key, and forwarded vars;
- **the rules themselves live in the agent**. The engine ships enough
  per-request context (`host`, `sni`, `uri`, TLS info, plus arbitrary
  `xngin_var` KVs) for one agent to select the right ruleset.

## One fleet, many vhosts

```nginx
http {
    xngin_agent_group fleet {
        server 10.0.0.11:9000;
        server 10.0.0.12:9000 weight=2;
        server 10.0.0.13:9000 backup resolve;
        keepalive 4;
        balance hash $binary_remote_addr;
    }

    xngin_cache_zone verdicts:16m;
    xngin_ban_zone bans:4m;

    server {
        server_name a.example.com;

        xngin_enable on;
        xngin_group fleet timeout=30ms fail=close;
        xngin_body_inspect on;
        xngin_var policy "tenant-a";            # agent reads vars.policy
        xngin_cache_key "a|$uri$is_args$args";  # per-vhost keyspace
        xngin_header_exclude cookie;
        proxy_pass http://backend_a;
    }

    server {
        server_name b.example.com;

        xngin_enable on;
        xngin_group fleet timeout=10ms fail=open;
        xngin_group audit mode=async;           # chained second group
        xngin_var policy "tenant-b";
        xngin_cache_key "b|$uri$is_args$args";
        xngin_response on;
        proxy_pass http://backend_b;
    }
}
```

All vhosts referencing `fleet` share the same persistent conns —
`keepalive` conns per worker per weight unit, multiplexed by stream id
(256 streams/conn default). There is no per-vhost conn overhead and no
head-of-line queueing between vhosts at the conn level.

## Per-vhost knobs

Everything below is location-conf, so it can be set at `server{}`
(inherits to all its locations) or inside a `location{}` (replaces the
inherited value for that location only). See `config-reference.md` for
defaults.

| knob | per-vhost use |
|---|---|
| `xngin_enable` | opt a vhost in/out; `on` at `http{}` would blanket-enable |
| `xngin_group name [timeout=] [fail=] [mode=]` | pick the fleet; **repeatable** = sequential decision chain, each step with its own overrides |
| `xngin_mode` / `xngin_timeout` / `xngin_fail` | enforce vs. observe posture, latency bound, blast radius when the agent is down |
| `xngin_body_inspect` / `xngin_body_max` / `xngin_body_replace` | request-body capture per vhost |
| `xngin_response` / `xngin_response_group` / `xngin_res_body_max` | held upstream-response round-trip; may use a different group than requests |
| `xngin_var <name> <complex>` | arbitrary KVs in the NOTIFY `vars` field — the policy-token mechanism below |
| `xngin_cache_key` | engine-side verdict-cache key template |
| `xngin_header_include` / `xngin_header_exclude` | per-vhost header hygiene toward the agent |
| `xngin_internal` | skip subrequests/internal redirects |

## Telling the agent which policy applies

Every NOTIFY already carries `method`, `scheme`, `host` (the client
Host header), `uri`, `http-version`, `headers`, `src-ip`/`src-port`,
`dst-ip`/`dst-port`, `tls`, `tls-version`, `sni`, `alpn`, `ja4`,
`ch-raw`, `request-id`, and `body-len`/`body-truncated`. Two ways for
the agent to pick a ruleset:

1. **Key off `host`/`sni` directly.** Works out of the box, but both
   are client-controlled wire values — fine for routing, weak as a
   security boundary.
2. **Ship a config-bound policy token** (recommended for tenant
   identity): `xngin_var policy "tenant-a"` is set in the vhost's
   config, so the client cannot spoof it. It arrives in the NOTIFY's
   `vars` KVL on both request and response streams.

```go
// Go SDK: read the policy token, fall back to host
func policyOf(r *xngin.Request) string {
    if kvl, ok := r.Fields["vars"].([]xngin.Pair); ok {
        if v, ok := xngin.PairsGet(kvl, "policy"); ok {
            if s, ok := v.(string); ok {
                return s
            }
        }
    }
    return r.Get("host")
}
```

```rust
// Rust SDK
fn policy_of(req: &Request) -> String {
    if let Some(Value::Kvl(pairs)) = req.fields.get("vars") {
        for (k, v) in pairs {
            if k == "policy" {
                if let Value::Str(s) = v { return s.clone(); }
            }
        }
    }
    match req.fields.get("host") {
        Some(Value::Str(s)) => s.clone(),
        _ => String::new(),
    }
}
```

Because it's a complex value, `xngin_var` also forwards anything nginx
knows that the wire doesn't show — `$ssl_client_s_dn`, GeoIP results,
`$server_name`, map-derived tenant ids.

## Isolation boundaries

| shared thing | scope |
|---|---|
| agent conns (`xngin_agent_group`) | shared by every vhost referencing the group; streams multiplex freely across vhosts |
| verdict cache (`xngin_cache_zone`) | one shm zone; node identity is **(group-name, key)** — vhosts on the same group share entries for equal keys, vhosts on different groups never see each other's entries even for identical keys |
| `cache-drop` CONTROL | evicts only entries stored by the pushing group |
| `ban-ip` CONTROL | enforced only in locations whose `xngin_group` chain reaches the pushing group |
| `ban-ja4` CONTROL / `xngin_tls_deny` | resolved per-server by SNI (below) |
| ban store (`xngin_ban_zone`) | one shm zone; scoping is by group reach, not by vhost |

### Verdict cache

Cache lookups only run for **single-step** locations (a chain's cached
step would skip the earlier groups). When several vhosts share a group,
their keys share one namespace — so bake the vhost or policy into the
template:

```nginx
xngin_cache_key "a|$binary_remote_addr$uri";
```

When vhosts use **different** groups, the `(group, key)` identity makes
them fully isolated — identical keys can't see or overwrite each other,
and a `cache-drop` pushed by group A can't evict group B's entry for
the same key.

### JA4 bans and `xngin_tls_deny` across vhosts

`xngin_tls_inspect on` still belongs on the **default server** of each
`listen` — the ClientHello callback runs on the default server's
SSL_CTX before SNI switching. But the ban check itself is now
per-server:

- at hello time the engine decodes the SNI and resolves it to a server
  the same way `ngx_http_find_virtual_server` does (combined hash, then
  regex names);
- the resolved server's own `xngin_tls_deny` list applies, and pushed
  `ban-ja4` ops only fire if **that server's** locations can reach the
  pushing group — a ban pushed by group A kills `a.example.com`
  handshakes but leaves `b.example.com` handshakes on the same listen
  untouched;
- no SNI, an unparsable SNI, or an SNI matching no `server_name` falls
  back to the default server's entry.

Consequences for multi-vhost TLS:

- every vhost keeps its own static `xngin_tls_deny` list — a
  non-default vhost can list JA4s without enabling `xngin_tls_inspect`
  itself, as long as the default server captures hellos;
- per-tenant JA4 bans require per-tenant groups (the ban binds to
  "servers that can reach the pushing group"), or the shared group plus
  an agent that only pushes bans meant for all tenants.

## Separate groups when sharing isn't enough

Declare a second `xngin_agent_group` — possibly pointing at the same
agent endpoints — when a vhost needs:

- a different mTLS identity (each group has its own SSL_CTX /
  `ssl_certificate`);
- a separate failure domain (one group's conn pool wedging can't stall
  another's traffic);
- hard verdict-cache and JA4-ban isolation without key-prefixing
  discipline;
- a different agent binary/ruleset entirely (per-tenant WAF vs. shared
  rate-limiter — chain them: `xngin_group tenant-waf; xngin_group
  shared-acl;`).

```nginx
xngin_agent_group tenant-c {
    server 10.0.0.20:9000;
    ssl on;
    ssl_trusted_certificate /etc/xngin/ca.pem;
    ssl_certificate     /etc/xngin/engine-c.pem;   # distinct identity
    ssl_certificate_key /etc/xngin/engine-c.key;
    ssl_server_name agents.internal;
}
```

## Gotchas

- **Inheritance is all-or-nothing per directive.** A location that sets
  one `xngin_var` replaces the parent's whole var list; same for
  `xngin_group` steps and the header include/exclude lists. Repeat the
  shared bits in the child or factor them into an `include` file.
- **`host` is the client's Host header**, not the matched
  `server_name` — a request with `Host: a.example.com` lands on the
  default server if no vhost matches. Use an `xngin_var` token, not the
  wire `host`, when the policy choice must be trustworthy.
- **Slow-agent blast radius is per-group, not per-vhost.** Vhosts
  sharing a group share its conns; a stalled agent affects them all.
  `xngin_timeout`/`xngin_fail` bound the decision-side damage.
- **`xngin_response_group` defaults to the request group** — set it
  when response inspection should run on a different fleet.
- **`vars` in a verdict are marked mutable** and prevent that verdict
  from being cached — per-tenant verdict metadata is free, but such
  verdicts won't skip the wire on repeat traffic.
