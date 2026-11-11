# Security Policy

xngin sits inline on production traffic — request bodies, TLS
ClientHellos, and allow/deny decisions. We take that seriously.

## Reporting a vulnerability

**Do not open a public issue.** Use one of:

- GitHub → Security → "Report a vulnerability" (private advisory)
- Email: the maintainer address listed on the GitHub profile

Include: affected version/commit, reproduction or traffic capture,
and whether the issue is in the module, an SDK, or the protocol.

We aim to acknowledge within 48 hours and will coordinate disclosure
with you. Fixes land on `main` and are tagged before publication.

## Scope

- `module/` C code — memory safety, filter/lifecycle bugs, TLS capture
- XNAP codec parsing in all three implementations (Go/Rust/Python harness)
- Fail-open/close semantics, verdict cache correctness
- Denial of service via malformed frames or oversized bodies

Out of scope: the example agents (edge-guard, mini-waf, ja4-fp) are
demonstrations, not hardened production WAFs.

## Supported versions

| Version         | Supported |
|-----------------|-----------|
| main            | yes       |
| tagged releases | latest only until 1.0 |
