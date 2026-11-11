# Latency analysis

The SPOE-style model adds one IPC round-trip to the request path in
blocking mode. Design goal: < 1 ms added p99 for a co-located agent.

## Where the latency comes from

| Component | Cost | Mitigation |
|---|---|---|
| connect(2)/accept | high (~ms) | none on hot path: persistent pre-warmed conns from worker init |
| TLS handshake | would dominate | not used; UDS for local, plain TCP remote (TLS is an ops-layer concern — stunnel/mTLS sidecar if needed) |
| frame write + read | ~50-150 µs UDS | one frame out, one frame back; small binary frames, no headers/JSON |
| serialization | low | zero-copy mostly: headers encoded straight into one wbuf |
| queuing under load | bounded | max-streams per conn, keepalive N conns per agent |
| agent compute | app-dependent | keep handlers nonblocking; SDKs run handler per stream |

## Why custom binary (XNAP) instead of HTTP/2+gRPC

- h2 server inside nginx module = large dep (h2 codec, HPACK, protobuf);
  XNAP codec is ~400 lines C with zero deps.
- h2 SETTINGS/HEADERS machinery adds bytes + state per request; XNAP is
  ~30-60 bytes overhead per request.
- Same multiplexing benefit as h2 with a fraction of the complexity.

## Why one multiplexed conn (not conn-per-request or a big pool)

- conn-per-request: full connect+handshake cost on the critical path —
  defeats the purpose.
- Multiplexed: streams are independent, replies matched by stream-id,
  frames may interleave. HoL blocking is bounded by small frames and the
  `keepalive N` escape hatch.
- nginx workers are single-threaded: no locks, no atomics on the hot path.

## Removing latency entirely

- **Async mode** (`xngin_mode async`): NOTIFY goes out, request proceeds;
  verdict is logged (score/reason/vars). Detection mode for rollouts.
- **Verdict cache** (`xngin_cache_key` + zone + agent `cache-ttl`): repeat
  keys never hit the wire — the biggest real-world win for rate-limit /
  reputation agents (deny verdicts are the ones worth caching).
- **Speculative early verdict**: an agent MAY reply before `BODY LAST`,
  so headers-only decisions return on the first frame.

## Failure latency

- `xngin_timeout` (default 50 ms) bounds worst-case blocking delay.
- Conn failure mid-flight replays the stream on another conn once —
  one extra dispatch, not a new connect.
- Missed pongs (2 × `ping_interval`) mark a conn down and reconnect.

## Future (documented, not built)

- Shared-memory ring transport for co-located agents (memfd + SPMC ring)
  would cut the syscall round-trip entirely — ~10-20 µs decisions.
- UDP/fire-and-forget telemetry channel for high-rate async reporting.
