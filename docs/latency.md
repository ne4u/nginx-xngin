# Latency analysis

The SPOE-style model adds one IPC round-trip to the request path in
blocking mode. Design goal: < 1 ms added p99 for a co-located agent.

## Where the latency comes from

| Component | Cost | Mitigation |
|---|---|---|
| connect(2)/accept | high (~ms) | none on hot path: persistent pre-warmed conns from worker init |
| TLS handshake | would dominate | amortized: persistent pre-warmed conns mean the handshake happens once per conn lifetime. Optional `ssl on` (SPEC §1.1) gives mTLS for compliance; steady state is just the record layer (~22B/frame) |
| frame write + read | ~2 µs UDS (`sys` on the C echo lane) | one frame out, one frame back; small binary frames, no headers/JSON |
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

## Not building

A shared-memory ring (memfd + SPMC) for co-located agents was measured
and dropped. On the C echo lane the whole blocking round trip is ~5µs:
~2µs inside send/recv, under 1µs encoding, and ~4µs of wakeup and
propagation. A ring would still need a wakeup (eventfd or kqueue), so
it would not remove that residue. Only a poll-mode transport could,
and that spends a core at idle. Agent time dominates every slower
lane (Go ~12µs, Python stub ~50µs).

Still unbuilt, and separate from that decision: a UDP fire-and-forget
telemetry channel for high-rate async reporting.

## Measured

Headline numbers from `test/bench/bench.py` (full tables, methodology
and run-to-run consistency in `docs/benchmarks.md`):

- **Engine floor (C echo): ~5µs round trip, ~0µs vs baseline p50.**
  End-to-end throughput matches the no-offload baseline. Well under
  the < 1 ms p99 goal.
- **Blocking Go agent: ~+12µs p50** over baseline. Go mTLS adds ~6µs
  on top of Go plaintext; the engine-side record layer is ~2µs of that.
- **Python stub: ~+50µs p50.** That is the stub, not the codec.
- **Async mode and verdict-cache hits: free** — indistinguishable from
  the no-offload baseline.
- **Body inspection** adds a few microseconds at 1 KiB and ~140µs at
  64 KiB over the stub blocking lane; encode stays ~1–3µs.
