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

## Measured (localhost loopback, macOS arm64, nginx 1.31.8, 4 workers)

`test/bench/bench.py` — one nginx port, one lane per feature; content
handler is `empty_gif` so numbers isolate xngin's cost (no upstream
noise). Serial keep-alive prober, 500 reqs/lane after warmup; `ab -k
-c 50 -n 10000` for throughput. Stub agent on UDS (allow-all) and
loopback TCP.

| Lane | p50 | p99 | added vs baseline | ab -c50 rps |
|---|---|---|---|---|
| baseline (no offload) | 33 µs | 70 µs | — | 73 000 |
| blocking, UDS agent | 89 µs | 164 µs | **+54 µs** | 39 800 |
| async (fire-and-forget) | 26 µs | 81 µs | ~0 (noise) | 73 600 |
| verdict cache hit | 27 µs | 78 µs | ~0 (noise) | 75 300 |
| body inspect, 1 KiB POST | 98 µs | 195 µs | +62 µs | 29 500 |
| response inspection | 91 µs | 192 µs | +59 µs | 36 800 |
| deny 403 (no content) | 87 µs | 198 µs | +58 µs | 36 000 |
| blocking, TCP agent | 102 µs | 171 µs | +68 µs | 33 300 |

### Reading the numbers

- **Blocking UDS costs ~54 µs at p50** — one XNAP round-trip plus frame
  encode/decode. Well under the < 1 ms p99 design goal (p99 adds ~94 µs).
- **Async and cache hits are free** — within measurement noise of the
  no-offload baseline; they are the right mode for latency-sensitive
  paths.
- **Body inspection adds ~8 µs** over plain blocking for a 1 KiB body —
  client-body read plus one extra BODY frame round-trip.
- **Response inspection costs about a second round trip** — the staged
  `http-response` exchange adds ~5 µs over blocking on a 43-byte
  response; cost scales with buffered body size.
- **Loopback TCP vs UDS is ~14 µs** — small enough that remote agents
  are viable when UDS isn't.
- **Throughput halves in blocking mode** (73 k → 40 k rps at c=50) —
  every request serializes an agent round-trip over shared conns. Async
  and cache-hit lanes keep full baseline throughput.

### Caveats

- Loopback only; real networks add the agent's actual distance.
- `$xngin_agent_rtt_us` is derived from `ngx_current_msec` (ms
  resolution) and quantizes to whole milliseconds — use the serial
  prober deltas above for µs precision.
- The stub agent answers in < 100 µs; real agents add their own
  compute time on top of the transport deltas shown here.
