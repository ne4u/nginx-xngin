# Benchmark results

Measured overhead of `ngx_http_xngin_module` per feature lane, relative
to a no-offload baseline on the same nginx instance.

## Methodology

- `test/bench/bench.py` — one nginx (4 workers), one `location` per
  lane, single agent group. Content handler is `empty_gif` (in-process,
  C-speed) so numbers isolate xngin's cost — no upstream noise.
- **Serial latency**: single keep-alive connection, 50 warmup + 500
  timed requests per lane.
- **Throughput**: `ab -k -c 50 -n 10000` per lane.
- **Agent RTT**: `$xngin_agent_rtt_us` parsed from the access log —
  derived from `ngx_current_msec` so it quantizes to whole ms; serial
  deltas are the authoritative µs numbers.
- Stub agent (`allow-all`, `res_default allow`) on a Unix socket; a
  second agent on loopback TCP for the transport-comparison lane.
- Environment: localhost loopback, macOS arm64, nginx 1.31.8,
  `xngin_timeout 200ms`, `xngin_fail close`.

## Results — two consecutive runs (consistency check)

| Lane | run A p50 | run B p50 | Δ | run A p99 | run B p99 | run A rps | run B rps | Δ |
|---|---|---|---|---|---|---|---|---|
| baseline (no offload) | 33µs | 33µs | −2% | 70µs | 65µs | 73,050 | 81,272 | +11% |
| blocking, UDS | 89µs | 90µs | +1% | 164µs | 146µs | 39,782 | 38,439 | −3% |
| async (fire-and-forget) | 26µs | 26µs | −1% | 81µs | 73µs | 73,615 | 75,302 | +2% |
| verdict cache hit | 27µs | 25µs | −7% | 78µs | 83µs | 75,282 | 74,695 | −1% |
| body inspect, 1KiB POST | 98µs | 94µs | −3% | 195µs | 183µs | 29,484 | 29,219 | −1% |
| response inspection | 91µs | 91µs | +1% | 192µs | 162µs | 36,798 | 37,353 | +2% |
| deny 403 (no content) | 87µs | 91µs | +5% | 198µs | 198µs | 35,995 | 34,483 | −4% |
| blocking, TCP agent | 102µs | 100µs | −2% | 171µs | 196µs | 33,256 | 33,875 | +2% |

Zero unexpected-status responses in either run. p50 run-to-run variance
≤7%, throughput variance ≤11% — the numbers are repeatable.

## Added latency vs baseline (mean serial)

| Lane | run A | run B | verdict |
|---|---|---|---|
| blocking, UDS | +54µs | +56µs | one XNAP round-trip ≈ 55µs |
| async | −5µs | −5µs | free (noise) |
| cache hit | −2µs | −6µs | free (noise) |
| body inspect, 1KiB | +62µs | +61µs | +~7µs over blocking |
| response inspection | +59µs | +60µs | +~5µs over blocking |
| deny 403 | +58µs | +58µs | ≈ blocking (no content work) |
| blocking, TCP | +68µs | +66µs | +~12µs over UDS |

## Takeaways

- **Blocking UDS offload costs ~55µs at p50, ~+90µs at p99** — far
  under the <1ms p99 design goal in `docs/latency.md`.
- **Async mode and verdict-cache hits are free** — indistinguishable
  from the no-offload baseline. Use them on latency-critical paths.
- **Body inspection adds ~7µs** for a 1KiB body (client-body read +
  BODY frame round-trip); cost scales with body size.
- **Response inspection adds ~5µs** — the staged `http-response`
  exchange is cheap on small bodies; scales with buffered bytes.
- **Loopback TCP is ~12µs slower than UDS** — remote agents are viable
  when UDS isn't an option.
- **Throughput halves in blocking mode** (≈73k → ≈39k rps at c=50):
  every request serializes a round-trip over shared agent conns. Async
  and cache-hit lanes retain full baseline throughput.

## Caveats

- Loopback only — a remote agent adds real network RTT on top.
- The stub agent answers in <100µs; real agents add their own compute.
- `empty_gif` baseline measures protocol/filter overhead, not the
  proxying path; upstream costs are additive in production.

## Reproduce

```sh
export XNGIN_NGINX_BIN=/path/to/nginx
export XNGIN_MODULE_SO=/path/to/objs/ngx_http_xngin_module.so
python3 test/bench/bench.py                 # 300 serial / 5000 ab
python3 test/bench/bench.py --serial-n 500 --ab-n 10000   # this run
```

Results JSON is written under `/tmp/xngin-bench-*/bench.json`.
