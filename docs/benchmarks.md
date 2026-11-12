# Benchmark results

Measured overhead of `ngx_http_xngin_module` per feature lane, relative
to a no-offload baseline on the same nginx instance.

## Methodology

- `test/bench/bench.py` — one nginx (4 workers), one `location` per
  lane, agent groups on UDS, loopback TCP and a real Go agent.
  Content handler is `empty_gif` (in-process, C-speed) so numbers
  isolate xngin's cost — no upstream noise. (POST returns 405 there;
  the access-phase offload work still runs.)
- **Serial latency**: single keep-alive connection, 50 warmup + 500
  timed requests per lane.
- **Throughput**: `ab -k -c 50 -n 10000` per lane.
- **Agent RTT**: `$xngin_agent_rtt_us` parsed from the access log —
  genuine microseconds (`gettimeofday`); values blend the serial and
  `ab` runs, so serial p50/p99 remain the authoritative per-request
  latency.
- Stub agent (`allow-all`, `res_default allow`) on a Unix socket; a
  second stub on loopback TCP; the Go `edge-guard` example agent
  (`-rate 0`, allow-all) on a third UDS for the real-agent lane.
- Environment: localhost loopback, macOS arm64, nginx 1.31.8,
  `xngin_timeout 200ms`, `xngin_fail close`.
- Since the streaming-dispatch change, request/response BODY frames
  are forwarded as the upload/download arrives — the blocking lanes
  now overlap the client transfer with agent analysis instead of
  buffering first.

## Results — two consecutive runs (consistency check)

| Lane | run A p50 | run B p50 | Δ | run A p99 | run B p99 | run A rps | run B rps | Δ |
|---|---|---|---|---|---|---|---|---|
| baseline (no offload) | 33µs | 33µs | 0% | 60µs | 64µs | 78,465 | 77,698 | −1% |
| blocking, UDS (stub) | 88µs | 89µs | +1% | 163µs | 167µs | 41,351 | 38,828 | −6% |
| async (fire-and-forget) | 27µs | 34µs | +26% | 78µs | 75µs | 77,347 | 76,685 | −1% |
| verdict cache hit | 26µs | 30µs | +15% | 53µs | 65µs | 78,703 | 77,804 | −1% |
| body inspect, 1KiB POST | 95µs | 90µs | −5% | 167µs | 161µs | 29,216 | 28,570 | −2% |
| body inspect, 64KiB POST | 239µs | 240µs | 0% | 435µs | 461µs | 9,306 | 9,126 | −2% |
| response inspection | 93µs | 80µs | −14% | 173µs | 161µs | 37,627 | 38,321 | +2% |
| deny 403 (no content) | 91µs | 88µs | −3% | 148µs | 159µs | 34,372 | 37,251 | +8% |
| blocking, TCP agent | 101µs | 100µs | −1% | 199µs | 203µs | 33,385 | 34,094 | +2% |
| blocking, Go agent | 42µs | 42µs | 0% | 100µs | 116µs | 66,146 | 64,823 | −2% |

Zero unexpected-status responses in either run. p50 run-to-run
variance ≤26% on the near-baseline lanes (noise at 25–35µs), ≤5% on
all offload lanes; throughput variance ≤6%.

## Added latency vs baseline (mean serial)

| Lane | run A | run B | verdict |
|---|---|---|---|
| blocking, UDS (stub) | +55µs | +54µs | one XNAP round-trip ≈ 55µs vs stub |
| async | −2µs | 0µs | free (noise) |
| cache hit | −5µs | −2µs | free (noise) |
| body inspect, 1KiB | +61µs | +57µs | +~5µs over blocking |
| body inspect, 64KiB | +204µs | +203µs | streaming: ~3.2µs/KiB over blocking |
| response inspection | +60µs | +48µs | ≈ blocking (streamed overlap) |
| deny 403 | +59µs | +53µs | ≈ blocking (no content work) |
| blocking, TCP | +70µs | +68µs | +~14µs over UDS |
| blocking, Go agent | +15µs | +13µs | real wire cost: ~14µs/round-trip |

## Takeaways

- **Blocking UDS offload costs ~55µs p50 against the Python stub** —
  but ~40µs of that is the stub itself. Against the Go `edge-guard`
  agent the same round-trip costs **~14µs p50** (66k rps ≈ 85% of
  baseline): protocol overhead is genuinely tiny; agent speed decides.
- **Async mode and verdict-cache hits are free** — indistinguishable
  from the no-offload baseline. Use them on latency-critical paths.
- **Body inspection scales ~3µs/KiB** — 1KiB ≈ +5µs over blocking,
  64KiB ≈ +150µs over blocking. Streaming dispatch (frames forwarded
  as the client uploads) means the agent's analysis overlaps the
  transfer rather than starting after it.
- **Response inspection ≈ blocking on small bodies** — the
  `http-response` NOTIFY goes out at header time and body frames
  stream during the download, so the second round-trip is largely
  hidden behind the response transfer.
- **Loopback TCP is ~14µs slower than UDS** — remote agents are viable
  when UDS isn't an option.
- **Throughput halves in blocking mode vs the stub** (≈77k → ≈40k rps
  at c=50): every request serializes a round-trip over shared agent
  conns. With the Go agent it holds ≈65k rps — agent concurrency is
  the throughput ceiling, not the wire.

## Caveats

- Loopback only — a remote agent adds real network RTT on top.
- The stub agent (Python asyncio) has ~40µs floor of its own; the
  `go-block` lane is the honest measure of wire/protocol cost.
- `empty_gif` baseline measures protocol/filter overhead, not the
  proxying path; upstream costs are additive in production.
- `$xngin_agent_rtt_us` blends serial and concurrent samples; under
  `ab -c 50` it reflects queue wait on shared conns, not per-request
  cost.

## Reproduce

```sh
export XNGIN_NGINX_BIN=/path/to/nginx
export XNGIN_MODULE_SO=/path/to/objs/ngx_http_xngin_module.so
python3 test/bench/bench.py                 # 300 serial / 5000 ab
python3 test/bench/bench.py --serial-n 500 --ab-n 10000   # this run
```

The Go lane builds `agents/go/cmd/edge-guard` on the fly and is skipped
when `go` isn't installed. Results JSON is written under
`/tmp/xngin-bench-*/bench.json`.
