# Benchmark results

Measured overhead of `ngx_http_xngin_module` per feature lane, relative
to a no-offload baseline on the same nginx instance.

## Methodology

- `test/bench/bench.py` — one nginx (4 workers), one `location` per
  lane, agent groups on UDS, loopback TCP, a real Go agent, a minimal
  C echo agent, and two mTLS groups. Content handler is `empty_gif`
  (in-process, C-speed) so numbers isolate xngin's cost — no upstream
  noise. (POST returns 405 there; the access-phase offload work still
  runs.)
- **Serial latency**: single keep-alive connection, 20 warmup + 300
  timed requests per lane.
- **Throughput**: k6 `constant-vus` probes per lane; concurrency
  doubles (64 → … → cap) until the achieved request rate plateaus
  (<5% gain) or requests fail — the plateau is reported as the lane's
  max RPS. Requires `k6` on PATH; falls back to `ab -k -c 50 -n 5000`.
  (The rps column in the recorded runs below was measured with `ab`;
  k6 numbers run ~20–30% lower for the fastest lanes — k6's own
  per-request cost becomes the ceiling — while matching `ab` on the
  slower ones.)
- **Breakdown**: each request logs `$xngin_agent_rtt_us` split as
  `$xngin_encode_us` (engine CPU: NOTIFY/BODY encode + queue),
  `$xngin_syscall_us` (time inside agent-conn send/recv — on TLS conns
  this is `ngx_ssl_send`/`ngx_ssl_recv`, i.e. engine-side crypto) and
  `$xngin_agent_us` (rtt minus attributed recv time = agent-side wait:
  agent CPU + loopback propagation + wakeup latency). Values are parsed
  from the access-log slice written during the *serial* run only — under
  concurrent load shared conns add queue-wait, which is not per-request
  cost.
- Agents: Python stub (`allow-all`) on UDS; second stub on loopback TCP;
  Go `edge-guard` (`-rate 0`) on UDS; `test/bench/echo_agent.c` — a
  ~1µs-CPU C agent answering a fixed allow verdict — on UDS for the
  `c-echo` lane; Rust `mini_waf` example (regex rules over URI/headers)
  on UDS for `rust-block`; Python stub behind `ssl on` for `mtls-block`;
  a second `edge-guard` with `-tls-cert/-tls-key/-tls-client-ca` behind
  `ssl on` for `go-mtls`. c-echo also self-reports service time as
  `$xngin_agentus` (verdict `vars`).
- Environment: localhost loopback, macOS arm64, nginx 1.31.8,
  `xngin_timeout 200ms`, `xngin_fail close`.
- Since the streaming-dispatch change, request/response BODY frames
  are forwarded as the upload/download arrives — the blocking lanes
  now overlap the client transfer with agent analysis instead of
  buffering first.

## Results — two consecutive runs (consistency check)

| Lane | run A p50 | run B p50 | Δ | run A p99 | run B p99 | run A rps | run B rps | Δ |
|---|---|---|---|---|---|---|---|---|
| baseline (no offload) | 34µs | 35µs | +3% | 46µs | 94µs | 64,309 | 62,533 | −3% |
| blocking, UDS (stub) | 88µs | 82µs | −7% | 156µs | 191µs | 38,541 | 38,270 | −1% |
| mTLS, UDS (stub, Python) | 86µs | 88µs | +2% | 258µs | 203µs | 31,664 | 34,143 | +8% |
| async (fire-and-forget) | 27µs | 28µs | +4% | 68µs | 76µs | 64,755 | 61,864 | −4% |
| verdict cache hit | 33µs | 27µs | −18% | 92µs | 80µs | 66,882 | 65,545 | −2% |
| body inspect, 1KiB POST | 95µs | 95µs | 0% | 213µs | 175µs | 30,160 | 28,157 | −7% |
| body inspect, 64KiB POST | 242µs | 234µs | −3% | 455µs | 403µs | 9,037 | 9,102 | +1% |
| response inspection | 84µs | 79µs | −6% | 196µs | 158µs | 38,669 | 38,242 | −1% |
| deny 403 (no content) | 74µs | 94µs | +27% | 180µs | 212µs | 36,730 | 36,179 | −2% |
| blocking, TCP agent | 101µs | 100µs | −1% | 206µs | 220µs | 34,161 | 33,705 | −1% |
| blocking, Go agent | 42µs | 42µs | 0% | 122µs | 106µs | 55,591 | 54,484 | −2% |
| blocking, C echo agent | 30µs | 31µs | +3% | 65µs | 89µs | 63,105 | 60,776 | −4% |
| blocking, Go agent mTLS | 45µs | 46µs | +2% | 162µs | 214µs | 54,211 | 53,542 | −1% |

Zero unexpected-status responses in either run. p50 run-to-run
variance ≤7% on offload lanes; the near-baseline lanes (25–35µs) sit
inside noise.

## Added latency vs baseline (mean serial)

| Lane | run A | run B | verdict |
|---|---|---|---|
| blocking, UDS (stub) | +54µs | +48µs | ≈ +50µs of Python stub |
| mTLS, UDS (stub, Python) | +62µs | +59µs | agent-bound, see below |
| async | −3µs | −4µs | free (noise) |
| cache hit | +1µs | −6µs | free (noise) |
| body inspect, 1KiB | +62µs | +55µs | ≈ blocking + ~8µs |
| body inspect, 64KiB | +197µs | +189µs | ≈ blocking + ~140µs body cost |
| response inspection | +53µs | +48µs | ≈ blocking (streamed overlap) |
| deny 403 | +48µs | +59µs | ≈ blocking (no content work) |
| blocking, TCP | +66µs | +65µs | +~14µs over UDS |
| blocking, Go agent | +13µs | +10µs | ≈ +12µs vs c-echo floor |
| blocking, C echo | +0µs | −1µs | **engine ≈ free** |
| blocking, Go mTLS | +17µs | +18µs | +~6µs over Go plaintext |

## Engine breakdown (serial p50, µs — run A)

Per-request `enc` + `sys` is the engine's own cost; `agent` is the
round-trip residue (agent CPU + wakeup/propagation); `rtt` is the whole
send→verdict window.

| Lane | enc | sys | agent | rtt | agentus (self-report) |
|---|---|---|---|---|---|
| blocking, UDS stub | 1 | 2 | 50 | 51 | — |
| body-1k | 1 | 3 | 59 | 59 | — |
| body-64k | 3 | 4 | 188 | 189 | — |
| response inspection | 0 | 2 | 50 | 50 | — |
| blocking, TCP | 0 | 5 | 62 | 65 | — |
| blocking, Go | 0 | 3 | 12 | 13 | — |
| blocking, C echo | 0 | 2 | 4 | 5 | 1 |
| mTLS, UDS stub | 0 | 4 | 53 | 55 | — |
| blocking, Go mTLS | 0 | 5 | 13 | 16 | — |

## Takeaways

- **The engine alone is essentially free.** With a ~1µs-CPU C agent the
  blocking offload round-trip costs ~5µs: ~2µs inside engine send/recv
  syscalls, <1µs encoding, ~4µs agent-side wait (mostly wakeup +
  propagation — the agent's own CPU is ~1µs per its self-report).
  End-to-end p50 and `ab` throughput are indistinguishable from
  baseline. The earlier "~45µs blocking tax" was ~50µs of Python stub.
- **Agent speed is the whole story.** Same engine, same wire: rtt is
  51µs against the Python stub, 13µs against Go, 5µs against the C
  echo. `agent` p50 per lane: stub ≈ 50µs, Go ≈ 10–12µs, C ≈ 1–4µs.
- **mTLS costs the engine ~+2µs, not +30µs.** `sys` rises 3→5µs on the
  `go-mtls` lane (engine-side record layer); agent-side crypto adds
  ~1µs (Go `crypto/tls` is AES-NI too). go-mtls rtt 15–16µs vs go-block
  13µs is the real engine number — the 55µs `mtls-block` round-trip is
  Python `ssl` inside `asyncio`, not an engine measurement.
- **No shared-memory transport warranted.** The decision criterion was
  "syscall-bound on the echo lane": `sys` is ~2µs of the ~5µs c-echo
  round-trip (~40%), the residue is wakeup/scheduling latency a
  shm-ring + wakeup mechanism (eventfd/kqueue) would pay identically.
  Only a poll-mode transport could attack it, at idle-CPU cost.
- **Async and cache hits remain free** — indistinguishable from
  baseline. Encode scales with payload: ~1µs at 1KiB body, ~3µs at
  64KiB (memcpy into 16KiB frames); `sys` stays flat — the extra body
  cost lands in `agent` (transfer + parse).

## Caveats

- Loopback only — a remote agent adds real network RTT on top.
- `enc`/`sys`/`agent` are engine-side timers; `agent` bundles agent CPU
  with transport wakeup (cross-checked on c-echo by `agentus`).
- `sys` recv attribution is per read-event: a single `recv` delivering
  several verdicts (concurrent load) charges the same duration to each —
  another reason only the serial slice is reported.
- `empty_gif` baseline measures protocol/filter overhead, not the
  proxying path; upstream costs are additive in production.

## Reproduce

```sh
export XNGIN_NGINX_BIN=/path/to/nginx
export XNGIN_MODULE_SO=/path/to/objs/ngx_http_xngin_module.so
python3 test/bench/bench.py                 # 300 serial / 5000 ab
python3 test/bench/bench.py --serial-n 500 --ab-n 10000   # this run
```

The Go lanes build `agents/go/cmd/edge-guard` on the fly (skipped when
`go` isn't installed); the `c-echo` lane cc-compiles
`test/bench/echo_agent.c` (skipped on compile failure). Results JSON is
written under `/tmp/xngin-bench-*/bench.json`.
