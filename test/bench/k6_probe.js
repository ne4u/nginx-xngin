// xngin max-RPS probe: drives a fixed concurrency at the lane URL.
// bench.py doubles --vus between probes until the achieved request
// rate plateaus — the plateau is the lane's closed-loop throughput
// ceiling (the same model `ab -c N` measures, pushed past N=50).
//
// NOTE: __ENV is not usable inside `export const options` (k6 v2
// silently ignores the options object when it references init-env),
// so --vus/--duration come in on the k6 command line instead.
//
// Env: K6_URL (required), K6_METHOD (GET), K6_WANT (expected status,
// 200), K6_BODY_LEN (request body size, empty = no body).

import http from 'k6/http';

const WANT = parseInt(__ENV.K6_WANT || '200');
const METHOD = __ENV.K6_METHOD || 'GET';
const BODY = __ENV.K6_BODY_LEN
  ? 'x'.repeat(parseInt(__ENV.K6_BODY_LEN, 10))
  : null;

const params = {
  headers: { 'Content-Type': 'application/octet-stream' },
  responseCallback: http.expectedStatuses(WANT),
  responseType: 'none',
  timeout: '10s',
};

export default function () {
  http.request(METHOD, __ENV.K6_URL, METHOD === 'GET' ? null : BODY,
               params);
}
