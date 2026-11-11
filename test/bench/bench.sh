#!/usr/bin/env bash
# Latency bench: baseline nginx vs xngin blocking vs async vs cache-hit.
#
# Usage: bench.sh [url-base] [duration]
# Requires: wrk (brew install wrk) or vegeta.
#
# Measures *added* latency by comparing proxy_pass-only responses
# (location /baseline) against offload-enabled locations.

set -euo pipefail
BASE="${1:-http://127.0.0.1:8080}"
DUR="${2:-10s}"

bench() {
    local name="$1" path="$2"
    if command -v wrk >/dev/null; then
        echo "== $name =="
        wrk -t2 -c50 -d"$DUR" --latency "$BASE$path" 2>&1 | \
            grep -E "Latency|Requests/sec"
    else
        echo "wrk not installed; run: brew install wrk" >&2
        exit 1
    fi
}

echo "baseline (proxy only, no offload):"
bench baseline /baseline/

echo "xngin blocking (UDS, local agent):"
bench blocking /

echo "xngin async (fire-and-forget):"
bench async /monitor/

echo "xngin blocking with cache-hit (repeat client):"
bench cache-hit /
