"""End-to-end scenario tests: nginx + xngin module + stub agent + backend."""

import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import time

import pytest


ALLOW = {"default": {"action": "allow", "score": 0, "reason": "clean",
                     "vars": {"rule": "default-allow"}},
         "rules": []}


def test_allow(stack):
    s = stack(agents_rules=[ALLOW]).start()
    st, _, body = s.request("/")
    assert st == 200
    assert json.loads(body)["path"] == "/"


def test_deny(stack):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/admin"},
         "verdict": {"action": "deny", "status": 403,
                     "reason": "admin blocked", "score": 90}}]}
    s = stack(agents_rules=[rules]).start()
    st, _, _ = s.request("/")
    assert st == 200
    st, _, body = s.request("/admin/panel")
    assert st == 403
    time.sleep(0.3)
    assert "act=deny" in s.access_log()


def test_deny_custom_body(stack):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/no"},
         "verdict": {"action": "deny", "status": 451,
                     "body": "legal block", "content_type": "text/plain"}}]}
    s = stack(agents_rules=[rules]).start()
    st, hdrs, body = s.request("/no")
    assert st == 451
    assert body == b"legal block"


def test_redirect(stack):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/redir"},
         "verdict": {"action": "redirect",
                     "location": "https://example.com/landing",
                     "status": 302}}]}
    s = stack(agents_rules=[rules]).start()
    st, hdrs, _ = s.request("/redir")
    assert st == 302
    assert hdrs.get("Location") == "https://example.com/landing"


def test_header_mutation(stack):
    rules = {"default": {"action": "allow",
                         "hdr_set": {"x-xngin": "seen"},
                         "hdr_unset": ["x-secret"]},
             "rules": []}
    s = stack(agents_rules=[rules]).start()
    st, _, body = s.request("/", headers={"x-secret": "s3cr3t"})
    assert st == 200
    bh = json.loads(body)["headers"]
    assert bh.get("x-xngin") == "seen"
    assert "x-secret" not in bh


def test_vars_exposed(stack):
    s = stack(agents_rules=[ALLOW]).start()
    s.request("/")
    time.sleep(0.3)
    assert "rule=default-allow" in s.access_log()


def test_async_mode(stack):
    """async: deny verdict must NOT block the request."""
    rules = {"default": {"action": "deny", "status": 403,
                         "reason": "would-block"}, "rules": []}
    s = stack(agents_rules=[rules], loc_extra="xngin_mode async;").start()
    st, _, _ = s.request("/")
    assert st == 200  # request proceeded despite deny verdict


def test_timeout_fail_close(stack):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/"},
         "behavior": {"drop": True},
         "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], timeout="150ms", fail="close").start()
    st, _, _ = s.request("/")
    assert st == 503
    time.sleep(0.3)
    assert "err=timeout" in s.access_log()


def test_timeout_fail_open(stack):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/"},
         "behavior": {"drop": True},
         "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], timeout="150ms", fail="open").start()
    st, _, _ = s.request("/")
    assert st == 200


def test_agent_failover(stack):
    """kill agent0 mid-flight: streams replay on agent1."""
    drop = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/"},
         "behavior": {"drop": True},
         "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[drop, ALLOW], timeout="1s").start()
    s.agents[0].kill()
    time.sleep(0.3)
    st, _, _ = s.request("/")
    assert st == 200


def test_agent_down_fail_close(stack):
    """all agents dead + fail close -> 503."""
    s = stack(agents_rules=[ALLOW], timeout="200ms", fail="close").start()
    s.agents[0].kill()
    time.sleep(0.3)
    st, _, _ = s.request("/")
    assert st == 503


def test_body_inspect(stack):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/post", "body_contains": "evil"},
         "verdict": {"action": "deny", "status": 403,
                     "reason": "evil body"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; xngin_body_max 16k;").start()
    st, _, _ = s.request("/post", method="POST",
                         data=b"this body is evil", headers={
                             "content-type": "text/plain"})
    assert st == 403
    st, _, _ = s.request("/post", method="POST", data=b"harmless",
                         headers={"content-type": "text/plain"})
    assert st == 200


def test_verdict_cache(stack):
    rules = {"default": {"action": "deny", "status": 403,
                         "reason": "cached-deny", "cache_ttl": 60},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_cache_key $binary_remote_addr;",
              main_extra="xngin_cache_zone vcache:1m;").start()
    st, _, _ = s.request("/")
    assert st == 403
    st, _, _ = s.request("/")
    assert st == 403
    time.sleep(0.3)
    st_, _, _ = s.request("/")
    assert "cache=hit" in s.access_log()
    # only the first request reached the agent
    assert s.agents[0].stats()["notifies"] <= 3


def test_cache_deny_replaces_allow(stack):
    """a later verdict for the same key replaces the cached entry —
    the deny must not sit behind a dead allow duplicate."""
    import threading

    # the stub resolves streams in notify order on one conn: the allow
    # lands first (~400ms), the deny — dispatched meanwhile — lands
    # last (~1.2s) and must replace it
    rules = {"default": {"action": "allow"},
             "rules": [
                 {"match": {"header": {"x-med": "1"}},
                  "behavior": {"delay_ms": 400},
                  "verdict": {"action": "allow", "reason": "med-allow",
                              "cache_ttl": 60}},
                 {"match": {"header": {"x-slow": "1"}},
                  "behavior": {"delay_ms": 800},
                  "verdict": {"action": "deny", "status": 403,
                              "reason": "late-deny", "cache_ttl": 60}}]}
    s = stack(agents_rules=[rules], timeout="2s",
              loc_extra="xngin_cache_key $arg_k;",
              main_extra="xngin_cache_zone vcache:1m;").start()

    res = {}
    t1 = threading.Thread(target=lambda: res.__setitem__(
        "a", s.request("/?k=x", headers={"x-med": "1"})))
    t1.start()
    time.sleep(0.15)   # req1's notify precedes req2's on the conn;
                     # req2's lookup runs while req1 is still in flight
    t2 = threading.Thread(target=lambda: res.__setitem__(
        "b", s.request("/?k=x", headers={"x-slow": "1"})))
    t2.start()

    t1.join(timeout=5)
    t2.join(timeout=5)
    assert res["a"][0] == 200   # allow landed first and was cached
    assert res["b"][0] == 403   # deny landed second: replaced the allow

    # the replace was in place — a cache hit now denies, not a dead
    # allow duplicate
    st, _, _ = s.request("/?k=x")
    assert st == 403

    time.sleep(0.3)
    assert "cache=hit" in s.access_log()


def test_cache_crc32_collision(stack):
    """different keys sharing a crc32 must coexist: lookup walks every
    equal-hash node, not just the first on the descent path."""
    import zlib

    # verified: zlib.crc32 == ngx_crc32_long for both
    k1, k2 = "k29685295", "k32060020"
    assert zlib.crc32(k1.encode()) == zlib.crc32(k2.encode()) \
        == 0x3973d855

    rules = {"default": {"action": "allow", "cache_ttl": 60},
             "rules": [
                 {"match": {"uri_contains": k2},
                  "verdict": {"action": "deny", "status": 403,
                              "reason": "k2-blocked", "cache_ttl": 60}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_cache_key $arg_k;",
              main_extra="xngin_cache_zone vcache:1m;").start()

    st, _, _ = s.request(f"/?k={k1}")
    assert st == 200                      # miss -> allow stored
    st, _, _ = s.request(f"/?k={k2}")
    assert st == 403                      # miss -> deny stored beside k1

    # repeats resolve to their own cached verdicts, not each other's
    st, _, _ = s.request(f"/?k={k2}")
    assert st == 403
    st, _, _ = s.request(f"/?k={k1}")
    assert st == 200

    time.sleep(0.3)
    # both repeats were hits — a key hidden behind its crc32 sibling
    # would have fallen through to the agent again
    assert s.access_log().count("cache=hit") == 2


def test_stream_table_churn(stack):
    """600 requests over one keepalive conn: every stream-table slot
    on the single agent conn cycles (> XNAP_STREAM_TABLE_CAP)."""
    import http.client

    s = stack(agents_rules=[ALLOW]).start()
    conn = http.client.HTTPConnection("127.0.0.1", s.listen_port,
                                      timeout=10)
    try:
        for i in range(600):
            conn.request("GET", f"/r{i}")
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200
            assert json.loads(body)["path"] == f"/r{i}"
    finally:
        conn.close()


def test_garbage_agent(stack):
    """agent sends garbage: conn reset, fail close -> 503."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/"},
         "behavior": {"garbage": True},
         "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], timeout="500ms", fail="close").start()
    st, _, _ = s.request("/")
    assert st == 503


def _raw_frame_agent(stack, raw_hex):
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/"},
         "behavior": {"raw_hex": raw_hex},
         "verdict": {"action": "allow"}}]}
    return stack(agents_rules=[rules], timeout="500ms", fail="close").start()


def _assert_frame_rejected(s):
    st, _, _ = s.request("/")
    assert st == 503
    # the worker survived: it still answers (fail close) on a new conn
    st, _, _ = s.request("/")
    assert st == 503
    log = s.error_log()
    assert "exited on signal" not in log
    assert "exited with code" not in log


def test_short_frame_missing_fid(stack):
    """frame-len 6, PING, sid 1, no fid: rejected, no OOB read/overflow."""
    s = _raw_frame_agent(stack, "06080000000001" + "00" * 16)
    _assert_frame_rejected(s)
    assert "bad frame header" in s.error_log()


def test_overlong_sid_varint(stack):
    """sid of 20 continuation bytes: rejected, no unbounded shift."""
    s = _raw_frame_agent(stack, "1a0800000000" + "80" * 20)
    _assert_frame_rejected(s)
    assert "bad frame header" in s.error_log()


def test_tcp_agent(stack):
    """agent over TCP works as well as UDS."""
    s = stack(agents_rules=[ALLOW], tcp_agents=True).start()
    st, _, _ = s.request("/")
    assert st == 200


def _wait_hello(agent):
    for _ in range(30):
        hello = (agent.stats() or {}).get("hello")
        if hello:
            return hello
        time.sleep(0.1)
    return None


def test_tls_inspect(stack):
    """xngin_tls_inspect captures ClientHello: ja4 + ch-raw reach the agent."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_tls_inspect on;").start()
    st, _, _ = s.request("/")
    assert st == 200

    hello = _wait_hello(s.agents[0])
    assert hello, "agent did not see TLS fields"

    assert re.match(r"^[tq][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}"
                    r"_[0-9a-f]{12}_[0-9a-f]{12}$", hello["ja4"])
    assert hello["tls-version"].startswith("TLSv1.")

    assert hello["ch_raw_len"] > 100
    raw = bytes.fromhex(hello["ch_raw_hex"])
    assert raw[0] == 0x01                            # client_hello msg type
    assert int.from_bytes(raw[1:4], "big") == len(raw) - 4
    # legacy_version major is 3
    assert raw[4] == 0x03

    # independent oracle: recompute JA4 from ch-raw, must match engine
    import ja4 as ja4_oracle
    oracle_ja4, oracle_ja4r = ja4_oracle.compute_ja4(raw)
    assert oracle_ja4 == hello["ja4"], \
        f"engine ja4 {hello['ja4']} != oracle {oracle_ja4}"
    assert oracle_ja4r[:10] == hello["ja4"][:10]


def test_tls_deny(stack):
    """xngin_tls_deny aborts the handshake for a matching JA4."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_tls_inspect on;").start()
    s.request("/")
    hello = _wait_hello(s.agents[0])
    assert hello and hello["ja4"]
    ja4 = hello["ja4"]

    s2 = stack(agents_rules=[ALLOW], ssl=True, http_ready=False, sub="deny",
               srv_extra="xngin_tls_inspect on; "
                         f"xngin_tls_deny {ja4};").start()

    with pytest.raises(OSError):
        s2.request("/")

    # handshake died before any HTTP request reached the agent
    assert (s2.agents[0].stats() or {}).get("notifies", 0) == 0


def test_tls_deny_nonmatch(stack):
    """a JA4 denylist that doesn't match still lets the handshake through."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_tls_inspect on; "
                        "xngin_tls_deny "
                        "t13i0000h0_aaaaaaaaaaaa_bbbbbbbbbbbb;").start()
    st, _, _ = s.request("/")
    assert st == 200


# ---- Phase 1: verdict-time request/response mutation ----

def test_req_body_mutation(stack):
    """req-body replaces the body forwarded upstream."""
    rules = {"default": {"action": "allow",
                         "req_body": "REWRITTEN-BY-AGENT"},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; xngin_body_max 16k;").start()
    st, _, body = s.request("/post", method="POST", data=b"original body",
                            headers={"content-type": "text/plain"})
    assert st == 200
    echo = json.loads(body)
    assert echo["body"] == "REWRITTEN-BY-AGENT"
    # Content-Length must match the replacement, not the original
    assert int(echo["headers"]["content-length"]) == len("REWRITTEN-BY-AGENT")


def test_res_hdr_mutation(stack):
    """res-hdr-set / res-hdr-unset apply to the downstream response."""
    rules = {"default": {"action": "allow",
                         "res_hdr_set": {"x-agent-tag": "waf"},
                         "res_hdr_unset": ["x-backend-tag"]},
             "rules": []}
    s = stack(agents_rules=[rules]).start()
    st, hdrs, _ = s.request("/")
    assert st == 200
    assert hdrs.get("x-agent-tag") == "waf"
    assert "x-backend-tag" not in hdrs


def test_res_body_blind(stack):
    """res-body replaces the upstream response body (no inspection)."""
    rules = {"default": {"action": "allow",
                         "res_body": "REPLACED-RESPONSE"},
             "rules": []}
    s = stack(agents_rules=[rules]).start()
    st, _, body = s.request("/")
    assert st == 200
    assert body == b"REPLACED-RESPONSE"


# ---- Phase 2: http-response round-trip ----

RESPOND = "xngin_response on; xngin_res_body_max 64k;"


def _wait_stats(agent, key, timeout=2.0):
    """poll agent stats until *key* is truthy (stats flush is periodic)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = (agent.stats() or {}).get(key)
        if v:
            return v
        time.sleep(0.1)
    return (agent.stats() or {}).get(key)


def test_http_response_inspect(stack):
    """agent sees status/headers/body of the upstream response."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "allow"},
             "rules": [], "res_rules": [
                 {"match": {"body_contains": '"path": "/tag"'},
                  "verdict": {"action": "allow",
                              "res_hdr_set": {"x-filtered": "yes"},
                              "res_body": "masked",
                              "vars": {"res_rule": "pii-redact"}}}]}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    st, hdrs, body = s.request("/tag")
    assert st == 200
    assert hdrs.get("x-filtered") == "yes"
    assert body == b"masked"
    lr = _wait_stats(s.agents[0], "last_response")
    assert lr and lr["status"] == 200 and lr["uri"] == "/tag"
    assert "res=pii-redact" in s.access_log()


def test_response_allow_passthrough(stack):
    """no matching res_rule: buffered response passes through unmodified."""
    s = stack(agents_rules=[ALLOW], loc_extra=RESPOND).start()
    st, _, body = s.request("/")
    assert st == 200
    assert json.loads(body)["path"] == "/"
    assert _wait_stats(s.agents[0], "res_notifies") > 0


def test_response_deny(stack):
    """deny on a response stream discards the held response."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "deny", "status": 418,
                             "body": "no tea", "content_type": "text/plain"},
             "rules": []}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    st, _, body = s.request("/")
    assert st == 418
    assert body == b"no tea"


def test_response_cap_bypass(stack):
    """body over xngin_res_body_max: no round-trip, response untouched."""
    # echo backend returns the request body: a 30KB POST produces a
    # ~30KB response, blowing past res_body_max (1k)
    big = b"x" * 30000
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "deny", "status": 500},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_response on; xngin_res_body_max 1k;"
                        " xngin_body_inspect on; xngin_body_max 128k;"
              ).start()
    before = _wait_stats(s.agents[0], "res_notifies")
    st, _, body = s.request("/", method="POST", data=big,
                            headers={"content-type": "text/plain"})
    assert st == 200                      # not the res deny
    echo = json.loads(body)
    assert echo["body"] == big.decode()   # full body came back uninspected
    time.sleep(0.7)                       # outlive the stats flush interval
    # the oversized response bypassed inspection entirely
    assert s.agents[0].stats().get("res_notifies", 0) == before


def test_response_timeout_fail_close(stack):
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "allow"},
             "rules": [], "res_rules": [
                 {"match": {},
                  "behavior": {"drop": True},
                  "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], timeout="150ms", fail="close",
              loc_extra=RESPOND).start()
    st, _, _ = s.request("/")
    assert st == 503


def test_response_timeout_fail_open(stack):
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "allow"},
             "rules": [], "res_rules": [
                 {"match": {},
                  "behavior": {"drop": True},
                  "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], timeout="150ms", fail="open",
              loc_extra=RESPOND).start()
    st, _, body = s.request("/")
    assert st == 200
    assert json.loads(body)["path"] == "/"


# ---- Phase 3: ja4-fp example agent ----

GO = os.environ.get("XNGIN_GO", "go")


@pytest.fixture(scope="module")
def ja4_bin(tmp_path_factory):
    out = tmp_path_factory.mktemp("bin") / "ja4-fp"
    r = subprocess.run(
        [GO, "build", "-o", str(out), "./cmd/ja4-fp"],
        cwd=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "..", "agents", "go"),
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"ja4-fp build failed: {r.stderr}")
    return str(out)


def test_ja4_agent(stack, ja4_bin):
    """ja4-fp recomputes JA4 from ch-raw; headers + vars reach nginx."""
    s = stack(agents_rules=[ALLOW],
              go_agent=[ja4_bin, "-listen", "{listen}"],
              ssl=True, srv_extra="xngin_tls_inspect on;",
              loc_extra="add_header x-echo-ja4 $xngin_agent_ja4 always;"
              ).start()
    st, hdrs, _ = s.request("/")
    assert st == 200
    ja4 = hdrs.get("x-ja4")
    assert ja4 and ja4 == hdrs.get("x-echo-ja4")
    assert re.match(r"^t[0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}"
                    r"_[0-9a-f]{12}_[0-9a-f]{12}$", ja4)
    assert hdrs.get("x-ja4-raw", "").startswith(ja4[:10])
    time.sleep(0.3)
    log = s.access_log()
    assert f"aja4={ja4}" in log
    assert "jm=1" in log          # agent JA4 == engine JA4
    assert "ja4=" + ja4 in log    # $xngin_ja4 is the same value

    # oracle: capture ch-raw on a stub-backed stack (same python TLS
    # client → same JA4), recompute, must match the agent headers exactly
    s2 = stack(agents_rules=[ALLOW], ssl=True,
               srv_extra="xngin_tls_inspect on;", sub="oracle").start()
    st2, _, _ = s2.request("/")
    assert st2 == 200
    hello = _wait_hello(s2.agents[0])
    assert hello and hello.get("ch_raw_hex")

    import ja4 as ja4_oracle
    o_ja4, o_ja4r = ja4_oracle.compute_ja4(
        bytes.fromhex(hello["ch_raw_hex"]))
    assert o_ja4 == ja4                      # engine == agent == oracle
    assert o_ja4r == hdrs.get("x-ja4-raw")   # raw JA4 fully verified



def test_mtls(stack):
    """engine<->agent over mutual TLS: normal verdict flow."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/admin"},
         "verdict": {"action": "deny", "status": 403,
                     "reason": "admin blocked", "score": 90}}]}
    s = stack(agents_rules=[rules], mtls=True, timeout="1s").start()
    st, _, _ = s.request("/")
    assert st == 200
    st, _, _ = s.request("/admin/x")
    assert st == 403
    # second request proves the TLS conn carries multiple requests
    st, _, _ = s.request("/admin/y")
    assert st == 403


def test_mtls_tcp(stack):
    """mTLS over a TCP listener too."""
    s = stack(agents_rules=[ALLOW], mtls=True, timeout="1s",
              tcp_agents=True).start()
    st, _, _ = s.request("/")
    assert st == 200


def test_mtls_wrong_ca(stack):
    """engine trusts an unrelated CA: agent cert rejected, conn drops,
    fail-close -> 503."""
    s = stack(agents_rules=[ALLOW], mtls=True, wrong_ca=True,
              timeout="500ms", fail="close").start()
    st, _, _ = s.request("/")
    assert st == 503


def test_mtls_no_client_cert(stack):
    """engine presents no client cert but agent requires one:
    handshake fails -> fail-close 503."""
    s = stack(agents_rules=[ALLOW], mtls=True, client_cert=False,
              timeout="500ms", fail="close").start()
    st, _, _ = s.request("/")
    assert st == 503


def test_mtls_plaintext_agent(stack):
    """engine TLS on, agent TLS off: ClientHello is garbage to the
    agent -> conn drops -> fail-close 503."""
    s = stack(agents_rules=[ALLOW], mtls=True, agent_tls=False,
              timeout="500ms", fail="close").start()
    st, _, _ = s.request("/")
    assert st == 503


# ------------------------------------------------------------------ #
# borrowed BODY payloads (zero-copy) + request cleanup                 #
# ------------------------------------------------------------------ #

def _poll_stats(fn, pred, timeout=5.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last is not None and pred(last):
            return last
        time.sleep(0.1)
    return last


def test_body_borrow_conn_close(stack):
    """A stalled agent leaves borrowed BODY pkts queued on the conn;
    the client then closes mid-flight.  Request cleanup must
    materialize them into owned copies so every streamed byte still
    reaches the agent."""
    body = b"A" * (512 * 1024)
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/up"},
         "behavior": {"early": True, "delay_ms": 900},
         "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], tcp_agents=True, timeout="3s",
              loc_extra="xngin_body_inspect on; xngin_body_max 1m;").start()

    sock = socket.create_connection(("127.0.0.1", s.listen_port), 5)
    sock.sendall(b"POST /up HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: application/octet-stream\r\n"
                 b"Content-Length: " + str(len(body)).encode()
                 + b"\r\n\r\n" + body)
    sock.close()   # close while the agent conn queue is backlogged

    st = _poll_stats(s.agents[0].stats,
                     lambda d: d.get("body_bytes", 0) >= len(body))
    assert st is not None and st["body_bytes"] == len(body)
    assert "exited on signal" not in s.error_log()


def test_resp_borrow_conn_close(stack):
    """Held response bytes are pool memory borrowed into BODY frames;
    closing the client while the agent is stalled must not corrupt or
    lose the still-queued response payload."""
    rules = {"res_default": {"action": "allow"}, "res_rules": [
        {"match": {"uri_contains": "/big"},
         "behavior": {"early": True, "delay_ms": 1500},
         "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], tcp_agents=True, timeout="4s",
              loc_extra="xngin_response on; xngin_res_body_max 1m;").start()

    sock = socket.create_connection(("127.0.0.1", s.listen_port), 5)
    sock.sendall(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
    time.sleep(0.5)   # let the backend deliver + frames queue up
    sock.close()

    st = _poll_stats(s.agents[0].stats,
                     lambda d: d.get("body_bytes", 0) >= 512 * 1024,
                     timeout=8)
    # other requests (e.g. fixture warmup) may contribute bytes too
    assert st is not None and st["body_bytes"] >= 512 * 1024
    assert "exited on signal" not in s.error_log()


# ------------------------------------------------------------------ #
# xngin_body_replace off (opt-in: no single-buf capture)               #
# ------------------------------------------------------------------ #

def test_body_replace_off(stack):
    """Without request_body_in_single_buf the filter still streams the
    whole body to the agent (as copies) — body matching keeps working
    and the upstream receives the original body."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"body_contains": "evil"},
         "verdict": {"action": "deny", "status": 403,
                     "body": "denied-body"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; xngin_body_max 1m; "
                        "xngin_body_replace off;").start()

    body = b"Z" * 70000   # > client_body_buffer_size: multi-buf chain
    conn = http.client.HTTPConnection("127.0.0.1", s.listen_port, timeout=5)
    conn.request("POST", "/", body)
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()
    assert resp.status == 200
    assert data["body"] == body.decode()

    conn = http.client.HTTPConnection("127.0.0.1", s.listen_port, timeout=5)
    conn.request("POST", "/", b"prefix-evil-suffix")
    resp = conn.getresponse()
    text = resp.read()
    conn.close()
    assert resp.status == 403
    assert b"denied-body" in text


def test_body_replace_off_contract_violation(stack):
    """xngin_body_replace off is a contract; an agent that breaks it
    still gets its req-body applied (with a logged warning)."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/repl"},
         "verdict": {"action": "allow", "req_body": "FORGED"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; xngin_body_max 1m; "
                        "xngin_body_replace off;").start()

    conn = http.client.HTTPConnection("127.0.0.1", s.listen_port, timeout=5)
    conn.request("POST", "/repl", b"original")
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()
    assert resp.status == 200
    assert data["body"] == "FORGED"
    assert "xngin_body_replace off" in s.error_log()


# ------------------------------------------------------------------ #
# xngin_upload_drain off (opt-in: answer-and-close on early verdicts)  #
# ------------------------------------------------------------------ #

def test_early_deny_close(stack):
    """upload_drain off: a deny verdict while the upload is still in
    flight is sent immediately and the connection is closed instead of
    draining the rest of the body."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/deny"},
         "behavior": {"early": True},
         "verdict": {"action": "deny", "status": 403,
                     "body": "denied-early"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; xngin_body_max 1m; "
                        "xngin_upload_drain off;").start()

    sock = socket.create_connection(("127.0.0.1", s.listen_port), 5)
    sock.settimeout(5)
    # CL under client_max_body_size but far from sent: upload in flight
    sock.sendall(b"POST /deny HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Length: 999999\r\n\r\n" + b"x" * 1000)

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(65536)
        if not chunk:
            break
        resp += chunk
    assert b" 403 " in resp.split(b"\r\n", 1)[0]

    # server must close: recv drains the deny body then hits EOF
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            pytest.fail("connection not closed after early deny")
        if not chunk:
            break
    sock.close()
    assert "exited on signal" not in s.error_log()


def test_upload_drain_default(stack):
    """Default upload_drain on: an early deny verdict is stashed until
    the upload completes, and the keep-alive connection survives."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/deny"},
         "behavior": {"early": True},
         "verdict": {"action": "deny", "status": 403,
                     "body": "denied-drain"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; xngin_body_max 1m;").start()

    body = b"d" * 4096
    sock = socket.create_connection(("127.0.0.1", s.listen_port), 5)
    sock.sendall(b"POST /deny HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Length: " + str(len(body)).encode()
                 + b"\r\n\r\n" + body[:1024])

    # verdict already reached nginx, but the drain must finish first —
    # nothing on the wire yet
    sock.settimeout(0.5)
    try:
        got = sock.recv(65536)
        assert got == b"", "early response despite pending upload"
    except socket.timeout:
        pass

    sock.sendall(body[1024:])
    sock.settimeout(5)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(65536)
        assert chunk != b"", "connection closed before drain verdict"
        resp += chunk
    assert b" 403 " in resp.split(b"\r\n", 1)[0]

    # keep-alive still usable on the same connection
    hdr_end = resp.index(b"\r\n\r\n") + 4
    body_len = int(re.search(
        br"content-length: *(\d+)", resp[:hdr_end], re.I).group(1))
    have = len(resp) - hdr_end
    while have < body_len:
        have += len(sock.recv(65536))

    sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    resp2 = sock.recv(65536)
    assert b" 200 " in resp2.split(b"\r\n", 1)[0]
    sock.close()


# ---- xngin_var / header filtering (NOTIFY enrichment) ----

def test_xngin_var_forward(stack):
    """xngin_var values land in the NOTIFY 'vars' KVL."""
    s = stack(agents_rules=[ALLOW],
              loc_extra="xngin_var tenant $http_x_tenant;"
                        " xngin_var remote $remote_addr;").start()
    st, _, _ = s.request("/", headers={"x-tenant": "acme"})
    assert st == 200
    ln = _wait_stats(s.agents[0], "last_notify")
    assert ln, "no last_notify in stub stats"
    v = dict(ln["vars"])
    assert v.get("tenant") == "acme"
    assert v.get("remote") == "127.0.0.1"


def test_header_exclude(stack):
    """xngin_header_exclude drops named headers from the NOTIFY."""
    s = stack(agents_rules=[ALLOW],
              loc_extra="xngin_header_exclude cookie;"
                        " xngin_header_exclude authorization;").start()
    s.request("/", headers={"cookie": "session=abc",
                            "authorization": "Bearer tok",
                            "x-ok": "1"})
    ln = _wait_stats(s.agents[0], "last_notify")
    hdrs = dict(ln["headers"])
    names = [h[0] for h in ln["headers"]]
    assert "x-ok" in names
    assert "cookie" not in names
    assert "authorization" not in names


def test_header_include(stack):
    """xngin_header_include allowlists the NOTIFY headers."""
    s = stack(agents_rules=[ALLOW],
              loc_extra="xngin_header_include host;"
                        " xngin_header_include x-ok;").start()
    s.request("/", headers={"cookie": "session=abc",
                            "x-ok": "1",
                            "user-agent": "pytest"})
    ln = _wait_stats(s.agents[0], "last_notify")
    names = sorted(h[0] for h in ln["headers"])
    assert names == ["host", "x-ok"]


def test_response_notify_context(stack):
    """http-response NOTIFY carries req-headers + vars (filtered)."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "allow"},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra=RESPOND +
                        " xngin_var tenant $http_x_tenant;"
                        " xngin_header_exclude cookie;").start()
    st, _, _ = s.request("/", headers={"x-tenant": "acme",
                                       "cookie": "session=abc"})
    assert st == 200
    lr = _wait_stats(s.agents[0], "last_response")
    assert lr, "no http-response notify"
    kvs = lr["kvs"]
    req_hdrs = [h[0] for h in kvs["req-headers"]]
    assert "x-tenant" in req_hdrs
    assert "cookie" not in req_hdrs        # exclude applies here too
    assert "set-cookie" not in [h[0] for h in kvs["headers"]]
    assert dict(kvs["vars"]).get("tenant") == "acme"


# ---- operational edges: rich cache, $xngin_agent, status, internal ----

def test_cache_deny_body_replay(stack):
    """cached deny carries its body + extra headers — no round trip."""
    rules = {"default": {"action": "deny", "status": 451,
                         "reason": "branded",
                         "body": "BRANDED-BLOCK",
                         "content_type": "text/plain",
                         "res_hdr_set": {"x-block-ref": "r-1"},
                         "cache_ttl": 60},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_cache_key $binary_remote_addr;",
              main_extra="xngin_cache_zone vcache:1m;").start()
    st, hdrs, body = s.request("/")
    assert st == 451 and body == b"BRANDED-BLOCK"
    assert hdrs.get("x-block-ref") == "r-1"
    time.sleep(0.7)
    n1 = s.agents[0].stats().get("notifies", 0)
    st, hdrs, body = s.request("/")
    assert st == 451 and body == b"BRANDED-BLOCK"
    assert hdrs.get("x-block-ref") == "r-1"
    assert "cache=hit" in s.access_log()
    assert s.agents[0].stats().get("notifies", 0) == n1


def test_xngin_agent_var(stack):
    """$xngin_agent names the conn that served the decision."""
    s = stack(agents_rules=[ALLOW]).start()
    s.request("/")
    time.sleep(0.3)
    log = s.access_log()
    assert "agent=unix:" in log


def test_xngin_status_endpoint(stack):
    """xngin_status location emits pool health + cache counters."""
    blocks = "location = /status { xngin_status; }"
    s = stack(agents_rules=[ALLOW], loc_blocks=blocks,
              main_extra="xngin_cache_zone vcache:1m;").start()
    st, _, body = s.request("/status")
    assert st == 200
    j = json.loads(body)
    g = j["groups"][0]
    assert g["name"] == "waf"
    conns = g["agents"][0]["conns"]
    assert conns and conns[0]["ready"] is True
    assert j["cache"]["enabled"] is True


def test_xngin_internal_off(stack):
    """xngin_internal off: internal redirects skip the agent."""
    blocks = ("error_page 404 = @nf;\n"
              "location = /gone { try_files /none =404; }\n"
              "location @nf { xngin_enable on; xngin_group waf;"
              " xngin_internal off; empty_gif; }")
    s = stack(agents_rules=[ALLOW], loc_blocks=blocks).start()
    time.sleep(0.7)
    n1 = s.agents[0].stats().get("notifies", 0)
    st, _, _ = s.request("/gone")
    assert st == 200
    time.sleep(0.7)
    # /gone has no xngin; @nf declined internally -> agent untouched
    assert s.agents[0].stats().get("notifies", 0) == n1


def test_xngin_internal_default(stack):
    """default (on): the internal-redirected location is consulted."""
    blocks = ("error_page 404 = @nf;\n"
              "location = /gone { try_files /none =404; }\n"
              "location @nf { xngin_enable on; xngin_group waf;"
              " xngin_timeout 300ms; empty_gif; }")
    s = stack(agents_rules=[ALLOW], loc_blocks=blocks).start()
    time.sleep(0.7)
    n1 = s.agents[0].stats().get("notifies", 0)
    st, _, _ = s.request("/gone")
    assert st == 200
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) > n1


# ---- group balancing: backup, hash pick, DNS re-resolution ----

def test_backup_failover(stack):
    """backup servers take traffic only once all primaries are out."""
    rules_b = {"default": {"action": "deny", "status": 403,
                           "reason": "backup"}, "rules": []}
    s = stack(agents_rules=[ALLOW, rules_b],
              server_suffix=["", " backup"]).start()
    st, _, _ = s.request("/")
    assert st == 200
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) >= 1
    assert s.agents[1].stats().get("notifies", 0) == 0

    s.agents[0].kill()

    denied = False
    for _ in range(40):
        st, _, _ = s.request("/")
        if st == 403:
            denied = True
            break
        time.sleep(0.25)
    assert denied, "backup agent never picked up traffic"
    time.sleep(0.7)
    assert s.agents[1].stats().get("notifies", 0) >= 1


def test_balance_hash(stack):
    """balance hash $arg_k: same key -> same agent conn."""
    ra = {"default": {"action": "deny", "status": 418, "reason": "A"},
          "rules": []}
    rb = {"default": {"action": "deny", "status": 419, "reason": "B"},
          "rules": []}
    s = stack(agents_rules=[ra, rb],
              group_extra="balance hash $arg_k;").start()
    st1, _, _ = s.request("/?k=x")
    for _ in range(5):
        st, _, _ = s.request("/?k=x")
        assert st == st1
    assert st1 in (418, 419)


def _dns_reply(q, ip):
    """minimal answer echoing the question section; A queries get an A
    record, anything else (e.g. AAAA) gets an empty NOERROR."""
    import struct
    if len(q) < 12:
        return None
    i = 12
    while i < len(q) and q[i]:
        i += q[i] + 1
    i += 1                      # root label
    qtype = struct.unpack(">H", q[i:i + 2])[0] if i + 2 <= len(q) else 0
    i += 4                      # qtype + qclass
    if i > len(q):
        return None
    hdr = bytearray(q[:12])
    hdr[2] = 0x81
    hdr[3] = 0x80
    hdr[8] = hdr[9] = hdr[10] = hdr[11] = 0
    if qtype == 1:              # A
        hdr[6] = 0
        hdr[7] = 1
        ans = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 1, 4)
               + socket.inet_aton(ip))
        return bytes(hdr) + q[12:i] + ans
    hdr[6] = hdr[7] = 0         # no records for other qtypes
    return bytes(hdr) + q[12:i]


class _DnsStub:
    """one-question DNS responder; answer_ip() decides per query."""

    def __init__(self, answer_ip):
        from stacklib import free_port
        self.answer_ip = answer_ip
        self.port = free_port()
        self.queries = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", self.port))
        import threading
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(512)
            except OSError:
                return
            self.queries += 1
            resp = _dns_reply(data, self.answer_ip())
            if resp:
                self.sock.sendto(resp, peer)


def test_resolve_rediscovery(stack):
    """server ... resolve: unresolvable at config load, then DNS brings
    up the right address after a refresh."""
    state = {"n": 0}

    def answer():
        state["n"] += 1
        # unroutable for the first answers, then the real address —
        # the conn bound to the stale IP must be recycled
        return "10.255.255.1" if state["n"] <= 2 else "127.0.0.1"

    dns = _DnsStub(answer)
    s = stack(agents_rules=[ALLOW], tcp_agents=True,
              server_hosts=["agent.test"],
              server_suffix=[" resolve"],
              group_extra="resolve_interval 5s;",
              main_extra=f"resolver 127.0.0.1:{dns.port} valid=1s;"
              ).start()

    # before the good answer lands the agent is unreachable -> 503
    st, _, _ = s.request("/")
    assert st == 503

    for _ in range(60):
        st, _, _ = s.request("/")
        if st == 200:
            break
        time.sleep(0.5)
    assert st == 200, "agent never came up after DNS change"


# ---- sequential groups ----

DENY403 = {"default": {"action": "deny", "status": 403,
                       "reason": "step1-deny"}, "rules": []}
DENY451 = {"default": {"action": "deny", "status": 451,
                       "reason": "step2-deny"}, "rules": []}
CHAIN2 = "xngin_group auth;\n            xngin_group waf2;"


def test_chain_two_groups(stack):
    """allow at step 1 advances to step 2; step 2's verdict wins."""
    s = stack(agents_rules=[ALLOW, DENY451],
              extra_groups={"auth": [0], "waf2": [1]},
              loc_group=CHAIN2).start()
    st, _, _ = s.request("/")
    assert st == 451
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) >= 1
    assert s.agents[1].stats().get("notifies", 0) >= 1


def test_chain_first_denies(stack):
    """a deny at step 1 short-circuits: step 2 never sees the request."""
    s = stack(agents_rules=[DENY403, ALLOW],
              extra_groups={"auth": [0], "waf2": [1]},
              loc_group=CHAIN2).start()
    st, _, _ = s.request("/")
    assert st == 403
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) >= 1
    assert s.agents[1].stats().get("notifies", 0) == 0


def test_chain_all_allow(stack):
    """all steps allow -> request proceeds."""
    s = stack(agents_rules=[ALLOW, ALLOW],
              extra_groups={"auth": [0], "waf2": [1]},
              loc_group=CHAIN2).start()
    st, _, _ = s.request("/")
    assert st == 200
    time.sleep(0.7)
    assert s.agents[1].stats().get("notifies", 0) >= 1


def test_chain_step_fail_open(stack):
    """fail=open on a dead step skips to the next step."""
    s = stack(agents_rules=[ALLOW],
              extra_groups={"dead": ["unix:/tmp/xngin-dead-ng.sock"],
                            "waf2": [0]},
              loc_group="xngin_group dead fail=open timeout=100ms;\n"
                        "            xngin_group waf2;").start()
    st, _, _ = s.request("/")
    assert st == 200
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) >= 1


def test_chain_step_fail_close(stack):
    """fail=close on a dead step 503s before reaching step 2."""
    s = stack(agents_rules=[ALLOW, ALLOW],
              extra_groups={"dead": ["unix:/tmp/xngin-dead-ng.sock"],
                            "waf2": [1]},
              loc_group="xngin_group dead fail=close timeout=100ms;\n"
                        "            xngin_group waf2;").start()
    st, _, _ = s.request("/")
    assert st == 503
    time.sleep(0.7)
    assert s.agents[1].stats().get("notifies", 0) == 0


def test_chain_step_timeout(stack):
    """per-step timeout: slow step 1 fails open, step 2 still serves —
    and the late step-1 verdict is ignored (stale stream)."""
    slow = {"default": {"action": "deny", "status": 403},
            "rules": [{"match": {"header": {"x-any": "1"}},
                       "behavior": {"delay_ms": 900},
                       "verdict": {"action": "deny", "status": 403}}]}
    s = stack(agents_rules=[slow, ALLOW],
              extra_groups={"auth": [0], "waf2": [1]},
              loc_group="xngin_group auth fail=open timeout=50ms;\n"
                        "            xngin_group waf2 timeout=500ms;"
              ).start()
    st, _, _ = s.request("/", headers={"x-any": "1"})
    # step 1 times out at 50ms -> fail open -> step 2 allows (200);
    # the deny verdict landing ~900ms later must not corrupt state
    assert st == 200
    time.sleep(1.0)
    st, _, _ = s.request("/", headers={"x-any": "1"})
    assert st == 200


# ---- Phase 5: CONTROL push ops (ban-ip / ban-ja4 / cache-drop) ----

def test_control_caps(stack):
    """ENGINE_HELLO advertises CAP_PUSH so agents may send CONTROL."""
    s = stack(agents_rules=[ALLOW]).start()
    s.request("/")
    time.sleep(0.6)
    eh = (s.agents[0].stats() or {}).get("engine_hello") or {}
    assert eh.get("capabilities", 0) & 0x10


def test_control_ban_ip(stack):
    """ban-ip pushed by the agent denies the client in POST_READ."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/ban"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "ban-ip", "ip": "127.0.0.1",
                                  "ttl": 60}}}]}
    s = stack(agents_rules=[rules]).start()
    assert s.request("/")[0] == 200
    assert s.request("/ban")[0] == 200
    time.sleep(0.3)
    assert s.request("/")[0] == 403


def test_control_ban_ip_zone(stack):
    """bans survive in the shared xngin_ban_zone."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/ban"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "ban-ip", "ip": "127.0.0.1",
                                  "ttl": 60}}}]}
    s = stack(agents_rules=[rules],
              main_extra="xngin_ban_zone bans:1m;").start()
    assert s.request("/ban")[0] == 200
    time.sleep(0.3)
    assert s.request("/")[0] == 403


def test_control_ban_ip_ttl(stack):
    """ban entries expire after their ttl."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/ban"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "ban-ip", "ip": "127.0.0.1",
                                  "ttl": 2}}}]}
    s = stack(agents_rules=[rules]).start()
    assert s.request("/ban")[0] == 200
    time.sleep(0.3)
    assert s.request("/")[0] == 403
    time.sleep(2.6)
    assert s.request("/")[0] == 200


def test_control_ban_ja4(stack):
    """ban-ja4 aborts the next ClientHello carrying that JA4."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/banja4"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "ban-ja4", "ja4": "$hello",
                                  "ttl": 60}}}]}
    s = stack(agents_rules=[rules], ssl=True,
              srv_extra="xngin_tls_inspect on;").start()
    assert s.request("/")[0] == 200
    hello = _wait_hello(s.agents[0])
    assert hello and hello["ja4"]
    assert s.request("/banja4")[0] == 200
    time.sleep(0.3)
    with pytest.raises(OSError):
        s.request("/")


def _tls_request(s, sni, path="/", host=None):
    """HTTPS GET with an explicit SNI name (None sends none at all);
    Host defaults to the SNI so request routing matches."""
    ctx = ssl._create_unverified_context()
    sock = socket.create_connection(("127.0.0.1", s.listen_port), 5)
    conn = ctx.wrap_socket(sock, server_hostname=sni)
    try:
        conn.sendall(f"GET {path} HTTP/1.1\r\n"
                     f"Host: {host or sni or '127.0.0.1'}\r\n"
                     "Connection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        conn.close()
    return int(data.split(b" ", 2)[1]), data


def _vhost_b(default_inspect):
    """second server{} on the same listen: b.example, group gB; takes
    default_server + tls_inspect when *default_inspect*."""
    def blocks(s):
        return f"""
    server {{
        listen {s.listen_port} ssl{" default_server" if default_inspect else ""};
        server_name b.example;
        ssl_certificate {s.cert};
        ssl_certificate_key {s.key};
        {"xngin_tls_inspect on;" if default_inspect else ""}
        location / {{
            xngin_enable on;
            xngin_group gB;
            proxy_pass http://backend;
        }}
    }}"""
    return blocks


def test_control_ban_ja4_sni_scoped(stack):
    """a ban-ja4 binds only the server whose locations use the pushing
    group — other vhosts on the same listen keep completing their
    handshakes; no SNI follows the default server."""
    # JA4's d/i flag differs between SNI and no-SNI hellos, so both
    # variants are pushed separately: /banja4-sni over an SNI conn,
    # /banja4-nosni over a no-SNI conn whose Host header still routes
    # to a.example (and therefore to group gA)
    rules_a = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/banja4"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "ban-ja4", "ja4": "$hello",
                                  "ttl": 60}}}]}
    extra = {"gA": [0], "gB": [1]}

    # default server a.example uses gA; vhost b.example uses gB
    sa = stack(agents_rules=[rules_a, ALLOW], ssl=True, sub="sni-a",
               extra_groups=extra, loc_group="xngin_group gA;",
               srv_extra="server_name a.example;\n"
                         "        xngin_tls_inspect on;",
               server_blocks=_vhost_b(False)).start()

    assert _tls_request(sa, "a.example", "/banja4-sni")[0] == 200
    assert _tls_request(sa, None, "/banja4-nosni",
                        host="a.example")[0] == 200
    time.sleep(0.3)

    with pytest.raises(OSError):                 # SNI=a -> gA ban
        _tls_request(sa, "a.example")
    with pytest.raises(OSError):                 # no SNI -> default a
        _tls_request(sa, None)
    assert _tls_request(sa, "b.example")[0] == 200   # gB untouched

    # default server b.example uses gB; vhost a.example uses gA
    sb = stack(agents_rules=[rules_a, ALLOW], ssl=True, sub="sni-b",
               extra_groups=extra, loc_group="xngin_group gA;",
               srv_extra="server_name a.example;",
               server_blocks=_vhost_b(True)).start()

    assert _tls_request(sb, "a.example", "/banja4-sni")[0] == 200
    assert _tls_request(sb, None, "/banja4-nosni",
                        host="a.example")[0] == 200
    time.sleep(0.3)

    with pytest.raises(OSError):                 # SNI=a -> gA ban
        _tls_request(sb, "a.example")
    assert _tls_request(sb, "b.example")[0] == 200   # gB untouched
    # default b is out of the ban's group scope — even though a ban
    # for this client's no-SNI JA4 exists (bound to gA)
    assert _tls_request(sb, None)[0] == 200


def test_control_cache_drop(stack):
    """cache-drop evicts a cached verdict so the next request re-decides."""
    rules = {"default": {"action": "allow", "cache_ttl": 60}, "rules": [
        {"match": {"uri_contains": "/drop"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "cache-drop",
                                  "key": "/cache-me"}}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_cache_key $uri;",
              main_extra="xngin_cache_zone vcache:1m;").start()
    s.request("/cache-me")
    s.request("/cache-me")            # replayed from cache
    time.sleep(0.6)
    n0 = (s.agents[0].stats() or {}).get("notifies", 0)
    s.request("/drop")                # pushes cache-drop "/cache-me"
    time.sleep(0.3)
    s.request("/cache-me")            # back to the agent
    s.request("/cache-me")            # cached again
    time.sleep(0.6)
    n1 = (s.agents[0].stats() or {}).get("notifies", 0)
    assert n1 - n0 == 2               # drop + re-decide, then hit


def test_control_unknown_op(stack):
    """an unknown CONTROL op is logged and ignored, not fatal."""
    rules = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/x"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "bogus-op", "ttl": 1}}}]}
    s = stack(agents_rules=[rules]).start()
    assert s.request("/x")[0] == 200
    time.sleep(0.3)
    assert s.request("/")[0] == 200


# ---- Phase 4: decompression, local responses, streamed replacement ----

def test_resp_gzip_inspect(stack):
    """gzip wire body: agent inspects the inflated plaintext."""
    import gzip as _gz
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "deny", "status": 500},
             "rules": [], "res_rules": [
                 {"match": {"body_contains": '"path": "/gzip"'},
                  "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    st, hdrs, body = s.request("/gzip")
    assert st == 200                       # agent matched on plaintext
    hdrs = {k.lower(): v for k, v in hdrs.items()}
    assert hdrs.get("content-encoding") == "gzip"
    assert json.loads(_gz.decompress(body))["path"] == "/gzip"
    time.sleep(0.6)
    ln = (s.agents[0].stats() or {}).get("last_body") or ""
    assert '"path": "/gzip"' in ln         # BODY frames were inflated


def test_resp_brotli_inspect(stack):
    """brotli wire body: agent inspects the inflated plaintext."""
    import brotli as _br
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "deny", "status": 500},
             "rules": [], "res_rules": [
                 {"match": {"body_contains": '"path": "/br"'},
                  "verdict": {"action": "allow"}}]}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    st, hdrs, body = s.request("/br")
    assert st == 200
    hdrs = {k.lower(): v for k, v in hdrs.items()}
    assert hdrs.get("content-encoding") == "br"
    assert json.loads(_br.decompress(body))["path"] == "/br"


def test_resp_local_inspect(stack):
    """nginx-generated (local) responses reach the agent too."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "deny", "status": 451,
                             "body": "local blocked",
                             "content_type": "text/plain"},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra=RESPOND, loc_blocks='''
        location /gif {
            empty_gif;
            xngin_enable on;
            xngin_group waf;
            xngin_response on;
            xngin_res_body_max 64k;
        }
''').start()
    st, _, body = s.request("/gif")        # local empty_gif response
    assert st == 451                       # denied by res_default
    assert body == b"local blocked"


def test_resp_own_deny_not_inspected(stack):
    """the module's own deny page must not trigger response inspection."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "allow"},
             "rules": [
                 {"match": {"uri_contains": "/no"},
                  "verdict": {"action": "deny", "status": 403}}]}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    s.request("/")                         # upstream resp → inspected
    time.sleep(0.6)
    n0 = (s.agents[0].stats() or {}).get("res_notifies", 0)
    st, _, _ = s.request("/no")
    assert st == 403
    time.sleep(0.6)
    n1 = (s.agents[0].stats() or {}).get("res_notifies", 0)
    assert n1 == n0                        # deny page not re-inspected


def test_streamed_res_replace(stack):
    """body-stream verdict + BODY frames replace the response body."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "allow", "body_stream": True},
             "rules": [], "res_rules": [
                 {"match": {"body_contains": '"path": "/"'},
                  "verdict": {"action": "allow", "body_stream": True},
                  "behavior": {"stream_body": "STREAMED-REPLACEMENT"}}]}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    st, _, body = s.request("/")
    assert st == 200
    assert body == b"STREAMED-REPLACEMENT"


def test_streamed_req_replace(stack):
    """body-stream verdict + BODY frames replace the request body."""
    rules = {"default": {"action": "allow", "body_stream": True},
             "rules": [
                 {"match": {"uri_contains": "/p"},
                  "verdict": {"action": "allow", "body_stream": True},
                  "behavior": {"stream_body": "REPLACED-REQ-BODY"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on; "
                        "xngin_body_replace on;").start()
    st, _, body = s.request("/p", method="POST", data=b"original",
                            headers={"content-type": "text/plain"})
    assert st == 200
    assert json.loads(body)["body"] == "REPLACED-REQ-BODY"


# ---- review-fix regressions ----

def test_control_ban_ip_scoped(stack):
    """a ban pushed by group A does not deny locations using group B."""
    rules_a = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/ban"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "ban-ip", "ip": "127.0.0.1",
                                  "ttl": 60}}}]}
    s = stack(agents_rules=[rules_a, ALLOW],
              extra_groups={"gA": [0], "gB": [1]},
              loc_group="xngin_group gA;",
              loc_blocks='''
        location /other {
            xngin_enable on;
            xngin_group gB;
            proxy_pass http://backend;
        }''').start()
    assert s.request("/other")[0] == 200
    assert s.request("/ban")[0] == 200    # gA pushes the ban
    time.sleep(0.3)
    assert s.request("/")[0] == 403       # / uses gA -> banned
    assert s.request("/other")[0] == 200  # /other uses gB -> not banned


def test_control_cache_drop_scoped(stack):
    """cache-drop only evicts entries the pushing group itself stored."""
    rules_a = {"default": {"action": "allow"}, "rules": [
        {"match": {"uri_contains": "/drop"},
         "verdict": {"action": "allow"},
         "behavior": {"control": {"op": "cache-drop",
                                  "key": "/cb"}}}]}
    rules_b = {"default": {"action": "allow", "cache_ttl": 60},
               "rules": []}
    s = stack(agents_rules=[rules_a, rules_b],
              extra_groups={"gA": [0], "gB": [1]},
              loc_group="xngin_group gA;",
              main_extra="xngin_cache_zone vcache:1m;",
              loc_blocks='''
        location /cb {
            xngin_enable on;
            xngin_group gB;
            xngin_cache_key $uri;
            proxy_pass http://backend;
        }''').start()
    s.request("/cb")                     # stored under group gB
    s.request("/cb")                     # replayed from cache
    time.sleep(0.7)
    n0 = s.agents[1].stats().get("notifies", 0)
    s.request("/drop")                   # gA pushes cache-drop "/cb"
    time.sleep(0.3)
    s.request("/cb")                     # entry survives: no re-decide
    time.sleep(0.7)
    assert s.agents[1].stats().get("notifies", 0) == n0


def test_cache_group_scoped(stack):
    """the verdict-cache node identity is (group, key): two groups with
    equal-length names and the same xngin_cache_key neither see nor
    overwrite each other's entries, and cache-drop removes only the
    pushing group's node."""
    rules_a = {"default": {"action": "deny", "status": 403,
                           "reason": "ga-deny", "cache_ttl": 60},
               "rules": [
                   {"match": {"uri_contains": "/drop"},
                    "verdict": {"action": "allow"},
                    "behavior": {"control": {"op": "cache-drop",
                                             "key": "x"}}}]}
    rules_b = {"default": {"action": "allow", "cache_ttl": 60},
               "rules": []}
    s = stack(agents_rules=[rules_a, rules_b],
              extra_groups={"gA": [0], "gB": [1]},
              loc_group="xngin_group gA;",
              loc_extra="xngin_cache_key $arg_k;",
              main_extra="xngin_cache_zone vcache:1m;",
              loc_blocks='''
        location /b {
            xngin_enable on;
            xngin_group gB;
            xngin_cache_key $arg_k;
            proxy_pass http://backend;
        }
        location /drop {
            xngin_enable on;
            xngin_group gA;
            proxy_pass http://backend;
        }''').start()

    assert s.request("/?k=x")[0] == 403       # gA stores a deny
    assert s.request("/b?k=x")[0] == 200      # gB: gA's deny is invisible
    assert s.request("/?k=x")[0] == 403       # gB's allow did not replace it
    time.sleep(0.7)
    n_a = s.agents[0].stats().get("notifies", 0)
    n_b = s.agents[1].stats().get("notifies", 0)

    assert s.request("/?k=x")[0] == 403       # replayed from gA's entry
    assert s.request("/b?k=x")[0] == 200      # replayed from gB's entry
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) == n_a
    assert s.agents[1].stats().get("notifies", 0) == n_b

    s.request("/drop")                        # gA pushes cache-drop "x"
    time.sleep(0.7)
    n_a2 = s.agents[0].stats().get("notifies", 0)  # /drop counted too

    assert s.request("/b?k=x")[0] == 200      # gB's entry survives
    time.sleep(0.7)
    assert s.agents[1].stats().get("notifies", 0) == n_b

    assert s.request("/?k=x")[0] == 403       # gA's node gone: re-decide
    time.sleep(0.7)
    assert s.agents[0].stats().get("notifies", 0) == n_a2 + 1


def test_control_before_hello_ignored(stack):
    """CONTROL frames sent before AGENT_HELLO are ignored."""
    rules = {"default": {"action": "allow"}, "rules": [],
             "control_before_hello": [
                 {"op": "ban-ip", "ip": "127.0.0.1", "ttl": 60}]}
    s = stack(agents_rules=[rules]).start()
    assert s.request("/")[0] == 200      # ban never installed


def test_chain_cache_ttl_does_not_skip_step(stack):
    """a later step's cache-ttl must not replay over the chain:
    multi-step locations bypass the location verdict cache."""
    rules2 = {"default": {"action": "allow", "cache_ttl": 60},
              "rules": []}
    s = stack(agents_rules=[ALLOW, rules2],
              extra_groups={"auth": [0], "waf2": [1]},
              loc_group=CHAIN2,
              loc_extra="xngin_cache_key $uri;",
              main_extra="xngin_cache_zone vcache:1m;").start()
    assert s.request("/c")[0] == 200
    time.sleep(0.7)
    n0 = s.agents[0].stats().get("notifies", 0)
    assert s.request("/c")[0] == 200
    time.sleep(0.7)
    # step 1 was consulted again — no location-wide allow replay
    assert s.agents[0].stats().get("notifies", 0) == n0 + 1


def test_cache_deny_keepalive(stack):
    """cached deny on a keep-alive POST drains the body so the next
    request on the connection still parses."""
    rules = {"default": {"action": "deny", "status": 403, "body": "no",
                        "content_type": "text/plain", "cache_ttl": 60},
             "rules": []}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_cache_key $binary_remote_addr;",
              main_extra="xngin_cache_zone vcache:1m;").start()
    assert s.request("/")[0] == 403      # caches the deny
    conn = http.client.HTTPConnection("127.0.0.1", s.listen_port,
                                      timeout=5)
    for body in (b"x=1", b"x=2", b"x=3"):
        conn.request("POST", "/", body=body,
                     headers={"content-type":
                              "application/x-www-form-urlencoded"})
        r = conn.getresponse()
        data = r.read()
        assert r.status == 403
        assert data == b"no"
    conn.close()


def test_streamed_req_replace_true(stack):
    """body-stream encoded as VT_TRUE (not UINT) opens the stream."""
    rules = {"default": {"action": "allow"},
             "rules": [
                 {"match": {"uri_contains": "/p"},
                  "verdict": {"action": "allow", "body_stream": "true"},
                  "behavior": {"stream_body": "TRUE-REPL"}}]}
    s = stack(agents_rules=[rules],
              loc_extra="xngin_body_inspect on;").start()
    st, _, body = s.request("/p", method="POST", data=b"orig",
                            headers={"content-type": "text/plain"})
    assert st == 200
    assert json.loads(body)["body"] == "TRUE-REPL"


def test_resp_gzip_over_cap_bypasses(stack):
    """decoded body over res_body_max passes the original compressed
    response through instead of failing closed."""
    rules = {"default": {"action": "allow"},
             "res_default": {"action": "deny", "status": 500},
             "rules": []}
    s = stack(agents_rules=[rules], loc_extra=RESPOND).start()
    st, hdrs, body = s.request("/gzip-big")
    assert st == 200                     # bypass, not 503
    hdrs = {k.lower(): v for k, v in hdrs.items()}
    assert hdrs.get("content-encoding") == "gzip"
    import gzip as _gz
    assert _gz.decompress(body) == b"P" * (200 * 1024)


# ---- HTTP/2 connection fingerprint (Akamai format) ----

import h2fp as h2

H2_SETTINGS = [(h2.S_TABLE, 8192), (h2.S_STREAMS, 100),
               (h2.S_WINDOW, 6291456), (h2.S_FRAME, 16384),
               (h2.S_PUSH, 0)]
H2_WINDOW = 15663105
H2_PRIOS = [(5, True, 0, 200), (3, False, 0, 150)]
H2_ORDER = "p,s,a,m"                     # exercise order tracking


def _h2_request(s, use_ssl, settings=H2_SETTINGS, window=H2_WINDOW,
                prios=H2_PRIOS, order=H2_ORDER):
    scheme = "https" if use_ssl else "http"
    sock = h2.connect("127.0.0.1", s.listen_port, use_ssl=use_ssl)
    try:
        h2.h2_handshake(sock, settings, window, prios,
                        order=order, scheme=scheme,
                        authority="127.0.0.1")
    finally:
        sock.close()


def _last_notify(agent, timeout=2.0):
    """poll agent stats until a notify has landed."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        n = (agent.stats() or {}).get("last_notify")
        if n:
            return n
        time.sleep(0.1)
    return (agent.stats() or {}).get("last_notify") or {}


def test_h2fp_tls(stack):
    """Akamai h2 fingerprint over TLS matches the frames we sent."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_h2_inspect on; http2 on;").start()
    _h2_request(s, use_ssl=True)
    n = _last_notify(s.agents[0])
    want = h2.akamai_fp(H2_SETTINGS, H2_WINDOW, H2_PRIOS, H2_ORDER)
    assert n.get("h2-fp") == want


def test_h2fp_cleartext(stack):
    """h2c prior-knowledge conns get fingerprinted via the listen tee."""
    s = stack(agents_rules=[ALLOW],
              srv_extra="xngin_h2_inspect on; http2 on;").start()
    _h2_request(s, use_ssl=False)
    n = _last_notify(s.agents[0])
    want = h2.akamai_fp(H2_SETTINGS, H2_WINDOW, H2_PRIOS, H2_ORDER)
    assert n.get("h2-fp") == want


def test_h2fp_http1_none(stack):
    """an http/1.1 request on an h2-enabled server carries no h2-fp."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_h2_inspect on; http2 on;").start()
    st, _, _ = s.request("/")            # http.client -> h1
    assert st == 200
    n = _last_notify(s.agents[0])
    assert n and "h2-fp" not in n


def test_h2fp_without_tls_inspect(stack):
    """xngin_h2_inspect alone emits h2-fp but no ja4/ch-raw."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_h2_inspect on; http2 on;").start()
    _h2_request(s, use_ssl=True)
    n = _last_notify(s.agents[0])
    assert n.get("h2-fp")
    assert "ja4" not in n and "ch-raw" not in n


def test_tls_inspect_without_h2(stack):
    """xngin_tls_inspect alone emits ja4 but no h2-fp on an h2 conn."""
    s = stack(agents_rules=[ALLOW], ssl=True,
              srv_extra="xngin_tls_inspect on; http2 on;").start()
    _h2_request(s, use_ssl=True)
    n = _last_notify(s.agents[0])
    assert n.get("ja4")
    assert "h2-fp" not in n


def test_h3fp_quic(stack):
    """QUIC listener: h3 stream tee yields h3-fp; the hello carries a
    q-prefixed JA4 plus the raw transport params."""
    s = stack(agents_rules=[ALLOW], ssl=True, quic=True,
              srv_extra="xngin_tls_inspect on; xngin_h2_inspect on;"
              ).start()

    rc = subprocess.run(
        ["curl", "--http3-only", "-k", "-s", "-o", "/dev/null",
         "-w", "%{http_code}",
         f"https://127.0.0.1:{s.listen_port}/"],
        capture_output=True, text=True, timeout=15)
    assert rc.stdout == "200", f"curl h3 failed: {rc.stderr}"

    hello = _wait_hello(s.agents[0])
    assert hello, "agent saw no hello fields"

    # JA4 transport char is 'q' on QUIC
    assert hello["ja4"].startswith("q"), hello["ja4"]

    # transport params: raw ext + ordered id list
    assert hello["quic-tp"]
    assert re.match(r"^[0-9]+(,[0-9]+)*$", hello["quic-tps"])

    # h3-fp: settings|order — nghttp3 sends >=1 setting and pseudo
    # headers for a GET
    fp = hello["h3-fp"]
    assert fp, "no h3-fp captured"
    settings, _, order = fp.rpartition("|")
    assert re.match(r"^[0-9]+:[0-9]+(,[0-9]+:[0-9]+)*$", settings), fp
    assert re.match(r"^[msap](,[msap])*$", order), fp
    assert not hello["h2-fp"]


def test_h3fp_big_headers_and_reuse(stack):
    """A first HEADERS frame larger than the per-stream fp buffer still
    yields the pseudo-header order (buffered prefix), and later
    requests on the same QUIC conn — whose streams skip the tee —
    still carry the session's h3-fp."""
    s = stack(agents_rules=[ALLOW], ssl=True, quic=True,
              srv_extra="xngin_h2_inspect on;"
                        " large_client_header_buffers 4 16k;").start()

    url = f"https://127.0.0.1:{s.listen_port}/"
    rc = subprocess.run(
        ["curl", "--http3-only", "-k", "-s", "-o", "/dev/null",
         "-o", "/dev/null", "-w", "%{http_code}\n",
         "-H", "X-Big: " + "z" * 6000, url, url],
        capture_output=True, text=True, timeout=15)
    assert rc.stdout.split() == ["200", "200"], \
        f"curl h3 failed: {rc.stdout!r} {rc.stderr}"

    deadline = time.time() + 5
    while time.time() < deadline \
            and (s.agents[0].stats() or {}).get("notifies", 0) < 2:
        time.sleep(0.1)
    st = s.agents[0].stats() or {}
    assert st.get("notifies", 0) >= 2

    # stats.hello tracks the latest notify: request 2's stream
    fp = (st.get("hello") or {}).get("h3-fp")
    assert fp, "second request lost h3-fp"
    settings, _, order = fp.rpartition("|")
    assert settings, fp
    assert sorted(order.split(",")) == ["a", "m", "p", "s"], fp
