"""End-to-end scenario tests: nginx + xngin module + stub agent + backend."""

import http.client
import json
import os
import re
import socket
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
