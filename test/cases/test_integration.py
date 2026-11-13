"""End-to-end scenario tests: nginx + xngin module + stub agent + backend."""

import json
import os
import re
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
