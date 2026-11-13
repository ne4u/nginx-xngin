#!/usr/bin/env python3
"""Scriptable XNAP stub agent for integration tests.

Usage:
    stub_agent.py --listen unix:/tmp/xngin.sock \
                  --rules rules.json [--stats stats.json]

Rules JSON format:
{
  "default": {"action": "allow"},
  "rules": [
    {
      "match": {"uri_contains": "/admin", "header": {"x-bad": "1"},
                "method": "POST", "src_ip": "1.2.3.4"},
      "verdict": {"action": "deny", "status": 403, "reason": "blocked",
                  "body": "no", "content_type": "text/plain",
                  "location": "https://x/", "hdr_set": {"k": "v"},
                  "hdr_unset": ["h"], "vars": {"k": "v"},
                  "cache_ttl": 30, "score": 42},
      "behavior": {"delay_ms": 100, "drop": false, "abort": false,
                   "garbage": false, "raw_hex": "0608000000..."}
    }
  ]
}

Special behaviors: delay_ms, drop (never answer), abort (ABORT frame),
garbage (send malformed bytes instead of a frame), raw_hex (send these
exact bytes instead of a verdict).

Stats file is refreshed every 0.5s: {"notifies": N, "verdicts": N, ...}
"""

import argparse
import asyncio
import ipaddress
import json
import os
import sys

import xnap


class Stats:
    def __init__(self):
        self.notifies = 0
        self.res_notifies = 0
        self.verdicts = 0
        self.bodies = 0
        self.pings = 0
        self.conns = 0
        self.aborts = 0
        self.hello = None
        self.last_response = None


stats = Stats()


def load_rules(path):
    if not path:
        return {"default": {"action": "allow"}, "rules": []}
    with open(path) as f:
        return json.load(f)


def match_rule(rule, kvs, headers):
    m = rule.get("match", {})
    d = dict(kvs)
    if "uri_contains" in m and m["uri_contains"] not in d.get("uri", ""):
        return False
    if "method" in m and m["method"] != d.get("method", ""):
        return False
    if "src_ip" in m:
        sip = d.get("src-ip")
        if str(sip) != m["src_ip"]:
            return False
    if "header" in m:
        for hk, hv in m["header"].items():
            vals = headers.get(hk.lower(), [])
            if hv not in vals:
                return False
    # body_contains is evaluated in decide() once BODY frames have arrived
    return True


def build_verdict(v):
    payload = bytearray()
    payload += xnap.enc_kv("action", v.get("action", "allow"))
    if "status" in v:
        payload += xnap.enc_kv("status", xnap.Raw(
            xnap.VT_INT32, xnap.enc_svarint(v["status"])))
    if "body" in v:
        payload += xnap.enc_kv("body", v["body"])
    if "content_type" in v:
        payload += xnap.enc_kv("content-type", v["content_type"])
    if "location" in v:
        payload += xnap.enc_kv("location", v["location"])
    if "hdr_set" in v:
        payload += xnap.enc_kv("hdr-set",
                               [(k, vv) for k, vv in v["hdr_set"].items()])
    if "hdr_unset" in v:
        payload += xnap.enc_kv("hdr-unset", xnap.StrList(v["hdr_unset"]))
    if "req_body" in v:
        payload += xnap.enc_kv("req-body", v["req_body"])
    if "res_hdr_set" in v:
        payload += xnap.enc_kv("res-hdr-set",
                               [(k, vv) for k, vv in v["res_hdr_set"].items()])
    if "res_hdr_unset" in v:
        payload += xnap.enc_kv("res-hdr-unset",
                               xnap.StrList(v["res_hdr_unset"]))
    if "res_body" in v:
        payload += xnap.enc_kv("res-body", v["res_body"])
    if "vars" in v:
        payload += xnap.enc_kv("vars",
                               [(k, vv) for k, vv in v["vars"].items()])
    if "cache_ttl" in v:
        payload += xnap.enc_kv("cache-ttl", xnap.Raw(
            xnap.VT_UINT32, xnap.enc_varint(v["cache_ttl"])))
    if "reason" in v:
        payload += xnap.enc_kv("reason", v["reason"])
    if "score" in v:
        payload += xnap.enc_kv("score", xnap.Raw(
            xnap.VT_INT32, xnap.enc_svarint(v["score"])))
    return bytes(payload)


class Conn:
    def __init__(self, rules):
        self.rules = rules
        self.buf = b""
        self.streams = {}   # sid -> {kvs, headers, bodies, msg}
        self.next_fid = {}

    async def run(self, reader, writer):
        stats.conns += 1
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                self.buf += data
                frames, self.buf = xnap.feed(self.buf)
                for fr in frames:
                    out = await self.handle(fr)
                    if out is not None:
                        writer.write(out)
                        await writer.drain()
                    if fr.type == xnap.FT_DISCON:
                        writer.close()
                        return
        except (xnap.ProtoError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def handle(self, fr):
        if fr.type == xnap.FT_ENGINE_HELLO:
            p = bytearray()
            p += xnap.enc_kv("version", xnap.Raw(
                xnap.VT_UINT32, xnap.enc_varint(xnap.VERSION)))
            p += xnap.enc_kv("max-frame-size", xnap.Raw(
                xnap.VT_UINT32, xnap.enc_varint(16384)))
            p += xnap.enc_kv("max-streams", xnap.Raw(
                xnap.VT_UINT32, xnap.enc_varint(256)))
            p += xnap.enc_kv("capabilities", xnap.Raw(
                xnap.VT_UINT32,
                xnap.enc_varint(xnap.CAP_BODY | xnap.CAP_ASYNC
                                | xnap.CAP_VCACHE | xnap.CAP_RESP)))
            p += xnap.enc_kv("agent-id", "xnap-stub/1")
            return xnap.enc_frame(xnap.FT_AGENT_HELLO, 0, 0, 0, bytes(p))

        if fr.type == xnap.FT_PING:
            stats.pings += 1
            return xnap.enc_frame(xnap.FT_PONG, 0, fr.sid, fr.fid, fr.payload)

        if fr.type == xnap.FT_ABORT:
            stats.aborts += 1
            self.streams.pop(fr.sid, None)
            return None

        if fr.type == xnap.FT_BODY:
            st = self.streams.get(fr.sid)
            if st is not None:
                st["bodies"].append(fr.payload)
                stats.bodies += 1
                if fr.flags & xnap.FL_BODY_LAST:
                    v = await self.decide(fr.sid)
                    if v is not None:
                        return v
            return None

        if fr.type == xnap.FT_NOTIFY:
            stats.notifies += 1
            try:
                msg, kvs = fr.notify_msg()
            except Exception:
                print("BAD NOTIFY payload:", fr.payload.hex(), flush=True)
                raise
            headers = xnap.headers_dict(kvs)
            kd = dict(kvs)
            if "ja4" in kd or "ch-raw" in kd:
                ch_raw = kd.get("ch-raw") or b""
                stats.hello = {
                    "ja4": kd.get("ja4"),
                    "sni": kd.get("sni"),
                    "tls-version": kd.get("tls-version"),
                    "alpn": kd.get("alpn"),
                    "ch_raw_len": len(ch_raw),
                    "ch_raw_hex": ch_raw.hex(),
                }
            if msg == "http-response":
                stats.res_notifies += 1
                stats.last_response = {
                    "status": kd.get("status"),
                    "uri": kd.get("uri"),
                    "headers": headers,
                    "request-id": kd.get("request-id"),
                }
            self.streams[fr.sid] = {
                "msg": msg, "kvs": kvs, "headers": headers,
                "bodies": [], "async": bool(fr.flags & xnap.FL_NOTIFY_ASYNC),
            }
            if fr.flags & xnap.FL_NOTIFY_HAS_BODY:
                return None   # wait for BODY LAST
            return await self.decide(fr.sid)

        if fr.type == xnap.FT_DISCON:
            return None

        return None

    async def decide(self, sid):
        st = self.streams.pop(sid, None)
        if st is None:
            return None

        if st["msg"] == "http-response":
            return await self.decide_res(sid, st)

        kvs, headers = st["kvs"], st["headers"]
        rule = None
        for r in self.rules.get("rules", []):
            if match_rule(r, kvs, headers):
                bc = r.get("match", {}).get("body_contains")
                if bc:
                    body = b"".join(st["bodies"])
                    if bc.encode() not in body:
                        continue
                rule = r
                break

        verdict = (rule or {}).get("verdict") or self.rules.get(
            "default", {"action": "allow"})
        behavior = (rule or {}).get("behavior", {})

        if behavior.get("drop"):
            return None
        if behavior.get("abort"):
            stats.verdicts += 1
            return xnap.enc_frame(xnap.FT_ABORT, 0, sid, 0, b"")
        if behavior.get("garbage"):
            stats.verdicts += 1
            return b"\xff\xff\xff\xff garbage-not-a-frame"
        if behavior.get("raw_hex"):
            stats.verdicts += 1
            return bytes.fromhex(behavior["raw_hex"])
        if behavior.get("delay_ms"):
            await asyncio.sleep(behavior["delay_ms"] / 1000)

        stats.verdicts += 1
        payload = build_verdict(verdict)
        return xnap.enc_frame(xnap.FT_VERDICT, xnap.FL_FIN, sid, 0,
                              payload)

    async def decide_res(self, sid, st):
        """Verdict for an http-response stream: rules under "res_rules",
        fallback "res_default"."""
        kvs, headers = st["kvs"], st["headers"]
        body = b"".join(st["bodies"])
        kd = dict(kvs)

        rule = None
        for r in self.rules.get("res_rules", []):
            m = r.get("match", {})
            if "status" in m and m["status"] != kd.get("status"):
                continue
            if "uri_contains" in m \
                    and m["uri_contains"] not in kd.get("uri", ""):
                continue
            if "res_header" in m:
                miss = False
                for hk, hv in m["res_header"].items():
                    if hv not in headers.get(hk.lower(), []):
                        miss = True
                if miss:
                    continue
            if "body_contains" in m \
                    and m["body_contains"].encode() not in body:
                continue
            rule = r
            break

        verdict = (rule or {}).get("verdict") or self.rules.get(
            "res_default", {"action": "allow"})
        behavior = (rule or {}).get("behavior", {})

        if behavior.get("drop"):
            return None
        if behavior.get("delay_ms"):
            await asyncio.sleep(behavior["delay_ms"] / 1000)

        stats.verdicts += 1
        payload = build_verdict(verdict)
        return xnap.enc_frame(xnap.FT_VERDICT, xnap.FL_FIN, sid, 0,
                              payload)


async def stats_writer(path):
    while True:
        try:
            with open(path, "w") as f:
                json.dump(stats.__dict__, f)
        except Exception:
            pass
        await asyncio.sleep(0.5)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True,
                    help="unix:/path or tcp:port or tcp:host:port")
    ap.add_argument("--rules", default=None)
    ap.add_argument("--stats", default=None)
    args = ap.parse_args()

    rules = load_rules(args.rules)

    async def cb(r, w):
        await Conn(rules).run(r, w)

    if args.listen.startswith("unix:"):
        path = args.listen[5:]
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv = await asyncio.start_unix_server(cb, path)
        os.chmod(path, 0o777)
    else:
        parts = args.listen[4:].split(":")
        host = parts[0] if len(parts) > 1 else "127.0.0.1"
        port = int(parts[-1])
        srv = await asyncio.start_server(cb, host, port)
        args.listen = f"tcp:{host}:{port}"

    if args.stats:
        asyncio.create_task(stats_writer(args.stats))

    print(f"stub-agent listening on {args.listen}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
