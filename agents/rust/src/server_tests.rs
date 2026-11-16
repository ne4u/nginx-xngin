//! Server-level tests over tokio duplex streams: handshake, head-of-line
//! independence, and the early-verdict path.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

use crate::proto::*;
use crate::server::*;

fn notify_payload(msg: &str, kvs: &[(&str, Value)]) -> Vec<u8> {
    let mut p = Vec::new();
    enc_varint(&mut p, msg.len() as u64);
    p.extend_from_slice(msg.as_bytes());
    for (k, v) in kvs {
        enc_kv(&mut p, k, v);
    }
    p
}

async fn send(c: &mut DuplexStream, f: &Frame) {
    c.write_all(&f.marshal()).await.unwrap();
}

/// Read frames until one matches `want`; returns every frame seen so
/// callers can assert on ordering.
async fn read_through(c: &mut DuplexStream, want_typ: u8, want_sid: u64) -> Vec<Frame> {
    let mut buf = Vec::new();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let n = c.read_buf(&mut buf).await.unwrap();
            assert!(n > 0, "conn closed waiting for type {want_typ}");
            for f in feed(&mut buf).unwrap() {
                let done = f.typ == want_typ && f.sid == want_sid;
                out.push(f);
                if done {
                    return;
                }
            }
        }
    })
    .await
    .expect("timed out waiting for frame");
    out
}

fn spawn_conn<H: AgentHandler>(handler: H) -> DuplexStream {
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(conn(
        Box::new(server),
        Arc::new(handler),
        Arc::new("test-agent/1".to_string()),
        256,
        DEFAULT_MAX_FRAME,
        None,
    ));
    client
}

async fn handshake(c: &mut DuplexStream) {
    send(
        c,
        &Frame::new(FT_ENGINE_HELLO, 0, 0, 0, {
            let mut p = Vec::new();
            enc_kv(&mut p, "version", &Value::Uint(VERSION as u64));
            p
        }),
    )
    .await;
    read_through(c, FT_AGENT_HELLO, 0).await;
}

struct Gated {
    gate: Arc<Notify>,
}

#[async_trait]
impl AgentHandler for Gated {
    async fn handle(&self, req: &Request) -> Verdict {
        if req.get("uri") == Some("/slow") {
            self.gate.notified().await;
        }
        Verdict::allow()
    }
}

/// A blocked handler on one stream must not delay verdicts for other
/// streams — the whole point of spawning decide tasks.
#[tokio::test]
async fn slow_handler_does_not_stall_others() {
    let gate = Arc::new(Notify::new());
    let mut c = spawn_conn(Gated { gate: gate.clone() });
    handshake(&mut c).await;

    send(
        &mut c,
        &Frame::new(
            FT_NOTIFY,
            0,
            1,
            0,
            notify_payload("http-request", &[("uri", Value::Str("/slow".into()))]),
        ),
    )
    .await;
    // sid 3 lands while sid 1's handler is parked on the gate
    send(
        &mut c,
        &Frame::new(
            FT_NOTIFY,
            0,
            3,
            0,
            notify_payload("http-request", &[("uri", Value::Str("/fast".into()))]),
        ),
    )
    .await;

    read_through(&mut c, FT_VERDICT, 3).await;

    gate.notify_waiters();
    read_through(&mut c, FT_VERDICT, 1).await;
}

struct Early;

#[async_trait]
impl AgentHandler for Early {
    async fn handle(&self, _req: &Request) -> Verdict {
        Verdict::deny(500, "handle must not run")
    }

    async fn early_verdict(&self, req: &Request) -> Option<Verdict> {
        assert!(req.body.is_empty());
        let mut v = Verdict::allow();
        v.reason = Some("early".into());
        Some(v)
    }
}

#[tokio::test]
async fn early_verdict_precedes_body() {
    let mut c = spawn_conn(Early);
    handshake(&mut c).await;

    send(
        &mut c,
        &Frame::new(
            FT_NOTIFY,
            FL_NOTIFY_HAS_BODY,
            1,
            0,
            notify_payload("http-request", &[("method", Value::Str("POST".into()))]),
        ),
    )
    .await;

    let f = read_through(&mut c, FT_VERDICT, 1).await.remove(0);
    let kvs = f.kvs().unwrap();
    assert_eq!(
        kvs.iter().find(|(k, _)| k == "reason"),
        Some(&("reason".to_string(), Value::Str("early".into())))
    );

    // BODY after the verdict is ignored; the conn still answers PING.
    send(
        &mut c,
        &Frame::new(FT_BODY, FL_BODY_LAST, 1, 0, b"late".to_vec()),
    )
    .await;
    send(&mut c, &Frame::new(FT_PING, 0, 0, 0, b"x".to_vec())).await;
    for f in read_through(&mut c, FT_PONG, 0).await {
        assert_ne!(f.typ, FT_VERDICT, "verdict for a decided stream");
    }
}
