//! Head-of-line blocking regression test: multiplexes streams on one
//! conn through a handler that sleeps for `/slow` URIs. With spawned
//! per-stream decision tasks the fast verdicts return immediately;
//! when `decide()` ran inline in the read loop every stream queued
//! behind the slow one. Self-contained (public API only) so the same
//! file compiles against a pre-concurrency checkout.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use xngin_rs::proto::*;
use xngin_rs::server::{AgentHandler, Request, Server, Verdict};

const DELAY: Duration = Duration::from_millis(30);

struct H;

impl AgentHandler for H {
    fn handle<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: &'life1 Request,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let slow = matches!(req.fields.get("uri"),
                            Some(Value::Str(s)) if s == "/slow");
        Box::pin(async move {
            if slow {
                tokio::time::sleep(DELAY).await;
            }
            Verdict::allow()
        })
    }
}

fn notify(sid: u64, uri: &str) -> Vec<u8> {
    let mut p = Vec::new();
    enc_varint(&mut p, "http-request".len() as u64);
    p.extend_from_slice(b"http-request");
    enc_kv(&mut p, "uri", &Value::Str(uri.into()));
    Frame::new(FT_NOTIFY, FL_FIN, sid, 0, p).marshal()
}

/// Read frames until `done` over the sid->latency verdict map closes.
async fn read_verdicts(c: &mut TcpStream, n_want: usize,
                       start: Instant) -> HashMap<u64, Duration> {
    let mut buf: Vec<u8> = Vec::new();
    let mut got = HashMap::new();
    let mut tmp = [0u8; 8192];
    while got.len() < n_want {
        let n = tokio::time::timeout(Duration::from_secs(15),
                                   c.read(&mut tmp))
            .await.expect("read timeout").expect("read");
        assert!(n > 0, "conn closed");
        buf.extend_from_slice(&tmp[..n]);
        for f in feed(&mut buf).expect("feed") {
            if f.typ == FT_VERDICT {
                got.entry(f.sid).or_insert_with(|| start.elapsed());
            }
        }
    }
    got
}

async fn connect() -> TcpStream {
    // Reserve an ephemeral port, then let the server bind it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap().local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = Server::new(H)
            .listen(&format!("tcp:127.0.0.1:{port}")).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut p = Vec::new();
    enc_kv(&mut p, "version", &Value::Uint(VERSION as u64));
    c.write_all(&Frame::new(FT_ENGINE_HELLO, 0, 0, 0, p).marshal())
        .await.unwrap();
    // Drain AGENT_HELLO.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = c.read(&mut tmp).await.unwrap();
        buf.extend_from_slice(&tmp[..n]);
        if feed(&mut buf).unwrap().iter().any(|f| f.typ == FT_AGENT_HELLO) {
            break;
        }
    }
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_stream_does_not_block_fast_streams() {
    const N_FAST: u64 = 24;
    let mut c = connect().await;

    let start = Instant::now();
    let mut out = notify(1, "/slow");
    for i in 0..N_FAST {
        out.extend_from_slice(&notify(3 + 2 * i, "/fast"));
    }
    c.write_all(&out).await.unwrap();
    let lat = read_verdicts(&mut c, (N_FAST + 1) as usize, start).await;

    let mut fast: Vec<Duration> = lat.iter()
        .filter(|(sid, _)| **sid != 1).map(|(_, d)| *d).collect();
    fast.sort();
    let (p50, max) = (fast[fast.len() / 2], *fast.last().unwrap());
    eprintln!("slow verdict {:?}; fast p50 {:?}, max {:?}",
              lat[&1], p50, max);
    assert!(max < DELAY,
            "fast streams blocked behind slow handler: max {max:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_slow_streams_wall_time() {
    const N: u64 = 16;
    let mut c = connect().await;

    let start = Instant::now();
    let mut out = Vec::new();
    for i in 0..N {
        out.extend_from_slice(&notify(1 + 2 * i, "/slow"));
    }
    c.write_all(&out).await.unwrap();
    let lat = read_verdicts(&mut c, N as usize, start).await;
    let wall = start.elapsed();
    let max = lat.values().max().copied().unwrap_or_default();
    eprintln!("{N} x {DELAY:?} handlers completed in wall {wall:?} \
               (max stream {max:?})");
    assert!(wall < Duration::from_millis(DELAY.as_millis() as u64) * N as u32 / 2,
            "streams serialized: wall {wall:?}");
}
