//! Direct XNAP throughput probe — drives the wire protocol against a
//! live mini_waf agent with NO nginx in the path. Diagnostic for
//! separating agent-side throughput from engine-mediated throughput
//! (e.g. the macOS loopback TCP delivery coalescing that caps the
//! nginx rust-tcp bench lane: see docs/benchmarks.md).
//! Not a #[test]: run with
//!   cargo test --test direct_bench -- --ignored --nocapture
//! Env: XNAP_ADDR (e.g. "tcp:127.0.0.1:9000" or "unix:/tmp/x.sock"),
//!      XNAP_CONNS (default 8), XNAP_INFLIGHT (default 64),
//!      XNAP_SECS (default 5)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use xngin_rs::proto::*;

fn notify(sid: u64) -> Vec<u8> {
    let mut p = Vec::new();
    enc_varint(&mut p, "http-request".len() as u64);
    p.extend_from_slice(b"http-request");
    enc_kv(&mut p, "uri", &Value::Str("/x".into()));
    Frame::new(FT_NOTIFY, FL_FIN, sid, 0, p).marshal()
}

async fn handshake<W: AsyncWriteExt + Unpin, R: AsyncReadExt + Unpin>(
    wr: &mut W, rd: &mut R, buf: &mut Vec<u8>) {
    let mut p = Vec::new();
    enc_kv(&mut p, "version", &Value::Uint(VERSION as u64));
    wr.write_all(&Frame::new(FT_ENGINE_HELLO, 0, 0, 0, p).marshal())
        .await.unwrap();
    let mut tmp = [0u8; 4096];
    loop {
        let n = rd.read(&mut tmp).await.unwrap();
        buf.extend_from_slice(&tmp[..n]);
        if feed(buf).unwrap().iter().any(|f| f.typ == FT_AGENT_HELLO) {
            return;
        }
    }
}

// A conn task: writer keeps INFLIGHT notify frames outstanding; reader
// counts verdicts.
async fn run_conn<WH, RH>(mut wr: WH, mut rd: RH, inflight: usize,
                          counter: Arc<AtomicU64>, stop: Duration)
where
    WH: AsyncWriteExt + Unpin + Send + 'static,
    RH: AsyncReadExt + Unpin + Send + 'static,
{
    let mut buf = Vec::new();
    handshake(&mut wr, &mut rd, &mut buf).await;

    // writer: continuously top up `inflight` outstanding notifies,
    // woken by the reader on every verdict batch.
    let outstanding = Arc::new(AtomicU64::new(0));
    let wake = Arc::new(tokio::sync::Notify::new());
    let wout = outstanding.clone();
    let wwake = wake.clone();
    let wtask = tokio::spawn(async move {
        let mut sid = 1u64;
        let mut batch = Vec::new();
        let deadline = Instant::now() + stop;
        loop {
            let need = inflight as u64 - wout.load(Ordering::Relaxed);
            if need == 0 {
                tokio::select! {
                    _ = wwake.notified() => {}
                    _ = tokio::time::sleep_until(deadline.into()) => break,
                }
                continue;
            }
            for _ in 0..need {
                batch.extend_from_slice(&notify(sid));
                sid += 2;
            }
            wout.fetch_add(need, Ordering::Relaxed);
            if wr.write_all(&batch).await.is_err() {
                return;
            }
            batch.clear();
        }
    });

    let mut tmp = [0u8; 64 * 1024];
    let reader = async {
        loop {
            match rd.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    let fs = match feed(&mut buf) {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    for f in fs {
                        if f.typ == FT_VERDICT {
                            counter.fetch_add(1, Ordering::Relaxed);
                            outstanding.fetch_sub(1, Ordering::Relaxed);
                            wake.notify_one();
                        }
                    }
                }
            }
        }
    };
    // conn stays open — bound the run by the deadline + slack
    let _ = tokio::time::timeout(stop + Duration::from_secs(2),
                               reader).await;
    wtask.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn direct_throughput() {
    let addr = std::env::var("XNAP_ADDR").unwrap();
    let conns: usize =
        std::env::var("XNAP_CONNS").unwrap_or("8".into()).parse().unwrap();
    let inflight: usize = std::env::var("XNAP_INFLIGHT")
        .unwrap_or("64".into()).parse().unwrap();
    let secs: u64 =
        std::env::var("XNAP_SECS").unwrap_or("5".into()).parse().unwrap();
    let counter = Arc::new(AtomicU64::new(0));

    let mut tasks = Vec::new();
    for _ in 0..conns {
        let c = counter.clone();
        let addr = addr.clone();
        tasks.push(tokio::spawn(async move {
            if let Some(a) = addr.strip_prefix("tcp:") {
                let s = TcpStream::connect(a).await.unwrap();
                let _ = s.set_nodelay(true);
                let (rd, wr) = tokio::io::split(s);
                run_conn(wr, rd, inflight, c,
                         Duration::from_secs(secs)).await;
            } else {
                let path = addr.strip_prefix("unix:").unwrap();
                let s = UnixStream::connect(path).await.unwrap();
                let (rd, wr) = tokio::io::split(s);
                run_conn(wr, rd, inflight, c,
                         Duration::from_secs(secs)).await;
            }
        }));
    }
    let t0 = Instant::now();
    for t in tasks {
        let _ = t.await;
    }
    let el = t0.elapsed().as_secs_f64();
    let n = counter.load(Ordering::Relaxed);
    eprintln!("{addr}: {n} verdicts in {el:.1}s = {:.0} rps",
              n as f64 / el);
}
