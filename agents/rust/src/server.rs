//! XNAP agent server: listener, handshake, stream demux, verdict writeback.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::proto::*;

/// One offload decision request.
#[derive(Debug, Default)]
pub struct Request {
    pub msg: String,
    pub fields: HashMap<String, Value>,
    /// lowercased header name -> values
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
    pub async_mode: bool,
    pub body_truncated: bool,
}

impl Request {
    pub fn get(&self, name: &str) -> Option<&str> {
        match self.fields.get(name) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn get_ip(&self, name: &str) -> Option<IpAddr> {
        match self.fields.get(name) {
            Some(Value::Ipv4(a)) => Some(IpAddr::V4(*a)),
            Some(Value::Ipv6(a)) => Some(IpAddr::V6(*a)),
            _ => None,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
}

/// The decision returned for one stream.
#[derive(Debug, Default)]
pub struct Verdict {
    pub action: String, // "allow" | "deny" | "redirect"
    pub status: Option<i32>,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub set_headers: Vec<(String, String)>,
    pub unset_headers: Vec<String>,
    /// replace the request body forwarded upstream (needs body capture)
    pub req_body: Option<Vec<u8>>,
    /// response headers set/replaced toward the client
    pub res_set_headers: Vec<(String, String)>,
    /// response headers removed toward the client
    pub res_unset_headers: Vec<String>,
    /// replace the response body
    pub res_body: Option<Vec<u8>>,
    pub vars: Vec<(String, String)>,
    pub cache_ttl: Option<u32>,
    pub reason: Option<String>,
    pub score: Option<i64>,
}

impl Verdict {
    pub fn allow() -> Self {
        Verdict { action: "allow".into(), ..Default::default() }
    }

    pub fn deny(status: i32, reason: &str) -> Self {
        Verdict {
            action: "deny".into(),
            status: Some(status),
            reason: Some(reason.into()),
            ..Default::default()
        }
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut out = Vec::new();
        enc_kv(&mut out, "action", &Value::Str(self.action.clone()));
        if let Some(s) = self.status {
            enc_kv(&mut out, "status", &Value::Int(s as i64));
        }
        if let Some(b) = &self.body {
            enc_kv(&mut out, "body", &Value::Bin(b.clone()));
        }
        if let Some(ct) = &self.content_type {
            enc_kv(&mut out, "content-type", &Value::Str(ct.clone()));
        }
        if let Some(l) = &self.location {
            enc_kv(&mut out, "location", &Value::Str(l.clone()));
        }
        if !self.set_headers.is_empty() {
            let kvl: Vec<(String, Value)> = self
                .set_headers
                .iter()
                .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                .collect();
            enc_kv(&mut out, "hdr-set", &Value::Kvl(kvl));
        }
        if !self.unset_headers.is_empty() {
            enc_kv(&mut out, "hdr-unset",
                   &Value::StrList(self.unset_headers.clone()));
        }
        if let Some(b) = &self.req_body {
            enc_kv(&mut out, "req-body", &Value::Bin(b.clone()));
        }
        if !self.res_set_headers.is_empty() {
            let kvl: Vec<(String, Value)> = self
                .res_set_headers
                .iter()
                .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                .collect();
            enc_kv(&mut out, "res-hdr-set", &Value::Kvl(kvl));
        }
        if !self.res_unset_headers.is_empty() {
            enc_kv(&mut out, "res-hdr-unset",
                   &Value::StrList(self.res_unset_headers.clone()));
        }
        if let Some(b) = &self.res_body {
            enc_kv(&mut out, "res-body", &Value::Bin(b.clone()));
        }
        if !self.vars.is_empty() {
            let kvl: Vec<(String, Value)> = self
                .vars
                .iter()
                .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                .collect();
            enc_kv(&mut out, "vars", &Value::Kvl(kvl));
        }
        if let Some(t) = self.cache_ttl {
            enc_kv(&mut out, "cache-ttl", &Value::Uint(t as u64));
        }
        if let Some(r) = &self.reason {
            enc_kv(&mut out, "reason", &Value::Str(r.clone()));
        }
        if let Some(s) = self.score {
            enc_kv(&mut out, "score", &Value::Int(s));
        }
        out
    }
}

/// Implement this to build an agent.
#[async_trait::async_trait]
pub trait AgentHandler: Send + Sync + 'static {
    async fn handle(&self, req: &Request) -> Verdict;

    /// Opt-in early verdict (SPEC §4.2): called once per NOTIFY that
    /// carries HAS_BODY, before the request body finishes uploading —
    /// on the stream's own task, so it cannot stall the read loop.
    /// Return `Some` to answer immediately and close the stream (the
    /// engine stops sending BODY); `None` keeps accumulating BODY
    /// frames and calls [`handle`](Self::handle) at LAST. `req.body`
    /// is always empty at this point.
    async fn early_verdict(&self, _req: &Request) -> Option<Verdict> {
        None
    }
}

/// XNAP server.
pub struct Server<H> {
    pub handler: H,
    pub agent_id: String,
    pub max_streams: u32,
    pub max_frame: u32,
    /// TLS on the listener (engine connects as the TLS client).
    /// Build via [`crate::tls::server_config`]; with a client CA it
    /// becomes mutual TLS.
    pub tls: Option<Arc<ServerConfig>>,
}

impl<H: AgentHandler> Server<H> {
    pub fn new(handler: H) -> Self {
        Server {
            handler,
            agent_id: "xngin-rs/1".into(),
            max_streams: 256,
            max_frame: DEFAULT_MAX_FRAME,
            tls: None,
        }
    }

    /// `addr` = "unix:/path" or "tcp:host:port" / "tcp:port".
    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let handler = Arc::new(self.handler);
        let agent_id = Arc::new(self.agent_id);
        let (max_streams, max_frame, tls) =
            (self.max_streams, self.max_frame, self.tls);

        if let Some(path) = addr.strip_prefix("unix:") {
            let _ = std::fs::remove_file(path);
            let l = UnixListener::bind(path)?;
            loop {
                let (sock, _) = l.accept().await?;
                tokio::spawn(conn(Box::new(sock), handler.clone(),
                                  agent_id.clone(), max_streams,
                                  max_frame, tls.clone()));
            }
        } else {
            let a = addr.strip_prefix("tcp:").unwrap_or(addr);
            let a = if a.contains(':') { a.to_string() }
                    else { format!("0.0.0.0:{a}") };
            let l = TcpListener::bind(&a).await?;
            loop {
                let (sock, _) = l.accept().await?;
                let _ = sock.set_nodelay(true);
                tokio::spawn(conn(Box::new(sock), handler.clone(),
                                  agent_id.clone(), max_streams,
                                  max_frame, tls.clone()));
            }
        }
    }
}

/// Body accumulator for a stream awaiting LAST. The Request itself is
/// owned by the stream task, so nothing here is held across an await
/// and no per-stream lock can stall the read loop.
struct Slot {
    body: Vec<u8>,
    done: oneshot::Sender<(Vec<u8>, bool)>,
}

type Streams = Arc<Mutex<HashMap<u64, Slot>>>;

/// Object-safe stream type for plaintext or TLS connections.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T> Io for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// Conn write side: drains the marshal queue in batches so a burst of
/// verdicts costs one write and one flush, not one syscall per frame.
/// On write failure it signals `stop` so the read loop gives up too —
/// a dead write side must not queue frames forever.
async fn writer<W>(mut wr: W, mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
                   stop: oneshot::Sender<()>)
where
    W: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(64 * 1024);
    while let Some(first) = rx.recv().await {
        out.extend_from_slice(&first);
        while let Ok(next) = rx.try_recv() {
            out.extend_from_slice(&next);
        }
        if wr.write_all(&out).await.is_err()
            || wr.flush().await.is_err()
        {
            let _ = stop.send(());
            return;
        }
        out.clear();
    }
}

fn send_frame(wtx: &mpsc::UnboundedSender<Vec<u8>>, f: &Frame) {
    let _ = wtx.send(f.marshal());
}

fn send_verdict(wtx: &mpsc::UnboundedSender<Vec<u8>>, sid: u64,
                v: Verdict) {
    send_frame(wtx, &Frame::new(FT_VERDICT, FL_FIN, sid, 0, v.marshal()));
}

/// Headers-only stream: run `handle` on its own task, bounded by the
/// max-streams semaphore so one slow handler stalls only itself.
async fn decide_task<H>(handler: Arc<H>,
                        wtx: mpsc::UnboundedSender<Vec<u8>>,
                        sem: Arc<Semaphore>, req: Request, sid: u64)
where
    H: AgentHandler,
{
    let _permit = match sem.acquire_owned().await {
        Ok(p) => p,
        Err(_) => return,
    };
    let v = handler.handle(&req).await;
    send_verdict(&wtx, sid, v);
}

/// Body-carrying stream: the task owns the Request; the body arrives
/// through the oneshot at LAST. `early_verdict` may answer first.
async fn stream_task<H>(handler: Arc<H>, streams: Streams,
                        wtx: mpsc::UnboundedSender<Vec<u8>>,
                        sem: Arc<Semaphore>, mut req: Request,
                        rx: oneshot::Receiver<(Vec<u8>, bool)>, sid: u64)
where
    H: AgentHandler,
{
    {
        let _permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        if let Some(v) = handler.early_verdict(&req).await {
            streams.lock().unwrap().remove(&sid);
            send_verdict(&wtx, sid, v);
            return;
        }
    }
    match rx.await {
        Ok((body, truncated)) => {
            req.body = body;
            req.body_truncated |= truncated;
        }
        Err(_) => {
            // aborted or conn died before LAST
            streams.lock().unwrap().remove(&sid);
            return;
        }
    }
    let v = {
        let _permit = match sem.acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        handler.handle(&req).await
    };
    send_verdict(&wtx, sid, v);
}

pub(crate) async fn conn<H>(sock: Box<dyn Io>, handler: Arc<H>,
                            agent_id: Arc<String>, max_streams: u32,
                            max_frame: u32, tls: Option<Arc<ServerConfig>>)
where
    H: AgentHandler,
{
    let sock: Box<dyn Io> = match tls {
        Some(cfg) => {
            match TlsAcceptor::from(cfg).accept(sock).await {
                Ok(s) => Box::new(s),
                Err(_) => return,    // TLS handshake failed: drop conn
            }
        }
        None => sock,
    };

    let (mut rd, wr) = tokio::io::split(sock);

    let (wtx, wrx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (stx, mut srx) = oneshot::channel::<()>();
    tokio::spawn(writer(wr, wrx, stx));

    let sem = Arc::new(Semaphore::new(max_streams.max(1) as usize));
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = BytesMut::with_capacity(64 * 1024);

    loop {
        // writer death (srx resolves) or read failure ends the conn
        let read = tokio::select! {
            r = rd.read_buf(&mut buf) => r,
            _ = &mut srx => return,
        };
        match read {
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }

        // walk complete frames over the buffer front without copying;
        // split_to + freeze moves the consumed prefix into a refcounted
        // chunk the dispatcher can slice at zero cost.
        let mut spans = Vec::new();
        let mut off = 0usize;
        loop {
            match next_frame(&buf[off..], max_frame) {
                Ok(Some(h)) => {
                    let base = off;
                    off += h.total;
                    spans.push((base, h));
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
        if off == 0 {
            continue;
        }
        let chunk = buf.split_to(off).freeze();

        for (base, h) in spans {
            let payload =
                chunk.slice(base + h.payload.start..base + h.payload.end);
            match h.typ {
                FT_ENGINE_HELLO => {
                    let mut p = Vec::new();
                    enc_kv(&mut p, "version", &Value::Uint(VERSION as u64));
                    enc_kv(&mut p, "max-frame-size",
                           &Value::Uint(max_frame as u64));
                    enc_kv(&mut p, "max-streams",
                           &Value::Uint(max_streams as u64));
                    enc_kv(&mut p, "capabilities",
                           &Value::Uint((CAP_BODY | CAP_ASYNC | CAP_VCACHE
                                         | CAP_RESP) as u64));
                    enc_kv(&mut p, "agent-id",
                           &Value::Str(agent_id.as_str().to_string()));
                    send_frame(&wtx,
                               &Frame::new(FT_AGENT_HELLO, 0, 0, 0, p));
                }
                FT_PING => {
                    send_frame(&wtx, &Frame::new(FT_PONG, 0, h.sid, h.fid,
                                                 payload.to_vec()));
                }
                FT_ABORT => {
                    streams.lock().unwrap().remove(&h.sid);
                }
                FT_BODY => {
                    let mut map = streams.lock().unwrap();
                    if let Some(slot) = map.get_mut(&h.sid) {
                        slot.body.extend_from_slice(&payload);
                        if h.flags & FL_BODY_LAST != 0 {
                            let truncated =
                                h.flags & FL_BODY_TRUNCATED != 0;
                            if let Some(slot) = map.remove(&h.sid) {
                                let _ =
                                    slot.done.send((slot.body, truncated));
                            }
                        }
                    }
                }
                FT_NOTIFY => {
                    let req = match parse_notify(&payload) {
                        Ok((msg, kvs)) => build_request(msg, kvs, h.flags),
                        Err(_) => continue,
                    };
                    if h.flags & FL_NOTIFY_HAS_BODY != 0 {
                        let (tx, rx) = oneshot::channel();
                        streams.lock().unwrap().insert(
                            h.sid,
                            Slot { body: Vec::new(), done: tx },
                        );
                        tokio::spawn(stream_task(
                            handler.clone(), streams.clone(),
                            wtx.clone(), sem.clone(), req, rx, h.sid,
                        ));
                    } else {
                        tokio::spawn(decide_task(
                            handler.clone(), wtx.clone(), sem.clone(),
                            req, h.sid,
                        ));
                    }
                }
                FT_DISCON => return,
                _ => {}
            }
        }
    }
}

fn build_request(msg: String, kvs: Vec<(String, Value)>,
                 flags: u32) -> Request {
    let mut req = Request {
        msg,
        async_mode: flags & FL_NOTIFY_ASYNC != 0,
        ..Default::default()
    };
    for (k, v) in kvs {
        match k.as_str() {
            "headers" => {
                if let Value::Kvl(pairs) = v {
                    for (hk, hv) in pairs {
                        if let Value::Str(s) = hv {
                            req.headers.entry(hk).or_default().push(s);
                        }
                    }
                }
            }
            "body-truncated" => {
                req.body_truncated = matches!(v, Value::Bool(true));
            }
            _ => {
                req.fields.insert(k, v);
            }
        }
    }
    req
}


