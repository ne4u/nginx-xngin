//! XNAP agent server: listener, handshake, stream demux, verdict writeback.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;

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
}

/// XNAP server.
pub struct Server<H> {
    pub handler: H,
    pub agent_id: String,
    pub max_streams: u32,
    pub max_frame: u32,
}

impl<H: AgentHandler> Server<H> {
    pub fn new(handler: H) -> Self {
        Server {
            handler,
            agent_id: "xngin-rs/1".into(),
            max_streams: 256,
            max_frame: DEFAULT_MAX_FRAME,
        }
    }

    /// `addr` = "unix:/path" or "tcp:host:port" / "tcp:port".
    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let handler = Arc::new(self.handler);
        let agent_id = Arc::new(self.agent_id);
        let (max_streams, max_frame) = (self.max_streams, self.max_frame);

        if let Some(path) = addr.strip_prefix("unix:") {
            let _ = std::fs::remove_file(path);
            let l = UnixListener::bind(path)?;
            loop {
                let (sock, _) = l.accept().await?;
                tokio::spawn(conn(sock, handler.clone(), agent_id.clone(),
                                  max_streams, max_frame));
            }
        } else {
            let a = addr.strip_prefix("tcp:").unwrap_or(addr);
            let a = if a.contains(':') { a.to_string() }
                    else { format!("0.0.0.0:{a}") };
            let l = TcpListener::bind(&a).await?;
            loop {
                let (sock, _) = l.accept().await?;
                let _ = sock.set_nodelay(true);
                tokio::spawn(conn(sock, handler.clone(), agent_id.clone(),
                                  max_streams, max_frame));
            }
        }
    }
}

struct StreamState {
    req: Request,
}

type Streams = Arc<Mutex<HashMap<u64, StreamState>>>;

async fn write_frame<W>(w: &Arc<Mutex<W>>, f: &Frame) -> bool
where
    W: AsyncWriteExt + Unpin + Send,
{
    let mut g = w.lock().await;
    g.write_all(&f.marshal()).await.is_ok()
        && g.flush().await.is_ok()
}

async fn decide<H, S>(handler: &Arc<H>, streams: &Streams,
                      wr: &Arc<Mutex<WriteHalf<S>>>, sid: u64) -> bool
where
    H: AgentHandler,
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let st = streams.lock().await.remove(&sid);
    if let Some(st) = st {
        let v = handler.handle(&st.req).await;
        return write_frame(wr, &Frame::new(FT_VERDICT, FL_FIN, sid, 0,
                                         v.marshal())).await;
    }
    true
}

async fn conn<H, S>(sock: S, handler: Arc<H>, agent_id: Arc<String>,
                    _max_streams: u32, max_frame: u32)
where
    H: AgentHandler,
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut rd, wr_inner) = tokio::io::split(sock);
    let wr = Arc::new(Mutex::new(wr_inner));

    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match rd.read_buf(&mut buf).await {
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }

        let frames = match feed_max(&mut buf, max_frame) {
            Ok(f) => f,
            Err(_) => return,
        };

        for fr in frames {
            match fr.typ {
                FT_ENGINE_HELLO => {
                    let mut p = Vec::new();
                    enc_kv(&mut p, "version", &Value::Uint(VERSION as u64));
                    enc_kv(&mut p, "max-frame-size",
                           &Value::Uint(max_frame as u64));
                    enc_kv(&mut p, "max-streams", &Value::Uint(256));
                    enc_kv(&mut p, "capabilities",
                           &Value::Uint((CAP_BODY | CAP_ASYNC | CAP_VCACHE
                                         | CAP_RESP) as u64));
                    enc_kv(&mut p, "agent-id",
                           &Value::Str(agent_id.as_str().to_string()));
                    if !write_frame(&wr,
                                    &Frame::new(FT_AGENT_HELLO, 0, 0, 0, p))
                        .await
                    {
                        return;
                    }
                }
                FT_PING => {
                    if !write_frame(&wr,
                                    &Frame::new(FT_PONG, 0, fr.sid, fr.fid,
                                                fr.payload)).await {
                        return;
                    }
                }
                FT_ABORT => {
                    streams.lock().await.remove(&fr.sid);
                }
                FT_BODY => {
                    let mut done = false;
                    {
                        let mut map = streams.lock().await;
                        if let Some(st) = map.get_mut(&fr.sid) {
                            st.req.body.extend_from_slice(&fr.payload);
                            if fr.flags & FL_BODY_LAST != 0 {
                                st.req.body_truncated |=
                                    fr.flags & FL_BODY_TRUNCATED != 0;
                                done = true;
                            }
                        }
                    }
                    if done && !decide(&handler, &streams, &wr, fr.sid).await {
                        return;
                    }
                }
                FT_NOTIFY => {
                    let req = match fr.notify() {
                        Ok((msg, kvs)) => build_request(msg, kvs, fr.flags),
                        Err(_) => continue,
                    };
                    let has_body = fr.flags & FL_NOTIFY_HAS_BODY != 0;
                    streams.lock().await.insert(fr.sid, StreamState { req });
                    if !has_body
                        && !decide(&handler, &streams, &wr, fr.sid).await
                    {
                        return;
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


