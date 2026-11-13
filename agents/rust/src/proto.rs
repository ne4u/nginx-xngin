//! XNAP wire codec (SPEC.md v1): varints, typed values, KV payloads, frames.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const VERSION: u32 = 1;
/// Default `max-frame-size` (SPEC.md §3).
pub const DEFAULT_MAX_FRAME: u32 = 16384;

// frame types
pub const FT_ENGINE_HELLO: u8 = 0x01;
pub const FT_AGENT_HELLO: u8 = 0x02;
pub const FT_DISCON: u8 = 0x03;
pub const FT_NOTIFY: u8 = 0x04;
pub const FT_VERDICT: u8 = 0x05;
pub const FT_BODY: u8 = 0x06;
pub const FT_ABORT: u8 = 0x07;
pub const FT_PING: u8 = 0x08;
pub const FT_PONG: u8 = 0x09;

// stream flags
pub const FL_FIN: u32 = 0x01;
pub const FL_ABORT: u32 = 0x02;
pub const FL_NOTIFY_HAS_BODY: u32 = 1 << 8;
pub const FL_NOTIFY_ASYNC: u32 = 1 << 9;
pub const FL_BODY_LAST: u32 = 1 << 8;
pub const FL_BODY_TRUNCATED: u32 = 1 << 9;

// capabilities
pub const CAP_BODY: u32 = 0x01;
pub const CAP_ASYNC: u32 = 0x02;
pub const CAP_VCACHE: u32 = 0x04;
pub const CAP_RESP: u32 = 0x08;

#[derive(Debug)]
pub struct ProtoError(pub &'static str);

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "xnap protocol error: {}", self.0)
    }
}

impl std::error::Error for ProtoError {}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Str(String),
    Bin(Vec<u8>),
    Kvl(Vec<(String, Value)>),
    StrList(Vec<String>),
}

// ---------- varint ----------

pub fn enc_varint(dst: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        dst.push((v as u8) | 0x80);
        v >>= 7;
    }
    dst.push(v as u8);
}

pub fn enc_svarint(dst: &mut Vec<u8>, v: i64) {
    enc_varint(dst, ((v << 1) ^ (v >> 63)) as u64)
}

// ---------- value encode ----------

pub fn enc_value(dst: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => dst.push(0x00),
        Value::Bool(true) => dst.push(0x01),
        Value::Bool(false) => dst.push(0x02),
        Value::Int(i) => {
            dst.push(0x04);
            enc_svarint(dst, *i);
        }
        Value::Uint(u) => {
            dst.push(0x06);
            enc_varint(dst, *u);
        }
        Value::Ipv4(a) => {
            dst.push(0x07);
            dst.extend_from_slice(&a.octets());
        }
        Value::Ipv6(a) => {
            dst.push(0x08);
            dst.extend_from_slice(&a.octets());
        }
        Value::Str(s) => {
            dst.push(0x09);
            enc_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
        }
        Value::Bin(b) => {
            dst.push(0x0a);
            enc_varint(dst, b.len() as u64);
            dst.extend_from_slice(b);
        }
        Value::Kvl(kvs) => {
            let mut inner = Vec::new();
            for (k, vv) in kvs {
                enc_kv(&mut inner, k, vv);
            }
            dst.push(0x0b);
            enc_varint(dst, inner.len() as u64);
            dst.extend_from_slice(&inner);
        }
        Value::StrList(items) => {
            dst.push(0x0c);
            enc_varint(dst, items.len() as u64);
            for s in items {
                enc_varint(dst, s.len() as u64);
                dst.extend_from_slice(s.as_bytes());
            }
        }
    }
}

pub fn enc_kv(dst: &mut Vec<u8>, name: &str, v: &Value) {
    enc_varint(dst, name.len() as u64);
    dst.extend_from_slice(name.as_bytes());
    enc_value(dst, v);
}

// ---------- decode ----------

pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn varint(&mut self) -> Result<u64, ProtoError> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() || shift >= 70 {
                return Err(ProtoError("varint"));
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }

    pub fn svarint(&mut self) -> Result<i64, ProtoError> {
        let v = self.varint()?;
        Ok(((v >> 1) as i64) ^ -((v & 1) as i64))
    }

    fn need(&self, n: usize) -> Result<(), ProtoError> {
        if self.buf.len() - self.pos < n {
            return Err(ProtoError("truncated"));
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn value(&mut self) -> Result<Value, ProtoError> {
        let t = *self.take(1)?.first().unwrap();
        match t {
            0x00 => Ok(Value::Null),
            0x01 => Ok(Value::Bool(true)),
            0x02 => Ok(Value::Bool(false)),
            0x03 | 0x04 => Ok(Value::Int(self.svarint()?)),
            0x05 | 0x06 => Ok(Value::Uint(self.varint()?)),
            0x07 => {
                let b = self.take(4)?;
                Ok(Value::Ipv4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            0x08 => {
                let b = self.take(16)?;
                let mut o = [0u8; 16];
                o.copy_from_slice(b);
                Ok(Value::Ipv6(Ipv6Addr::from(o)))
            }
            0x09 => {
                let n = self.varint()? as usize;
                let s = self.take(n)?;
                String::from_utf8(s.to_vec())
                    .map(Value::Str)
                    .map_err(|_| ProtoError("utf8"))
            }
            0x0a => {
                let n = self.varint()? as usize;
                Ok(Value::Bin(self.take(n)?.to_vec()))
            }
            0x0b => {
                let n = self.varint()? as usize;
                let sub = self.take(n)?;
                let mut r = Reader::new(sub);
                let mut out = Vec::new();
                while !r.eof() {
                    let (k, v) = r.kv()?;
                    out.push((k, v));
                }
                Ok(Value::Kvl(out))
            }
            0x0c => {
                let n = self.varint()?;
                // every element needs at least one byte (its length varint)
                let remaining = (self.buf.len() - self.pos) as u64;
                let mut out = Vec::with_capacity(n.min(remaining) as usize);
                for _ in 0..n {
                    let ln = self.varint()? as usize;
                    let s = self.take(ln)?;
                    out.push(
                        String::from_utf8(s.to_vec())
                            .map_err(|_| ProtoError("utf8"))?,
                    );
                }
                Ok(Value::StrList(out))
            }
            _ => Err(ProtoError("bad value type")),
        }
    }

    /// Next (name, value) or None at end of payload.
    pub fn kv(&mut self) -> Result<(String, Value), ProtoError> {
        let n = self.varint()? as usize;
        let name = String::from_utf8(self.take(n)?.to_vec())
            .map_err(|_| ProtoError("utf8"))?;
        let v = self.value()?;
        Ok((name, v))
    }

    pub fn kv_list(&mut self) -> Result<Vec<(String, Value)>, ProtoError> {
        let mut out = Vec::new();
        while !self.eof() {
            out.push(self.kv()?);
        }
        Ok(out)
    }
}

// ---------- frames ----------

#[derive(Debug, Clone)]
pub struct Frame {
    pub typ: u8,
    pub flags: u32,
    pub sid: u64,
    pub fid: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(typ: u8, flags: u32, sid: u64, fid: u64, payload: Vec<u8>) -> Self {
        Frame { typ, flags, sid, fid, payload }
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(self.payload.len() + 16);
        body.push(self.typ);
        body.extend_from_slice(&self.flags.to_be_bytes());
        enc_varint(&mut body, self.sid);
        enc_varint(&mut body, self.fid);
        body.extend_from_slice(&self.payload);
        let mut out = Vec::with_capacity(body.len() + 10);
        enc_varint(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }

    /// Parse the NOTIFY payload: (msg-name, kv pairs)
    pub fn notify(&self) -> Result<(String, Vec<(String, Value)>), ProtoError> {
        let mut r = Reader::new(&self.payload);
        let n = r.varint()? as usize;
        let msg = String::from_utf8(r.take(n)?.to_vec())
            .map_err(|_| ProtoError("utf8"))?;
        Ok((msg, r.kv_list()?))
    }

    pub fn kvs(&self) -> Result<Vec<(String, Value)>, ProtoError> {
        Reader::new(&self.payload).kv_list()
    }
}

/// Peek a varint without consuming: Ok(Some((value, nbytes))) when complete,
/// Ok(None) when the buffer ends mid-varint, Err on overlong encoding.
fn peek_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, ProtoError> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(Some((v, i + 1)));
        }
        shift += 7;
        if shift >= 70 {
            return Err(ProtoError("overlong varint"));
        }
    }
    Ok(None)
}

/// Drain complete frames from `buf`, leaving the partial tail in place.
/// Frames larger than [`DEFAULT_MAX_FRAME`] are rejected.
pub fn feed(buf: &mut Vec<u8>) -> Result<Vec<Frame>, ProtoError> {
    feed_max(buf, DEFAULT_MAX_FRAME)
}

/// Like [`feed`], but rejects frames whose `frame-len` exceeds `max_frame`.
pub fn feed_max(buf: &mut Vec<u8>, max_frame: u32)
    -> Result<Vec<Frame>, ProtoError>
{
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while let Some((flen, hdr_len)) = peek_varint(&buf[pos..])? {
        if flen < 6 {
            return Err(ProtoError("bad frame len"));
        }
        if flen > max_frame as u64 {
            return Err(ProtoError("frame too large"));
        }
        let flen = flen as usize;
        let fstart = pos + hdr_len;
        if buf.len() - fstart < flen {
            break; // incomplete frame
        }
        let fend = fstart + flen;

        let mut fr = Reader::new(&buf[fstart..fend]);
        let typ = fr.take(1)?[0];
        let flags = u32::from_be_bytes(fr.take(4)?.try_into().unwrap());
        let sid = fr.varint()?;
        let fid = fr.varint()?;
        let payload = fr.buf[fr.pos..].to_vec();

        frames.push(Frame { typ, flags, sid, fid, payload });
        pos = fend;
    }
    buf.drain(..pos);
    Ok(frames)
}
