use super::*;

#[test]
fn varint_roundtrip() {
    for v in [0u64, 1, 127, 128, 300, 16384, 1 << 32, u64::MAX] {
        let mut b = Vec::new();
        enc_varint(&mut b, v);
        let mut r = Reader::new(&b);
        assert_eq!(r.varint().unwrap(), v);
        assert!(r.eof());
    }
}

#[test]
fn svarint_roundtrip() {
    for v in [0i64, 1, -1, 42, -300, 1 << 40, -(1 << 40), i64::MIN + 1] {
        let mut b = Vec::new();
        enc_svarint(&mut b, v);
        let mut r = Reader::new(&b);
        assert_eq!(r.svarint().unwrap(), v);
    }
}

#[test]
fn value_roundtrip() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let cases = vec![
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(-42),
        Value::Uint(300),
        Value::Ipv4(Ipv4Addr::new(10, 0, 0, 7)),
        Value::Ipv6(Ipv6Addr::LOCALHOST),
        Value::Str("hello".into()),
        Value::Bin(vec![1, 2, 3]),
        Value::StrList(vec!["a".into(), "b".into()]),
        Value::Kvl(vec![("k".into(), Value::Str("v".into())),
                        ("n".into(), Value::Int(7))]),
    ];
    for c in cases {
        let mut b = Vec::new();
        enc_value(&mut b, &c);
        let mut r = Reader::new(&b);
        let got = r.value().unwrap();
        assert_eq!(got, c);
    }
}

#[test]
fn frame_roundtrip() {
    let mut p = Vec::new();
    enc_kv(&mut p, "action", &Value::Str("allow".into()));
    enc_kv(&mut p, "score", &Value::Int(7));
    let f = Frame::new(FT_VERDICT, FL_FIN, 41, 2, p);
    let wire = f.marshal();

    let mut buf = wire.clone();
    let frames = feed(&mut buf).unwrap();
    assert_eq!(frames.len(), 1);
    assert!(buf.is_empty());
    let g = &frames[0];
    assert_eq!((g.typ, g.sid, g.fid), (FT_VERDICT, 41, 2));
    let kvs = g.kvs().unwrap();
    assert_eq!(kvs[0], ("action".into(), Value::Str("allow".into())));
    assert_eq!(kvs[1], ("score".into(), Value::Int(7)));
}

#[test]
fn partial_frames() {
    let f = Frame::new(FT_PING, 0, 1, 0, b"ab".to_vec()).marshal();
    for cut in 1..f.len() {
        let mut buf = f[..cut].to_vec();
        let frames = feed(&mut buf).unwrap();
        assert!(frames.is_empty(), "cut {cut}");
        assert_eq!(buf.len(), cut);
    }
}

#[test]
fn notify_parse() {
    let mut p = Vec::new();
    enc_varint(&mut p, 12);
    p.extend_from_slice(b"http-request");
    enc_kv(&mut p, "method", &Value::Str("GET".into()));
    enc_kv(&mut p, "headers",
           &Value::Kvl(vec![("host".into(), Value::Str("x".into()))]));
    let f = Frame::new(FT_NOTIFY, 0, 1, 0, p);
    let (msg, kvs) = f.notify().unwrap();
    assert_eq!(msg, "http-request");
    assert_eq!(kvs[0].0, "method");
}

#[test]
fn strlist_huge_count_is_err_not_abort() {
    // STRLIST with count 2^60 and no elements
    let wire = [0x0c, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10];
    let mut r = Reader::new(&wire);
    assert!(r.value().is_err());
}

#[test]
fn strlist_count_exceeding_elements_is_err() {
    let mut wire = Vec::new();
    enc_value(&mut wire, &Value::StrList(vec!["a".into(), "b".into()]));
    wire[1] = 3; // claim 3 elements, only 2 present
    assert!(Reader::new(&wire).value().is_err());
}

#[test]
fn feed_rejects_oversized_frame() {
    // header alone declaring DEFAULT_MAX_FRAME + 1 must fail immediately
    let mut buf = Vec::new();
    enc_varint(&mut buf, DEFAULT_MAX_FRAME as u64 + 1);
    assert!(feed(&mut buf).is_err());

    let mut buf = Vec::new();
    enc_varint(&mut buf, u64::MAX);
    assert!(feed(&mut buf).is_err());

    let f = Frame::new(FT_PING, 0, 1, 0, vec![0u8; 100]).marshal();
    let mut buf = f.clone();
    assert!(feed_max(&mut buf, 50).is_err());
    let mut buf = f;
    assert_eq!(feed_max(&mut buf, 200).unwrap().len(), 1);
}

#[test]
fn feed_accepts_max_sized_frame() {
    let body_len = DEFAULT_MAX_FRAME as usize;
    // type(1) + flags(4) + sid(1) + fid(1) + payload
    let f = Frame::new(FT_PING, 0, 1, 0, vec![0u8; body_len - 7]).marshal();
    let mut buf = f;
    assert_eq!(feed(&mut buf).unwrap().len(), 1);
    assert!(buf.is_empty());
}
