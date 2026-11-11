//! Conformance vs shared vectors.json (test/conformance/vectors.json).

use serde_json::Value as J;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::proto::*;

fn load() -> Vec<J> {
    let doc: J = serde_json::from_str(include_str!(
        "../../../test/conformance/vectors.json"
    ))
    .unwrap();
    doc["vectors"].as_array().unwrap().clone()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Convert JSON 'expect' to our decoded Value form.
fn expect_to_value(j: &J) -> Value {
    match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => Value::Int(n.as_i64().unwrap()),
        J::String(s) => {
            // ip strings decode to Ipv4/Ipv6
            if let Ok(a) = s.parse::<Ipv4Addr>() {
                return Value::Ipv4(a);
            }
            if let Ok(a) = s.parse::<Ipv6Addr>() {
                return Value::Ipv6(a);
            }
            Value::Str(s.clone())
        }
        J::Array(arr) => {
            let items: Vec<String> = arr
                .iter()
                .map(|e| e.as_str().unwrap().to_string())
                .collect();
            Value::StrList(items)
        }
        J::Object(o) => {
            if let Some(h) = o.get("$bytes") {
                return Value::Bin(unhex(h.as_str().unwrap()));
            }
            if let Some(ps) = o.get("$pairs") {
                let kvl: Vec<(String, Value)> = ps
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        let a = p.as_array().unwrap();
                        (a[0].as_str().unwrap().to_string(),
                         expect_to_value(&a[1]))
                    })
                    .collect();
                return Value::Kvl(kvl);
            }
            panic!("bad expect object {o:?}");
        }
    }
}

/// Semantic comparison ignoring UINT/INT width distinctions.
fn semantic_eq(got: &Value, want: &Value) -> bool {
    match (got, want) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Uint(a), Value::Int(b)) => *a as i64 == *b,
        (Value::Int(a), Value::Uint(b)) => *a == *b as i64,
        (Value::Uint(a), Value::Uint(b)) => a == b,
        (Value::Kvl(g), Value::Kvl(w)) => {
            g.len() == w.len()
                && g.iter().zip(w.iter()).all(|((gk, gv), (wk, wv))| {
                    gk == wk && semantic_eq(gv, wv)
                })
        }
        _ => got == want,
    }
}

#[test]
fn conformance() {
    for v in load() {
        let name = v["name"].as_str().unwrap();
        let wire = unhex(v["hex"].as_str().unwrap());
        let kind = v["kind"].as_str().unwrap();

        match kind {
            "varint" => {
                let mut r = Reader::new(&wire);
                assert_eq!(r.varint().unwrap() as i64,
                           v["value"].as_i64().unwrap(), "{name}");
            }
            "svarint" => {
                let mut r = Reader::new(&wire);
                assert_eq!(r.svarint().unwrap(),
                           v["value"].as_i64().unwrap(), "{name}");
            }
            "value" => {
                let mut r = Reader::new(&wire);
                let got = r.value().unwrap();
                let want = expect_to_value(&v["expect"]);
                assert!(semantic_eq(&got, &want),
                        "{name}: {got:?} != {want:?}");
            }
            "kv" => {
                let mut r = Reader::new(&wire);
                let (k, got) = r.kv().unwrap();
                assert_eq!(k, v["kname"].as_str().unwrap(), "{name}");
                let want = expect_to_value(&v["expect"]);
                assert!(semantic_eq(&got, &want),
                        "{name}: {got:?} != {want:?}");
            }
            "frame" => {
                let mut buf = wire.clone();
                let frames = feed(&mut buf).unwrap();
                assert_eq!(frames.len(), 1, "{name}");
                assert!(buf.is_empty(), "{name}");
                let f = &frames[0];
                assert_eq!(f.typ, v["ftype"].as_u64().unwrap() as u8,
                           "{name}");
                assert_eq!(f.flags, v["flags"].as_u64().unwrap() as u32,
                           "{name}");
                assert_eq!(f.sid, v["sid"].as_u64().unwrap(), "{name}");
                assert_eq!(f.fid, v["fid"].as_u64().unwrap(), "{name}");
                let kvs = f.kvs().unwrap();
                let exp = v["expect_kv"].as_array().unwrap();
                assert_eq!(kvs.len(), exp.len(), "{name}");
                for ((gk, gv), e) in kvs.iter().zip(exp.iter()) {
                    let ea = e.as_array().unwrap();
                    assert_eq!(gk, ea[0].as_str().unwrap(), "{name}");
                    assert!(
                        semantic_eq(gv, &expect_to_value(&ea[1])),
                        "{name}: {gv:?} != {:?}",
                        ea[1]
                    );
                }
            }
            _ => panic!("unknown kind {kind}"),
        }
    }
}
