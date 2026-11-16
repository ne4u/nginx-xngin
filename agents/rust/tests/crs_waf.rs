//! Unit tests for the crs_waf example handler: profile selection via
//! the NOTIFY `vars` KVL, request/response phase wiring, and verdict
//! shape — all against inline SecRule confs (no CRS download needed).

#[path = "../examples/crs_waf/waf.rs"]
mod waf;

use std::collections::HashMap;

use xngin_rs::{AgentHandler, Request, Value};
use zentinel_modsec::ModSecurity;

use waf::CrsWaf;

const STRICT: &str = r#"
SecRuleEngine On
SecRule ARGS "@contains evil" "id:1,phase:2,deny,status:403,msg:'evil arg'"
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
    "id:2,phase:1,deny,status:403"
"#;

const LENIENT: &str = r#"
SecRuleEngine On
SecRule ARGS "@contains apiattack" "id:9,phase:2,deny,status:403"
"#;

const DETECT: &str = r#"
SecRuleEngine DetectionOnly
SecRule ARGS "@contains evil" "id:1,phase:2,deny,status:403"
"#;

const RESP_RULES: &str = r#"
SecRuleEngine On
SecResponseBodyAccess On
SecRule RESPONSE_BODY "@contains secret" "id:5,phase:4,deny,status:403"
"#;

fn waf(profiles: &[(&str, &str)], default: Option<&str>) -> CrsWaf {
    let mut rulesets = HashMap::new();
    for (name, conf) in profiles {
        rulesets.insert(
            name.to_string(),
            ModSecurity::from_string(conf).unwrap(),
        );
    }
    CrsWaf {
        rulesets,
        policy_var: "waf_profile".into(),
        default_profile: default.map(str::to_string),
    }
}

fn req(uri: &str, profile: Option<&str>) -> Request {
    let mut r = Request {
        msg: "http-request".into(),
        ..Default::default()
    };
    r.fields.insert("uri".into(), Value::Str(uri.into()));
    r.fields.insert("method".into(), Value::Str("GET".into()));
    if let Some(p) = profile {
        r.fields.insert(
            "vars".into(),
            Value::Kvl(vec![("waf_profile".into(), Value::Str(p.into()))]),
        );
    }
    r
}

#[tokio::test]
async fn profile_selects_ruleset() {
    let w = waf(&[("strict", STRICT), ("lenient", LENIENT)], None);
    // "evil" arg trips STRICT but not LENIENT.
    let d = w.handle(&req("/x?q=evil", Some("strict"))).await;
    assert_eq!(d.action, "deny");
    assert_eq!(d.status, Some(403));
    let a = w.handle(&req("/x?q=evil", Some("lenient"))).await;
    assert_eq!(a.action, "allow");
}

#[tokio::test]
async fn args_rules_see_query_string() {
    let w = waf(&[("strict", STRICT)], None);
    let d = w.handle(&req("/search?q=evil-thing", Some("strict"))).await;
    assert_eq!(d.action, "deny");
    assert!(d.vars.iter().any(|(k, v)| k == "waf_rules" && v.contains("1")));
}

#[tokio::test]
async fn missing_profile_uses_default() {
    let w = waf(&[("strict", STRICT), ("lenient", LENIENT)],
                Some("lenient"));
    let a = w.handle(&req("/x?q=evil", None)).await;
    assert_eq!(a.action, "allow");
}

#[tokio::test]
async fn unknown_profile_fails_closed() {
    let w = waf(&[("strict", STRICT)], Some("strict"));
    let d = w.handle(&req("/x", Some("nope"))).await;
    assert_eq!(d.action, "deny");
    assert_eq!(d.status, Some(500));
}

#[tokio::test]
async fn no_var_no_default_fails_closed() {
    let w = waf(&[("strict", STRICT)], None);
    let d = w.handle(&req("/x", None)).await;
    assert_eq!(d.action, "deny");
    assert_eq!(d.status, Some(500));
}

#[tokio::test]
async fn phase1_denies_early() {
    let w = waf(&[("strict", STRICT)], None);
    let mut r = req("/x", Some("strict"));
    r.headers.insert("user-agent".into(), vec!["sqlmap/1.0".into()]);
    let v = w.early_verdict(&r).await;
    assert_eq!(v.map(|v| v.action), Some("deny".into()));
    // same request minus the bad UA does not verdict early
    let r2 = req("/x", Some("strict"));
    assert!(w.early_verdict(&r2).await.is_none());
}

#[tokio::test]
async fn detection_only_allows_and_reports() {
    let w = waf(&[("audit", DETECT)], None);
    let v = w.handle(&req("/x?q=evil", Some("audit"))).await;
    assert_eq!(v.action, "allow");
    assert!(v.vars.iter().any(|(k, v)| k == "waf_rules" && v.contains("1")));
}

#[tokio::test]
async fn response_body_rules_deny() {
    let w = waf(&[("resp", RESP_RULES)], None);
    let resp = |body: &[u8]| {
        let mut r = Request {
            msg: "http-response".into(),
            body: body.to_vec(),
            ..Default::default()
        };
        r.fields.insert("uri".into(), Value::Str("/x".into()));
        r.fields.insert("method".into(), Value::Str("GET".into()));
        r.fields.insert(
            "vars".into(),
            Value::Kvl(vec![("waf_profile".into(), Value::Str("resp".into()))]),
        );
        r
    };
    let d = w.handle(&resp(b"the secret payload")).await;
    assert_eq!(d.action, "deny");
    assert_eq!(d.status, Some(403));
    assert_eq!(w.handle(&resp(b"benign")).await.action, "allow");
}
