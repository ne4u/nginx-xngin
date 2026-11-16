//! mini-waf: a real-world xngin agent — regex WAF rules over URI, headers
//! and (optionally) request body, accumulating an anomaly score.
//!
//!   mini_waf --listen unix:/tmp/xngin-waf.sock --threshold 100
//!
//! Rules ship with a score; exceeding --threshold denies with 403.

use std::env;
use std::path::Path;

use async_trait::async_trait;
use regex::bytes::Regex;
use xngin_rs::{AgentHandler, Request, Server, Verdict};

struct Rule {
    name: &'static str,
    scope: Scope,
    re: Regex,
    score: i64,
}

#[derive(Clone, Copy)]
enum Scope {
    Uri,
    Header(&'static str),
    Body,
}

struct MiniWaf {
    rules: Vec<Rule>,
    threshold: i64,
}

fn rules() -> Vec<Rule> {
    vec![
        Rule { name: "path-traversal", scope: Scope::Uri, score: 80,
               re: Regex::new(r"\.\./|\.\.\\").unwrap() },
        Rule { name: "sqli-union", scope: Scope::Uri, score: 90,
               re: Regex::new(r"(?i)union\s+(all\s+)?select").unwrap() },
        Rule { name: "sqli-tautology", scope: Scope::Uri, score: 70,
               re: Regex::new(r"(?i)('|%27)\s*or\s*'?[0-9a-z]+\s*=\s*'?[0-9a-z]+")
                   .unwrap() },
        Rule { name: "xss-script", scope: Scope::Uri, score: 60,
               re: Regex::new(r"(?i)<\s*script|javascript:").unwrap() },
        Rule { name: "bad-ua", scope: Scope::Header("user-agent"), score: 50,
               re: Regex::new(r"(?i)(sqlmap|nikto|masscan|nmap|acunetix)")
                   .unwrap() },
        Rule { name: "proto-environ", scope: Scope::Uri, score: 85,
               re: Regex::new(r"(?i)/proc/self/environ|/etc/passwd").unwrap() },
        Rule { name: "body-sqli", scope: Scope::Body, score: 90,
               re: Regex::new(r"(?i)union\s+(all\s+)?select|drop\s+table")
                   .unwrap() },
        Rule { name: "body-shell", scope: Scope::Body, score: 75,
               re: Regex::new(r"(?i)(cmd|exec|system|passthru)\s*\(\s*\$")
                   .unwrap() },
    ]
}

impl MiniWaf {
    /// Rule matches borrowed from the request — no per-rule copies.
    fn subject<'a>(rule: &Rule, req: &'a Request) -> Option<&'a [u8]> {
        match rule.scope {
            Scope::Uri => req.get("uri").map(str::as_bytes),
            Scope::Header(h) => req.header(h).map(str::as_bytes),
            Scope::Body => {
                if req.body.is_empty() {
                    None
                } else {
                    Some(&req.body)
                }
            }
        }
    }

    /// Score the header/URI rules only (usable before the body lands).
    fn score_headers(&self, req: &Request) -> (i64, Vec<&'static str>) {
        let mut score: i64 = 0;
        let mut hits: Vec<&'static str> = Vec::new();
        for rule in &self.rules {
            if matches!(rule.scope, Scope::Body) {
                continue;
            }
            if Self::subject(rule, req)
                .is_some_and(|s| rule.re.is_match(s))
            {
                score += rule.score;
                hits.push(rule.name);
            }
        }
        (score, hits)
    }
}

#[async_trait]
impl AgentHandler for MiniWaf {
    /// Early deny: when URI/header rules alone cross the threshold the
    /// verdict can go out at NOTIFY time — body rules never run on that
    /// stream (the engine stops sending BODY after the verdict).
    async fn early_verdict(&self, req: &Request) -> Option<Verdict> {
        let (score, hits) = self.score_headers(req);
        if score < self.threshold {
            return None;
        }
        let mut v =
            Verdict::deny(403, &format!("waf-early: {}", hits.join(",")));
        v.score = Some(score);
        v.vars.push(("waf_rules".into(), hits.join(",")));
        Some(v)
    }

    async fn handle(&self, req: &Request) -> Verdict {
        let mut score: i64 = 0;
        let mut hits: Vec<&'static str> = Vec::new();

        for rule in &self.rules {
            if let Some(s) = Self::subject(rule, req) {
                if rule.re.is_match(s) {
                    score += rule.score;
                    hits.push(rule.name);
                }
            }
        }

        let mut v = if score >= self.threshold {
            Verdict::deny(403, &format!("waf: {}", hits.join(",")))
        } else {
            Verdict::allow()
        };

        v.score = Some(score);
        if !hits.is_empty() {
            v.vars.push(("waf_rules".into(), hits.join(",")));
        }
        v
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut listen = "unix:/tmp/xngin-waf.sock".to_string();
    let mut threshold: i64 = 100;
    let mut cert = None;
    let mut key = None;
    let mut client_ca = None;

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                listen = args[i + 1].clone();
                i += 1;
            }
            "--threshold" => {
                threshold = args[i + 1].parse().expect("threshold");
                i += 1;
            }
            "--tls-cert" => {
                cert = Some(args[i + 1].clone());
                i += 1;
            }
            "--tls-key" => {
                key = Some(args[i + 1].clone());
                i += 1;
            }
            "--tls-client-ca" => {
                client_ca = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    eprintln!("mini-waf listening on {listen} (threshold {threshold})");
    let waf = MiniWaf { rules: rules(), threshold };
    let mut srv = Server::new(waf);
    srv.agent_id = "mini-waf/1.0".into();
    if let Some(c) = cert {
        srv.tls = Some(xngin_rs::tls::server_config(
            Path::new(&c),
            Path::new(key.as_deref().expect("--tls-key")),
            client_ca.as_deref().map(Path::new),
        )?);
    }
    srv.listen(&listen).await
}
