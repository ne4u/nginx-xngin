//! mini-waf: a real-world xngin agent — regex WAF rules over URI, headers
//! and (optionally) request body, accumulating an anomaly score.
//!
//!   mini_waf --listen unix:/tmp/xngin-waf.sock --threshold 100
//!
//! Rules ship with a score; exceeding --threshold denies with 403.

use std::env;

use async_trait::async_trait;
use regex::Regex;
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

#[async_trait]
impl AgentHandler for MiniWaf {
    async fn handle(&self, req: &Request) -> Verdict {
        let mut score: i64 = 0;
        let mut hits: Vec<&'static str> = Vec::new();

        for rule in &self.rules {
            let subject = match rule.scope {
                Scope::Uri => req.get("uri").map(str::to_string),
                Scope::Header(h) => req.header(h).map(str::to_string),
                Scope::Body => {
                    if req.body.is_empty() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&req.body).into_owned())
                    }
                }
            };
            if let Some(s) = subject {
                if rule.re.is_match(&s) {
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
            _ => {}
        }
        i += 1;
    }

    eprintln!("mini-waf listening on {listen} (threshold {threshold})");
    let waf = MiniWaf { rules: rules(), threshold };
    let mut srv = Server::new(waf);
    srv.agent_id = "mini-waf/1.0".into();
    srv.listen(&listen).await
}
