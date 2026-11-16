//! crs-waf core: per-request ruleset selection + zentinel-modsec
//! transaction glue. Kept in its own module so tests/crs_waf.rs can
//! `#[path]`-include it without the CLI in main.rs.

use std::collections::HashMap;

use xngin_rs::{AgentHandler, Request, Value, Verdict};
use zentinel_modsec::{ModSecurity, Transaction};

/// One xngin WAF agent: a map of named rulesets ("profiles"), each an
/// independent ModSecurity engine built from its own conf file — a full
/// CRS tree or a tuned subset. nginx blocks pick a profile by shipping
/// `xngin_var <policy_var> "<name>"` in the NOTIFY `vars` KVL.
pub struct CrsWaf {
    pub rulesets: HashMap<String, ModSecurity>,
    /// NOTIFY `vars` key carrying the profile name (default
    /// "waf_profile").
    pub policy_var: String,
    /// Profile used when the var is absent or empty.
    pub default_profile: Option<String>,
}

impl CrsWaf {
    /// Resolve the request's profile to a loaded engine. Missing or
    /// unknown profiles fail closed: a WAF that can't find its rules
    /// must not silently pass traffic.
    fn engine_for<'a>(&'a self, req: &Request)
                      -> Result<(String, &'a ModSecurity), String> {
        let name = match var_of(req, &self.policy_var) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => match &self.default_profile {
                Some(d) => d.clone(),
                None => {
                    return Err(format!(
                        "crs-waf: no {} var and no default profile",
                        self.policy_var))
                }
            },
        };
        match self.rulesets.get(&name) {
            Some(m) => Ok((name, m)),
            None => Err(format!("crs-waf: unknown profile '{name}'")),
        }
    }

    /// Populate a transaction's request context: addresses, URI, method,
    /// protocol and request headers — everything phase-1 rules see.
    /// Header pairs come from the request `headers` KVL on
    /// `http-request` and from `req-headers` on `http-response`.
    fn tx_request(&self, waf: &ModSecurity, req: &Request,
                  response_stream: bool) -> zentinel_modsec::Result<Transaction> {
        let mut tx = waf.new_transaction();
        if let Some(ip) = req.get_ip("src-ip") {
            tx.set_client_addr(&ip.to_string(), u16_of(req, "src-port"));
        }
        if let Some(ip) = req.get_ip("dst-ip") {
            tx.set_server_addr(&ip.to_string(), u16_of(req, "dst-port"));
        }
        if let Some(host) = req.get("host") {
            if !host.is_empty() {
                tx.set_server_name(host);
            }
        }
        tx.process_uri(
            req.get("uri").unwrap_or("/"),
            req.get("method").unwrap_or("GET"),
            &protocol(req),
        )?;
        if response_stream {
            if let Some(Value::Kvl(pairs)) = req.fields.get("req-headers") {
                for (k, v) in pairs {
                    if let Value::Str(s) = v {
                        tx.add_request_header(k, s)?;
                    }
                }
            }
        } else {
            for (k, vs) in &req.headers {
                for v in vs {
                    tx.add_request_header(k, v)?;
                }
            }
        }
        Ok(tx)
    }

    /// Turn a modsec intervention into a verdict. XNAP has no
    /// connection-drop action, so `drop_connection` collapses to deny.
    fn deny_of(&self, itv: &zentinel_modsec::Intervention,
               tx: &Transaction, profile: &str) -> Verdict {
        let mut v = if let Some(url) = &itv.url {
            let mut v = Verdict {
                action: "redirect".into(),
                location: Some(url.clone()),
                ..Default::default()
            };
            v.status = Some(if itv.status == 0 { 302 } else { itv.status as i32 });
            v
        } else {
            let reason = itv.log.clone().unwrap_or_else(|| {
                format!("crs-waf: rules {}", itv.rule_ids.join(","))
            });
            let status = if itv.status == 0 { 403 } else { itv.status as i32 };
            Verdict::deny(status, &reason)
        };
        v.score = Some(tx.anomaly_score() as i64);
        v.vars.push(("waf_profile".into(), profile.into()));
        v.vars.push(("waf_rules".into(), itv.rule_ids.join(",")));
        v
    }

    /// Allow verdict annotated with score and any rules that matched
    /// under DetectionOnly.
    fn allow_of(&self, tx: &Transaction, profile: &str) -> Verdict {
        let mut v = Verdict::allow();
        v.score = Some(tx.anomaly_score() as i64);
        v.vars.push(("waf_profile".into(), profile.into()));
        if !tx.matched_rules().is_empty() {
            v.vars.push(("waf_rules".into(), tx.matched_rules().join(",")));
        }
        v
    }

    /// http-request: phases 1+2. `process_request_body` runs even with
    /// no body — CRS ARGS/query rules are phase:2 and only evaluate
    /// there.
    fn handle_request(&self, waf: &ModSecurity, req: &Request,
                      profile: &str) -> Verdict {
        let mut tx = match self.tx_request(waf, req, false) {
            Ok(t) => t,
            Err(e) => return Verdict::deny(500, &format!("crs-waf: {e}")),
        };
        if tx.process_request_headers().is_err() {
            return Verdict::deny(500, "crs-waf: header phase error");
        }
        if let Some(i) = tx.intervention() {
            return self.deny_of(i, &tx, profile);
        }
        if !req.body.is_empty() {
            let _ = tx.append_request_body(&req.body);
        }
        if tx.process_request_body().is_err() {
            return Verdict::deny(500, "crs-waf: body phase error");
        }
        match tx.intervention() {
            Some(i) => self.deny_of(i, &tx, profile),
            None => self.allow_of(&tx, profile),
        }
    }

    /// http-response (`xngin_response on`): rebuild request context
    /// from `req-headers`, then run response phases 3+4 — CRS
    /// RESPONSE-9xx data-leak rules live there. An intervention
    /// discards the held response and denies.
    fn handle_response(&self, waf: &ModSecurity, req: &Request,
                       profile: &str) -> Verdict {
        let mut tx = match self.tx_request(waf, req, true) {
            Ok(t) => t,
            Err(e) => return Verdict::deny(500, &format!("crs-waf: {e}")),
        };
        if tx.process_request_headers().is_err()
            || tx.process_request_body().is_err()
        {
            return Verdict::deny(500, "crs-waf: request replay error");
        }
        for (k, vs) in &req.headers {
            for v in vs {
                if tx.add_response_header(k, v).is_err() {
                    return Verdict::deny(500, "crs-waf: response header error");
                }
            }
        }
        if tx.process_response_headers().is_err() {
            return Verdict::deny(500, "crs-waf: response phase error");
        }
        if !req.body.is_empty() {
            let _ = tx.append_response_body(&req.body);
        }
        if tx.process_response_body().is_err() {
            return Verdict::deny(500, "crs-waf: response body phase error");
        }
        match tx.intervention() {
            Some(i) => self.deny_of(i, &tx, profile),
            None => self.allow_of(&tx, profile),
        }
    }
}

#[async_trait::async_trait]
impl AgentHandler for CrsWaf {
    /// Early deny: phase-1 rules (protocol enforcement, header rules)
    /// can answer at NOTIFY time — the body upload is cut short and
    /// `handle` never runs on that stream. Phase-2 (ARGS/body) rules
    /// always wait for `handle`.
    async fn early_verdict(&self, req: &Request) -> Option<Verdict> {
        if req.msg != "http-request" {
            return None;
        }
        let (profile, waf) = self.engine_for(req).ok()?;
        let mut tx = self.tx_request(waf, req, false).ok()?;
        if tx.process_request_headers().is_err() {
            return None;
        }
        tx.intervention().map(|i| self.deny_of(i, &tx, &profile))
    }

    async fn handle(&self, req: &Request) -> Verdict {
        let (profile, waf) = match self.engine_for(req) {
            Ok(v) => v,
            Err(e) => return Verdict::deny(500, &e),
        };
        if req.msg == "http-response" {
            self.handle_response(waf, req, &profile)
        } else {
            self.handle_request(waf, req, &profile)
        }
    }
}

/// A `vars` KVL field lookup.
fn var_of<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    if let Some(Value::Kvl(pairs)) = req.fields.get("vars") {
        for (k, v) in pairs {
            if k == name {
                if let Value::Str(s) = v {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn u16_of(req: &Request, name: &str) -> u16 {
    match req.fields.get(name) {
        Some(Value::Uint(u)) => *u as u16,
        Some(Value::Int(i)) => *i as u16,
        _ => 0,
    }
}

/// `http-version` is "1.0"/"1.1"/"2"; modsec wants a protocol string.
fn protocol(req: &Request) -> String {
    match req.get("http-version") {
        Some(v) if v.starts_with("HTTP/") => v.to_string(),
        Some(v) => format!("HTTP/{v}"),
        None => "HTTP/1.1".into(),
    }
}
