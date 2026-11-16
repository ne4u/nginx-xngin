//! crs-waf: a real-world xngin agent — OWASP CRS / ModSecurity WAF with
//! a different ruleset per nginx server/location block.
//!
//!   crs_waf --listen unix:/tmp/xngin-waf.sock \
//!           --profile storefront=/etc/crs/storefront.conf \
//!           --profile api-strict=/etc/crs/api-strict.conf \
//!           --default-profile storefront
//!
//! Each --profile name=path loads an independent ModSecurity engine
//! from a conf file that may `Include` a full CRS tree. nginx blocks
//! pick a profile with `xngin_var waf_profile "<name>"` — the var
//! rides the NOTIFY `vars` KVL, so it is config-bound and cannot be
//! spoofed by the client. See docs/multi-vhost.md.
//!
//! Request-phase rules (phases 1+2) run on `http-request` streams —
//! phase-1 hits deny at NOTIFY time before the body finishes uploading.
//! Response-phase rules (phases 3+4, CRS RESPONSE-9xx data-leak rules)
//! run on `http-response` streams for vhosts with `xngin_response on`.
//! Body rules need `xngin_body_inspect on` plus `SecRequestBodyAccess
//! On` in the profile conf.

mod waf;

use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::exit;

use xngin_rs::Server;
use zentinel_modsec::ModSecurity;

use waf::CrsWaf;

fn usage() -> ! {
    eprintln!(
        "usage: crs_waf --listen ADDR --profile NAME=CONF [--profile ...] \\\n\
         \x20      [--policy-var waf_profile] [--default-profile NAME] \\\n\
         \x20      [--tls-cert P --tls-key P [--tls-client-ca P]]"
    );
    exit(2);
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut listen = "unix:/tmp/xngin-waf.sock".to_string();
    let mut profiles: Vec<(String, String)> = Vec::new();
    let mut policy_var = "waf_profile".to_string();
    let mut default_profile = None;
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
            "--profile" => {
                let spec = &args[i + 1];
                match spec.split_once('=') {
                    Some((n, p)) if !n.is_empty() && !p.is_empty() => {
                        profiles.push((n.to_string(), p.to_string()));
                    }
                    _ => {
                        eprintln!("bad --profile '{spec}': want NAME=CONF");
                        exit(2);
                    }
                }
                i += 1;
            }
            "--policy-var" => {
                policy_var = args[i + 1].clone();
                i += 1;
            }
            "--default-profile" => {
                default_profile = Some(args[i + 1].clone());
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
            _ => usage(),
        }
        i += 1;
    }

    if profiles.is_empty() {
        eprintln!("no --profile given: need at least one ruleset");
        usage();
    }

    let mut rulesets = HashMap::new();
    for (name, path) in &profiles {
        match ModSecurity::from_file(path) {
            Ok(m) => {
                eprintln!("profile '{name}': {} rules from {path}",
                          m.rule_count());
                rulesets.insert(name.clone(), m);
            }
            Err(e) => {
                eprintln!("profile '{name}': {path}: {e}");
                exit(1);
            }
        }
    }
    if let Some(d) = &default_profile {
        if !rulesets.contains_key(d) {
            eprintln!("--default-profile '{d}' is not a loaded --profile");
            exit(2);
        }
    }

    eprintln!(
        "crs-waf listening on {listen} ({} profiles, policy var '{policy_var}')",
        rulesets.len()
    );
    let mut srv = Server::new(CrsWaf { rulesets, policy_var, default_profile });
    srv.agent_id = "crs-waf/1.0".into();
    if let Some(c) = cert {
        srv.tls = Some(xngin_rs::tls::server_config(
            Path::new(&c),
            Path::new(key.as_deref().expect("--tls-key")),
            client_ca.as_deref().map(Path::new),
        )?);
    }
    srv.listen(&listen).await
}
