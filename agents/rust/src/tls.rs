//! TLS transport for engine<->agent connections (the agent is the TLS
//! server; the engine connects as client).
//!
//! Backed by rustls with the `aws-lc-rs` crypto provider — AWS-LC is
//! FIPS 140-3 validated, so this path can satisfy FedRAMP/FIPS module
//! requirements (unlike pure-Rust crypto crates).

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use rustls_pemfile::{certs, private_key};
pub use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

fn rd(p: &Path) -> io::Result<BufReader<File>> {
    Ok(BufReader::new(File::open(p)?))
}

fn err(msg: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

/// Install the aws-lc-rs process-default provider (idempotent). Called
/// automatically by [`server_config`]; call it explicitly if you build
/// rustls `ServerConfig`s yourself.
pub fn ensure_aws_lc() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Build the agent-side `ServerConfig` from PEM files.
///
/// `client_ca` enables mutual TLS: the engine must present a client
/// certificate chaining to that CA. `None` = server-auth-only TLS.
pub fn server_config(cert: &Path, key: &Path, client_ca: Option<&Path>)
    -> io::Result<Arc<ServerConfig>>
{
    ensure_aws_lc();

    let chain: Vec<CertificateDer<'static>> =
        certs(&mut rd(cert)?).collect::<Result<_, _>>()?;
    if chain.is_empty() {
        return Err(err("cert file has no PEM certificates"));
    }

    let key: PrivateKeyDer<'static> = private_key(&mut rd(key)?)?
        .ok_or_else(|| err("key file has no PEM private key"))?;

    let builder = ServerConfig::builder();
    let builder = match client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in certs(&mut rd(ca)?) {
                roots.add(c?).map_err(err)?;
            }
            let verifier =
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(err)?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    builder.with_single_cert(chain, key).map(Arc::new).map_err(err)
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::TlsConnector;

    struct Pems {
        ca: String,
        srv_crt: String,
        srv_key: String,
        cli_crt: String,
        cli_key: String,
    }

    fn pems() -> Pems {
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["test-ca".into()]).unwrap();
        ca_params.is_ca =
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let srv_params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let srv_key = rcgen::KeyPair::generate().unwrap();
        let srv = srv_params.signed_by(&srv_key, &ca, &ca_key).unwrap();

        let cli_params =
            rcgen::CertificateParams::new(vec!["engine".into()]).unwrap();
        let cli_key = rcgen::KeyPair::generate().unwrap();
        let cli = cli_params.signed_by(&cli_key, &ca, &ca_key).unwrap();

        Pems {
            ca: ca.pem(),
            srv_crt: srv.pem(),
            srv_key: srv_key.serialize_pem(),
            cli_crt: cli.pem(),
            cli_key: cli_key.serialize_pem(),
        }
    }

    fn wr_tmp(name: &str, data: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("xngin-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    fn client_cfg(ca_pem: &str, client: Option<(&str, &str)>)
        -> Arc<ClientConfig>
    {
        let mut roots = RootCertStore::empty();
        for c in certs(&mut ca_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let b = ClientConfig::builder().with_root_certificates(roots);
        let cfg = match client {
            Some((crt, key)) => {
                let chain: Vec<_> = certs(&mut crt.as_bytes())
                    .map(|c| c.unwrap())
                    .collect();
                let k = private_key(&mut key.as_bytes()).unwrap().unwrap();
                b.with_client_auth_cert(chain, k).unwrap()
            }
            None => b.with_no_client_auth(),
        };
        Arc::new(cfg)
    }

    fn cli_connect<S>(cfg: Arc<ClientConfig>, io: S)
        -> impl std::future::Future<
            Output = Result<tokio_rustls::client::TlsStream<S>,
                            io::Error>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        TlsConnector::from(cfg)
            .connect(ServerName::try_from("localhost").unwrap(), io)
    }

    #[tokio::test]
    async fn mtls_handshake_and_data() {
        let p = pems();
        let cfg = server_config(&wr_tmp("srv.pem", &p.srv_crt),
                                &wr_tmp("srv.key", &p.srv_key),
                                Some(&wr_tmp("ca.pem", &p.ca)))
            .unwrap();

        let (cs, ss) = duplex(4096);
        let accept = tokio_rustls::TlsAcceptor::from(cfg).accept(ss);
        let connect = cli_connect(
            client_cfg(&p.ca, Some((&p.cli_crt, &p.cli_key))), cs);

        let (s, c) = tokio::join!(accept, connect);
        let mut s = s.unwrap();
        let mut c = c.unwrap();

        c.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
    }

    #[tokio::test]
    async fn mtls_rejects_certless_client() {
        let p = pems();
        let cfg = server_config(&wr_tmp("srv2.pem", &p.srv_crt),
                                &wr_tmp("srv2.key", &p.srv_key),
                                Some(&wr_tmp("ca2.pem", &p.ca)))
            .unwrap();

        let (cs, ss) = duplex(4096);
        let accept = tokio_rustls::TlsAcceptor::from(cfg).accept(ss);
        let connect = cli_connect(client_cfg(&p.ca, None), cs);

        let (s, c) = tokio::join!(accept, connect);
        assert!(s.is_err() || c.is_err());
    }

    #[tokio::test]
    async fn server_auth_only_accepts_certless() {
        let p = pems();
        let cfg = server_config(&wr_tmp("srv3.pem", &p.srv_crt),
                                &wr_tmp("srv3.key", &p.srv_key),
                                None)
            .unwrap();

        let (cs, ss) = duplex(4096);
        let accept = tokio_rustls::TlsAcceptor::from(cfg).accept(ss);
        let connect = cli_connect(client_cfg(&p.ca, None), cs);

        let (s, c) = tokio::join!(accept, connect);
        s.unwrap();
        c.unwrap();
    }
}
