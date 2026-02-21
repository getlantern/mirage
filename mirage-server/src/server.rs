//! TCP/TLS listener and accept loop.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::ServerConfig;
use crate::connection;
use crate::cover::CoverProxy;
use crate::manifest::ManifestHandle;

/// Run the server accept loop.
pub async fn run(
    config: Arc<ServerConfig>,
    manifest_handle: Option<ManifestHandle>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen_addr).await?;
    info!(addr = %config.listen_addr, tls = config.tls, "listening");

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_sessions));
    let cover = Arc::new(CoverProxy::new(&config));

    // Optional TLS acceptor
    let tls_acceptor = if config.tls {
        Some(build_tls_acceptor(&config)?)
    } else {
        None
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("shutting down listener");
                break;
            }
            result = listener.accept() => {
                let (tcp_stream, peer_addr) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        continue;
                    }
                };

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(%peer_addr, "max sessions reached, dropping");
                        drop(tcp_stream);
                        continue;
                    }
                };

                let config = config.clone();
                let cover = cover.clone();
                let tls_acceptor = tls_acceptor.clone();
                let cancel = cancel.clone();
                let manifest_rx = manifest_handle.as_ref().map(|h| h.clone());

                tokio::spawn(async move {
                    let _permit = permit;

                    let result = match tls_acceptor {
                        Some(acceptor) => {
                            let tls_stream = match acceptor.accept(tcp_stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(%peer_addr, error = %e, "TLS handshake failed");
                                    return;
                                }
                            };
                            connection::handle(
                                tls_stream, peer_addr, config, cover, manifest_rx, cancel,
                            ).await
                        }
                        None => {
                            connection::handle(
                                tcp_stream, peer_addr, config, cover, manifest_rx, cancel,
                            ).await
                        }
                    };

                    if let Err(e) = result {
                        warn!(%peer_addr, error = %e, "connection error");
                    }
                });
            }
        }
    }

    Ok(())
}

fn build_tls_acceptor(
    config: &ServerConfig,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::io::BufReader;
    use tokio_rustls::rustls::{self, ServerConfig as RustlsConfig};

    let cert_path = config.tls_cert_path.as_ref().unwrap();
    let key_path = config.tls_key_path.as_ref().unwrap();

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("open cert {}: {}", cert_path.display(), e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("open key {}: {}", key_path.display(), e))?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
    let keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_file))
        .collect::<Result<Vec<_>, _>>()?;
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let mut tls_config = RustlsConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))?;

    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}
