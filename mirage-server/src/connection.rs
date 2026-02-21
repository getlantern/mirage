//! Per-connection handler: H2 handshake, auth validation, session establishment.
//!
//! Unauthenticated connections are transparently reverse-proxied to the cover
//! site for the full connection lifetime, making the server indistinguishable
//! from the real site it masquerades as.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use h2::server::{self, Connection, SendResponse};
use h2::RecvStream;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mirage_core::crypto;

use crate::config::ServerConfig;
use crate::cover::CoverProxy;
use crate::manifest::ManifestHandle;
use crate::relay;

/// Handle a single connection (post-TLS if applicable).
pub async fn handle<IO>(
    io: IO,
    peer_addr: SocketAddr,
    config: Arc<ServerConfig>,
    cover: Arc<CoverProxy>,
    manifest_handle: Option<ManifestHandle>,
    cancel: CancellationToken,
) -> anyhow::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut h2 = server::handshake(io).await?;
    debug!(%peer_addr, "H2 handshake complete");

    // Accept the first stream — should be the auth request (stream 1).
    let (request, respond) = match h2.accept().await {
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(e.into()),
        None => return Ok(()), // client closed immediately
    };

    let auth_result = try_auth(request, respond, &config, &cover).await;

    let session = match auth_result {
        Ok(s) => s,
        Err(_) => {
            // Auth failed — become a transparent reverse proxy for the cover
            // site. Proxy every subsequent stream until the client disconnects.
            info!(%peer_addr, "unauthenticated, proxying to cover site");
            proxy_remaining_streams(&mut h2, &cover, &cancel).await;
            return Ok(());
        }
    };

    info!(%peer_addr, "authenticated, starting relay");

    // Accept stream 3 — the data tunnel stream.
    let (data_request, data_respond) = match h2.accept().await {
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(e.into()),
        None => return Ok(()),
    };

    relay::run(
        data_request,
        data_respond,
        session,
        config,
        manifest_handle,
        cancel,
    )
    .await?;

    // Drain any remaining streams gracefully.
    while let Some(result) = h2.accept().await {
        if result.is_err() {
            break;
        }
    }

    Ok(())
}

/// Accept and proxy all remaining H2 streams to the cover site.
///
/// Each stream is spawned as a separate task so concurrent requests
/// (which real browsers make) are handled in parallel, matching normal
/// browsing behavior exactly.
async fn proxy_remaining_streams<IO>(
    h2: &mut Connection<IO, Bytes>,
    cover: &Arc<CoverProxy>,
    cancel: &CancellationToken,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = h2.accept() => {
                match accepted {
                    Some(Ok((request, respond))) => {
                        let cover = cover.clone();
                        tokio::spawn(async move {
                            cover.proxy_stream(request, respond).await;
                        });
                    }
                    Some(Err(e)) => {
                        debug!(error = %e, "cover proxy H2 accept error");
                        break;
                    }
                    None => break, // client closed connection
                }
            }
        }
    }
}

/// Attempt to authenticate the first stream.
/// On success, returns an established `Session`.
/// On failure, proxies the request to the cover site and returns Err.
async fn try_auth(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    config: &ServerConfig,
    cover: &CoverProxy,
) -> anyhow::Result<crypto::Session> {
    // Extract the _session cookie from the request headers.
    let auth_b64 = match extract_auth_cookie(&request) {
        Some(v) => v,
        None => {
            // No cookie at all — just a normal browser request. Proxy it.
            cover.proxy_stream(request, respond).await;
            return Err(anyhow::anyhow!("no auth cookie"));
        }
    };

    // Validate auth token and establish session.
    match crypto::Session::from_server_handshake(
        &config.server_private_key,
        &config.psk,
        &auth_b64,
    ) {
        Ok((session, session_token_b64)) => {
            // Send 200 response with set-cookie header containing session token.
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/json; charset=utf-8")
                .header("cache-control", "no-cache, no-store, must-revalidate")
                .header(
                    "set-cookie",
                    format!(
                        "_session={}; Path=/; Secure; HttpOnly; SameSite=Strict",
                        session_token_b64
                    ),
                )
                .header("server", "nginx/1.25.4")
                .body(())
                .unwrap();

            let mut send = respond.send_response(response, false)?;

            // Send a small JSON body to complete the "normal" response.
            let body = Bytes::from_static(
                b"{\"status\":\"ok\",\"version\":\"2.1.0\",\"ts\":1700000000}",
            );
            send.send_data(body, false)?;

            Ok(session)
        }
        Err(_) => {
            // Invalid token — proxy to cover site (indistinguishable from
            // a normal request that happens to have a stale cookie).
            warn!("auth validation failed, proxying to cover site");
            cover.proxy_stream(request, respond).await;
            Err(anyhow::anyhow!("auth failed"))
        }
    }
}

/// Extract the `_session=<value>` from the Cookie header.
fn extract_auth_cookie<T>(request: &Request<T>) -> Option<String> {
    for value in request.headers().get_all("cookie") {
        let s = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for part in s.split(';') {
            let trimmed = part.trim();
            if let Some(val) = trimmed.strip_prefix("_session=") {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}
