//! Cover site reverse proxy for unauthenticated connections.
//!
//! When authentication fails, the server becomes a transparent reverse proxy
//! for the configured cover site origin. Every H2 stream is forwarded —
//! method, path, headers, body — so the connection is indistinguishable from
//! a real visitor browsing the cover site.

use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::Request;
use tracing::{debug, warn};

use crate::config::ServerConfig;

/// Headers forwarded from the client request to the cover site.
const FORWARD_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "referer",
    "if-modified-since",
    "if-none-match",
    "range",
    "cookie",
];

/// Headers forwarded from the cover site response back to the client.
const FORWARD_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "content-length",
    "cache-control",
    "etag",
    "last-modified",
    "date",
    "server",
    "vary",
    "content-language",
    "set-cookie",
    "location",
    "x-frame-options",
    "strict-transport-security",
    "content-security-policy",
];

/// Transparent reverse proxy to the configured cover site origin.
pub struct CoverProxy {
    client: reqwest::Client,
    origin: String,
}

impl CoverProxy {
    pub fn new(config: &ServerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.cover_site_timeout_secs))
            .redirect(reqwest::redirect::Policy::none()) // let client follow redirects itself
            .build()
            .expect("reqwest client");

        CoverProxy {
            client,
            origin: config.cover_site_origin.clone(),
        }
    }

    /// Proxy a single H2 stream to the cover site.
    ///
    /// Forwards the full request (method, path, headers, body) and streams
    /// the cover site's response back to the client.
    pub async fn proxy_stream(
        &self,
        request: Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) {
        let method = request.method().clone();
        let path = request
            .uri()
            .path_and_query()
            .map(|pq: &http::uri::PathAndQuery| pq.as_str())
            .unwrap_or("/");
        let url = format!("{}{}", self.origin, path);

        // Build the outbound request to the cover site.
        let mut upstream_req = self.client.request(
            reqwest::Method::from_bytes(method.as_str().as_bytes())
                .unwrap_or(reqwest::Method::GET),
            &url,
        );

        // Forward selected client headers.
        for &name in FORWARD_REQUEST_HEADERS {
            for val in request.headers().get_all(name) {
                if let Ok(s) = val.to_str() {
                    upstream_req = upstream_req.header(name, s);
                }
            }
        }

        // Collect the request body (if any).
        let mut recv = request.into_body();
        let mut body_bytes = Vec::new();
        while let Some(chunk) = recv.data().await {
            match chunk {
                Ok(data) => {
                    let len = data.len();
                    body_bytes.extend_from_slice(&data);
                    let _ = recv.flow_control().release_capacity(len);
                }
                Err(_) => break,
            }
        }
        if !body_bytes.is_empty() {
            upstream_req = upstream_req.body(body_bytes);
        }

        debug!(url = %url, method = %method, "proxying to cover site");

        match upstream_req.send().await {
            Ok(upstream_resp) => {
                let status = upstream_resp.status().as_u16();
                let mut builder = http::Response::builder().status(status);

                for &name in FORWARD_RESPONSE_HEADERS {
                    for val in upstream_resp.headers().get_all(name) {
                        builder = builder.header(name, val.as_bytes());
                    }
                }

                let response = builder.body(()).unwrap();
                match respond.send_response(response, false) {
                    Ok(mut send) => {
                        match upstream_resp.bytes().await {
                            Ok(body) if !body.is_empty() => {
                                let _ = send.send_data(
                                    Bytes::from(body.to_vec()),
                                    true,
                                );
                            }
                            _ => {
                                let _ = send.send_data(Bytes::new(), true);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to send cover response");
                    }
                }
            }
            Err(e) => {
                warn!(url = %url, error = %e, "cover site upstream failed");
                let response = http::Response::builder()
                    .status(503)
                    .header("content-type", "text/html")
                    .header("server", "nginx/1.25.4")
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(response, false) {
                    let body = Bytes::from_static(
                        b"<html><body><h1>503 Service Temporarily Unavailable</h1></body></html>",
                    );
                    let _ = send.send_data(body, true);
                }
            }
        }
    }
}
