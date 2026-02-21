//! Bidirectional data relay: H2 stream <-> upstream TCP.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use mirage_core::config::{DomainUpdate, TrafficProfileConfig};
use mirage_core::crypto::Session;
use mirage_core::framing::{self, FrameType};
use mirage_core::traffic_shaper::TrafficShaper;

use crate::config::ServerConfig;
use crate::manifest::{self, ManifestHandle};

/// Run the data relay on stream 3.
pub async fn run(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    mut session: Session,
    config: Arc<ServerConfig>,
    manifest_handle: Option<ManifestHandle>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    // Send 200 OK response on the data stream to keep it open.
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();
    let mut send_stream = respond.send_response(response, false)?;
    let mut recv_stream = request.into_body();

    let mut shaper = TrafficShaper::new(&TrafficProfileConfig::default());
    let _idle_timeout = Duration::from_secs(config.session_idle_timeout_secs);
    let connect_timeout = Duration::from_secs(config.upstream_connect_timeout_secs);

    // Upstream TCP connection (established on CONNECT frame).
    let mut upstream: Option<TcpStream> = None;
    let mut upstream_buf = vec![0u8; 16384];

    // MIRAGE frame reassembly buffer for DATA payloads that may span H2 DATA frames.
    let mut mirage_buf = Vec::with_capacity(65536);

    // Push current domain manifest to the client if available.
    if let Some(ref mh) = manifest_handle {
        if let Some(ref manifest) = *mh.borrow() {
            let update = DomainUpdate::Full(manifest.as_ref().clone());
            let payload = manifest::encode_domain_update(&update);
            let frame = session.encrypt_frame(FrameType::DomainUpdate as u8, &payload);
            let shaped = shaper.shape_outbound(&frame);
            for chunk in shaped {
                let _ = send_stream.send_data(Bytes::from(chunk), false);
            }
            debug!(version = manifest.version, "pushed domain manifest to client");
        }
    }

    // Padding timer: check every second.
    let mut padding_interval = interval(Duration::from_secs(1));
    padding_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Build the select based on whether we have an upstream connection.
        tokio::select! {
            _ = cancel.cancelled() => {
                // Graceful shutdown: send Close frame.
                let close = session.encrypt_frame(FrameType::Close as u8, &[]);
                let _ = send_stream.send_data(Bytes::from(close), false);
                break;
            }

            // Read from H2 recv_stream (client -> server).
            h2_data = recv_stream.data() => {
                match h2_data {
                    Some(Ok(data)) => {
                        // Release flow control capacity.
                        let len: usize = data.len();
                        if len > 0 {
                            let _ = recv_stream.flow_control().release_capacity(len);
                        }

                        mirage_buf.extend_from_slice(&data);

                        // Parse complete MIRAGE frames from the buffer.
                        while let Some((_ft, _len, _seq, total)) =
                            framing::try_parse_frame_header(&mirage_buf)
                        {
                            let frame_bytes: Vec<u8> = mirage_buf.drain(..total).collect();

                            match session.decrypt_frame(&frame_bytes) {
                                Ok((frame_type, plaintext)) => {
                                    match FrameType::from_u8(frame_type) {
                                        Some(FrameType::Data) => {
                                            if let Some(ref mut up) = upstream {
                                                if let Err(e) = up.write_all(&plaintext).await {
                                                    warn!(error = %e, "upstream write failed");
                                                    break;
                                                }
                                            }
                                        }
                                        Some(FrameType::Connect) => {
                                            upstream = handle_connect(
                                                &plaintext,
                                                &mut session,
                                                &mut send_stream,
                                                &mut shaper,
                                                connect_timeout,
                                            ).await;
                                        }
                                        Some(FrameType::Ping) => {
                                            let pong = session.encrypt_frame(FrameType::Pong as u8, &plaintext);
                                            let shaped = shaper.shape_outbound(&pong);
                                            for chunk in shaped {
                                                let _ = send_stream.send_data(Bytes::from(chunk), false);
                                            }
                                        }
                                        Some(FrameType::KeyRotate) => {
                                            match session.handle_key_rotation(&plaintext) {
                                                Ok(ack_payload) => {
                                                    let ack = session.encrypt_frame(FrameType::KeyAck as u8, &ack_payload);
                                                    let _ = send_stream.send_data(Bytes::from(ack), false);
                                                }
                                                Err(e) => {
                                                    warn!(error = ?e, "key rotation failed");
                                                    break;
                                                }
                                            }
                                        }
                                        Some(FrameType::KeyAck) => {
                                            if let Err(e) = session.handle_key_ack(&plaintext) {
                                                warn!(error = ?e, "key ack failed");
                                                break;
                                            }
                                        }
                                        Some(FrameType::Close) => {
                                            debug!("received Close frame");
                                            return Ok(());
                                        }
                                        Some(FrameType::Pad) => {} // discard
                                        Some(FrameType::DomainReport) => {
                                            debug!(
                                                payload_len = plaintext.len(),
                                                "received DomainReport from client"
                                            );
                                        }
                                        Some(FrameType::DomainUpdate) => {} // server-originated only
                                        _ => {}
                                    }
                                }
                                Err(e) => {
                                    warn!(error = ?e, "decrypt failed");
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        debug!(error = %e, "H2 recv error");
                        break;
                    }
                    None => {
                        debug!("H2 stream ended");
                        break;
                    }
                }
            }

            // Read from upstream TCP (upstream -> client).
            upstream_data = async {
                match upstream.as_mut() {
                    Some(up) => up.read(&mut upstream_buf).await,
                    None => {
                        // No upstream yet; pend forever.
                        std::future::pending::<std::io::Result<usize>>().await
                    }
                }
            } => {
                match upstream_data {
                    Ok(0) => {
                        // Upstream closed.
                        let close = session.encrypt_frame(FrameType::Close as u8, &[]);
                        let _ = send_stream.send_data(Bytes::from(close), false);
                        upstream = None;
                    }
                    Ok(n) => {
                        let data_frame = session.encrypt_frame(
                            FrameType::Data as u8,
                            &upstream_buf[..n],
                        );
                        let shaped = shaper.shape_outbound(&data_frame);
                        for chunk in shaped {
                            if let Err(e) = send_stream.send_data(Bytes::from(chunk), false) {
                                warn!(error = %e, "H2 send failed");
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "upstream read error");
                        upstream = None;
                    }
                }
            }

            // Periodic padding + key rotation check.
            _ = padding_interval.tick() => {
                if let Some(padding) = shaper.maybe_generate_padding() {
                    let pad_frame = session.encrypt_frame(FrameType::Pad as u8, &padding);
                    let _ = send_stream.send_data(Bytes::from(pad_frame), false);
                }

                if session.needs_key_rotation() {
                    if let Ok(rotate_payload) = session.initiate_key_rotation() {
                        let rotate_frame = session.encrypt_frame(
                            FrameType::KeyRotate as u8,
                            &rotate_payload,
                        );
                        let _ = send_stream.send_data(Bytes::from(rotate_frame), false);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a CONNECT frame: parse target, connect upstream, send ConnectOk/Err.
async fn handle_connect(
    payload: &[u8],
    session: &mut Session,
    send_stream: &mut h2::SendStream<Bytes>,
    shaper: &mut TrafficShaper,
    connect_timeout: Duration,
) -> Option<TcpStream> {
    let (addr_type, addr_bytes, port) = framing::parse_connect_payload(payload)?;

    let target = match addr_type {
        framing::AddressType::IPv4 => {
            if addr_bytes.len() != 4 {
                return None;
            }
            format!(
                "{}.{}.{}.{}:{}",
                addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], port
            )
        }
        framing::AddressType::IPv6 => {
            if addr_bytes.len() != 16 {
                return None;
            }
            let mut s = String::from("[");
            for (i, chunk) in addr_bytes.chunks(2).enumerate() {
                if i > 0 {
                    s.push(':');
                }
                s.push_str(&format!("{:02x}{:02x}", chunk[0], chunk[1]));
            }
            s.push_str(&format!("]:{}", port));
            s
        }
        framing::AddressType::Domain => {
            let domain = std::str::from_utf8(addr_bytes).ok()?;
            format!("{}:{}", domain, port)
        }
    };

    debug!(target = %target, "CONNECT request");

    match timeout(connect_timeout, TcpStream::connect(&target)).await {
        Ok(Ok(stream)) => {
            let ok_frame = session.encrypt_frame(FrameType::ConnectOk as u8, &[]);
            let shaped = shaper.shape_outbound(&ok_frame);
            for chunk in shaped {
                let _ = send_stream.send_data(Bytes::from(chunk), false);
            }
            Some(stream)
        }
        Ok(Err(e)) => {
            warn!(target = %target, error = %e, "upstream connect failed");
            let err_frame = session.encrypt_frame(FrameType::ConnectErr as u8, &[0x01]);
            let _ = send_stream.send_data(Bytes::from(err_frame), false);
            None
        }
        Err(_) => {
            warn!(target = %target, "upstream connect timed out");
            let err_frame = session.encrypt_frame(FrameType::ConnectErr as u8, &[0x02]);
            let _ = send_stream.send_data(Bytes::from(err_frame), false);
            None
        }
    }
}
