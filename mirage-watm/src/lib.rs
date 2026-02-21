//! MIRAGE WATM — Multiplexed Indistinguishable Relaying with Adaptive Gateway Emulation
//!
//! A WATER v1 compatible WebAssembly Transport Module implementing the MIRAGE
//! censorship circumvention protocol.
//!
//! MIRAGE operates as an authenticated overlay within genuine CDN-terminated TLS
//! connections, encoding proxy traffic as standard HTTP/2 frames. This eliminates
//! TLS fingerprinting, encapsulated TLS detection, cross-layer RTT fingerprinting,
//! and active probing as attack vectors.

#![no_main]
#![allow(static_mut_refs)]

pub mod http2;
pub mod wasi_io;

extern crate alloc;
use alloc::vec::Vec;
use core::ffi::c_int;

use mirage_core::config;
use mirage_core::crypto;
use mirage_core::framing;
use mirage_core::traffic_shaper;

// ---------------------------------------------------------------------------
// WATER host imports
// ---------------------------------------------------------------------------

extern "C" {
    /// Request the WATER host to establish a TCP connection.
    fn water_dial(
        network: *const u8,
        network_len: u32,
        address: *const u8,
        address_len: u32,
    ) -> c_int;

    /// Request the WATER host to accept an incoming connection.
    fn water_accept() -> c_int;
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static mut STATE: Option<MirageState> = None;

struct MirageState {
    config: config::MirageConfig,
    ctrl_fd: c_int,
    internal_fd: c_int,
    net_fd: c_int,
    session: Option<crypto::Session>,
    shaper: traffic_shaper::TrafficShaper,
    /// Receive buffer for reassembling HTTP/2 frames from the network.
    recv_buf: Vec<u8>,
    /// Whether we're shutting down.
    shutting_down: bool,
}

// ---------------------------------------------------------------------------
// WATM v1 exported functions
// ---------------------------------------------------------------------------

/// Initialize the transport module. Called once after instantiation.
#[no_mangle]
pub extern "C" fn watm_init_v1() -> c_int {
    // Register WASI clock functions with mirage-core
    mirage_core::clock::set_clock_fns(
        wasi_io::clock_seconds,
        wasi_io::clock_nanos,
    );
    0
}

/// Receive the control pipe file descriptor for configuration delivery.
#[no_mangle]
pub extern "C" fn watm_ctrlpipe_v1(ctrl_fd: c_int) -> c_int {
    match init_from_ctrl_pipe(ctrl_fd) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Establish an outgoing connection (client/dialer mode).
/// `internal_fd` is the application-side pipe; returns the network-side fd.
#[no_mangle]
pub extern "C" fn watm_dial_v1(internal_fd: c_int) -> c_int {
    match dial(internal_fd) {
        Ok(fd) => fd,
        Err(e) => -e,
    }
}

/// Accept an incoming connection (server/listener mode).
/// `internal_fd` is the application-side pipe; returns the network-side fd.
#[no_mangle]
pub extern "C" fn watm_accept_v1(internal_fd: c_int) -> c_int {
    match accept(internal_fd) {
        Ok(fd) => fd,
        Err(e) => -e,
    }
}

/// Associate an incoming connection with an outgoing one (relay mode).
#[no_mangle]
pub extern "C" fn watm_associate_v1() -> c_int {
    // Relay mode: accept from CDN, dial to upstream
    match associate() {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Start the blocking worker loop.
#[no_mangle]
pub extern "C" fn watm_start_v1() -> c_int {
    match event_loop() {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

fn init_from_ctrl_pipe(ctrl_fd: c_int) -> Result<(), c_int> {
    // Read length-prefixed config from the control pipe
    let config_bytes = wasi_io::read_all(ctrl_fd as u32).map_err(|_| 1)?;
    let config: config::MirageConfig =
        postcard::from_bytes(&config_bytes).map_err(|_| 2)?;

    let shaper = traffic_shaper::TrafficShaper::new(&config.traffic_profile);

    unsafe {
        STATE = Some(MirageState {
            config,
            ctrl_fd,
            internal_fd: -1,
            net_fd: -1,
            session: None,
            shaper,
            recv_buf: Vec::with_capacity(65536),
            shutting_down: false,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client-side dial
// ---------------------------------------------------------------------------

fn dial(internal_fd: c_int) -> Result<c_int, c_int> {
    let state = unsafe { STATE.as_mut().ok_or(1)? };
    state.internal_fd = internal_fd;

    // Build the CDN address — use fallback IPs if configured, otherwise hostname
    let addr = if !state.config.cdn_ips.is_empty() {
        alloc::format!("{}:443", state.config.cdn_ips[0])
    } else {
        alloc::format!("{}:443", state.config.cdn_hostname)
    };

    // Ask WATER host to establish TCP connection to the CDN
    let net_fd = unsafe {
        water_dial(
            b"tcp".as_ptr(),
            3,
            addr.as_ptr(),
            addr.len() as u32,
        )
    };
    if net_fd < 0 {
        return Err(3);
    }
    state.net_fd = net_fd;

    // Perform client handshake
    perform_client_handshake(state)?;

    Ok(net_fd)
}

// ---------------------------------------------------------------------------
// Server-side accept
// ---------------------------------------------------------------------------

fn accept(internal_fd: c_int) -> Result<c_int, c_int> {
    let state = unsafe { STATE.as_mut().ok_or(1)? };
    state.internal_fd = internal_fd;

    let net_fd = unsafe { water_accept() };
    if net_fd < 0 {
        return Err(3);
    }
    state.net_fd = net_fd;

    perform_server_handshake(state)?;

    Ok(net_fd)
}

// ---------------------------------------------------------------------------
// Relay / associate mode
// ---------------------------------------------------------------------------

fn associate() -> Result<(), c_int> {
    // In relay mode, the WATER host has already set up both fds.
    // We just need to prepare state for the event loop.
    Ok(())
}

// ---------------------------------------------------------------------------
// Client handshake
// ---------------------------------------------------------------------------

fn perform_client_handshake(state: &mut MirageState) -> Result<(), c_int> {
    let net_fd = state.net_fd as u32;

    // Step 1: Send HTTP/2 connection preface
    wasi_io::write_all(net_fd, http2::CONNECTION_PREFACE).map_err(|_| 10)?;

    // Step 2: Send SETTINGS frame
    let settings = http2::encode_settings(&http2::default_client_settings());
    wasi_io::write_all(net_fd, &settings).map_err(|_| 11)?;

    // Step 3: Send connection-level WINDOW_UPDATE for large receive window
    http2::send_initial_window_update(net_fd).map_err(|_| 11)?;

    // Step 4: Generate authentication token
    let (auth_token, client_ephemeral_secret) = crypto::AuthToken::generate(
        &state.config.server_public_key,
        &state.config.psk,
    );
    let auth_b64 = auth_token.to_base64();

    // Step 5: Build and send authentication request as HTTP/2 HEADERS
    let path = alloc::format!(
        "{}config?t={}&v=1",
        state.config.origin_path_prefix,
        auth_token.timestamp
    );
    let headers_frame = http2::encode_request_headers(
        1, // stream_id 1 for the auth request
        &state.config.cdn_hostname,
        &path,
        &auth_b64,
    );
    wasi_io::write_all(net_fd, &headers_frame).map_err(|_| 12)?;

    // Step 6: Read server response frames until we get a HEADERS + DATA
    // The server responds with: SETTINGS + SETTINGS ACK + HEADERS (with set-cookie) + DATA
    let mut got_session_cookie = None;
    let mut frames_read = 0;
    let max_frames = 20; // Safety limit

    while got_session_cookie.is_none() && frames_read < max_frames {
        let frame = http2::read_frame(net_fd).map_err(|_| 13)?;
        frames_read += 1;

        match frame.frame_type {
            http2::frame_type::SETTINGS => {
                if frame.flags & http2::flags::ACK == 0 {
                    // Send SETTINGS ACK
                    let ack = http2::encode_settings_ack();
                    wasi_io::write_all(net_fd, &ack).map_err(|_| 13)?;
                }
            }
            http2::frame_type::HEADERS => {
                // Try to extract session cookie from the HEADERS payload
                if let Some(cookie) = http2::extract_session_cookie(&frame.payload) {
                    got_session_cookie = Some(cookie);
                }
            }
            http2::frame_type::DATA => {
                // The response body — if we haven't found the cookie in
                // HEADERS yet, check the raw frame bytes too
                if got_session_cookie.is_none() {
                    // Cookie should be in HEADERS, not DATA. Continue.
                }
            }
            http2::frame_type::WINDOW_UPDATE => {}
            http2::frame_type::PING => {
                if frame.flags & http2::flags::ACK == 0 && frame.payload.len() == 8 {
                    let mut opaque = [0u8; 8];
                    opaque.copy_from_slice(&frame.payload);
                    let pong = http2::encode_ping_ack(&opaque);
                    wasi_io::write_all(net_fd, &pong).map_err(|_| 13)?;
                }
            }
            _ => {} // Skip unknown frames
        }
    }

    let session_token = got_session_cookie.ok_or(14)?;

    // Step 7: Derive session keys
    let session = crypto::Session::from_client_handshake(
        &client_ephemeral_secret,
        &state.config.server_public_key,
        &state.config.psk,
        &auth_token,
        &session_token,
    )
    .map_err(|_| 15)?;

    state.session = Some(session);
    Ok(())
}

// ---------------------------------------------------------------------------
// Server handshake
// ---------------------------------------------------------------------------

fn perform_server_handshake(state: &mut MirageState) -> Result<(), c_int> {
    let net_fd = state.net_fd as u32;

    // Step 1: Read and verify HTTP/2 connection preface (24 bytes)
    let mut preface_buf = [0u8; 24];
    wasi_io::read_exact(net_fd, &mut preface_buf).map_err(|_| 20)?;

    if &preface_buf != http2::CONNECTION_PREFACE {
        // Not valid HTTP/2 — serve cover site or reject
        return Err(21);
    }

    // Step 2: Read client's SETTINGS frame
    let settings_frame = http2::read_frame(net_fd).map_err(|_| 22)?;
    if settings_frame.frame_type != http2::frame_type::SETTINGS {
        return Err(22);
    }

    // Step 3: Send our SETTINGS
    let our_settings = http2::encode_settings(&http2::default_client_settings());
    wasi_io::write_all(net_fd, &our_settings).map_err(|_| 22)?;

    // Step 4: Send SETTINGS ACK for client's settings
    let ack = http2::encode_settings_ack();
    wasi_io::write_all(net_fd, &ack).map_err(|_| 22)?;

    // Step 5: Send connection-level WINDOW_UPDATE
    http2::send_initial_window_update(net_fd).map_err(|_| 22)?;

    // Step 6: Read frames until we get the auth HEADERS request
    let mut auth_cookie = None;
    let mut frames_read = 0;
    let max_frames = 20;

    while auth_cookie.is_none() && frames_read < max_frames {
        let frame = http2::read_frame(net_fd).map_err(|_| 23)?;
        frames_read += 1;

        match frame.frame_type {
            http2::frame_type::HEADERS => {
                // Extract auth token from cookie header in HPACK payload
                if let Some(cookie) = http2::extract_auth_cookie(&frame.payload) {
                    auth_cookie = Some(cookie);
                }
            }
            http2::frame_type::SETTINGS => {
                if frame.flags & http2::flags::ACK == 0 {
                    let ack = http2::encode_settings_ack();
                    wasi_io::write_all(net_fd, &ack).map_err(|_| 23)?;
                }
            }
            http2::frame_type::WINDOW_UPDATE => {}
            _ => {}
        }
    }

    let auth_b64 = auth_cookie.ok_or(23)?;

    // Step 7: Validate authentication and establish session
    let server_secret = state.config.server_private_key.as_ref().ok_or(24)?;
    let (session, response_token) = crypto::Session::from_server_handshake(
        server_secret,
        &state.config.psk,
        &auth_b64,
    )
    .map_err(|_| 24)?;

    // Step 8: Send response with session cookie
    let response_frame = http2::encode_response_with_cookie(1, &response_token);
    wasi_io::write_all(net_fd, &response_frame).map_err(|_| 25)?;

    state.session = Some(session);
    Ok(())
}

// ---------------------------------------------------------------------------
// Main event loop
// ---------------------------------------------------------------------------

/// Helper macro to get session from state, avoiding borrow issues.
impl MirageState {
    fn session_mut(&mut self) -> Result<&mut crypto::Session, c_int> {
        self.session.as_mut().ok_or(2)
    }
}

fn event_loop() -> Result<(), c_int> {
    let state = unsafe { STATE.as_mut().ok_or(1)? };
    if state.session.is_none() {
        return Err(2);
    }

    let internal_fd = state.internal_fd as u32;
    let net_fd = state.net_fd as u32;
    let data_stream_id = state.session.as_ref().unwrap().data_stream_id();

    let mut app_buf = [0u8; 16384];
    let mut net_buf = [0u8; 65536];

    loop {
        if state.shutting_down {
            return Ok(());
        }

        let timeout_ns: u64 = 1_000_000_000; // 1 second
        let ready_fds =
            wasi_io::poll_read_timeout(&[internal_fd, net_fd], timeout_ns)
                .map_err(|_| 30)?;

        if ready_fds.is_empty() {
            maybe_send_padding(state, net_fd, data_stream_id)?;
            check_key_rotation(state, net_fd, data_stream_id)?;
            continue;
        }

        for &fd in &ready_fds {
            if fd == internal_fd {
                handle_app_data(state, internal_fd, net_fd, data_stream_id, &mut app_buf)?;
            } else if fd == net_fd {
                handle_net_data(state, internal_fd, net_fd, data_stream_id, &mut net_buf)?;
            }
        }

        maybe_send_padding(state, net_fd, data_stream_id)?;
        check_key_rotation(state, net_fd, data_stream_id)?;
    }
}

/// Handle data from the application (internal_fd -> encrypt -> network).
fn handle_app_data(
    state: &mut MirageState,
    internal_fd: u32,
    net_fd: u32,
    stream_id: u32,
    buf: &mut [u8],
) -> Result<(), c_int> {
    let n = wasi_io::read(internal_fd, buf).map_err(|_| 31)?;
    if n == 0 {
        // Application closed — send MIRAGE Close frame + HTTP/2 GOAWAY
        let session = state.session_mut()?;
        let close_frame = session.encrypt_frame(framing::FrameType::Close as u8, &[]);
        let http2_data = http2::encode_data_frame(stream_id, &close_frame);
        wasi_io::write_all(net_fd, &http2_data).map_err(|_| 32)?;

        let goaway = http2::encode_goaway(stream_id, http2::error_code::NO_ERROR);
        wasi_io::write_all(net_fd, &goaway).map_err(|_| 32)?;

        state.shutting_down = true;
        return Ok(());
    }

    // Encrypt the application data
    let session = state.session_mut()?;
    let mirage_frame = session.encrypt_frame(framing::FrameType::Data as u8, &buf[..n]);

    // Apply traffic shaping
    let shaped = state.shaper.shape_outbound(&mirage_frame);

    for chunk in shaped {
        let http2_data = http2::encode_data_frame(stream_id, &chunk);
        wasi_io::write_all(net_fd, &http2_data).map_err(|_| 33)?;
    }

    Ok(())
}

/// Handle data from the network (network -> HTTP/2 parse -> decrypt -> application).
fn handle_net_data(
    state: &mut MirageState,
    internal_fd: u32,
    net_fd: u32,
    stream_id: u32,
    buf: &mut [u8],
) -> Result<(), c_int> {
    let n = wasi_io::read(net_fd, buf).map_err(|_| 34)?;
    if n == 0 {
        state.shutting_down = true;
        return Ok(());
    }

    state.recv_buf.extend_from_slice(&buf[..n]);

    // Process complete HTTP/2 frames from the reassembly buffer
    loop {
        let frame = match http2::try_parse_frame(&state.recv_buf) {
            Some((frame, consumed)) => {
                state.recv_buf.drain(..consumed);
                frame
            }
            None => break,
        };

        match frame.frame_type {
            http2::frame_type::DATA => {
                if frame.payload.is_empty() {
                    continue;
                }

                // Replenish flow control windows
                if frame.length > 0 {
                    let wu_conn = http2::encode_window_update(0, frame.length);
                    wasi_io::write_all(net_fd, &wu_conn).map_err(|_| 34)?;
                    if frame.stream_id != 0 {
                        let wu_stream = http2::encode_window_update(frame.stream_id, frame.length);
                        wasi_io::write_all(net_fd, &wu_stream).map_err(|_| 34)?;
                    }
                }

                // Parse MIRAGE frames from the DATA payload
                let mut payload = &frame.payload[..];
                while let Some((_ft, _len, _seq, total)) =
                    framing::try_parse_frame_header(payload)
                {
                    let mirage_frame_bytes = &payload[..total];
                    payload = &payload[total..];

                    let session = state.session_mut()?;
                    match session.decrypt_frame(mirage_frame_bytes) {
                        Ok((frame_type, plaintext)) => {
                            dispatch_mirage_frame(
                                state, internal_fd, net_fd,
                                stream_id, frame_type, &plaintext,
                            )?;
                        }
                        Err(_) => {
                            state.shutting_down = true;
                            return Err(38);
                        }
                    }
                }
            }
            http2::frame_type::SETTINGS => {
                if frame.flags & http2::flags::ACK == 0 {
                    let ack = http2::encode_settings_ack();
                    wasi_io::write_all(net_fd, &ack).map_err(|_| 34)?;
                }
            }
            http2::frame_type::PING => {
                if frame.flags & http2::flags::ACK == 0 && frame.payload.len() == 8 {
                    let mut opaque = [0u8; 8];
                    opaque.copy_from_slice(&frame.payload);
                    let pong = http2::encode_ping_ack(&opaque);
                    wasi_io::write_all(net_fd, &pong).map_err(|_| 34)?;
                }
            }
            http2::frame_type::WINDOW_UPDATE => {}
            http2::frame_type::GOAWAY => {
                state.shutting_down = true;
                return Ok(());
            }
            http2::frame_type::RST_STREAM => {
                if frame.stream_id == stream_id {
                    state.shutting_down = true;
                    return Ok(());
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Dispatch a decrypted MIRAGE frame to the appropriate handler.
fn dispatch_mirage_frame(
    state: &mut MirageState,
    internal_fd: u32,
    net_fd: u32,
    stream_id: u32,
    frame_type: u8,
    plaintext: &[u8],
) -> Result<(), c_int> {
    match framing::FrameType::from_u8(frame_type) {
        Some(framing::FrameType::Data) => {
            if !plaintext.is_empty() {
                wasi_io::write_all(internal_fd, plaintext).map_err(|_| 35)?;
            }
        }
        Some(framing::FrameType::Connect) => {
            handle_connect_request(state, net_fd, stream_id, plaintext)?;
        }
        Some(framing::FrameType::ConnectOk) => {}
        Some(framing::FrameType::ConnectErr) => {
            state.shutting_down = true;
        }
        Some(framing::FrameType::Ping) => {
            let session = state.session_mut()?;
            let pong = session.encrypt_frame(framing::FrameType::Pong as u8, plaintext);
            let http2_pong = http2::encode_data_frame(stream_id, &pong);
            wasi_io::write_all(net_fd, &http2_pong).map_err(|_| 36)?;
        }
        Some(framing::FrameType::Pong) => {}
        Some(framing::FrameType::KeyRotate) => {
            let session = state.session_mut()?;
            let ack_payload = session.handle_key_rotation(plaintext).map_err(|_| 37)?;
            let ack_frame = session.encrypt_frame(framing::FrameType::KeyAck as u8, &ack_payload);
            let http2_ack = http2::encode_data_frame(stream_id, &ack_frame);
            wasi_io::write_all(net_fd, &http2_ack).map_err(|_| 37)?;
        }
        Some(framing::FrameType::KeyAck) => {
            let session = state.session_mut()?;
            session.handle_key_ack(plaintext).map_err(|_| 37)?;
        }
        Some(framing::FrameType::Close) => {
            state.shutting_down = true;
        }
        Some(framing::FrameType::Pad) => {}
        Some(framing::FrameType::DomainUpdate) => {
            // Deserialize the DomainUpdate from the plaintext and forward
            // it to the WATER host via the control pipe as a ControlMessage.
            if let Ok(domain_update) =
                postcard::from_bytes::<config::DomainUpdate>(plaintext)
            {
                let ctrl_msg = config::ControlMessage::DomainUpdate(domain_update);
                if let Ok(encoded) = postcard::to_allocvec(&ctrl_msg) {
                    let ctrl_fd = state.ctrl_fd as u32;
                    let _ = wasi_io::write_all(ctrl_fd, &encoded);
                }
            }
        }
        Some(framing::FrameType::DomainReport) => {
            // Client does not handle DomainReport frames (server-side only).
        }
        None => {}
    }
    Ok(())
}

/// Handle a CONNECT request from a client (server-side only).
fn handle_connect_request(
    state: &mut MirageState,
    net_fd: u32,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), c_int> {
    let (addr_type, addr_bytes, port) =
        framing::parse_connect_payload(payload).ok_or(40)?;

    // Build the target address string
    let target = match addr_type {
        framing::AddressType::IPv4 => {
            if addr_bytes.len() != 4 {
                return Err(40);
            }
            alloc::format!(
                "{}.{}.{}.{}:{}",
                addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                port
            )
        }
        framing::AddressType::IPv6 => {
            // Simplified: format as hex pairs
            let mut s = alloc::string::String::from("[");
            for (i, chunk) in addr_bytes.chunks(2).enumerate() {
                if i > 0 {
                    s.push(':');
                }
                s.push_str(&alloc::format!("{:02x}{:02x}", chunk[0], chunk[1]));
            }
            s.push_str(&alloc::format!("]:{}", port));
            s
        }
        framing::AddressType::Domain => {
            let domain = core::str::from_utf8(addr_bytes).map_err(|_| 40)?;
            alloc::format!("{}:{}", domain, port)
        }
    };

    // Ask WATER host to dial the upstream target
    let upstream_fd = unsafe {
        water_dial(
            b"tcp".as_ptr(),
            3,
            target.as_ptr(),
            target.len() as u32,
        )
    };

    if upstream_fd < 0 {
        // Send CONNECT_ERR
        let session = state.session_mut()?;
        let err_frame = session.encrypt_frame(
            framing::FrameType::ConnectErr as u8,
            &[0x01], // Generic connection error
        );
        let http2_err = http2::encode_data_frame(stream_id, &err_frame);
        wasi_io::write_all(net_fd, &http2_err).map_err(|_| 41)?;
        return Err(41);
    }

    // Send CONNECT_OK
    let session = state.session_mut()?;
    let ok_frame = session.encrypt_frame(
        framing::FrameType::ConnectOk as u8,
        &[],
    );
    let http2_ok = http2::encode_data_frame(stream_id, &ok_frame);
    wasi_io::write_all(net_fd, &http2_ok).map_err(|_| 41)?;

    // Update internal_fd to point to the upstream connection
    // (subsequent Data frames are relayed to/from this upstream)
    let state = unsafe { STATE.as_mut().ok_or(1)? };
    state.internal_fd = upstream_fd;

    Ok(())
}

/// Generate and send padding traffic if the shaper decides it's time.
fn maybe_send_padding(
    state: &mut MirageState,
    net_fd: u32,
    stream_id: u32,
) -> Result<(), c_int> {
    if let Some(padding) = state.shaper.maybe_generate_padding() {
        let session = state.session_mut()?;
        let pad_frame = session.encrypt_frame(
            framing::FrameType::Pad as u8,
            &padding,
        );
        let http2_pad = http2::encode_data_frame(stream_id, &pad_frame);
        wasi_io::write_all(net_fd, &http2_pad).map_err(|_| 39)?;
    }
    Ok(())
}

/// Check and initiate key rotation if needed.
fn check_key_rotation(
    state: &mut MirageState,
    net_fd: u32,
    stream_id: u32,
) -> Result<(), c_int> {
    let session = state.session_mut()?;
    if session.needs_key_rotation() {
        let rotate_payload = session.initiate_key_rotation()
            .map_err(|_| 40)?;
        let rotate_frame = session.encrypt_frame(
            framing::FrameType::KeyRotate as u8,
            &rotate_payload,
        );
        let http2_rotate = http2::encode_data_frame(stream_id, &rotate_frame);
        wasi_io::write_all(net_fd, &http2_rotate).map_err(|_| 40)?;
    }
    Ok(())
}
