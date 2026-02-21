//! Minimal HTTP/2 framing for the MIRAGE protocol.
//!
//! Implements only the HTTP/2 frame types needed by MIRAGE:
//! - HEADERS (type 0x01): for request/response headers
//! - DATA (type 0x00): for carrying MIRAGE encrypted payloads
//! - SETTINGS (type 0x04): for connection setup
//! - WINDOW_UPDATE (type 0x08): for flow control
//! - GOAWAY (type 0x07): for connection teardown
//!
//! This is NOT a full HTTP/2 implementation. It constructs valid HTTP/2 frames
//! that carry MIRAGE data while looking like normal web traffic to any observer.

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// HTTP/2 connection preface (RFC 9113, Section 3.4).
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame types.
#[allow(dead_code)]
pub mod frame_type {
    pub const DATA: u8 = 0x00;
    pub const HEADERS: u8 = 0x01;
    pub const PRIORITY: u8 = 0x02;
    pub const RST_STREAM: u8 = 0x03;
    pub const SETTINGS: u8 = 0x04;
    pub const PUSH_PROMISE: u8 = 0x05;
    pub const PING: u8 = 0x06;
    pub const GOAWAY: u8 = 0x07;
    pub const WINDOW_UPDATE: u8 = 0x08;
    pub const CONTINUATION: u8 = 0x09;
}

/// HTTP/2 frame header size (9 bytes: length(3) + type(1) + flags(1) + stream_id(4)).
pub const FRAME_HEADER_SIZE: usize = 9;

/// Default HTTP/2 initial window size.
pub const DEFAULT_WINDOW_SIZE: u32 = 65535;

/// Large window size we request to avoid flow control stalls.
pub const LARGE_WINDOW_SIZE: u32 = 16_777_215; // 2^24 - 1

/// HTTP/2 frame flags.
#[allow(dead_code)]
pub mod flags {
    pub const END_STREAM: u8 = 0x01;
    pub const ACK: u8 = 0x01; // Same bit, used for SETTINGS/PING
    pub const END_HEADERS: u8 = 0x04;
    pub const PADDED: u8 = 0x08;
    pub const PRIORITY_FLAG: u8 = 0x20;
}

/// HTTP/2 settings identifiers.
#[allow(dead_code)]
mod settings_id {
    pub const HEADER_TABLE_SIZE: u16 = 0x01;
    pub const ENABLE_PUSH: u16 = 0x02;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x03;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x04;
    pub const MAX_FRAME_SIZE: u16 = 0x05;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x06;
}

/// HTTP/2 error codes.
#[allow(dead_code)]
pub mod error_code {
    pub const NO_ERROR: u32 = 0x00;
    pub const PROTOCOL_ERROR: u32 = 0x01;
    pub const FLOW_CONTROL_ERROR: u32 = 0x03;
    pub const ENHANCE_YOUR_CALM: u32 = 0x0B;
}

/// A parsed HTTP/2 frame.
pub struct H2Frame {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Frame encoding
// ---------------------------------------------------------------------------

/// Encode an HTTP/2 frame header.
fn encode_frame_header(length: u32, ftype: u8, flags: u8, stream_id: u32) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = ((length >> 16) & 0xFF) as u8;
    header[1] = ((length >> 8) & 0xFF) as u8;
    header[2] = (length & 0xFF) as u8;
    header[3] = ftype;
    header[4] = flags;
    let sid = stream_id & 0x7FFF_FFFF;
    header[5] = ((sid >> 24) & 0xFF) as u8;
    header[6] = ((sid >> 16) & 0xFF) as u8;
    header[7] = ((sid >> 8) & 0xFF) as u8;
    header[8] = (sid & 0xFF) as u8;
    header
}

/// Realistic Chrome-like client settings.
pub fn default_client_settings() -> Vec<(u16, u32)> {
    vec![
        (settings_id::HEADER_TABLE_SIZE, 65536),
        (settings_id::ENABLE_PUSH, 0),
        (settings_id::MAX_CONCURRENT_STREAMS, 100),
        (settings_id::INITIAL_WINDOW_SIZE, 6291456),
        (settings_id::MAX_FRAME_SIZE, 16384),
        (settings_id::MAX_HEADER_LIST_SIZE, 262144),
    ]
}

/// Encode a SETTINGS frame.
pub fn encode_settings(settings: &[(u16, u32)]) -> Vec<u8> {
    let payload_len = settings.len() * 6;
    let header =
        encode_frame_header(payload_len as u32, frame_type::SETTINGS, 0, 0);

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload_len);
    frame.extend_from_slice(&header);
    for &(id, value) in settings {
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&value.to_be_bytes());
    }
    frame
}

/// Encode a SETTINGS ACK frame.
pub fn encode_settings_ack() -> Vec<u8> {
    encode_frame_header(0, frame_type::SETTINGS, flags::ACK, 0).to_vec()
}

/// Encode a WINDOW_UPDATE frame.
pub fn encode_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
    let header =
        encode_frame_header(4, frame_type::WINDOW_UPDATE, 0, stream_id);
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 4);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&(increment & 0x7FFF_FFFF).to_be_bytes());
    frame
}

/// Encode an HTTP/2 DATA frame.
pub fn encode_data_frame(stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let header = encode_frame_header(
        payload.len() as u32,
        frame_type::DATA,
        0,
        stream_id,
    );

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame
}

/// Encode an HTTP/2 DATA frame with the END_STREAM flag.
pub fn encode_data_frame_end(stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let header = encode_frame_header(
        payload.len() as u32,
        frame_type::DATA,
        flags::END_STREAM,
        stream_id,
    );

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame
}

/// Encode an HTTP/2 PING frame.
pub fn encode_ping(opaque_data: &[u8; 8]) -> Vec<u8> {
    let header = encode_frame_header(8, frame_type::PING, 0, 0);
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 8);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(opaque_data);
    frame
}

/// Encode an HTTP/2 PING ACK frame.
pub fn encode_ping_ack(opaque_data: &[u8; 8]) -> Vec<u8> {
    let header = encode_frame_header(8, frame_type::PING, flags::ACK, 0);
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 8);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(opaque_data);
    frame
}

/// Encode a GOAWAY frame.
pub fn encode_goaway(last_stream_id: u32, error_code: u32) -> Vec<u8> {
    let header = encode_frame_header(8, frame_type::GOAWAY, 0, 0);
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + 8);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&(last_stream_id & 0x7FFF_FFFF).to_be_bytes());
    frame.extend_from_slice(&error_code.to_be_bytes());
    frame
}

// ---------------------------------------------------------------------------
// HPACK header encoding (simplified)
// ---------------------------------------------------------------------------

/// Encode request HEADERS for the authentication handshake.
///
/// Uses literal header field without indexing (HPACK 6.2.2) for compatibility.
/// A production build could use indexed headers for efficiency, but literal
/// encoding is valid and slightly less fingerprintable (no state dependency).
pub fn encode_request_headers(
    stream_id: u32,
    authority: &str,
    path: &str,
    auth_cookie: &str,
) -> Vec<u8> {
    let mut header_block = Vec::with_capacity(512);

    // :method = GET  (indexed representation, index 2 in static table)
    header_block.push(0x82);
    // :scheme = https (indexed, index 7)
    header_block.push(0x87);
    // :path
    encode_hpack_literal_indexed_name(&mut header_block, 4, path.as_bytes());
    // :authority
    encode_hpack_literal_indexed_name(&mut header_block, 1, authority.as_bytes());
    // user-agent (realistic Chrome UA)
    encode_hpack_literal_new_name(
        &mut header_block,
        b"user-agent",
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    );
    // accept
    encode_hpack_literal_new_name(&mut header_block, b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    // accept-encoding
    encode_hpack_literal_new_name(
        &mut header_block,
        b"accept-encoding",
        b"gzip, deflate, br",
    );
    // accept-language
    encode_hpack_literal_new_name(
        &mut header_block,
        b"accept-language",
        b"en-US,en;q=0.9",
    );
    // cookie with auth token
    let cookie_value = alloc::format!("_session={}", auth_cookie);
    encode_hpack_literal_new_name(
        &mut header_block,
        b"cookie",
        cookie_value.as_bytes(),
    );

    let header = encode_frame_header(
        header_block.len() as u32,
        frame_type::HEADERS,
        flags::END_HEADERS,
        stream_id,
    );

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + header_block.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&header_block);
    frame
}

/// Encode response HEADERS with a set-cookie containing the session token.
pub fn encode_response_with_cookie(
    stream_id: u32,
    session_token: &str,
) -> Vec<u8> {
    let mut header_block = Vec::with_capacity(512);

    // :status = 200 (indexed, index 8)
    header_block.push(0x88);
    // content-type
    encode_hpack_literal_new_name(
        &mut header_block,
        b"content-type",
        b"application/json; charset=utf-8",
    );
    // cache-control
    encode_hpack_literal_new_name(
        &mut header_block,
        b"cache-control",
        b"no-cache, no-store, must-revalidate",
    );
    // set-cookie with session token
    let cookie = alloc::format!(
        "_session={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        session_token
    );
    encode_hpack_literal_new_name(
        &mut header_block,
        b"set-cookie",
        cookie.as_bytes(),
    );
    // server
    encode_hpack_literal_new_name(&mut header_block, b"server", b"nginx/1.25.4");
    // date
    encode_hpack_literal_new_name(
        &mut header_block,
        b"date",
        b"Thu, 01 Jan 2025 00:00:00 GMT",
    );

    // HEADERS frame (no END_STREAM since we send DATA after)
    let header = encode_frame_header(
        header_block.len() as u32,
        frame_type::HEADERS,
        flags::END_HEADERS,
        stream_id,
    );

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + header_block.len() + FRAME_HEADER_SIZE + 32);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&header_block);

    // Follow with a small JSON body as DATA frame
    let json_body = b"{\"status\":\"ok\",\"version\":\"2.1.0\",\"ts\":1700000000}";
    let data_header = encode_frame_header(
        json_body.len() as u32,
        frame_type::DATA,
        0, // Not END_STREAM — the stream stays open for the data tunnel
        stream_id,
    );
    frame.extend_from_slice(&data_header);
    frame.extend_from_slice(json_body);

    frame
}

/// HPACK: literal header field without indexing, new name (0x00 prefix).
fn encode_hpack_literal_new_name(buf: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    buf.push(0x00); // Literal, new name, no indexing
    encode_hpack_string(buf, name);
    encode_hpack_string(buf, value);
}

/// HPACK: literal header field without indexing, indexed name (0x0F prefix).
/// Uses the static table index for the header name.
fn encode_hpack_literal_indexed_name(buf: &mut Vec<u8>, index: u8, value: &[u8]) {
    // 4-bit prefix for "literal without indexing, indexed name"
    if index < 15 {
        buf.push(index); // fits in 4-bit prefix
    } else {
        buf.push(0x0F);
        buf.push(index - 15);
    }
    encode_hpack_string(buf, value);
}

/// HPACK string encoding: length prefix + raw bytes (no Huffman).
fn encode_hpack_string(buf: &mut Vec<u8>, s: &[u8]) {
    // Bit 7 = 0 means no Huffman encoding
    encode_hpack_integer_prefix(buf, s.len(), 7, 0x00);
    buf.extend_from_slice(s);
}

/// HPACK integer encoding (RFC 7541, Section 5.1).
/// Writes the integer with the given prefix bit count, OR'd with prefix_bits.
fn encode_hpack_integer_prefix(buf: &mut Vec<u8>, mut value: usize, prefix_size: u8, prefix_bits: u8) {
    let max_prefix = (1usize << prefix_size) - 1;
    if value < max_prefix {
        buf.push(prefix_bits | (value as u8));
    } else {
        buf.push(prefix_bits | (max_prefix as u8));
        value -= max_prefix;
        while value >= 128 {
            buf.push((value % 128 + 128) as u8);
            value /= 128;
        }
        buf.push(value as u8);
    }
}

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

/// Parse an HTTP/2 frame header from a 9-byte buffer.
pub fn parse_frame_header(buf: &[u8; 9]) -> (u32, u8, u8, u32) {
    let length =
        ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
    let ftype = buf[3];
    let flags = buf[4];
    let stream_id = u32::from_be_bytes([buf[5] & 0x7F, buf[6], buf[7], buf[8]]);
    (length, ftype, flags, stream_id)
}

/// Read a single complete HTTP/2 frame from a file descriptor.
/// Returns the parsed frame, or an error.
pub fn read_frame(fd: u32) -> Result<H2Frame, u16> {
    // Read the 9-byte header
    let mut header_buf = [0u8; 9];
    crate::wasi_io::read_exact(fd, &mut header_buf)?;

    let (length, ftype, flags, stream_id) = parse_frame_header(&header_buf);

    // Read the payload
    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        crate::wasi_io::read_exact(fd, &mut payload)?;
    }

    Ok(H2Frame {
        length,
        frame_type: ftype,
        flags,
        stream_id,
        payload,
    })
}

/// Read HTTP/2 frames from a file descriptor, skipping non-DATA control frames
/// (SETTINGS, WINDOW_UPDATE, PING) and handling them automatically.
/// Returns the first DATA frame payload received, along with the stream ID.
///
/// Also sends SETTINGS ACK and PING ACK as needed, and sends WINDOW_UPDATEs
/// to keep the flow control window open.
pub fn read_data_frame(fd: u32, write_fd: u32) -> Result<(Vec<u8>, u32), u16> {
    loop {
        let frame = read_frame(fd)?;
        match frame.frame_type {
            frame_type::DATA => {
                // Send WINDOW_UPDATE to replenish the flow control window
                let wsize = frame.length;
                if wsize > 0 {
                    // Connection-level WINDOW_UPDATE
                    let wu_conn = encode_window_update(0, wsize);
                    crate::wasi_io::write_all(write_fd, &wu_conn)?;
                    // Stream-level WINDOW_UPDATE
                    if frame.stream_id != 0 {
                        let wu_stream = encode_window_update(frame.stream_id, wsize);
                        crate::wasi_io::write_all(write_fd, &wu_stream)?;
                    }
                }
                return Ok((frame.payload, frame.stream_id));
            }
            frame_type::SETTINGS => {
                if frame.flags & flags::ACK == 0 {
                    // Send SETTINGS ACK
                    let ack = encode_settings_ack();
                    crate::wasi_io::write_all(write_fd, &ack)?;
                }
                // SETTINGS ACK frames are just consumed
            }
            frame_type::PING => {
                if frame.flags & flags::ACK == 0 && frame.payload.len() == 8 {
                    let mut opaque = [0u8; 8];
                    opaque.copy_from_slice(&frame.payload);
                    let pong = encode_ping_ack(&opaque);
                    crate::wasi_io::write_all(write_fd, &pong)?;
                }
            }
            frame_type::WINDOW_UPDATE => {
                // Consume — we maintain a large window so we don't need to track this
            }
            frame_type::GOAWAY => {
                // Peer is shutting down
                return Err(0); // Clean shutdown signal
            }
            frame_type::RST_STREAM => {
                // Stream reset — treat as error for the specific stream
                continue;
            }
            frame_type::HEADERS => {
                // Response headers or trailers — consume (we extract cookies separately)
                continue;
            }
            _ => {
                // Unknown frame type — skip per HTTP/2 extensibility rules
                continue;
            }
        }
    }
}

/// Try to extract a complete HTTP/2 frame from a byte buffer.
/// Returns (H2Frame, bytes_consumed) or None if buffer is incomplete.
pub fn try_parse_frame(buf: &[u8]) -> Option<(H2Frame, usize)> {
    if buf.len() < FRAME_HEADER_SIZE {
        return None;
    }

    let length =
        ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
    let ftype = buf[3];
    let fflags = buf[4];
    let stream_id = u32::from_be_bytes([buf[5] & 0x7F, buf[6], buf[7], buf[8]]);

    let total = FRAME_HEADER_SIZE + length as usize;
    if buf.len() < total {
        return None;
    }

    let payload = buf[FRAME_HEADER_SIZE..total].to_vec();
    Some((
        H2Frame {
            length,
            frame_type: ftype,
            flags: fflags,
            stream_id,
            payload,
        },
        total,
    ))
}

/// Extract a DATA frame payload from a buffer, consuming and handling
/// non-DATA frames inline. Returns (payload, total_bytes_consumed).
pub fn extract_data_payload(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut offset = 0;
    while offset + FRAME_HEADER_SIZE <= buf.len() {
        let remaining = &buf[offset..];
        match try_parse_frame(remaining) {
            Some((frame, consumed)) => {
                offset += consumed;
                if frame.frame_type == frame_type::DATA {
                    return Some((frame.payload, offset));
                }
                // Skip non-DATA frames
            }
            None => break, // Incomplete frame
        }
    }
    if offset > 0 {
        // We consumed some non-DATA frames but no DATA yet
        Some((Vec::new(), offset))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Cookie extraction (simplified byte-pattern search)
// ---------------------------------------------------------------------------

/// Extract the session cookie value from an HTTP/2 response.
pub fn extract_session_cookie(response: &[u8]) -> Option<String> {
    extract_cookie_value(response, b"_session=")
}

/// Extract the auth cookie value from an HTTP/2 request.
pub fn extract_auth_cookie(request: &[u8]) -> Option<String> {
    extract_cookie_value(request, b"_session=")
}

/// Scan raw frame bytes for a cookie value by byte-pattern matching.
fn extract_cookie_value(data: &[u8], prefix: &[u8]) -> Option<String> {
    let pos = data
        .windows(prefix.len())
        .position(|w| w == prefix)?;

    let start = pos + prefix.len();
    let remaining = &data[start..];

    let end = remaining
        .iter()
        .position(|&b| b == b';' || b == b' ' || b == b'\r' || b == b'\n' || b == 0)
        .unwrap_or(remaining.len());

    if end == 0 {
        return None;
    }

    let value = &remaining[..end];
    String::from_utf8(value.to_vec()).ok()
}

/// Send the initial HTTP/2 connection-level WINDOW_UPDATE to set a large
/// receive window (avoids flow control stalls on large transfers).
pub fn send_initial_window_update(fd: u32) -> Result<(), u16> {
    // Increase the connection-level window beyond the default 65535
    let increment = LARGE_WINDOW_SIZE - DEFAULT_WINDOW_SIZE;
    let wu = encode_window_update(0, increment);
    crate::wasi_io::write_all(fd, &wu)
}
