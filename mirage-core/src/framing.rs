//! MIRAGE frame types and parsing utilities.
//!
//! MIRAGE frames are the inner protocol carried within HTTP/2 DATA frames.
//! Each frame is encrypted with ChaCha20-Poly1305 and includes a sequence
//! number for replay protection and ordering.
//!
//! Frame layout:
//!   [type: 1 byte] [length: 2 bytes BE] [seq: 4 bytes BE] [encrypted payload + tag]

extern crate alloc;
use alloc::vec::Vec;

/// MIRAGE protocol frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Tunneled application data.
    Data = 0x01,
    /// Request to establish a tunnel to a target address.
    Connect = 0x02,
    /// Tunnel establishment succeeded.
    ConnectOk = 0x03,
    /// Tunnel establishment failed.
    ConnectErr = 0x04,
    /// Keep-alive ping.
    Ping = 0x05,
    /// Ping response.
    Pong = 0x06,
    /// Initiate key rotation (contains new ephemeral public key).
    KeyRotate = 0x07,
    /// Acknowledge key rotation (contains new ephemeral public key).
    KeyAck = 0x08,
    /// Close a tunnel stream.
    Close = 0x09,
    /// Padding frame (discarded by receiver; used for traffic shaping).
    Pad = 0x0A,
    /// Server → Client: encrypted DomainUpdate payload.
    DomainUpdate = 0x0B,
    /// Client → Server: connection success/failure reports.
    DomainReport = 0x0C,
}

impl FrameType {
    /// Convert a raw byte to a FrameType, returning None for unknown types.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Connect),
            0x03 => Some(Self::ConnectOk),
            0x04 => Some(Self::ConnectErr),
            0x05 => Some(Self::Ping),
            0x06 => Some(Self::Pong),
            0x07 => Some(Self::KeyRotate),
            0x08 => Some(Self::KeyAck),
            0x09 => Some(Self::Close),
            0x0A => Some(Self::Pad),
            0x0B => Some(Self::DomainUpdate),
            0x0C => Some(Self::DomainReport),
            _ => None,
        }
    }
}

/// Minimum MIRAGE frame header size (type + length + seq).
pub const FRAME_HEADER_SIZE: usize = 7;

/// Poly1305 authentication tag size.
pub const AUTH_TAG_SIZE: usize = 16;

/// Maximum payload size per MIRAGE frame (excluding header and tag).
/// This is chosen to fit within typical HTTP/2 DATA frame limits.
pub const MAX_PAYLOAD_SIZE: usize = 16384 - FRAME_HEADER_SIZE - AUTH_TAG_SIZE;

/// Address types used in CONNECT frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    IPv6 = 0x02,
    Domain = 0x03,
}

impl AddressType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::IPv4),
            0x02 => Some(Self::IPv6),
            0x03 => Some(Self::Domain),
            _ => None,
        }
    }
}

/// Parse a CONNECT frame payload to extract the target address.
///
/// CONNECT payload format:
///   [addr_type: 1 byte] [address: variable] [port: 2 bytes BE]
///
/// IPv4: 4 bytes
/// IPv6: 16 bytes
/// Domain: 1 byte length + domain bytes
pub fn parse_connect_payload(
    payload: &[u8],
) -> Option<(AddressType, &[u8], u16)> {
    if payload.is_empty() {
        return None;
    }

    let addr_type = AddressType::from_u8(payload[0])?;
    let (addr, rest) = match addr_type {
        AddressType::IPv4 => {
            if payload.len() < 1 + 4 + 2 {
                return None;
            }
            (&payload[1..5], &payload[5..])
        }
        AddressType::IPv6 => {
            if payload.len() < 1 + 16 + 2 {
                return None;
            }
            (&payload[1..17], &payload[17..])
        }
        AddressType::Domain => {
            if payload.len() < 2 {
                return None;
            }
            let domain_len = payload[1] as usize;
            if payload.len() < 2 + domain_len + 2 {
                return None;
            }
            (&payload[2..2 + domain_len], &payload[2 + domain_len..])
        }
    };

    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);

    Some((addr_type, addr, port))
}

/// Encode a CONNECT frame payload for a domain target.
pub fn encode_connect_domain(domain: &str, port: u16) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();
    let mut payload = Vec::with_capacity(1 + 1 + domain_bytes.len() + 2);
    payload.push(AddressType::Domain as u8);
    payload.push(domain_bytes.len() as u8);
    payload.extend_from_slice(domain_bytes);
    payload.extend_from_slice(&port.to_be_bytes());
    payload
}

/// Encode a CONNECT frame payload for an IPv4 target.
pub fn encode_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 4 + 2);
    payload.push(AddressType::IPv4 as u8);
    payload.extend_from_slice(&ip);
    payload.extend_from_slice(&port.to_be_bytes());
    payload
}

/// Try to parse a MIRAGE frame from a byte buffer.
/// Returns (frame_type, length, seq, total_frame_size)
/// or None if the buffer does not contain a complete frame.
pub fn try_parse_frame_header(buf: &[u8]) -> Option<(u8, usize, u32, usize)> {
    if buf.len() < FRAME_HEADER_SIZE {
        return None;
    }

    let frame_type = buf[0];
    let length = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    let seq = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);

    let total = FRAME_HEADER_SIZE + length;
    if buf.len() < total {
        return None;
    }

    Some((frame_type, length, seq, total))
}
