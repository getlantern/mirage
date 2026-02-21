//! Cryptographic primitives for the MIRAGE protocol.
//!
//! Key hierarchy:
//!   Long-term: server X25519 keypair + PSK
//!   Per-session: ephemeral X25519 DH -> HKDF -> ChaCha20-Poly1305 session keys
//!   Key rotation: new ephemeral DH within session, forward-secrecy chain

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Helper to create HMAC instances without ambiguity.
fn new_hmac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length")
}

/// Maximum clock skew tolerance for authentication timestamps (seconds).
const MAX_CLOCK_SKEW: u64 = 120;

/// Threshold for triggering key rotation (sequence number).
const KEY_ROTATION_SEQ_THRESHOLD: u32 = 0x00FF_FF00;

/// Threshold for triggering key rotation (bytes transferred).
const KEY_ROTATION_BYTE_THRESHOLD: u64 = 1_073_741_824; // 1 GiB

// ---------------------------------------------------------------------------
// Authentication Token
// ---------------------------------------------------------------------------

/// The authentication token sent by the client in the initial HTTP request cookie.
/// Contains an ephemeral public key, timestamp, nonce, and HMAC tag.
pub struct AuthToken {
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub ephemeral_public: PublicKey,
    pub tag: [u8; 32],
}

impl AuthToken {
    /// Generate a new authentication token for a client connection.
    ///
    /// Returns the token and the ephemeral secret (needed for session key derivation).
    pub fn generate(
        server_public_key: &PublicKey,
        psk: &[u8; 32],
    ) -> (Self, StaticSecret) {
        let timestamp = crate::clock::clock_seconds();

        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("getrandom failed");

        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");
        let client_secret = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();

        let client_public = PublicKey::from(&client_secret);

        // Compute shared secret for authentication
        let shared = client_secret.diffie_hellman(server_public_key);

        // Derive authentication key
        let auth_key = derive_auth_key(shared.as_bytes(), psk, timestamp);

        // Build payload: timestamp || nonce || ephemeral_public
        let mut payload = Vec::with_capacity(56);
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(client_public.as_bytes());

        // Compute HMAC tag
        let mut mac = new_hmac(&auth_key);
        mac.update(&payload);
        let tag: [u8; 32] = mac.finalize().into_bytes().into();

        let token = AuthToken {
            timestamp,
            nonce,
            ephemeral_public: client_public,
            tag,
        };

        (token, client_secret)
    }

    /// Serialize the token to a base64url-encoded string suitable for a cookie value.
    /// Wire format: timestamp(8) || nonce(16) || ephemeral_public(32) || tag(32) = 88 bytes.
    pub fn to_base64(&self) -> alloc::string::String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let mut payload = Vec::with_capacity(88);
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(self.ephemeral_public.as_bytes());
        payload.extend_from_slice(&self.tag);
        URL_SAFE_NO_PAD.encode(&payload)
    }

    /// Deserialize a token from a base64url-encoded string.
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidToken)?;

        if bytes.len() != 88 {
            return Err(CryptoError::InvalidToken);
        }

        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&bytes[0..8]);
        let timestamp = u64::from_be_bytes(timestamp_bytes);

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[8..24]);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&bytes[24..56]);
        let ephemeral_public = PublicKey::from(pub_bytes);

        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[56..88]);

        Ok(AuthToken {
            timestamp,
            nonce,
            ephemeral_public,
            tag,
        })
    }

    /// Verify the token against the server's private key and PSK.
    /// Returns the raw DH shared secret bytes on success.
    pub fn verify(
        &self,
        server_secret: &StaticSecret,
        psk: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        // Check timestamp freshness
        let now = crate::clock::clock_seconds();
        let diff = if now > self.timestamp {
            now - self.timestamp
        } else {
            self.timestamp - now
        };
        if diff > MAX_CLOCK_SKEW {
            return Err(CryptoError::ExpiredTimestamp);
        }

        // Compute shared secret
        let shared = server_secret.diffie_hellman(&self.ephemeral_public);

        // Derive auth key
        let auth_key = derive_auth_key(shared.as_bytes(), psk, self.timestamp);

        // Rebuild payload and verify HMAC
        let mut payload = Vec::with_capacity(56);
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(self.ephemeral_public.as_bytes());

        let mut mac = new_hmac(&auth_key);
        mac.update(&payload);
        mac.verify_slice(&self.tag)
            .map_err(|_| CryptoError::InvalidHmac)?;

        let mut result = [0u8; 32];
        result.copy_from_slice(shared.as_bytes());
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Key Rotation State
// ---------------------------------------------------------------------------

/// Tracks the state of an in-progress key rotation.
enum KeyRotationState {
    /// No rotation in progress.
    Idle,
    /// We initiated rotation: sent our new public key, waiting for peer's.
    Initiated {
        new_secret: StaticSecret,
    },
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// An established MIRAGE session with symmetric encryption keys.
pub struct Session {
    client_write_key: Key,
    server_write_key: Key,
    client_seq: u32,
    server_seq: u32,
    bytes_transferred: u64,
    /// The stream ID used for the data tunnel (fixed after handshake).
    data_stream_id: u32,
    is_client: bool,
    rotation_state: KeyRotationState,
    /// Chaining value for forward secrecy across key rotations.
    chain_key: [u8; 32],
}

impl Session {
    /// Create a session from the client side after receiving the server's response.
    pub fn from_client_handshake(
        client_secret: &StaticSecret,
        server_public_key: &PublicKey,
        psk: &[u8; 32],
        auth_token: &AuthToken,
        session_token_b64: &str,
    ) -> Result<Self, CryptoError> {
        // Recompute the auth-phase shared secret
        let auth_shared = client_secret.diffie_hellman(server_public_key);
        let auth_key =
            derive_auth_key(auth_shared.as_bytes(), psk, auth_token.timestamp);

        // Decrypt the session token to get server's ephemeral public key + nonce
        let (server_ephemeral_pub, server_nonce) =
            decrypt_session_token(session_token_b64, &auth_key, &auth_token.nonce)?;

        // Compute the session DH
        let session_dh = client_secret.diffie_hellman(&server_ephemeral_pub);

        // Derive session keys
        let (client_write_key, server_write_key, chain_key) = derive_session_keys(
            session_dh.as_bytes(),
            auth_shared.as_bytes(),
            auth_token.timestamp,
            &auth_token.nonce,
            &server_nonce,
        );

        Ok(Session {
            client_write_key,
            server_write_key,
            client_seq: 0,
            server_seq: 0,
            bytes_transferred: 0,
            data_stream_id: 3, // Stream 1 used for auth, stream 3 for data tunnel
            is_client: true,
            rotation_state: KeyRotationState::Idle,
            chain_key,
        })
    }

    /// Create a session from the server side after validating the client's auth token.
    /// Returns (Session, encrypted_session_token_b64) to send in the response cookie.
    pub fn from_server_handshake(
        server_secret: &StaticSecret,
        psk: &[u8; 32],
        auth_token_b64: &str,
    ) -> Result<(Self, alloc::string::String), CryptoError> {
        // Parse and validate the auth token
        let auth_token = AuthToken::from_base64(auth_token_b64)?;
        let auth_shared_bytes = auth_token.verify(server_secret, psk)?;

        // Generate server ephemeral key
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");
        let server_ephemeral = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();
        let server_ephemeral_pub = PublicKey::from(&server_ephemeral);

        let mut server_nonce = [0u8; 16];
        getrandom::getrandom(&mut server_nonce).expect("getrandom failed");

        // Compute session DH
        let session_dh =
            server_ephemeral.diffie_hellman(&auth_token.ephemeral_public);

        // Derive session keys
        let (client_write_key, server_write_key, chain_key) = derive_session_keys(
            session_dh.as_bytes(),
            &auth_shared_bytes,
            auth_token.timestamp,
            &auth_token.nonce,
            &server_nonce,
        );

        // Encrypt the session token for the client
        let auth_key =
            derive_auth_key(&auth_shared_bytes, psk, auth_token.timestamp);
        let session_token = encrypt_session_token(
            &server_ephemeral_pub,
            &server_nonce,
            &auth_key,
            &auth_token.nonce,
        )?;

        let session = Session {
            client_write_key,
            server_write_key,
            client_seq: 0,
            server_seq: 0,
            bytes_transferred: 0,
            data_stream_id: 3,
            is_client: false,
            rotation_state: KeyRotationState::Idle,
            chain_key,
        };

        Ok((session, session_token))
    }

    /// Get the HTTP/2 stream ID for the data tunnel.
    pub fn data_stream_id(&self) -> u32 {
        self.data_stream_id
    }

    /// Whether this session is the client side.
    pub fn is_client(&self) -> bool {
        self.is_client
    }

    /// Encrypt a MIRAGE frame for transmission.
    pub fn encrypt_frame(&mut self, frame_type: u8, payload: &[u8]) -> Vec<u8> {
        let key = if self.is_client {
            &self.client_write_key
        } else {
            &self.server_write_key
        };
        let seq = if self.is_client {
            let s = self.client_seq;
            self.client_seq = s.wrapping_add(1);
            s
        } else {
            let s = self.server_seq;
            self.server_seq = s.wrapping_add(1);
            s
        };

        self.bytes_transferred += payload.len() as u64;
        encrypt_mirage_frame(key, seq, frame_type, payload)
    }

    /// Decrypt a received MIRAGE frame.
    pub fn decrypt_frame(&mut self, frame_data: &[u8]) -> Result<(u8, Vec<u8>), CryptoError> {
        let key = if self.is_client {
            &self.server_write_key
        } else {
            &self.client_write_key
        };
        let expected_seq = if self.is_client {
            let s = self.server_seq;
            self.server_seq = s.wrapping_add(1);
            s
        } else {
            let s = self.client_seq;
            self.client_seq = s.wrapping_add(1);
            s
        };

        let (frame_type, plaintext) =
            decrypt_mirage_frame(key, expected_seq, frame_data)?;
        self.bytes_transferred += plaintext.len() as u64;
        Ok((frame_type, plaintext))
    }

    /// Check if key rotation is needed based on sequence numbers or data volume.
    pub fn needs_key_rotation(&self) -> bool {
        if !matches!(self.rotation_state, KeyRotationState::Idle) {
            return false; // Already rotating
        }
        let max_seq = core::cmp::max(self.client_seq, self.server_seq);
        max_seq > KEY_ROTATION_SEQ_THRESHOLD
            || self.bytes_transferred > KEY_ROTATION_BYTE_THRESHOLD
    }

    /// Initiate key rotation. Returns a KEY_ROTATE frame payload containing
    /// our new ephemeral public key (32 bytes).
    pub fn initiate_key_rotation(&mut self) -> Result<Vec<u8>, CryptoError> {
        // Generate new ephemeral keypair
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");
        let new_secret = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();
        let new_public = PublicKey::from(&new_secret);

        let payload = new_public.as_bytes().to_vec();

        self.rotation_state = KeyRotationState::Initiated {
            new_secret,
        };

        Ok(payload)
    }

    /// Handle an incoming KEY_ROTATE frame from the peer.
    /// Returns the KEY_ACK frame payload (our new ephemeral public key, 32 bytes).
    pub fn handle_key_rotation(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if payload.len() != 32 {
            return Err(CryptoError::KeyRotationFailed);
        }

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(payload);
        let peer_new_public = PublicKey::from(pub_bytes);

        // Generate our new ephemeral keypair
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");
        let our_new_secret = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();
        let our_new_public = PublicKey::from(&our_new_secret);

        // Compute new DH shared secret
        let new_dh = our_new_secret.diffie_hellman(&peer_new_public);

        // Derive new session keys, chaining from the old chain_key for forward secrecy
        let (new_client_key, new_server_key, new_chain) =
            derive_rotation_keys(new_dh.as_bytes(), &self.chain_key);

        self.client_write_key = new_client_key;
        self.server_write_key = new_server_key;
        self.chain_key = new_chain;
        self.client_seq = 0;
        self.server_seq = 0;
        self.bytes_transferred = 0;
        self.rotation_state = KeyRotationState::Idle;

        Ok(our_new_public.as_bytes().to_vec())
    }

    /// Handle an incoming KEY_ACK frame (response to our KEY_ROTATE).
    pub fn handle_key_ack(&mut self, payload: &[u8]) -> Result<(), CryptoError> {
        if payload.len() != 32 {
            return Err(CryptoError::KeyRotationFailed);
        }

        let our_new_secret = match core::mem::replace(
            &mut self.rotation_state,
            KeyRotationState::Idle,
        ) {
            KeyRotationState::Initiated { new_secret, .. } => new_secret,
            _ => return Err(CryptoError::KeyRotationFailed),
        };

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(payload);
        let peer_new_public = PublicKey::from(pub_bytes);

        // Compute new DH shared secret
        let new_dh = our_new_secret.diffie_hellman(&peer_new_public);

        // Derive new session keys
        let (new_client_key, new_server_key, new_chain) =
            derive_rotation_keys(new_dh.as_bytes(), &self.chain_key);

        self.client_write_key = new_client_key;
        self.server_write_key = new_server_key;
        self.chain_key = new_chain;
        self.client_seq = 0;
        self.server_seq = 0;
        self.bytes_transferred = 0;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------

fn derive_auth_key(shared_secret: &[u8], psk: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(22);
    info.extend_from_slice(b"mirage-auth-v1");
    info.extend_from_slice(&timestamp.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(psk), shared_secret);
    let mut auth_key = [0u8; 32];
    hk.expand(&info, &mut auth_key).expect("HKDF expand failed");
    auth_key
}

fn derive_session_keys(
    dh_result: &[u8],
    auth_shared: &[u8],
    timestamp: u64,
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> (Key, Key, [u8; 32]) {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"mirage-session-v1");
    info.extend_from_slice(&timestamp.to_be_bytes());
    info.extend_from_slice(client_nonce);
    info.extend_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(auth_shared), dh_result);
    // 96 bytes: client_key(32) + server_key(32) + chain_key(32)
    let mut key_material = [0u8; 96];
    hk.expand(&info, &mut key_material).expect("HKDF expand");

    let client_key = *Key::from_slice(&key_material[0..32]);
    let server_key = *Key::from_slice(&key_material[32..64]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&key_material[64..96]);

    key_material.zeroize();

    (client_key, server_key, chain_key)
}

/// Derive new session keys during key rotation, chaining from the previous
/// chain_key for forward secrecy.
fn derive_rotation_keys(
    new_dh: &[u8],
    old_chain_key: &[u8; 32],
) -> (Key, Key, [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(old_chain_key), new_dh);
    let mut key_material = [0u8; 96];
    hk.expand(b"mirage-rotate-v1", &mut key_material)
        .expect("HKDF expand");

    let client_key = *Key::from_slice(&key_material[0..32]);
    let server_key = *Key::from_slice(&key_material[32..64]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&key_material[64..96]);

    key_material.zeroize();

    (client_key, server_key, chain_key)
}

// ---------------------------------------------------------------------------
// Session token encrypt/decrypt
// ---------------------------------------------------------------------------

/// Encrypt the session establishment token sent from server to client.
/// Plaintext: server_ephemeral_public(32) || server_nonce(16) = 48 bytes.
/// The nonce for AEAD is derived deterministically from auth_key + client_nonce
/// so both sides can compute it independently.
fn encrypt_session_token(
    server_ephemeral_pub: &PublicKey,
    server_nonce: &[u8; 16],
    auth_key: &[u8; 32],
    client_nonce: &[u8; 16],
) -> Result<alloc::string::String, CryptoError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Derive encryption key from auth_key + client_nonce
    let hk = Hkdf::<Sha256>::new(Some(client_nonce), auth_key);
    let mut enc_key = [0u8; 32];
    hk.expand(b"mirage-session-token-enc-v1", &mut enc_key)
        .expect("HKDF");

    // Derive AEAD nonce deterministically from auth_key + client_nonce
    // (both sides have these values before the session token is exchanged)
    let mut nonce_bytes = [0u8; 12];
    let mut nonce_material = [0u8; 12];
    let hk_nonce = Hkdf::<Sha256>::new(Some(client_nonce), auth_key);
    hk_nonce
        .expand(b"mirage-session-token-nonce-v1", &mut nonce_material)
        .expect("HKDF");
    nonce_bytes.copy_from_slice(&nonce_material[..12]);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&enc_key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Plaintext: server_ephemeral_public(32) || server_nonce(16)
    let mut plaintext = Vec::with_capacity(48);
    plaintext.extend_from_slice(server_ephemeral_pub.as_bytes());
    plaintext.extend_from_slice(server_nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    enc_key.zeroize();

    Ok(URL_SAFE_NO_PAD.encode(&ciphertext))
}

/// Decrypt the session token received from the server.
fn decrypt_session_token(
    token_b64: &str,
    auth_key: &[u8; 32],
    client_nonce: &[u8; 16],
) -> Result<(PublicKey, [u8; 16]), CryptoError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let ciphertext = URL_SAFE_NO_PAD
        .decode(token_b64)
        .map_err(|_| CryptoError::InvalidToken)?;

    // Derive the same encryption key the server used
    let hk = Hkdf::<Sha256>::new(Some(client_nonce), auth_key);
    let mut enc_key = [0u8; 32];
    hk.expand(b"mirage-session-token-enc-v1", &mut enc_key)
        .expect("HKDF");

    // Derive the same AEAD nonce
    let mut nonce_bytes = [0u8; 12];
    let mut nonce_material = [0u8; 12];
    let hk_nonce = Hkdf::<Sha256>::new(Some(client_nonce), auth_key);
    hk_nonce
        .expand(b"mirage-session-token-nonce-v1", &mut nonce_material)
        .expect("HKDF");
    nonce_bytes.copy_from_slice(&nonce_material[..12]);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&enc_key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    enc_key.zeroize();

    if plaintext.len() != 48 {
        return Err(CryptoError::InvalidToken);
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&plaintext[0..32]);
    let server_pub = PublicKey::from(pub_bytes);

    let mut server_nonce = [0u8; 16];
    server_nonce.copy_from_slice(&plaintext[32..48]);

    Ok((server_pub, server_nonce))
}

// ---------------------------------------------------------------------------
// MIRAGE frame encrypt/decrypt
// ---------------------------------------------------------------------------

fn encrypt_mirage_frame(key: &Key, seq: u32, frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key);

    // Nonce: 4 zero bytes || seq (4 bytes BE) || 4 zero bytes
    // This gives us a unique nonce per sequence number while keeping
    // the nonce space sparse (reducing multi-key collision risk).
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..8].copy_from_slice(&seq.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .expect("encryption should not fail");

    let length = ciphertext.len() as u16;

    // MIRAGE frame: type(1) || length(2 BE) || seq(4 BE) || ciphertext+tag
    let mut frame = Vec::with_capacity(7 + ciphertext.len());
    frame.push(frame_type);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&ciphertext);

    frame
}

fn decrypt_mirage_frame(
    key: &Key,
    expected_seq: u32,
    frame: &[u8],
) -> Result<(u8, Vec<u8>), CryptoError> {
    if frame.len() < 7 {
        return Err(CryptoError::FrameTooShort);
    }

    let frame_type = frame[0];
    let length = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    let seq = u32::from_be_bytes([frame[3], frame[4], frame[5], frame[6]]);

    if seq != expected_seq {
        return Err(CryptoError::SequenceMismatch);
    }

    if frame.len() < 7 + length {
        return Err(CryptoError::FrameTooShort);
    }

    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..8].copy_from_slice(&seq.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = &frame[7..7 + length];
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok((frame_type, plaintext))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum CryptoError {
    InvalidToken,
    ExpiredTimestamp,
    InvalidHmac,
    EncryptionFailed,
    DecryptionFailed,
    FrameTooShort,
    SequenceMismatch,
    KeyRotationFailed,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidToken => write!(f, "invalid token"),
            CryptoError::ExpiredTimestamp => write!(f, "expired timestamp"),
            CryptoError::InvalidHmac => write!(f, "invalid HMAC"),
            CryptoError::EncryptionFailed => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::FrameTooShort => write!(f, "frame too short"),
            CryptoError::SequenceMismatch => write!(f, "sequence mismatch"),
            CryptoError::KeyRotationFailed => write!(f, "key rotation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
