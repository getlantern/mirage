//! Ed25519 manifest signing and verification for domain rotation.
//!
//! Manifests are signed with Ed25519 (via `ed25519-dalek`). The verification
//! key is embedded in client binaries; the signing key is kept offline.
//!
//! Canonical serialization: all fields except `signature` are serialized in
//! declaration order using `postcard` (compact, deterministic, no_std-safe).
//! The signature covers these bytes.

extern crate alloc;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};

use crate::config::{DomainDelta, DomainEntry, DomainManifest};

/// Errors from manifest verification.
#[derive(Debug)]
pub enum ManifestError {
    /// The Ed25519 signature is invalid.
    InvalidSignature,
    /// The public key bytes are not a valid Ed25519 point.
    InvalidPublicKey,
    /// The manifest version is not newer than the current version.
    StaleVersion,
    /// The manifest has no domains.
    EmptyManifest,
}

/// Compute the canonical signing bytes for a `DomainManifest` (all fields
/// except `signature`).
pub fn manifest_signing_bytes(manifest: &DomainManifest) -> Vec<u8> {
    let mut buf = Vec::new();

    // version (8 bytes BE)
    buf.extend_from_slice(&manifest.version.to_be_bytes());
    // timestamp (8 bytes BE)
    buf.extend_from_slice(&manifest.timestamp.to_be_bytes());
    // number of domains (4 bytes BE)
    buf.extend_from_slice(&(manifest.domains.len() as u32).to_be_bytes());
    // each domain entry
    for entry in &manifest.domains {
        encode_domain_entry(&mut buf, entry);
    }
    // number of deprecated hostnames (4 bytes BE)
    buf.extend_from_slice(&(manifest.deprecated.len() as u32).to_be_bytes());
    for hostname in &manifest.deprecated {
        encode_string(&mut buf, hostname);
    }
    // refresh_interval_secs (8 bytes BE)
    buf.extend_from_slice(&manifest.refresh_interval_secs.to_be_bytes());

    buf
}

/// Compute the canonical signing bytes for a `DomainDelta`.
pub fn delta_signing_bytes(delta: &DomainDelta) -> Vec<u8> {
    let mut buf = Vec::new();

    // base_version (8 bytes BE)
    buf.extend_from_slice(&delta.base_version.to_be_bytes());
    // new_version (8 bytes BE)
    buf.extend_from_slice(&delta.new_version.to_be_bytes());
    // number of added entries (4 bytes BE)
    buf.extend_from_slice(&(delta.added.len() as u32).to_be_bytes());
    for entry in &delta.added {
        encode_domain_entry(&mut buf, entry);
    }
    // number of removed hostnames (4 bytes BE)
    buf.extend_from_slice(&(delta.removed.len() as u32).to_be_bytes());
    for hostname in &delta.removed {
        encode_string(&mut buf, hostname);
    }

    buf
}

/// Verify the Ed25519 signature on a `DomainManifest`.
pub fn verify_manifest(
    manifest: &DomainManifest,
    public_key: &[u8; 32],
) -> Result<(), ManifestError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| ManifestError::InvalidPublicKey)?;

    let sig_bytes: [u8; SIGNATURE_LENGTH] = manifest.signature;
    let signature =
        Signature::from_bytes(&sig_bytes);

    let message = manifest_signing_bytes(manifest);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ManifestError::InvalidSignature)
}

/// Verify the Ed25519 signature on a `DomainDelta`.
pub fn verify_delta(
    delta: &DomainDelta,
    public_key: &[u8; 32],
) -> Result<(), ManifestError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| ManifestError::InvalidPublicKey)?;

    let sig_bytes: [u8; SIGNATURE_LENGTH] = delta.signature;
    let signature =
        Signature::from_bytes(&sig_bytes);

    let message = delta_signing_bytes(delta);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ManifestError::InvalidSignature)
}

/// Sign a manifest with an Ed25519 secret key (provisioner-side).
/// Requires the `std` feature.
#[cfg(feature = "std")]
pub fn sign_manifest(manifest: &mut DomainManifest, secret_key: &[u8; 32]) {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(secret_key);
    let message = manifest_signing_bytes(manifest);
    let sig = signing_key.sign(&message);
    manifest.signature = sig.to_bytes();
}

/// Sign a delta with an Ed25519 secret key (provisioner-side).
/// Requires the `std` feature.
#[cfg(feature = "std")]
pub fn sign_delta(delta: &mut DomainDelta, secret_key: &[u8; 32]) {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(secret_key);
    let message = delta_signing_bytes(delta);
    let sig = signing_key.sign(&message);
    delta.signature = sig.to_bytes();
}

// ---------------------------------------------------------------------------
// Internal helpers for canonical encoding
// ---------------------------------------------------------------------------

fn encode_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_domain_entry(buf: &mut Vec<u8>, entry: &DomainEntry) {
    encode_string(buf, &entry.hostname);
    // cdn_ips count + each IP
    buf.extend_from_slice(&(entry.cdn_ips.len() as u32).to_be_bytes());
    for ip in &entry.cdn_ips {
        encode_string(buf, ip);
    }
    encode_string(buf, &entry.origin_path_prefix);
    buf.extend_from_slice(&entry.server_public_key);
    buf.extend_from_slice(&entry.psk);
    buf.push(entry.priority);
    // region_hint: 0 byte = None, 1 byte + string = Some
    match &entry.region_hint {
        Some(region) => {
            buf.push(1);
            encode_string(buf, region);
        }
        None => {
            buf.push(0);
        }
    }
    buf.extend_from_slice(&entry.valid_until.to_be_bytes());
}
