//! Manifest generation and Ed25519 signing.

use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::Deserialize;
use tracing::info;

use mirage_core::config::{DomainEntry, DomainManifest};
use mirage_core::manifest as manifest_crypto;

/// Domain pool configuration file (TOML).
#[derive(Deserialize)]
pub struct PoolConfig {
    /// Manifest version (auto-incremented).
    pub version: Option<u64>,
    /// Refresh interval in seconds.
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    /// Domain entries.
    pub domains: Vec<PoolDomainEntry>,
    /// Deprecated hostnames.
    #[serde(default)]
    pub deprecated: Vec<String>,
}

fn default_refresh() -> u64 {
    3600
}

/// A domain entry as specified in the pool config file.
#[derive(Deserialize)]
pub struct PoolDomainEntry {
    pub hostname: String,
    #[serde(default)]
    pub cdn_ips: Vec<String>,
    #[serde(default = "default_path_prefix")]
    pub origin_path_prefix: String,
    /// Base64url-encoded 32-byte server public key.
    pub server_public_key: String,
    /// Base64url-encoded 32-byte PSK.
    pub psk: String,
    #[serde(default = "default_priority")]
    pub priority: u8,
    pub region_hint: Option<String>,
    /// Unix timestamp (default: 0 = no expiry).
    #[serde(default)]
    pub valid_until: u64,
}

fn default_path_prefix() -> String {
    "/api/v2/".to_string()
}

fn default_priority() -> u8 {
    10
}

/// Generate an Ed25519 keypair and write to files.
pub fn cmd_keygen(private_key_path: &str, public_key_path: &str) -> anyhow::Result<()> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Write private key as raw 32 bytes, base64url-encoded.
    let sk_b64 = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    std::fs::write(private_key_path, &sk_b64)?;
    info!(path = private_key_path, "wrote signing key");

    // Write public key as raw 32 bytes, base64url-encoded.
    let vk_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    std::fs::write(public_key_path, &vk_b64)?;
    info!(path = public_key_path, "wrote verification key");

    println!("Signing key:      {}", private_key_path);
    println!("Verification key: {}", public_key_path);
    println!();
    println!("Verification key (base64url): {}", vk_b64);
    println!(
        "Embed this verification key in client binaries and server config."
    );

    Ok(())
}

/// Generate a signed manifest from a pool config file.
pub fn cmd_generate(pool_path: &str, key_path: &str, output_path: &str) -> anyhow::Result<()> {
    let pool_text = std::fs::read_to_string(pool_path)
        .map_err(|e| anyhow::anyhow!("read pool config {}: {}", pool_path, e))?;
    let pool: PoolConfig = toml::from_str(&pool_text)
        .map_err(|e| anyhow::anyhow!("parse pool config: {}", e))?;

    let secret_key = load_signing_key(key_path)?;

    let domains: Vec<DomainEntry> = pool
        .domains
        .into_iter()
        .map(|d| pool_entry_to_domain_entry(d))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let version = pool.version.unwrap_or(timestamp);

    let mut manifest = DomainManifest {
        version,
        timestamp,
        domains,
        deprecated: pool.deprecated,
        refresh_interval_secs: pool.refresh_interval_secs,
        signature: [0u8; 64],
    };

    manifest_crypto::sign_manifest(&mut manifest, &secret_key);

    let encoded = postcard::to_allocvec(&manifest)
        .map_err(|e| anyhow::anyhow!("serialize manifest: {}", e))?;

    std::fs::write(output_path, &encoded)?;

    info!(
        version = manifest.version,
        domains = manifest.domains.len(),
        size = encoded.len(),
        path = output_path,
        "wrote signed manifest"
    );

    println!("Manifest written to: {}", output_path);
    println!("  Version:  {}", manifest.version);
    println!("  Domains:  {}", manifest.domains.len());
    println!("  Size:     {} bytes", encoded.len());

    Ok(())
}

/// Sign an existing manifest file in place.
pub fn cmd_sign(file_path: &str, key_path: &str) -> anyhow::Result<()> {
    let data = std::fs::read(file_path)
        .map_err(|e| anyhow::anyhow!("read manifest {}: {}", file_path, e))?;

    let mut manifest: DomainManifest = postcard::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("deserialize manifest: {}", e))?;

    let secret_key = load_signing_key(key_path)?;
    manifest_crypto::sign_manifest(&mut manifest, &secret_key);

    let encoded = postcard::to_allocvec(&manifest)
        .map_err(|e| anyhow::anyhow!("serialize manifest: {}", e))?;

    std::fs::write(file_path, &encoded)?;

    println!("Manifest signed: {}", file_path);
    println!("  Version: {}", manifest.version);

    Ok(())
}

fn load_signing_key(path: &str) -> anyhow::Result<[u8; 32]> {
    let b64 = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read signing key {}: {}", path, e))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| anyhow::anyhow!("invalid signing key base64: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "signing key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn pool_entry_to_domain_entry(entry: PoolDomainEntry) -> anyhow::Result<DomainEntry> {
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(&entry.server_public_key)
        .map_err(|e| anyhow::anyhow!("invalid server_public_key for {}: {}", entry.hostname, e))?;
    if pk_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "server_public_key for {} must be 32 bytes",
            entry.hostname
        ));
    }
    let mut server_public_key = [0u8; 32];
    server_public_key.copy_from_slice(&pk_bytes);

    let psk_bytes = URL_SAFE_NO_PAD
        .decode(&entry.psk)
        .map_err(|e| anyhow::anyhow!("invalid psk for {}: {}", entry.hostname, e))?;
    if psk_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "psk for {} must be 32 bytes",
            entry.hostname
        ));
    }
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&psk_bytes);

    Ok(DomainEntry {
        hostname: entry.hostname,
        cdn_ips: entry.cdn_ips,
        origin_path_prefix: entry.origin_path_prefix,
        server_public_key,
        psk,
        priority: entry.priority,
        region_hint: entry.region_hint,
        valid_until: entry.valid_until,
    })
}

/// Load a manifest from a file (used by other modules).
pub fn load_manifest(path: &Path) -> anyhow::Result<DomainManifest> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("read manifest {}: {}", path.display(), e))?;
    let manifest: DomainManifest = postcard::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("deserialize manifest: {}", e))?;
    Ok(manifest)
}
