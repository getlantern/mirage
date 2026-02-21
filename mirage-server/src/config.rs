//! Server configuration: TOML deserialization + CLI args.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use std::path::PathBuf;
use x25519_dalek::StaticSecret;

/// Top-level server configuration file.
#[derive(Deserialize)]
pub struct ServerConfigFile {
    pub server: ServerSection,
    pub protocol: ProtocolSection,
    pub cover_site: CoverSiteSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Deserialize)]
pub struct ServerSection {
    pub listen_addr: String,
    #[serde(default)]
    pub tls: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Deserialize)]
pub struct ProtocolSection {
    /// Base64url-encoded 32-byte server private key.
    pub server_private_key: String,
    /// Base64url-encoded 32-byte pre-shared key.
    pub psk: String,
    /// Path to the signed domain manifest file (optional).
    pub manifest_path: Option<String>,
    /// Base64url-encoded 32-byte Ed25519 verification key for manifests (optional).
    pub manifest_verify_key: Option<String>,
}

#[derive(Deserialize)]
pub struct CoverSiteSection {
    pub origin: String,
    #[serde(default = "default_cover_timeout")]
    pub timeout_secs: u64,
}

fn default_cover_timeout() -> u64 {
    10
}

#[derive(Deserialize)]
pub struct LimitsSection {
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,
    #[serde(default = "default_idle_timeout")]
    pub session_idle_timeout_secs: u64,
    #[serde(default = "default_connect_timeout")]
    pub upstream_connect_timeout_secs: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: default_max_sessions(),
            session_idle_timeout_secs: default_idle_timeout(),
            upstream_connect_timeout_secs: default_connect_timeout(),
        }
    }
}

fn default_max_sessions() -> usize {
    10_000
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_connect_timeout() -> u64 {
    10
}

#[derive(Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

/// Parsed, validated server config ready for use.
pub struct ServerConfig {
    pub listen_addr: String,
    pub tls: bool,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub server_private_key: StaticSecret,
    pub psk: [u8; 32],
    pub cover_site_origin: String,
    pub cover_site_timeout_secs: u64,
    pub max_concurrent_sessions: usize,
    pub session_idle_timeout_secs: u64,
    pub upstream_connect_timeout_secs: u64,
    pub log_level: String,
    pub manifest_path: Option<PathBuf>,
    pub manifest_verify_key: Option<[u8; 32]>,
}

impl ServerConfig {
    pub fn from_file(file: ServerConfigFile) -> Result<Self, String> {
        let key_bytes = URL_SAFE_NO_PAD
            .decode(&file.protocol.server_private_key)
            .map_err(|e| format!("invalid server_private_key base64: {e}"))?;
        if key_bytes.len() != 32 {
            return Err(format!(
                "server_private_key must be 32 bytes, got {}",
                key_bytes.len()
            ));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let server_private_key = StaticSecret::from(key_arr);

        let psk_bytes = URL_SAFE_NO_PAD
            .decode(&file.protocol.psk)
            .map_err(|e| format!("invalid psk base64: {e}"))?;
        if psk_bytes.len() != 32 {
            return Err(format!("psk must be 32 bytes, got {}", psk_bytes.len()));
        }
        let mut psk = [0u8; 32];
        psk.copy_from_slice(&psk_bytes);

        if file.server.tls {
            if file.server.tls_cert_path.is_none() {
                return Err("tls=true but tls_cert_path is missing".into());
            }
            if file.server.tls_key_path.is_none() {
                return Err("tls=true but tls_key_path is missing".into());
            }
        }

        let manifest_verify_key = match &file.protocol.manifest_verify_key {
            Some(b64) => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|e| format!("invalid manifest_verify_key base64: {e}"))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "manifest_verify_key must be 32 bytes, got {}",
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            }
            None => None,
        };

        Ok(ServerConfig {
            listen_addr: file.server.listen_addr,
            tls: file.server.tls,
            tls_cert_path: file.server.tls_cert_path.map(PathBuf::from),
            tls_key_path: file.server.tls_key_path.map(PathBuf::from),
            server_private_key,
            psk,
            cover_site_origin: file.cover_site.origin,
            cover_site_timeout_secs: file.cover_site.timeout_secs,
            max_concurrent_sessions: file.limits.max_concurrent_sessions,
            session_idle_timeout_secs: file.limits.session_idle_timeout_secs,
            upstream_connect_timeout_secs: file.limits.upstream_connect_timeout_secs,
            log_level: file.logging.level,
            manifest_path: file.protocol.manifest_path.map(PathBuf::from),
            manifest_verify_key,
        })
    }
}
