//! MIRAGE configuration structures.
//!
//! Configuration is delivered to the WATM module via the WATER control pipe
//! and deserialized from the compact `postcard` binary format.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Custom serde for x25519-dalek types (they don't derive serde)
// ---------------------------------------------------------------------------

mod serde_public_key {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &PublicKey, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<PublicKey, D::Error> {
        let bytes: [u8; 32] = <[u8; 32]>::deserialize(de)?;
        Ok(PublicKey::from(bytes))
    }
}

mod serde_sig64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("64 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(arr)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<[u8; 64], A::Error> {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }
        de.deserialize_bytes(Visitor)
    }
}

mod serde_option_static_secret {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        key: &Option<StaticSecret>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        match key {
            Some(k) => ser.serialize_some(&k.to_bytes()),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<StaticSecret>, D::Error> {
        let opt: Option<[u8; 32]> = Option::deserialize(de)?;
        Ok(opt.map(StaticSecret::from))
    }
}

/// Top-level MIRAGE configuration delivered via the WATER control pipe.
#[derive(Serialize, Deserialize)]
pub struct MirageConfig {
    /// Server's X25519 public key (32 bytes).
    #[serde(with = "serde_public_key")]
    pub server_public_key: PublicKey,

    /// Pre-shared key for initial authentication (32 bytes).
    pub psk: [u8; 32],

    /// CDN hostname (e.g., "assets.example-cdn.com").
    pub cdn_hostname: String,

    /// Fallback CDN IP addresses (for when DNS is poisoned).
    pub cdn_ips: Vec<String>,

    /// URL path prefix for MIRAGE requests (e.g., "/api/v2/").
    pub origin_path_prefix: String,

    /// Traffic shaping profile.
    pub traffic_profile: TrafficProfileConfig,

    /// Operating mode.
    pub mode: OperatingMode,

    /// Maximum concurrent HTTP/2 streams to maintain.
    pub max_concurrent_streams: u16,

    /// Session duration range in seconds (min, max).
    pub session_duration_range: (u64, u64),

    /// Server private key (only present in server-side config).
    #[serde(
        with = "serde_option_static_secret",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub server_private_key: Option<StaticSecret>,
}

/// Operating mode for the MIRAGE transport.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatingMode {
    /// Traffic flows through a public CDN (Cloudflare, Fastly, etc.).
    CdnFronted,

    /// Direct TLS connection to the origin server.
    DirectTls,

    /// QUIC/HTTP3 mode (experimental).
    QuicExperimental,
}

/// Statistical distribution configuration for traffic shaping.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DistributionConfig {
    Normal { mu: f64, sigma: f64 },
    LogNormal { mu: f64, sigma: f64 },
    Exponential { lambda: f64 },
    Uniform { min: f64, max: f64 },
    Fixed { value: f64 },
}

/// Traffic profile configuration for adaptive traffic morphing.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrafficProfileConfig {
    /// Name of this profile (for logging/debugging).
    pub profile_name: String,

    /// Distribution of the number of HTTP/2 streams opened per session.
    pub streams_per_session: DistributionConfig,

    /// Distribution of time (milliseconds) between opening new streams.
    pub stream_open_interval_ms: DistributionConfig,

    /// Distribution of request sizes (bytes), including headers.
    pub request_sizes: DistributionConfig,

    /// Buckets for quantizing response sizes (bytes).
    pub response_size_buckets: Vec<u32>,

    /// Distribution of "think time" (milliseconds) between page loads.
    pub think_time_ms: DistributionConfig,

    /// Minimum padded request size in bytes.
    pub min_request_size: u32,

    /// Maximum padded request size in bytes.
    pub max_request_size: u32,

    /// Probability of generating a padding burst during idle periods.
    pub idle_padding_probability: f64,

    /// Size range for idle padding bursts (bytes).
    pub idle_padding_size_range: (u32, u32),
}

impl Default for TrafficProfileConfig {
    fn default() -> Self {
        Self {
            profile_name: String::from("default_news_browsing"),
            streams_per_session: DistributionConfig::LogNormal {
                mu: 2.5,
                sigma: 1.2,
            },
            stream_open_interval_ms: DistributionConfig::Exponential {
                lambda: 0.01,
            },
            request_sizes: DistributionConfig::Normal {
                mu: 500.0,
                sigma: 200.0,
            },
            response_size_buckets: alloc::vec![
                256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
            ],
            think_time_ms: DistributionConfig::LogNormal {
                mu: 8.5,
                sigma: 1.5,
            },
            min_request_size: 128,
            max_request_size: 4096,
            idle_padding_probability: 0.1,
            idle_padding_size_range: (64, 512),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain rotation types
// ---------------------------------------------------------------------------

/// A single domain endpoint in the rotation pool.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DomainEntry {
    /// CDN hostname (e.g., "assets.example-cdn.com").
    pub hostname: String,
    /// Fallback CDN IP addresses.
    pub cdn_ips: Vec<String>,
    /// URL path prefix for MIRAGE requests.
    pub origin_path_prefix: String,
    /// Server X25519 public key for this domain (may differ per domain).
    pub server_public_key: [u8; 32],
    /// Pre-shared key for this domain.
    pub psk: [u8; 32],
    /// Priority weight (higher = prefer). 0 = disabled.
    pub priority: u8,
    /// Optional geographic region hint (e.g., "us", "eu", "asia").
    pub region_hint: Option<String>,
    /// Unix timestamp after which this entry expires.
    pub valid_until: u64,
}

/// Signed domain manifest containing the full domain roster.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DomainManifest {
    /// Monotonically increasing version number.
    pub version: u64,
    /// Unix timestamp when this manifest was created.
    pub timestamp: u64,
    /// Active domain entries.
    pub domains: Vec<DomainEntry>,
    /// Hostnames being phased out (clients should stop using).
    pub deprecated: Vec<String>,
    /// Suggested seconds until next manifest check.
    pub refresh_interval_secs: u64,
    /// Ed25519 signature over the canonical serialization of all fields above.
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
}

/// Delta update (smaller than full manifest).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DomainDelta {
    /// Must match client's current manifest version.
    pub base_version: u64,
    /// New version after applying this delta.
    pub new_version: u64,
    /// New domain entries to add.
    pub added: Vec<DomainEntry>,
    /// Hostnames to remove from the active pool.
    pub removed: Vec<String>,
    /// Ed25519 signature.
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
}

/// Domain update delivered in-band or via control pipe.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DomainUpdate {
    /// Full manifest replacement.
    Full(DomainManifest),
    /// Incremental delta.
    Delta(DomainDelta),
}

// ---------------------------------------------------------------------------
// Key/profile update types
// ---------------------------------------------------------------------------

/// A key update message delivered via the WATER control pipe.
#[derive(Serialize, Deserialize)]
pub struct KeyUpdate {
    /// New server X25519 public key.
    #[serde(with = "serde_public_key")]
    pub new_server_public_key: PublicKey,
    /// New pre-shared key.
    pub new_psk: [u8; 32],
    /// Unix timestamp after which the new keys become effective.
    pub effective_after: u64,
}

/// A traffic profile update delivered via the WATER control pipe.
#[derive(Serialize, Deserialize)]
pub struct ProfileUpdate {
    pub new_traffic_profile: TrafficProfileConfig,
}

/// Control pipe message types.
#[derive(Serialize, Deserialize)]
pub enum ControlMessage {
    Config(MirageConfig),
    KeyUpdate(KeyUpdate),
    ProfileUpdate(ProfileUpdate),
    DomainUpdate(DomainUpdate),
    Shutdown,
}
