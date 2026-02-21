//! Adaptive traffic shaping for MIRAGE.
//!
//! The traffic shaper transforms MIRAGE frame streams to match statistical
//! profiles of real web browsing traffic. This addresses ML-based traffic
//! classifiers that analyze packet size distributions, timing, and
//! bidirectional ratios.
//!
//! Key techniques:
//! - Response size quantization (bucketing)
//! - Request padding to realistic sizes
//! - Idle-period padding to simulate AJAX polling
//! - Burst shaping to match page-load patterns

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::config::{DistributionConfig, TrafficProfileConfig};

/// Traffic shaper that adapts outbound traffic to match a statistical profile.
pub struct TrafficShaper {
    profile: TrafficProfileConfig,
    state: ShaperState,
}

/// Internal state for the traffic shaper.
struct ShaperState {
    /// Bytes sent since last padding injection.
    bytes_since_padding: u64,
    /// Number of frames sent in current burst.
    frames_in_burst: u32,
    /// Timestamp of last frame sent (nanoseconds).
    last_frame_time_ns: u64,
    /// Timestamp of last padding injection.
    last_padding_time_ns: u64,
    /// Simple PRNG state for lightweight randomness (xorshift64).
    /// Used for traffic shaping decisions where cryptographic randomness
    /// is unnecessary and expensive.
    rng_state: u64,
}

impl TrafficShaper {
    /// Create a new traffic shaper with the given profile.
    pub fn new(profile: &TrafficProfileConfig) -> Self {
        // Seed the PRNG from system randomness
        let mut seed_bytes = [0u8; 8];
        getrandom::getrandom(&mut seed_bytes).unwrap_or_default();
        let seed = u64::from_le_bytes(seed_bytes);

        TrafficShaper {
            profile: profile.clone(),
            state: ShaperState {
                bytes_since_padding: 0,
                frames_in_burst: 0,
                last_frame_time_ns: 0,
                last_padding_time_ns: 0,
                rng_state: if seed == 0 { 0xDEAD_BEEF_CAFE_BABE } else { seed },
            },
        }
    }

    /// Shape outbound data by applying padding and bucketing.
    ///
    /// Takes a MIRAGE frame (already encrypted) and returns one or more
    /// chunks that should be sent, potentially with added padding.
    pub fn shape_outbound(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let now = crate::clock::clock_nanos();
        self.state.last_frame_time_ns = now;
        self.state.bytes_since_padding += frame.len() as u64;
        self.state.frames_in_burst += 1;

        let mut result = Vec::new();

        // Quantize the frame size to the nearest response size bucket
        let target_size = self.quantize_size(frame.len());

        if target_size > frame.len() {
            // Need to add padding to reach the bucket size
            let mut padded = Vec::with_capacity(target_size);
            padded.extend_from_slice(frame);
            // Fill remaining space with random-looking padding
            // The padding is outside the MIRAGE frame, so it appears as
            // HTTP/2 DATA frame content that the receiver will ignore
            // (receiver parses MIRAGE frames from the DATA payload and
            // ignores trailing bytes)
            let padding_len = target_size - frame.len();
            let padding = self.generate_random_bytes(padding_len);
            padded.extend_from_slice(&padding);
            result.push(padded);
        } else {
            result.push(frame.to_vec());
        }

        result
    }

    /// Determine if padding traffic should be generated during an idle period.
    /// Returns Some(padding_bytes) if padding should be sent, None otherwise.
    pub fn maybe_generate_padding(&mut self) -> Option<Vec<u8>> {
        let now = crate::clock::clock_nanos();

        // Check if enough time has passed since last activity
        let elapsed_ms =
            (now.saturating_sub(self.state.last_frame_time_ns)) / 1_000_000;

        // Only generate padding if we have been idle for a while
        // (mimicking AJAX polling intervals)
        if elapsed_ms < 1000 {
            return None;
        }

        // Check against the idle padding probability
        let roll = self.next_random_f64();
        if roll > self.profile.idle_padding_probability {
            return None;
        }

        // Generate a padding burst of random size within the configured range
        let (min_size, max_size) = self.profile.idle_padding_size_range;
        let size = self.random_range(min_size as u64, max_size as u64) as usize;

        self.state.last_padding_time_ns = now;
        self.state.last_frame_time_ns = now;

        Some(self.generate_random_bytes(size))
    }

    /// Quantize a payload size to the nearest response size bucket.
    /// This reduces information leakage from exact payload sizes.
    fn quantize_size(&self, actual_size: usize) -> usize {
        for &bucket in &self.profile.response_size_buckets {
            if bucket as usize >= actual_size {
                return bucket as usize;
            }
        }
        // If larger than all buckets, round up to the nearest multiple
        // of the largest bucket
        let largest = *self.profile.response_size_buckets.last().unwrap_or(&16384) as usize;
        ((actual_size + largest - 1) / largest) * largest
    }

    /// Generate pseudo-random bytes for padding.
    /// Uses a fast PRNG since cryptographic randomness is not required for padding.
    fn generate_random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        for chunk in bytes.chunks_mut(8) {
            let val = self.next_random_u64();
            let val_bytes = val.to_le_bytes();
            let copy_len = chunk.len().min(8);
            chunk[..copy_len].copy_from_slice(&val_bytes[..copy_len]);
        }
        bytes
    }

    /// Xorshift64 PRNG -- fast, non-cryptographic random number generator.
    fn next_random_u64(&mut self) -> u64 {
        let mut x = self.state.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state.rng_state = x;
        x
    }

    /// Generate a random f64 in [0, 1).
    fn next_random_f64(&mut self) -> f64 {
        let val = self.next_random_u64();
        (val >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Generate a random integer in [min, max].
    fn random_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        let range = max - min + 1;
        min + (self.next_random_u64() % range)
    }

    /// Sample from a configured distribution.
    /// Returns a value following the distribution's parameters.
    #[allow(dead_code)]
    fn sample_distribution(&mut self, dist: &DistributionConfig) -> f64 {
        match dist {
            DistributionConfig::Fixed { value } => *value,
            DistributionConfig::Uniform { min, max } => {
                let t = self.next_random_f64();
                min + t * (max - min)
            }
            DistributionConfig::Exponential { lambda } => {
                // Inverse CDF: -ln(1 - U) / lambda
                let u = self.next_random_f64();
                let clamped = if u >= 1.0 { 1.0 - f64::EPSILON } else { u };
                -(1.0 - clamped).ln() / lambda
            }
            DistributionConfig::Normal { mu, sigma } => {
                // Box-Muller transform (simplified)
                let u1 = self.next_random_f64().max(f64::MIN_POSITIVE);
                let u2 = self.next_random_f64();
                let z = (-2.0 * u1.ln()).sqrt()
                    * (2.0 * core::f64::consts::PI * u2).cos();
                mu + sigma * z
            }
            DistributionConfig::LogNormal { mu, sigma } => {
                // Sample normal, then exponentiate
                let u1 = self.next_random_f64().max(f64::MIN_POSITIVE);
                let u2 = self.next_random_f64();
                let z = (-2.0 * u1.ln()).sqrt()
                    * (2.0 * core::f64::consts::PI * u2).cos();
                (mu + sigma * z).exp()
            }
        }
    }
}
