//! MIRAGE protocol core: shared crypto, framing, config, and traffic shaping.
//!
//! This crate is portable across native (std) and WASI targets via feature flags.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod clock;
pub mod config;
pub mod crypto;
pub mod framing;
pub mod manifest;
pub mod traffic_shaper;
