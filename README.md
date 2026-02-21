# MIRAGE

**Multiplexed Indistinguishable Relaying with Adaptive Gateway Emulation**

A CDN-native censorship circumvention transport protocol implemented as a [WATER](https://water.refraction.network/) (WebAssembly Transport Executables Runtime) v1 module. Compiles to a 110KB WASM binary.

## What it does

MIRAGE tunnels proxy traffic through genuine CDN-terminated TLS connections as standard HTTP/2, making it indistinguishable from normal web browsing to network observers. Unlike protocols that camouflage TLS (REALITY, ShadowTLS) or tunnel TLS inside TLS (Trojan, VMess), MIRAGE operates as an authenticated overlay *within* the CDN's own HTTP/2 connection.

```
Client (WASM) <--TLS--> CDN Edge <--TLS--> MIRAGE Origin <--> Target
                         (Cloudflare, etc.)

Observer sees: Standard HTTPS to cdn-provider.com
```

## Why it matters

MIRAGE is designed to resist all known detection techniques documented through 2025:

| Detection technique | How MIRAGE handles it |
|---|---|
| TLS fingerprinting (JA3/JA4, JARM) | CDN terminates TLS with its own stack |
| Encapsulated TLS fingerprinting (USENIX Security 2024) | No inner TLS handshake exists |
| Cross-layer RTT fingerprinting (NDSS 2025) | CDN edge equalizes RTT profiles |
| Post-handshake analysis (Aparecium) | CDN handles all TLS post-handshake |
| Active probing (replay, crafted) | Cover site serves legitimate responses |
| Entropy/DPI analysis | Traffic is valid HTTP/2 with proper HPACK headers |
| Protocol whitelisting (Iran) | Real HTTPS on port 443 |
| ML traffic classification | Adaptive traffic morphing matches real browsing profiles |

## Building

```bash
# Install Rust and the WASM target
rustup target add wasm32-wasip1

# Build
cargo build --target wasm32-wasip1 --release

# Output: target/wasm32-wasip1/release/mirage_watm.wasm (~110KB)
```

Optionally optimize further with [Binaryen](https://github.com/WebAssembly/binaryen):

```bash
wasm-opt -Os -o mirage-opt.wasm target/wasm32-wasip1/release/mirage_watm.wasm
```

## Architecture

### WATM v1 exports

The compiled WASM module exports the six functions required by the WATER v1 transport module interface:

| Export | Purpose |
|---|---|
| `watm_init_v1()` | Module initialization |
| `watm_ctrlpipe_v1(fd)` | Receive configuration via control pipe |
| `watm_dial_v1(internal_fd)` | Client-side: dial CDN, perform handshake |
| `watm_accept_v1(internal_fd)` | Server-side: accept connection, validate auth |
| `watm_associate_v1()` | Relay mode setup |
| `watm_start_v1()` | Enter the blocking event loop |

### Source modules

| File | Description |
|---|---|
| `src/lib.rs` | WATM entry points, connection lifecycle, poll-based event loop |
| `src/crypto.rs` | X25519 key exchange, HKDF derivation, ChaCha20-Poly1305 AEAD, HMAC-SHA256 auth tokens, forward-secret key rotation |
| `src/http2.rs` | Minimal HTTP/2 framing (HEADERS, DATA, SETTINGS, WINDOW_UPDATE, PING, GOAWAY) with HPACK encoding |
| `src/framing.rs` | MIRAGE inner frame types and CONNECT address parsing |
| `src/traffic_shaper.rs` | Response size bucketing, idle padding, statistical distribution sampling |
| `src/config.rs` | Configuration structures delivered via WATER control pipe (postcard serialization) |
| `src/wasi_io.rs` | WASI Preview 1 syscall wrappers (fd I/O, clocks, randomness, poll_oneoff) |

### Connection lifecycle

1. **Config delivery**: WATER host sends `MirageConfig` (server public key, PSK, CDN hostname, traffic profile) through the control pipe
2. **Dial/Accept**: Client dials CDN on port 443 via `water_dial`; server accepts via `water_accept`
3. **HTTP/2 setup**: Connection preface, SETTINGS exchange, WINDOW_UPDATE for large receive windows
4. **Authentication**: Client sends a GET request with an HMAC-authenticated cookie containing an ephemeral X25519 public key and timestamp. Server validates, responds with an encrypted session token in `set-cookie`
5. **Session keys**: Both sides derive symmetric ChaCha20-Poly1305 keys from ephemeral DH + PSK via HKDF
6. **Data tunnel**: Bidirectional relay of MIRAGE frames inside HTTP/2 DATA frames, with traffic shaping and periodic key rotation
7. **Teardown**: MIRAGE Close frame followed by HTTP/2 GOAWAY

### Cryptography

- **Key exchange**: X25519 ephemeral Diffie-Hellman (per session)
- **Key derivation**: HKDF-SHA256 with context binding (timestamps, nonces, protocol labels)
- **Encryption**: ChaCha20-Poly1305 AEAD with sequence-number-derived nonces
- **Authentication**: HMAC-SHA256 over auth tokens, PSK as additional authentication factor
- **Key rotation**: New ephemeral DH within session, chained from previous key material for forward secrecy. Triggers after 16M frames or 1 GiB transferred
- **Sensitive data**: Zeroized after use via the `zeroize` crate

### MIRAGE frame types

| Type | Name | Description |
|---|---|---|
| `0x01` | Data | Tunneled application data |
| `0x02` | Connect | Request tunnel to target address (IPv4/IPv6/domain) |
| `0x03` | ConnectOk | Tunnel established |
| `0x04` | ConnectErr | Tunnel failed |
| `0x05` | Ping | Keep-alive |
| `0x06` | Pong | Ping response |
| `0x07` | KeyRotate | Initiate in-session key rotation |
| `0x08` | KeyAck | Acknowledge key rotation |
| `0x09` | Close | Clean shutdown |
| `0x0A` | Pad | Padding (discarded by receiver) |

Frame wire format: `type(1) || length(2 BE) || seq(4 BE) || ciphertext || poly1305_tag(16)`

### Traffic shaping

The traffic shaper reduces side-channel information leakage:

- **Response size bucketing**: Quantizes outbound data to configurable size buckets (default: 256, 512, 1K, 2K, 4K, 8K, 16K, 32K, 64K)
- **Idle padding**: Probabilistic padding generation during quiet periods, mimicking AJAX polling patterns
- **Statistical sampling**: Log-normal, exponential, normal, and uniform distributions for realistic timing and sizing via Box-Muller and inverse-CDF transforms
- **Fast PRNG**: Xorshift64 for non-cryptographic traffic shaping decisions

### Dependencies

All pure-Rust, no C dependencies, WASM-compatible:

| Crate | Purpose |
|---|---|
| `chacha20poly1305` | AEAD encryption |
| `x25519-dalek` | Elliptic curve Diffie-Hellman |
| `hkdf`, `hmac`, `sha2` | Key derivation and authentication |
| `getrandom` | Backed by WASI `random_get` (custom registration) |
| `serde`, `postcard` | Compact binary config serialization |
| `base64` | Token encoding |
| `zeroize` | Secure memory clearing |

### Configuration

Configuration is delivered as `postcard`-serialized binary through the WATER control pipe:

```rust
MirageConfig {
    server_public_key: PublicKey,      // X25519 (32 bytes)
    psk: [u8; 32],                     // Pre-shared key
    cdn_hostname: String,              // e.g. "assets.example-cdn.com"
    cdn_ips: Vec<String>,              // Fallback IPs for DNS poisoning
    origin_path_prefix: String,        // e.g. "/api/v2/"
    traffic_profile: TrafficProfileConfig,
    mode: OperatingMode,               // CdnFronted | DirectTls | QuicExperimental
    max_concurrent_streams: u16,
    session_duration_range: (u64, u64),
    server_private_key: Option<StaticSecret>, // Server-side only
}
```

## Modes of operation

| Mode | Description | Detection resistance |
|---|---|---|
| **CDN-Fronted** (primary) | Traffic through Cloudflare/Fastly/etc. | Maximum -- CDN handles TLS, equalizes RTTs |
| **Direct TLS** (fallback) | Origin terminates TLS, serves cover site | Strong -- still defeats DPI, active probing |
| **QUIC/HTTP3** (experimental) | Over QUIC with HTTP/3 semantics | Variable -- depends on QUIC censorship landscape |

## Protocol specification

See [MIRAGE-protocol-specification.md](MIRAGE-protocol-specification.md) for the full protocol design, threat model, security analysis, and comparison with REALITY, naiveproxy, Shadowsocks-2022, Hysteria2, Trojan, and ShadowTLS v3.

## License

Apache-2.0 OR MIT
