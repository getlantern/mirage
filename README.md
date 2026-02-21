# MIRAGE

**Multiplexed Indistinguishable Relaying with Adaptive Gateway Emulation**

A CDN-native censorship circumvention transport protocol. The client is a [WATER](https://water.refraction.network/) (WebAssembly Transport Executables Runtime) v1 module that compiles to a 110KB WASM binary. The server is a native async Rust binary that handles authentication, encrypted relay, and transparent reverse-proxying of the cover site for unauthenticated visitors.

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

# Build everything (excluding WASM-only mirage-watm)
cargo build -p mirage-core -p mirage-server -p mirage-provisioner

# Build the WASM client module
cargo build -p mirage-watm --target wasm32-wasip1 --release
# Output: target/wasm32-wasip1/release/mirage_watm.wasm (~110KB)

# Build the server binary
cargo build -p mirage-server --release
# Output: target/release/mirage-server

# Build the provisioner CLI
cargo build -p mirage-provisioner --release
# Output: target/release/mirage-provisioner
```

Optionally optimize the WASM module further with [Binaryen](https://github.com/WebAssembly/binaryen):

```bash
wasm-opt -Os -o mirage-opt.wasm target/wasm32-wasip1/release/mirage_watm.wasm
```

## Architecture

### Workspace structure

The codebase is a Cargo workspace with four crates:

| Crate | Description |
|---|---|
| `mirage-core` | Shared portable library: crypto, framing, config, traffic shaping, clock abstraction, domain manifest signing/verification. Compiles to both WASM and native via feature gates (`std` / `wasi`) |
| `mirage-watm` | WATER v1 transport module (WASM client). Depends on mirage-core with `wasi` feature |
| `mirage-server` | Native async Rust server binary. Depends on mirage-core with `std` feature, plus tokio, h2, reqwest |
| `mirage-provisioner` | CLI tool for domain pool lifecycle: CDN provisioning (Cloudflare for SaaS), Ed25519 manifest signing, domain health monitoring |

### WATM v1 exports (client)

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

**mirage-core** (shared, portable):

| File | Description |
|---|---|
| `src/crypto.rs` | X25519 key exchange, HKDF derivation, ChaCha20-Poly1305 AEAD, HMAC-SHA256 auth tokens, forward-secret key rotation |
| `src/framing.rs` | MIRAGE inner frame types and CONNECT address parsing |
| `src/config.rs` | Configuration structures and domain rotation types (postcard serialization) |
| `src/manifest.rs` | Ed25519 manifest signing and verification for domain rotation |
| `src/traffic_shaper.rs` | Response size bucketing, idle padding, statistical distribution sampling |
| `src/clock.rs` | Platform-abstracted clocks (`std::time` on native, WASI syscalls on WASM) |

**mirage-watm** (WASM client):

| File | Description |
|---|---|
| `src/lib.rs` | WATM entry points, connection lifecycle, poll-based event loop, DomainUpdate forwarding to host |
| `src/http2.rs` | Minimal HTTP/2 framing (HEADERS, DATA, SETTINGS, WINDOW_UPDATE, PING, GOAWAY) with HPACK encoding |
| `src/wasi_io.rs` | WASI Preview 1 syscall wrappers (fd I/O, clocks, randomness, poll_oneoff) |

**mirage-server** (native server):

| File | Description |
|---|---|
| `src/main.rs` | CLI, config loading, manifest loading, tracing init, signal handling |
| `src/config.rs` | TOML config deserialization and validation |
| `src/server.rs` | TCP/TLS listener, accept loop, per-connection spawn with semaphore |
| `src/connection.rs` | H2 handshake, auth validation, session establishment, cover site fallback |
| `src/relay.rs` | Bidirectional encrypted relay (H2 DATA frames ↔ upstream TCP), DomainUpdate push to clients |
| `src/cover.rs` | Transparent reverse proxy to cover site for unauthenticated connections |
| `src/manifest.rs` | Manifest loading, verification, file watching for hot-reload, delta computation |

**mirage-provisioner** (CLI tool):

| File | Description |
|---|---|
| `src/main.rs` | CLI entry point with clap subcommands |
| `src/manifest.rs` | Ed25519 keygen, manifest generation from pool config, signing |
| `src/cloudflare.rs` | Cloudflare for SaaS API integration (custom hostname lifecycle) |
| `src/monitor.rs` | Domain health probing (TLS connect, HTTP status, blocked/alive detection) |
| `src/domain_gen.rs` | Plausible CDN-like domain name generation |

### Connection lifecycle (client)

1. **Config delivery**: WATER host sends `MirageConfig` (server public key, PSK, CDN hostname, traffic profile) through the control pipe
2. **Dial**: Client dials CDN on port 443 via `water_dial`
3. **HTTP/2 setup**: Connection preface, SETTINGS exchange, WINDOW_UPDATE for large receive windows
4. **Authentication**: Client sends a GET request with an HMAC-authenticated cookie containing an ephemeral X25519 public key and timestamp. Server validates, responds with an encrypted session token in `set-cookie`
5. **Session keys**: Both sides derive symmetric ChaCha20-Poly1305 keys from ephemeral DH + PSK via HKDF
6. **Data tunnel**: Bidirectional relay of MIRAGE frames inside HTTP/2 DATA frames, with traffic shaping and periodic key rotation
7. **Domain updates**: Server pushes `DomainUpdate` frames containing signed domain manifests; WATM forwards these to the WATER host via the control pipe for domain rotation
8. **Teardown**: MIRAGE Close frame followed by HTTP/2 GOAWAY

### Connection lifecycle (server)

1. **Accept**: TCP accept, optional TLS handshake (tokio-rustls for direct mode; plain H2 for CDN-fronted mode where the CDN terminates TLS)
2. **H2 handshake**: `h2::server::handshake()` — connection preface and SETTINGS exchange
3. **Auth check**: Accept stream 1, extract `_session=` cookie, validate HMAC token and X25519 handshake
4. **Auth failure → cover site**: If authentication fails (or no cookie present), the server becomes a **transparent reverse proxy** for the configured cover site. All subsequent H2 streams are forwarded — method, path, headers, body — for the full connection lifetime. Each stream is spawned concurrently, matching real browser behavior. The server is indistinguishable from the real cover site
5. **Auth success → relay**: Send `set-cookie` response with encrypted session token. Accept stream 3 as the data tunnel. Push current domain manifest as a `DomainUpdate` frame. Enter bidirectional relay: decrypt inbound MIRAGE frames, dispatch (Data, Connect, Ping, KeyRotate, Close, Pad, DomainReport), encrypt outbound with traffic shaping
6. **Teardown**: MIRAGE Close frame, H2 GOAWAY, graceful drain of remaining streams

### Cryptography

- **Key exchange**: X25519 ephemeral Diffie-Hellman (per session)
- **Key derivation**: HKDF-SHA256 with context binding (timestamps, nonces, protocol labels)
- **Encryption**: ChaCha20-Poly1305 AEAD with sequence-number-derived nonces
- **Authentication**: HMAC-SHA256 over auth tokens, PSK as additional authentication factor
- **Key rotation**: New ephemeral DH within session, chained from previous key material for forward secrecy. Triggers after 16M frames or 1 GiB transferred
- **Manifest signing**: Ed25519 signatures over canonical serialization of domain manifests
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
| `0x0B` | DomainUpdate | Server → Client: signed domain manifest or delta |
| `0x0C` | DomainReport | Client → Server: connection success/failure reports |

Frame wire format: `type(1) || length(2 BE) || seq(4 BE) || ciphertext || poly1305_tag(16)`

### Traffic shaping

The traffic shaper reduces side-channel information leakage:

- **Response size bucketing**: Quantizes outbound data to configurable size buckets (default: 256, 512, 1K, 2K, 4K, 8K, 16K, 32K, 64K)
- **Idle padding**: Probabilistic padding generation during quiet periods, mimicking AJAX polling patterns
- **Statistical sampling**: Log-normal, exponential, normal, and uniform distributions for realistic timing and sizing via Box-Muller and inverse-CDF transforms
- **Fast PRNG**: Xorshift64 for non-cryptographic traffic shaping decisions

## Domain rotation

MIRAGE includes a domain rotation system so that when a domain is blocked, clients automatically switch to another. The architecture separates concerns across layers:

### Data flow

```
┌─────────────────────────────────────────────────────┐
│  mirage-provisioner (CLI tool)                      │
│  Cloudflare API, domain lifecycle, manifest signing │
└──────────────────────┬──────────────────────────────┘
                       │ signed manifests
                       v
┌─────────────────────────────────────────────────────┐
│  mirage-server                                      │
│  Loads manifest, pushes DomainUpdate to clients     │
└──────────────────────┬──────────────────────────────┘
                       │ MIRAGE frame 0x0B
                       v
┌─────────────────────────────────────────────────────┐
│  mirage-watm / WATER host                           │
│  Receives updates, host manages rotation & retry    │
└─────────────────────────────────────────────────────┘
```

### Domain selection

Domain selection and retry logic lives in the WATER host (Go/native), not in the WATM module. The WATM module connects to one domain at a time. The host:

- Stores the domain manifest persistently
- Selects the best domain (weighted random, with failure tracking)
- Delivers the selected domain's config to WATM via the control pipe
- On connection failure, selects the next domain and re-invokes WATM
- On receiving a `DomainUpdate` from WATM: verifies the Ed25519 signature, merges into manifest, persists

### Manifest structure

A `DomainManifest` contains:

- Monotonically increasing version number
- List of `DomainEntry` records (hostname, CDN IPs, path prefix, server public key, PSK, priority, region hint, expiry)
- Deprecated hostnames (clients should stop using)
- Refresh interval hint
- Ed25519 signature over canonical serialization of all fields

Manifests are signed offline with Ed25519. The verification key is embedded in client binaries.

### Provisioner CLI

```
mirage-provisioner keygen                     # Generate Ed25519 signing keypair
mirage-provisioner domain add <hostname>      # Add domain to pool (register on CDN)
mirage-provisioner domain remove <hostname>   # Deprecate domain
mirage-provisioner domain list                # Show pool with status
mirage-provisioner domain age-check           # Check NRD status of pool
mirage-provisioner manifest generate          # Generate and sign manifest from pool
mirage-provisioner manifest sign <file>       # Sign an existing manifest
mirage-provisioner monitor run                # Probe domains, report blocked ones
```

### Domain lifecycle

```
Register domain (diverse registrars, legitimate-looking names)
    ↓  (immediate)
Set up landing page + DNS records (MX, SPF, DKIM)
    ↓  (wait 60+ days to clear NRD lists)
Activate on CDN (Cloudflare for SaaS API)
    ↓  (minutes — TLS cert auto-provisioned)
Add to manifest, sign, deploy to servers
    ↓
Server pushes to connected clients via DomainUpdate frame
    ↓
Monitor health (probe from censored regions)
    ↓  (if blocked)
Mark deprecated, remove from manifest, sign new version
Push update to clients, activate standby domain
```

### Bootstrapping

Priority order for a fresh client or one with all domains blocked:

1. **Embedded domains**: 10-20 domains shipped in the app binary, rotated per release, partitioned across distribution channels
2. **DNS TXT side channel**: Query `_mir.{domain}` for a signed, base64-encoded mini-manifest
3. **Social distribution**: Compact signed tokens (QR codes, short URLs) containing 1-3 domain entries
4. **Automated bots**: Telegram/email distribution with rate limiting

### Dependencies

All pure-Rust, no C dependencies. Core crate compiles to both WASM and native:

**mirage-core** (portable):

| Crate | Purpose |
|---|---|
| `chacha20poly1305` | AEAD encryption |
| `x25519-dalek` | Elliptic curve Diffie-Hellman |
| `ed25519-dalek` | Ed25519 manifest signatures |
| `hkdf`, `hmac`, `sha2` | Key derivation and authentication |
| `getrandom` | OS/WASI random source |
| `serde`, `postcard` | Compact binary config serialization |
| `base64` | Token encoding |
| `zeroize` | Secure memory clearing |

**mirage-server** (native, additional):

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `h2` | HTTP/2 server with low-level frame access |
| `reqwest` | Cover site reverse proxy |
| `tokio-rustls` | TLS termination (direct mode) |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `postcard` | Manifest serialization |

**mirage-provisioner** (native, additional):

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `reqwest` | Cloudflare API client, domain probing |
| `clap` | CLI with subcommands |
| `ed25519-dalek` | Keypair generation and signing |
| `rand` | Cryptographic randomness for keygen |
| `serde_json`, `toml` | Config file formats |

### Client configuration

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

### Server configuration

The server reads a TOML config file:

```toml
[server]
listen_addr = "0.0.0.0:443"
tls = true                              # false for CDN-fronted (plain h2c)
tls_cert_path = "/etc/mirage/cert.pem"  # only if tls = true
tls_key_path = "/etc/mirage/key.pem"

[protocol]
server_private_key = "<base64url 32 bytes>"
psk = "<base64url 32 bytes>"
manifest_path = "/etc/mirage/manifest.bin"        # optional: domain manifest
manifest_verify_key = "<base64url 32 bytes>"      # optional: Ed25519 verification key

[cover_site]
origin = "https://example-news-site.com"
timeout_secs = 10

[limits]
max_concurrent_sessions = 10000
session_idle_timeout_secs = 300
upstream_connect_timeout_secs = 10

[logging]
level = "info"
```

When `tls = false` (CDN-fronted mode), the CDN terminates TLS and forwards plain HTTP/2 to the origin. When `tls = true` (direct mode), the server terminates TLS itself using tokio-rustls with ALPN `h2`.

When `manifest_path` is set, the server loads the signed domain manifest on startup, watches the file for changes (30-second poll), and pushes the current manifest to each client as a `DomainUpdate` frame after session establishment.

## Cover site behavior

When a connection fails authentication (invalid token, missing cookie, or just a normal browser visit), the server does not reject the request or return a generic error. Instead, it becomes a **transparent reverse proxy** for the configured cover site for the **entire connection lifetime**:

- Every H2 stream is forwarded to the cover origin: method, path, headers, body
- Each stream is spawned concurrently, matching how real browsers send parallel requests
- Response headers (content-type, set-cookie, location, CSP, HSTS, etc.) are forwarded back faithfully
- Redirects are passed through so the client follows them naturally

This means an active prober connecting to the server sees exactly the same behavior as if they connected to the real cover site. There is no distinguishable difference — no error pages, no connection resets, no timing anomalies.

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
