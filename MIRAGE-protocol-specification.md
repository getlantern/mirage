# MIRAGE: Multiplexed Indistinguishable Relaying with Adaptive Gateway Emulation

## A Novel Censorship Circumvention Transport Protocol

**Version**: 1.0-draft
**Date**: 2026-02-21
**Target Runtime**: WATER (WebAssembly Transport Executables Runtime) v1
**Implementation Language**: Rust (wasm32-wasip1 target)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Comprehensive Analysis of Censorship Detection (2024-2026)](#2-comprehensive-analysis-of-censorship-detection-2024-2026)
3. [Threat Model](#3-threat-model)
4. [Design Rationale](#4-design-rationale)
5. [Protocol Overview](#5-protocol-overview)
6. [Handshake Specification](#6-handshake-specification)
7. [Data Transport Specification](#7-data-transport-specification)
8. [Active Probing Defense](#8-active-probing-defense)
9. [Traffic Shaping Strategy](#9-traffic-shaping-strategy)
10. [Key Management](#10-key-management)
11. [WATER Integration Architecture](#11-water-integration-architecture)
12. [Rust Implementation Considerations](#12-rust-implementation-considerations)
13. [Security Analysis](#13-security-analysis)
14. [Comparison with Existing Protocols](#14-comparison-with-existing-protocols)
15. [References](#15-references)

---

## 1. Executive Summary

MIRAGE is a censorship circumvention transport protocol designed to be statistically
indistinguishable from legitimate HTTPS traffic to major CDN endpoints (Cloudflare,
Akamai, Fastly). Unlike existing protocols that attempt to *look like* TLS from the
outside (REALITY, ShadowTLS) or that *use* a real TLS stack but leak side-channel
information (naiveproxy), MIRAGE takes a fundamentally different approach: it operates
as an authenticated overlay *within* genuine CDN-terminated TLS connections, ensuring
that no observer -- passive or active -- can distinguish MIRAGE traffic from ordinary
HTTPS browsing.

### Core Innovations

1. **CDN-Native Operation**: MIRAGE is designed to operate behind real CDN TLS
   termination (Cloudflare Workers, Cloudflare Tunnels, or similar). The outer TLS
   layer is handled entirely by the CDN, eliminating TLS fingerprinting as an attack
   vector. There is no "TLS inside TLS" -- the encapsulated TLS handshake
   fingerprinting attack from USENIX Security 2024 (Xue et al.) is structurally
   inapplicable.

2. **Cross-Layer RTT Alignment**: Addresses the NDSS 2025 finding (Xue et al.) that
   proxy traffic exhibits distinguishable cross-layer RTT discrepancies by operating
   at the application layer within the CDN's own TLS session, making the transport-
   and application-layer RTTs naturally aligned.

3. **HTTP/2 Semantic Conformance**: All MIRAGE traffic is valid HTTP/2 with proper
   frame semantics, header compression (HPACK), and multiplexed streams. This
   defeats entropy-based classifiers and protocol anomaly detectors.

4. **Adaptive Traffic Morphing**: MIRAGE shapes its traffic to match statistical
   profiles of real web browsing sessions collected from popular websites, including
   packet size distributions, inter-packet timing, and bidirectional byte ratios.

5. **Zero-Distinguishable Active Probing Response**: Any unauthenticated request to
   the MIRAGE endpoint receives a legitimate website response served by the CDN. The
   MIRAGE server process never handles unauthenticated traffic -- the CDN does.

6. **WATER-Native Design**: The protocol is designed from the ground up for the WATER
   WASM runtime, enabling dynamic transport updates without client redeployment.

---

## 2. Comprehensive Analysis of Censorship Detection (2024-2026)

### 2.1 What Censors CAN Do

Based on systematic analysis of the GFW Report findings, the Geedge/MESA leak
(September 2025), FOCI 2024-2025 proceedings, USENIX Security 2024, and NDSS 2025,
the following detection capabilities are confirmed or strongly evidenced:

#### 2.1.1 Deep Packet Inspection (DPI)

- **TLS SNI inspection**: All major censors (GFW, Iran, Russia/TSPU) inspect the
  Server Name Indication field in TLS ClientHello messages. Since April 2024, the GFW
  extends this to QUIC Initial packets, decrypting them at scale to extract SNI.

- **Protocol fingerprinting**: The GFW identifies protocol types by analyzing the
  first data packet's length and entropy. Shadowsocks was historically detected this
  way (GFW Report, "How China Detects and Blocks Shadowsocks").

- **Entropy analysis**: Fully random byte streams (as produced by Shadowsocks, VMess
  without TLS wrapping) are flagged as suspicious. The GFW and Iran's DPI systems can
  distinguish encrypted random streams from structured protocol traffic.

- **QUIC decryption**: Since January 2025, the GFW decrypts QUIC Client Initial
  packets at scale using the publicly known Initial keys derived from the connection
  ID, applying SNI-based blocking.

#### 2.1.2 TLS Fingerprinting

- **JA3/JA4 fingerprinting**: Censors and middleboxes classify TLS implementations
  by analyzing ClientHello parameters (cipher suites, extensions, elliptic curves,
  signature algorithms, GREASE values). JA4's GREASE detection flags 88% of spoofing
  attempts that use JA3-only evasion.

- **JARM server fingerprinting**: Active probes that send crafted TLS ClientHello
  messages and analyze ServerHello responses to fingerprint server software.

- **Post-handshake analysis**: The Aparecium tool demonstrated that REALITY and
  ShadowTLS v3 can be detected by analyzing TLS 1.3 post-handshake messages
  (NewSessionTicket). REALITY fails to send NewSessionTicket when mimicking OpenSSL,
  and ShadowTLS v3's HMAC tainting adds 4 bytes to message lengths.

#### 2.1.3 Encapsulated TLS Handshake Fingerprinting

The USENIX Security 2024 paper by Xue et al. demonstrated that ALL proxy protocols
that create a TLS-inside-TLS tunnel (VMess, VLESS, Trojan, Shadowsocks+TLS) exhibit
detectable patterns from the encapsulated handshake:

- Packet size sequences during connection establishment reveal the inner TLS handshake
- Detection achieves >70% true positive with <0.06% false positive
- Stream multiplexing reduces detection by ~70% but is limited with single streams
- Adding more encapsulation layers provides marginal benefit

#### 2.1.4 Cross-Layer RTT Fingerprinting

The NDSS 2025 paper demonstrated that proxy traffic creates measurable discrepancies
between transport-layer RTT (TCP handshake) and application-layer RTT (first
application data exchange). This technique:

- Is protocol-agnostic (works against all proxy protocols)
- Achieves 95% accuracy against Shadowsocks and VMess
- Cannot be fully mitigated by padding or traffic shaping alone
- Fundamentally exploits the extra network hop that proxying introduces

#### 2.1.5 Active Probing

- **Replay-based probing**: The GFW records connection payloads and replays them to
  test servers. Shadowsocks-2022 mitigates this with timestamp-based replay filters.

- **Crafted probes**: Seven different probe types are used against suspected
  Shadowsocks servers. Probes test for protocol-specific error behaviors.

- **Partial handshake probes**: Sending incomplete protocol messages to trigger
  distinguishable error responses.

- **HTTP(S) probing**: Making legitimate-looking HTTP requests to probe whether
  servers respond as expected web servers.

#### 2.1.6 Machine Learning Classifiers

- **CNN-based packet classification**: Lightweight CNNs operating on the first few
  packets' sizes, directions, and inter-arrival times achieve high accuracy in
  detecting encrypted proxy traffic.

- **Self-supervised learning**: ET-SSL and similar approaches use contrastive learning
  on flow-level statistical features without labeled data.

- **Graph neural networks**: Encode flow relationships and temporal patterns for
  improved classification of encrypted traffic.

#### 2.1.7 Infrastructure-Level Detection

- **Port-based blocking**: The GFW's August 2025 unconditional port 443 block
  demonstrates willingness to cause massive collateral damage.

- **IP reputation**: Known datacenter IP ranges face higher scrutiny.

- **Port forwarding detection**: REALITY manifests as port forwarding; the GFW has
  shown ability to detect and block all port forwarding to certain IPs.

- **Traffic volume triggers**: REALITY in Iran was blocked when traffic volume to a
  server exceeded certain thresholds within specific time windows.

- **Protocol whitelisting**: Iran deploys a protocol whitelister on ports 53, 80, 443
  that drops connections not matching DNS, HTTP, or TLS fingerprints. Russia's TSPU
  system employs similar whitelist-mode capabilities during security events.

#### 2.1.8 The Geedge/MESA Leak Revelations

The September 2025 leak of >500GB from Geedge Networks and the MESA Lab at the
Chinese Academy of Sciences confirmed:

- **TSG (Tiangou Secure Gateway)**: A traffic management platform enabling real-time
  tracking and control of network communications.

- **DPI capabilities**: Deep packet inspection targeting TLS/HTTPS metadata including
  SNI fields, distinguishing suspicious connections via entropy, timing, and payload
  structure anomalies.

- **VPN/Tor/Psiphon detection**: Specific detection modules for known circumvention
  tools with individual surveillance dashboards.

- **Export of censorship technology**: Systems exported to Myanmar, Pakistan, Ethiopia,
  Kazakhstan, and others under Belt & Road Initiative, meaning MIRAGE must also resist
  these deployed systems.

### 2.2 What Censors CANNOT Easily Do

1. **Decrypt CDN-terminated TLS**: Censors cannot decrypt traffic terminated by major
   CDNs (Cloudflare, Akamai) without either compromising the CDN's private keys or
   performing a visible man-in-the-middle attack that would break certificate
   validation for all users.

2. **Block all CDN traffic**: Major CDNs serve millions of domains including business-
   critical services. Blocking Cloudflare's IP ranges causes unacceptable collateral
   damage (though the GFW has shown brief willingness to accept this -- August 2025
   port 443 block lasted only 74 minutes).

3. **Distinguish HTTP/2 streams within a TLS session**: Once TLS is properly
   terminated by a CDN, the censor sees only the encrypted TLS record layer. Individual
   HTTP/2 streams and their content are invisible.

4. **Detect semantic-layer covert channels**: If proxy traffic is encoded as valid
   HTTP/2 request/response pairs with realistic headers, sizes, and timing, it is
   indistinguishable from legitimate browsing at the network layer.

5. **Perform timing attacks against CDN-proxied traffic**: CDN edge servers introduce
   natural latency variance that masks the extra hop to the origin server, neutralizing
   cross-layer RTT fingerprinting.

### 2.3 Emerging Threats (2026+)

- **AI-driven traffic analysis at scale**: As revealed in the Geedge leak, censors are
  investing in ML-based classifiers that can process traffic metadata at line speed.

- **Behavioral analysis**: Long-term monitoring of connection patterns (time of day,
  data volumes, session durations) to identify circumvention users through behavioral
  profiling rather than protocol analysis.

- **CDN cooperation**: Some censors may attempt to compel domestic CDN nodes to
  cooperate with censorship. MIRAGE must support configuration for CDN endpoints
  outside the censor's jurisdiction.

- **Encrypted DNS censorship**: As shown with ECH, censors block encrypted DNS (DoH,
  DoT, DoQ) to prevent clients from resolving CDN endpoints, requiring out-of-band
  distribution of IP addresses.

---

## 3. Threat Model

### 3.1 Adversary Capabilities

The adversary (censor) is modeled as a nation-state actor with the following
capabilities, consistent with the combined capabilities of the GFW, Iran's DPI/
whitelister, and Russia's TSPU as documented through 2025:

| Capability                   | Level    | Notes                                     |
|------------------------------|----------|-------------------------------------------|
| Passive traffic observation  | Full     | All packets, both directions              |
| DPI (protocol identification)| Full     | Including QUIC decryption, entropy checks |
| TLS fingerprinting           | Full     | JA3, JA4, JARM, post-handshake analysis   |
| Active probing               | Full     | Replay, crafted, partial handshake probes |
| ML traffic classification    | Advanced | CNN, GNN, self-supervised classifiers     |
| IP reputation/blocking       | Full     | Datacenter IP blocking, residual blocking |
| Temporal correlation         | Moderate | Connection timing correlation             |
| DNS manipulation             | Full     | DNS poisoning, blocking encrypted DNS     |
| Cross-layer RTT analysis     | Emerging | NDSS 2025 technique, not yet widely deployed |
| Collateral damage tolerance  | Limited  | Brief total blocks possible, sustained CDN blocks impractical |

### 3.2 Adversary Limitations

- Cannot break AES-256-GCM or ChaCha20-Poly1305 encryption
- Cannot compromise major CDN TLS private keys at scale
- Cannot sustain blocking of major CDN IP ranges for extended periods (>hours)
- Cannot inspect content of properly encrypted HTTP/2 streams
- Cannot distinguish CDN-proxied web browsing from CDN-proxied MIRAGE traffic at the
  network layer

### 3.3 Client Environment

- Client is in a censored region with full DPI and active probing
- Client has been provisioned with MIRAGE configuration out-of-band (shared secret
  or public key of server, CDN endpoint address)
- Client's DNS may be poisoned; client may need to use hardcoded CDN IP addresses
- Client's local device is NOT compromised (local adversary is out of scope)

### 3.4 Security Goals

1. **Unobservability**: A passive network observer cannot distinguish MIRAGE traffic
   from legitimate HTTPS traffic to the same CDN with probability significantly
   better than random guessing.

2. **Active probing resistance**: No probe to the MIRAGE endpoint produces a response
   distinguishable from a legitimate web server behind the same CDN.

3. **Replay resistance**: Replayed connection data does not produce valid MIRAGE
   sessions.

4. **Forward secrecy**: Compromise of long-term keys does not compromise past session
   keys.

5. **Data integrity**: Tampering with in-flight data is detected and the session is
   terminated.

6. **Unlinkability**: Different sessions from the same client cannot be linked by the
   adversary (absent traffic analysis outside the protocol).

---

## 4. Design Rationale

### 4.1 Why CDN-Native, Not TLS Camouflage

Existing approaches fall into two categories, both with fundamental weaknesses:

**TLS Camouflage (REALITY, ShadowTLS)**: These protocols perform a TLS handshake
that looks like a real handshake with a legitimate server, then diverge from the real
protocol. This approach is vulnerable to:
- Post-handshake message analysis (Aparecium)
- Active probing (connecting to the "real" server and comparing behavior)
- Port forwarding detection (GFW can detect REALITY as port forwarding)
- The fundamental problem: the server must behave identically to the camouflaged
  service under all conditions, which is an impossibly large attack surface.

**TLS Tunneling (Trojan, VMess+TLS, Shadowsocks+TLS)**: These protocols establish
a real TLS session, then tunnel proxy traffic inside. This approach is vulnerable to:
- Encapsulated TLS handshake fingerprinting (USENIX Security 2024)
- Cross-layer RTT fingerprinting (NDSS 2025)
- The fundamental problem: the nested protocol stack creates observable side channels.

**MIRAGE's approach**: By operating behind a real CDN, MIRAGE eliminates both attack
surfaces. The TLS is real and terminated by the CDN (no camouflage to detect). There
is no inner TLS handshake (no encapsulated handshake to fingerprint). The application-
layer protocol is HTTP/2 from end to end, so there is no protocol stack nesting. The
CDN's edge server acts as a natural relay, equalizing RTTs.

### 4.2 Why HTTP/2 Semantics, Not Raw Bytes

Many protocols (Shadowsocks, VMess) transmit raw encrypted bytes that lack the
statistical structure of real protocols. Even when wrapped in TLS, the *content*
patterns (message sizes, bidirectional ratios) differ from real HTTPS.

MIRAGE encodes all proxy data as HTTP/2 DATA frames within properly established
HTTP/2 streams, complete with realistic HEADERS frames using HPACK compression.
This means even if a censor could somehow decrypt the outer TLS (which they cannot
with CDN termination), the traffic would still look like normal HTTP/2.

### 4.3 Why Adaptive Traffic Morphing

The FOCI 2025 paper on formal verification of circumvention protocols argues that
indistinguishability claims require accurate models of real network traffic. Static
padding schemes are insufficient because they do not capture the complex correlations
in real web traffic (e.g., the relationship between request size and response size,
the timing between loading HTML and subsequent resource requests).

MIRAGE implements adaptive traffic morphing based on pre-collected statistical profiles
of real browsing sessions to popular websites. These profiles are distributed as part
of the WASM module configuration and can be updated dynamically through WATER.

### 4.4 Why WATER/WASM

The WATER framework (FOCI 2024, "Just add WATER") provides critical operational
advantages:
- **Dynamic updates**: Transport logic can be updated without app store review
- **Sandboxing**: WASM's memory-safe sandbox isolates protocol logic
- **Portability**: Single WASM binary runs on all platforms
- **Rapid deployment**: New evasion techniques can be deployed within hours of a
  censor deploying a new detection method

---

## 5. Protocol Overview

### 5.1 Architecture

```
+--------+       +------------+       +-----------+       +----------+
| Client | <---> | CDN Edge   | <---> | MIRAGE    | <---> | Target   |
| (WASM) |  TLS  | (Cloudflare|  TLS  | Origin    |       | (Internet|
|        |       |  etc.)     |       | Server    |       |  dest.)  |
+--------+       +------------+       +-----------+       +----------+
     |                 |                     |
     | Real TLS 1.3    | CDN internal        | Proxy to
     | (CDN cert)      | routing             | destination
     |                 |                     |
     | HTTP/2 with     |                     |
     | MIRAGE frames   |                     |
     | inside          |                     |

Observer sees: Standard HTTPS to cdn-provider.com
```

### 5.2 Connection Lifecycle

1. **DNS Resolution**: Client resolves the CDN hostname (or uses a hardcoded CDN
   anycast IP). The hostname corresponds to a legitimate-looking website (e.g.,
   `assets.example-cdn.com`).

2. **TLS Handshake**: Client performs a standard TLS 1.3 handshake with the CDN
   edge server. The ClientHello is indistinguishable from a normal browser because
   the client uses a real TLS library (or the platform's native TLS). The CDN's
   real certificate is used.

3. **HTTP/2 Connection Establishment**: Client sends HTTP/2 connection preface and
   SETTINGS frame, establishing a standard HTTP/2 connection.

4. **MIRAGE Authentication**: Client sends an HTTP/2 request that appears to be a
   normal web request (e.g., `GET /api/v2/config?t=<timestamp>`) but contains a
   cryptographic authentication token in a cookie or authorization header. This
   token is an HMAC over shared state.

5. **Session Establishment**: The MIRAGE origin server validates the authentication
   token. If valid, it responds with what appears to be a normal HTTP response but
   includes a session key derivation material in a header field. If invalid, the
   origin server returns a legitimate web page (the "cover site").

6. **Tunnel Streams**: Subsequent HTTP/2 streams carry tunneled data. Each stream
   looks like a web resource fetch (with appropriate HEADERS) and carries encrypted
   proxy data in DATA frames. Multiple streams are multiplexed to match the
   statistical profile of real browsing.

7. **Session Maintenance**: Periodic "keep-alive" requests that look like normal
   AJAX polling maintain the session and provide opportunities for key rotation.

8. **Teardown**: The HTTP/2 connection is closed normally with GOAWAY.

### 5.3 Modes of Operation

**Mode A -- CDN-Fronted (Primary)**:
Traffic flows through a public CDN (Cloudflare, Fastly, etc.). Provides maximum
resistance to all known detection techniques. Requires a CDN account.

**Mode B -- Direct TLS with Cover Server (Fallback)**:
When CDN fronting is unavailable, MIRAGE operates in direct mode where the origin
server terminates TLS itself but serves a real cover website for unauthenticated
requests. This mode is less resistant to cross-layer RTT fingerprinting but still
defeats DPI, TLS fingerprinting (using a real TLS stack), and active probing.

**Mode C -- QUIC/HTTP3 (Experimental)**:
Operates over QUIC using the same HTTP semantics. Benefits from QUIC's connection
migration for additional censorship resistance. Currently experimental due to
evolving QUIC censorship landscape.

---

## 6. Handshake Specification

### 6.1 Pre-Shared Configuration

Before the first connection, the client must possess (provisioned out-of-band):

```
MirageConfig {
    // Server identity
    server_public_key: [u8; 32],     // X25519 public key

    // CDN configuration
    cdn_hostname: String,             // e.g., "assets.example-cdn.com"
    cdn_ips: Vec<IpAddr>,            // Fallback IPs if DNS is poisoned
    origin_path_prefix: String,       // e.g., "/api/v2"

    // Cover site configuration
    cover_site_domain: String,        // Domain the site pretends to be

    // Authentication
    psk: [u8; 32],                   // Pre-shared key for initial auth

    // Traffic profile
    traffic_profile: TrafficProfile,  // Statistical model for traffic shaping

    // Protocol parameters
    max_concurrent_streams: u16,      // HTTP/2 stream limit
    session_duration_range: (u64, u64), // Min/max session duration in seconds
}
```

### 6.2 TLS and HTTP/2 Establishment

The client uses the platform's native TLS stack (or the CDN's standard TLS) --
there is no custom TLS implementation. This ensures the TLS fingerprint matches
exactly what the platform would produce for any HTTPS connection.

```
Client                              CDN Edge                    MIRAGE Origin
  |                                    |                             |
  |--- TLS 1.3 ClientHello ---------->|                             |
  |<-- TLS 1.3 ServerHello -----------|                             |
  |<-- {Certificate, CertVerify, Fin}-|                             |
  |--- {Finished} ------------------->|                             |
  |                                    |                             |
  |--- HTTP/2 Preface + SETTINGS ---->|                             |
  |<-- SETTINGS + SETTINGS ACK -------|                             |
  |--- SETTINGS ACK ----------------->|                             |
  |                                    |                             |
```

### 6.3 MIRAGE Authentication Handshake

#### Step 1: Client Authentication Request

The client sends what appears to be a normal HTTP/2 GET request:

```
HEADERS (stream_id=1):
  :method = GET
  :path = /api/v2/config?t=<unix_timestamp_seconds>&v=<version>
  :scheme = https
  :authority = <cdn_hostname>
  user-agent = <realistic_browser_ua>
  accept = application/json
  accept-encoding = gzip, deflate, br
  cookie = _session=<auth_token>; _pref=<noise>
  x-request-id = <request_nonce_hex>
```

Where:
- `<unix_timestamp_seconds>` is the current Unix timestamp (used for replay
  protection, must be within +/- 120 seconds of server time)
- `<version>` is a protocol version identifier
- `<auth_token>` is computed as described below
- `<request_nonce_hex>` is a 16-byte random nonce, hex-encoded

#### Step 2: Auth Token Construction

```
timestamp = current_unix_timestamp_seconds (8 bytes, big-endian)
nonce = random_bytes(16)
client_ephemeral_keypair = X25519::generate()
client_ephemeral_public = client_ephemeral_keypair.public_key()  // 32 bytes

payload = timestamp || nonce || client_ephemeral_public           // 56 bytes

shared_secret = X25519(client_ephemeral_keypair.secret, server_public_key)
auth_key = HKDF-SHA256(
    ikm = shared_secret,
    salt = psk,
    info = "mirage-auth-v1" || timestamp,
    length = 32
)

auth_tag = HMAC-SHA256(auth_key, payload)                         // 32 bytes

auth_token = Base64URL(payload || auth_tag)                       // 88 bytes base64
```

The auth_token is placed in the `_session` cookie, which at 88 characters is within
normal cookie size ranges. The cookie name and format are configurable.

#### Step 3: Server Validation

The MIRAGE origin server:

1. Extracts the auth_token from the cookie
2. Decodes and parses: `timestamp || nonce || client_ephemeral_public || auth_tag`
3. Checks timestamp is within +/- 120 seconds of server time
4. Checks nonce has not been seen (nonce cache with 240-second expiry for replay
   protection)
5. Computes `shared_secret = X25519(server_private_key, client_ephemeral_public)`
6. Derives `auth_key` using the same HKDF construction
7. Verifies `auth_tag == HMAC-SHA256(auth_key, payload)`

If validation **fails**: The server responds with a legitimate web page (the cover
site). The response is indistinguishable from what an unauthenticated visitor would
receive.

If validation **succeeds**: Proceed to step 4.

#### Step 4: Server Session Response

The server responds with what appears to be a normal JSON API response:

```
HEADERS (stream_id=1):
  :status = 200
  content-type = application/json
  cache-control = no-cache, no-store
  set-cookie = _session=<session_token>; Path=/; Secure; HttpOnly; SameSite=Strict
  x-request-id = <echoed_nonce>
  server = nginx

DATA (stream_id=1):
  {"status":"ok","version":"2.1","config":{"refresh":30,"endpoints":[...]}}
```

Where `<session_token>` contains:

```
server_ephemeral_keypair = X25519::generate()
server_ephemeral_public = server_ephemeral_keypair.public_key()  // 32 bytes
server_nonce = random_bytes(16)

// Derive session keys
dh_result = X25519(server_ephemeral_keypair.secret, client_ephemeral_public)
session_key_material = HKDF-SHA256(
    ikm = dh_result,
    salt = shared_secret,   // from auth step
    info = "mirage-session-v1" || timestamp || nonce || server_nonce,
    length = 64
)
client_write_key = session_key_material[0..32]
server_write_key = session_key_material[32..64]

session_payload = server_ephemeral_public || server_nonce          // 48 bytes
session_enc_key = HKDF-SHA256(ikm = auth_key, salt = nonce,
                              info = "mirage-session-enc-v1", length = 32)
session_nonce_iv = HKDF-SHA256(ikm = auth_key, salt = server_nonce,
                                info = "mirage-session-nonce-v1", length = 12)
encrypted_session = ChaCha20-Poly1305.Encrypt(
    key = session_enc_key,
    nonce = session_nonce_iv,
    aad = timestamp || nonce,
    plaintext = session_payload
)                                                                  // 64 bytes

session_token = Base64URL(encrypted_session)                       // ~88 bytes
```

The JSON body is legitimate-looking configuration data that serves as the cover
content. The actual session state is entirely in the cookie.

#### Step 5: Client Session Key Derivation

The client:
1. Decodes and decrypts the session_token from `set-cookie`
2. Extracts `server_ephemeral_public` and `server_nonce`
3. Computes `dh_result = X25519(client_ephemeral_secret, server_ephemeral_public)`
4. Derives `client_write_key` and `server_write_key` using the same HKDF construction

Both parties now share symmetric session keys with forward secrecy.

---

## 7. Data Transport Specification

### 7.1 Tunnel Framing

After session establishment, the client opens HTTP/2 streams to carry tunneled data.
Each stream resembles a web resource request.

#### Request Format (Client to Server)

```
HEADERS (stream_id=N):
  :method = POST
  :path = /api/v2/telemetry
  :scheme = https
  :authority = <cdn_hostname>
  content-type = application/octet-stream
  x-session-token = <compact_session_id>
  x-request-id = <stream_nonce>

DATA (stream_id=N):
  <encrypted_mirage_frames>
```

For downstream-heavy transfers (e.g., web browsing), the request may use GET with
the response carrying the bulk data:

```
HEADERS (stream_id=N):
  :method = GET
  :path = /api/v2/assets/<encoded_request>
  :scheme = https
  :authority = <cdn_hostname>
  accept = application/octet-stream
```

### 7.2 MIRAGE Frame Format

Within the HTTP/2 DATA frames, MIRAGE uses its own lightweight framing:

```
+-------+-------+-------+-------+-------+-------+-------+-------+
| Frame Type (1 byte)   | Length (2 bytes, big-endian)           |
+-------+-------+-------+-------+-------+-------+-------+-------+
| Sequence Number (4 bytes, big-endian)                         |
+-------+-------+-------+-------+-------+-------+-------+-------+
| Encrypted Payload (Length - 16 bytes)                         |
+-------+-------+-------+-------+-------+-------+-------+-------+
| Auth Tag (16 bytes, Poly1305)                                 |
+-------+-------+-------+-------+-------+-------+-------+-------+
```

**Frame Types**:

| Type | Name        | Description                                    |
|------|-------------|------------------------------------------------|
| 0x01 | DATA        | Tunneled application data                      |
| 0x02 | CONNECT     | Request to connect to a target (addr:port)     |
| 0x03 | CONNECT_OK  | Connection established                         |
| 0x04 | CONNECT_ERR | Connection failed                               |
| 0x05 | PING        | Keep-alive / latency measurement               |
| 0x06 | PONG        | Ping response                                  |
| 0x07 | KEY_ROTATE  | Initiate key rotation                          |
| 0x08 | KEY_ACK     | Acknowledge key rotation                       |
| 0x09 | CLOSE       | Close a tunnel stream                          |
| 0x0A | PAD         | Padding frame (for traffic shaping)            |

### 7.3 Encryption

Each MIRAGE frame's payload is encrypted with ChaCha20-Poly1305:

```
nonce = sequence_number (4 bytes) || stream_id (4 bytes) || zero_pad (4 bytes)
aad = frame_type (1 byte) || length (2 bytes) || sequence_number (4 bytes)

ciphertext || tag = ChaCha20-Poly1305.Seal(
    key = direction_key,     // client_write_key or server_write_key
    nonce = nonce,
    aad = aad,
    plaintext = payload
)
```

ChaCha20-Poly1305 is chosen over AES-GCM because:
1. It compiles efficiently to WASM (no hardware AES required)
2. It is constant-time in software (resistant to cache-timing attacks)
3. It is widely used in TLS 1.3 and WireGuard, well-analyzed

### 7.4 CONNECT Flow

To establish a tunnel to a target destination:

```
Client                                  MIRAGE Server
  |                                          |
  |-- CONNECT {addr="1.2.3.4:443"} -------->|
  |                                          |--- TCP connect to 1.2.3.4:443
  |<-- CONNECT_OK {stream_id=N} ------------|
  |                                          |
  |-- DATA {payload=<proxied_bytes>} ------->|---> forward to 1.2.3.4:443
  |<-- DATA {payload=<response_bytes>} ------|<--- receive from 1.2.3.4:443
  |                                          |
```

The CONNECT frame payload:

```
CONNECT Payload:
  Address Type (1 byte): 0x01=IPv4, 0x02=IPv6, 0x03=Domain
  Address: 4 bytes (IPv4) / 16 bytes (IPv6) / 1 byte length + domain bytes
  Port: 2 bytes (big-endian)
```

### 7.5 Multiplexing

MIRAGE supports multiple simultaneous tunnels via HTTP/2 stream multiplexing:

- Each tunnel maps to an HTTP/2 stream
- Streams are interleaved naturally by the HTTP/2 framing layer
- Stream priorities can be set to match realistic web traffic patterns
- The CDN handles HTTP/2 flow control transparently

This multiplexing serves dual purposes:
1. Performance: Multiple concurrent connections without head-of-line blocking
2. Detection resistance: Multiple streams per connection matches real browsing behavior
   and was shown to reduce encapsulated TLS detection by >70% (Xue et al., USENIX
   Security 2024) -- though MIRAGE does not have encapsulated TLS, multiplexing still
   improves statistical indistinguishability.

### 7.6 UDP Tunnel Support

For UDP-based applications (DNS, QUIC, gaming), MIRAGE supports UDP tunnel frames:

```
UDP_CONNECT Payload:
  Similar to CONNECT but indicates UDP

UDP_DATA Payload:
  Target Address (variable)
  Datagram Length (2 bytes)
  Datagram Data (variable)
```

UDP datagrams are carried within HTTP/2 DATA frames using the same encryption.
When HTTP/3 (QUIC) mode is available, MIRAGE can use HTTP/3 CONNECT-UDP (RFC 9298)
for lower-latency UDP proxying.

---

## 8. Active Probing Defense

### 8.1 Defense Architecture

MIRAGE's active probing defense is architecturally different from all existing
protocols. The defense is not a property of the MIRAGE protocol -- it is a property
of the deployment architecture:

```
Probe -----> CDN Edge -----> Origin Server
                                |
                          +-----------+
                          | Web App   |  <-- serves cover site
                          | (default) |
                          +-----------+
                          | MIRAGE    |  <-- only activated by
                          | Handler   |      authenticated requests
                          +-----------+
```

**Any unauthenticated request** (including all active probes) is handled by the web
application, which serves a legitimate website. The MIRAGE handler is never invoked
for unauthenticated traffic.

### 8.2 Specific Probe Resistance

| Probe Type                | Defense Mechanism                                |
|---------------------------|--------------------------------------------------|
| Replay of auth request    | Timestamp + nonce check rejects replays          |
| Crafted HTTP requests     | Served by cover website (legitimate responses)   |
| Partial TLS handshake     | Handled by CDN (not MIRAGE server)               |
| JARM fingerprinting       | CDN's TLS stack responds (matches CDN fingerprint)|
| HTTP/2 protocol probing   | CDN handles HTTP/2 protocol compliance           |
| Timing analysis of probes | CDN introduces natural latency variance          |
| POST with random data     | Cover site returns 400/404 (normal web behavior) |

### 8.3 Cover Site Requirements

The cover website should:
- Be a legitimate, functional website (not just a static page)
- Generate realistic response sizes and timing
- Support all standard HTTP methods
- Return appropriate error codes for invalid paths
- Have valid content (e.g., a blog, documentation site, or API)

Recommended: Use a real web application (WordPress, Ghost, a static site generator)
deployed alongside the MIRAGE handler on the same origin server.

---

## 9. Traffic Shaping Strategy

### 9.1 Traffic Profile Model

MIRAGE uses pre-collected statistical profiles of real web browsing sessions. A
traffic profile consists of:

```rust
struct TrafficProfile {
    // HTTP/2 stream patterns
    streams_per_session: Distribution,      // e.g., LogNormal(mu=2.5, sigma=1.2)
    stream_open_interval: Distribution,     // Time between opening new streams

    // Request patterns
    request_sizes: Distribution,            // Including headers
    response_sizes: Vec<WeightedDistribution>, // Different for HTML, JS, CSS, images

    // Timing
    think_time: Distribution,               // Time between page loads
    resource_fetch_burst: BurstProfile,     // Pattern of resource loading

    // Bidirectional ratios
    upload_download_ratio: Distribution,    // Typically 1:10 to 1:100 for browsing

    // Padding
    min_request_size: u32,                  // Minimum padded request size
    max_request_size: u32,                  // Maximum padded request size
    response_size_buckets: Vec<u32>,        // Quantize response sizes to buckets
}
```

### 9.2 Traffic Morphing Algorithm

When MIRAGE needs to transmit `N` bytes of proxy data:

1. **Bucket selection**: Choose the nearest response size bucket >= N + overhead
2. **Padding**: Add PAD frames to fill to the bucket size
3. **Timing**: If the transmission would violate the expected timing profile
   (e.g., sending data too quickly after a request), introduce artificial delay
4. **Stream management**: Open/close HTTP/2 streams at rates matching the profile
5. **Dummy traffic**: During idle periods, generate dummy requests/responses that
   match the profile's "keep-alive" patterns

### 9.3 Addressing the Network Stack Gap

The FOCI 2025 work on formal verification and the HotNets 2025 paper on network
stack effects both highlight that application-layer traffic shaping may not be
faithfully reflected at the packet level due to TCP segmentation, Nagle's algorithm,
and other transport-layer behaviors.

MIRAGE mitigates this by:
1. Operating at the HTTP/2 level (above TCP segmentation)
2. Using HTTP/2 DATA frame padding (standardized in RFC 9113)
3. Setting TCP_NODELAY where possible (platform-dependent)
4. Relying on the CDN's network stack for final packet construction, which adds
   a layer of natural noise that actually helps indistinguishability

### 9.4 Bidirectional Traffic Balance

Web browsing has characteristic bidirectional patterns. MIRAGE maintains realistic
ratios by:
- Padding upload streams to match typical POST/upload patterns
- Using multiple streams for large downloads (as browsers do)
- Interleaving keep-alive pings that resemble AJAX polling

---

## 10. Key Management

### 10.1 Key Hierarchy

```
Long-term identity:
  server_keypair: X25519 (rotated manually/out-of-band)
  psk: 256-bit pre-shared key (provisioned with config)
    |
    v
Per-session:
  client_ephemeral: X25519 (generated per connection)
  server_ephemeral: X25519 (generated per connection)
    |
    v  (HKDF)
  client_write_key: ChaCha20-Poly1305 (256-bit)
  server_write_key: ChaCha20-Poly1305 (256-bit)
    |
    v  (KEY_ROTATE)
  rotated_client_write_key: ChaCha20-Poly1305
  rotated_server_write_key: ChaCha20-Poly1305
```

### 10.2 Forward Secrecy

Forward secrecy is achieved through ephemeral X25519 key exchange on every session.
Compromise of the server's long-term key does not allow decryption of past sessions
because:
1. Each session uses a fresh ephemeral keypair
2. The ephemeral private keys are erased after session key derivation
3. The PSK provides an additional layer (even if the long-term key is compromised,
   sessions are still protected by the PSK)

### 10.3 In-Session Key Rotation

For long-lived sessions, MIRAGE supports key rotation:

```
Client                                  Server
  |                                          |
  |-- KEY_ROTATE {new_ephemeral_pub} ------->|
  |<-- KEY_ACK {new_ephemeral_pub} ----------|
  |                                          |
  |  Both derive new keys via HKDF:          |
  |  new_dh = X25519(new_priv, peer_new_pub) |
  |  new_keys = HKDF(new_dh, old_keys, ...)  |
  |                                          |
  |-- DATA (encrypted with new keys) ------->|
```

Key rotation occurs:
- After every 2^32 frames (to prevent nonce reuse)
- After every 1 GB of data transferred
- After every 1 hour of session duration
- On explicit client request

### 10.4 Session Resumption

MIRAGE supports session resumption to reduce handshake overhead:

After a successful session, the server issues a resumption ticket:
```
ticket = Encrypt(
    key = ticket_encryption_key,  // Server-side key, rotated periodically
    plaintext = session_id || client_id || expiry || session_keys_hash
)
```

On reconnection, the client includes the ticket in the auth cookie. The server
validates and restores session state, requiring only a single round trip.

Tickets expire after a configurable period (default: 24 hours) to limit the
window for traffic correlation.

---

## 11. WATER Integration Architecture

### 11.1 WATM Module Structure

MIRAGE is packaged as a WATER v1-compatible WebAssembly Transport Module (WATM):

```
mirage.wasm
  |
  +-- Exports (WATM v1 interface):
  |     watm_init_v1()          -> errno
  |     watm_ctrlpipe_v1(fd)    -> errno
  |     watm_dial_v1(int_fd)    -> net_fd
  |     watm_accept_v1(int_fd)  -> net_fd
  |     watm_associate_v1()     -> errno
  |     watm_start_v1()         -> errno
  |
  +-- Imports (from WATER host):
  |     water_dial(net, addr, addr_len) -> fd
  |     water_accept()                   -> fd
  |
  +-- WASI Preview 1 Imports:
        fd_read, fd_write, fd_close, random_get,
        clock_time_get, environ_get, environ_sizes_get,
        proc_exit
```

### 11.2 Module Lifecycle

```
WATER Host                          MIRAGE WATM
   |                                     |
   |-- instantiate(mirage.wasm) -------->|
   |                                     |
   |-- watm_init_v1() ----------------->|
   |                                     |-- Read config from env/ctrl pipe
   |                                     |-- Initialize crypto state
   |                                     |-- Load traffic profile
   |                                     |<- return 0 (success)
   |                                     |
   |-- watm_ctrlpipe_v1(ctrl_fd) ------>|
   |                                     |-- Store control pipe fd
   |                                     |<- return 0
   |                                     |
   |-- watm_dial_v1(internal_fd) ------>|
   |                                     |-- Call water_dial() to connect to CDN
   |                                     |-- Perform MIRAGE handshake over net_fd
   |                                     |-- Set up encryption state
   |                                     |<- return net_fd
   |                                     |
   |-- watm_start_v1() ---------------->|
   |                                     |-- Enter event loop:
   |                                     |     Read from internal_fd (app data)
   |                                     |     Encrypt + frame as HTTP/2
   |                                     |     Write to net_fd
   |                                     |     Read from net_fd (HTTP/2 responses)
   |                                     |     Decrypt + extract
   |                                     |     Write to internal_fd
   |                                     |
   |                                     |-- (blocking until connection closes)
   |                                     |<- return 0
```

### 11.3 Configuration Delivery

MIRAGE configuration is delivered through the WATER control pipe mechanism:

```
Control Pipe Messages:
  CONFIG_PUSH: {
    server_public_key: [u8; 32],
    psk: [u8; 32],
    cdn_hostname: String,
    cdn_ips: Vec<IpAddr>,
    origin_path_prefix: String,
    traffic_profile: TrafficProfile (serialized),
    mode: enum { CdnFronted, DirectTls, Quic },
  }

  KEY_UPDATE: {
    new_server_public_key: [u8; 32],
    new_psk: [u8; 32],
    effective_after: Timestamp,
  }

  PROFILE_UPDATE: {
    new_traffic_profile: TrafficProfile (serialized),
  }
```

### 11.4 Server-Side Architecture

The server component does NOT run as a WASM module (it runs natively for
performance). It consists of:

1. **CDN configuration**: Cloudflare Worker or Tunnel that routes authenticated
   requests to the MIRAGE origin handler.

2. **MIRAGE Origin Handler**: A Rust binary that:
   - Terminates HTTP/2 connections from the CDN
   - Validates MIRAGE authentication
   - Manages tunnel connections to target destinations
   - Serves the cover website for unauthenticated requests

3. **Cover Web Application**: A legitimate web application running on the same
   origin, serving real content.

---

## 12. Rust Implementation Considerations

### 12.1 Target and Toolchain

```toml
# .cargo/config.toml
[build]
target = "wasm32-wasip1"

[target.wasm32-wasip1]
runner = "wasmtime"
```

The build target is `wasm32-wasip1` (replacing the deprecated `wasm32-wasi` as of
Rust 1.84, January 2025).

### 12.2 Crate Dependencies

```toml
# Cargo.toml
[package]
name = "mirage-watm"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
# Cryptography (all WASM-compatible, no ring dependency)
chacha20poly1305 = "0.10"     # AEAD encryption
x25519-dalek = { version = "2", features = ["static_secrets"] }
hkdf = "0.12"
hmac = "0.12"
sha2 = "0.10"
rand_core = { version = "0.6", features = ["getrandom"] }
getrandom = { version = "0.2", features = ["wasi"] }  # WASI random source

# HTTP/2 framing (lightweight, no networking)
# Note: Full HTTP/2 may be too heavy for WASM; use minimal implementation
# httpframe = "0.1"  # or custom minimal HTTP/2 framer

# Serialization
serde = { version = "1", features = ["derive"], default-features = false }
serde_json = { version = "1", default-features = false, features = ["alloc"] }
postcard = "1"                 # Compact binary serialization for config

# Base64 encoding
base64 = { version = "0.22", default-features = false, features = ["alloc"] }

# WASI interface
wasi = "0.13"

[profile.release]
opt-level = "s"               # Optimize for size
lto = true                    # Link-time optimization
codegen-units = 1
strip = true
```

### 12.3 Key Design Decisions for WASM

1. **No `std` networking**: All I/O goes through WATER's file descriptor abstraction.
   The WASM module reads/writes to file descriptors provided by the host.

2. **No `ring` crate**: Ring does not compile to WASM. All crypto uses RustCrypto
   crates (chacha20poly1305, x25519-dalek, hkdf, etc.) which are pure Rust and
   WASM-compatible.

3. **Minimal HTTP/2 implementation**: Rather than pulling in a full HTTP/2 library
   (like h2), MIRAGE implements only the subset needed: HEADERS framing, DATA
   framing, SETTINGS, WINDOW_UPDATE, and GOAWAY. This keeps the WASM binary small.

4. **Allocator**: Use the default WASM allocator. For size optimization, consider
   `wee_alloc` (though it is no longer maintained) or `dlmalloc` (the default for
   wasm32-wasip1).

5. **Entropy source**: Use `getrandom` with the `wasi` feature, which maps to
   WASI's `random_get` syscall.

6. **No threads**: WASM (wasip1) has limited threading support. MIRAGE uses a
   single-threaded event loop with non-blocking I/O via `poll_oneoff` (WASI's
   polling mechanism).

### 12.4 Module Size Target

Target WASM binary size: <500 KB (compressed). This is achievable with:
- Release build with `opt-level = "s"` and LTO
- Minimal dependencies
- `wasm-opt` post-processing (from Binaryen toolchain)
- No format strings or complex error messages in release builds

### 12.5 Implementation Skeleton

```rust
// src/lib.rs -- MIRAGE WATM entry point

#![no_main]

mod crypto;
mod framing;
mod http2;
mod config;
mod traffic_shaper;
mod tunnel;

use core::ffi::c_int;

// WATM v1 exported functions

#[no_mangle]
pub extern "C" fn watm_init_v1() -> c_int {
    match mirage_init() {
        Ok(()) => 0,
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub extern "C" fn watm_ctrlpipe_v1(ctrl_fd: c_int) -> c_int {
    match mirage_set_ctrl_pipe(ctrl_fd) {
        Ok(()) => 0,
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub extern "C" fn watm_dial_v1(internal_fd: c_int) -> c_int {
    match mirage_dial(internal_fd) {
        Ok(net_fd) => net_fd,
        Err(e) => -(e as c_int),
    }
}

#[no_mangle]
pub extern "C" fn watm_accept_v1(internal_fd: c_int) -> c_int {
    match mirage_accept(internal_fd) {
        Ok(net_fd) => net_fd,
        Err(e) => -(e as c_int),
    }
}

#[no_mangle]
pub extern "C" fn watm_associate_v1() -> c_int {
    match mirage_associate() {
        Ok(()) => 0,
        Err(e) => e as c_int,
    }
}

#[no_mangle]
pub extern "C" fn watm_start_v1() -> c_int {
    match mirage_start() {
        Ok(()) => 0,
        Err(e) => e as c_int,
    }
}

// WATER host imports
extern "C" {
    fn water_dial(
        network: *const u8,
        network_len: u32,
        address: *const u8,
        address_len: u32,
    ) -> c_int;

    fn water_accept() -> c_int;
}

// ---------- Core implementation ----------

static mut STATE: Option<MirageState> = None;

struct MirageState {
    config: config::MirageConfig,
    ctrl_fd: c_int,
    internal_fd: c_int,
    net_fd: c_int,
    session: Option<tunnel::Session>,
    traffic_shaper: traffic_shaper::TrafficShaper,
}

fn mirage_init() -> Result<(), u32> {
    // Initialization deferred until config is received via ctrl pipe
    Ok(())
}

fn mirage_set_ctrl_pipe(ctrl_fd: c_int) -> Result<(), u32> {
    // Read configuration from control pipe
    let config_bytes = read_fd(ctrl_fd)?;
    let config: config::MirageConfig = postcard::from_bytes(&config_bytes)
        .map_err(|_| 1u32)?;

    let traffic_shaper = traffic_shaper::TrafficShaper::new(&config.traffic_profile);

    unsafe {
        STATE = Some(MirageState {
            config,
            ctrl_fd,
            internal_fd: -1,
            net_fd: -1,
            session: None,
            traffic_shaper,
        });
    }
    Ok(())
}

fn mirage_dial(internal_fd: c_int) -> Result<c_int, u32> {
    let state = unsafe { STATE.as_mut().ok_or(1u32)? };
    state.internal_fd = internal_fd;

    // Connect to CDN endpoint
    let addr = format!("{}:443", state.config.cdn_hostname);
    let net_fd = unsafe {
        water_dial(
            b"tcp\0".as_ptr(),
            3,
            addr.as_ptr(),
            addr.len() as u32,
        )
    };

    if net_fd < 0 {
        return Err(2);
    }
    state.net_fd = net_fd;

    // Perform MIRAGE handshake
    // Note: In CDN-fronted mode, the WATER host handles TLS.
    // MIRAGE operates at the HTTP/2 layer within the TLS connection.
    handshake::perform_handshake(state)?;

    Ok(net_fd)
}

fn mirage_accept(internal_fd: c_int) -> Result<c_int, u32> {
    let state = unsafe { STATE.as_mut().ok_or(1u32)? };
    state.internal_fd = internal_fd;

    let net_fd = unsafe { water_accept() };
    if net_fd < 0 {
        return Err(2);
    }
    state.net_fd = net_fd;

    // Handle incoming MIRAGE authentication
    handshake::accept_handshake(state)?;

    Ok(net_fd)
}

fn mirage_associate() -> Result<(), u32> {
    // For relay mode: associate internal and network connections
    Ok(())
}

fn mirage_start() -> Result<(), u32> {
    let state = unsafe { STATE.as_mut().ok_or(1u32)? };

    // Main event loop using WASI poll_oneoff
    loop {
        // Poll both internal_fd and net_fd for readability
        let events = wasi_poll(&[state.internal_fd, state.net_fd])?;

        for event in events {
            match event.fd {
                fd if fd == state.internal_fd => {
                    // Application data ready to send
                    let data = read_fd(fd)?;
                    if data.is_empty() {
                        // Connection closed
                        return Ok(());
                    }

                    // Encrypt, frame, and shape traffic
                    let session = state.session.as_mut().ok_or(3u32)?;
                    let frames = session.encrypt_and_frame(&data)?;
                    let shaped = state.traffic_shaper.shape(frames)?;

                    for chunk in shaped {
                        write_fd(state.net_fd, &chunk)?;
                    }
                }
                fd if fd == state.net_fd => {
                    // Network data received
                    let data = read_fd(fd)?;
                    if data.is_empty() {
                        return Ok(());
                    }

                    // Parse HTTP/2 frames, decrypt MIRAGE payloads
                    let session = state.session.as_mut().ok_or(3u32)?;
                    let plaintext = session.receive_and_decrypt(&data)?;

                    if !plaintext.is_empty() {
                        write_fd(state.internal_fd, &plaintext)?;
                    }
                }
                _ => {}
            }
        }

        // Traffic shaping: send padding/dummy data if needed
        if let Some(padding) = state.traffic_shaper.generate_padding()? {
            let session = state.session.as_mut().ok_or(3u32)?;
            let frames = session.encrypt_padding(&padding)?;
            write_fd(state.net_fd, &frames)?;
        }
    }
}

// WASI I/O helpers
fn read_fd(fd: c_int) -> Result<Vec<u8>, u32> {
    let mut buf = vec![0u8; 16384];
    let n = unsafe {
        let iov = wasi::Iovec {
            buf: buf.as_mut_ptr(),
            buf_len: buf.len(),
        };
        wasi::fd_read(fd as u32, &[iov]).map_err(|_| 4u32)?
    };
    buf.truncate(n);
    Ok(buf)
}

fn write_fd(fd: c_int, data: &[u8]) -> Result<(), u32> {
    let ciov = wasi::Ciovec {
        buf: data.as_ptr(),
        buf_len: data.len(),
    };
    unsafe {
        wasi::fd_write(fd as u32, &[ciov]).map_err(|_| 5u32)?;
    }
    Ok(())
}

fn wasi_poll(fds: &[c_int]) -> Result<Vec<PollEvent>, u32> {
    // Use wasi::poll_oneoff to wait for I/O readiness
    // Implementation omitted for brevity -- uses WASI subscription model
    todo!()
}

struct PollEvent {
    fd: c_int,
    readable: bool,
    writable: bool,
}
```

### 12.6 Crypto Module Skeleton

```rust
// src/crypto.rs

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead, KeyInit};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand_core::OsRng;

type HmacSha256 = Hmac<Sha256>;

pub struct SessionKeys {
    client_write_key: Key,
    server_write_key: Key,
    client_seq: u32,
    server_seq: u32,
}

pub struct AuthToken {
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub ephemeral_public: PublicKey,
    pub tag: [u8; 32],
}

impl AuthToken {
    pub fn generate(
        server_public_key: &PublicKey,
        psk: &[u8; 32],
    ) -> (Self, EphemeralSecret) {
        let timestamp = current_timestamp();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("getrandom failed");

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // Compute shared secret for auth
        let shared = client_secret.diffie_hellman(server_public_key);

        // Derive auth key
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&timestamp.to_be_bytes());

        let mut info = Vec::with_capacity(22);
        info.extend_from_slice(b"mirage-auth-v1");
        info.extend_from_slice(&timestamp_bytes);

        let hk = Hkdf::<Sha256>::new(Some(psk), shared.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(&info, &mut auth_key).expect("HKDF expand failed");

        // Compute HMAC
        let mut payload = Vec::with_capacity(56);
        payload.extend_from_slice(&timestamp_bytes);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(client_public.as_bytes());

        let mut mac = HmacSha256::new_from_slice(&auth_key)
            .expect("HMAC key length");
        mac.update(&payload);
        let tag: [u8; 32] = mac.finalize().into_bytes().into();

        let token = AuthToken {
            timestamp,
            nonce,
            ephemeral_public: client_public,
            tag,
        };

        // Note: we return the secret so the caller can complete
        // key derivation after receiving the server's response.
        // In practice, we would need to store this differently
        // since EphemeralSecret is consumed by diffie_hellman.
        // This is a simplification for the skeleton.
        // Real implementation uses StaticSecret for reuse.
        (token, client_secret)
    }

    pub fn to_base64(&self) -> String {
        let mut payload = Vec::with_capacity(88);
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(self.ephemeral_public.as_bytes());
        payload.extend_from_slice(&self.tag);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload)
    }
}

impl SessionKeys {
    pub fn derive(
        dh_result: &SharedSecret,
        auth_shared_secret: &[u8; 32],
        timestamp: u64,
        client_nonce: &[u8; 16],
        server_nonce: &[u8; 16],
    ) -> Self {
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(b"mirage-session-v1");
        info.extend_from_slice(&timestamp.to_be_bytes());
        info.extend_from_slice(client_nonce);
        info.extend_from_slice(server_nonce);

        let hk = Hkdf::<Sha256>::new(
            Some(auth_shared_secret),
            dh_result.as_bytes(),
        );
        let mut key_material = [0u8; 64];
        hk.expand(&info, &mut key_material).expect("HKDF expand");

        let client_write_key = Key::clone_from_slice(&key_material[0..32]);
        let server_write_key = Key::clone_from_slice(&key_material[32..64]);

        // Zeroize key material
        key_material.fill(0);

        SessionKeys {
            client_write_key,
            server_write_key,
            client_seq: 0,
            server_seq: 0,
        }
    }

    pub fn encrypt_client(&mut self, frame_type: u8, payload: &[u8]) -> Vec<u8> {
        let seq = self.client_seq;
        self.client_seq += 1;

        let cipher = ChaCha20Poly1305::new(&self.client_write_key);

        // Construct nonce: seq(4) || 0(8)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AAD: frame_type || length || seq
        let length = (payload.len() + 16) as u16; // +16 for auth tag
        let mut aad = Vec::with_capacity(7);
        aad.push(frame_type);
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(&seq.to_be_bytes());

        let ciphertext = cipher.encrypt(nonce, payload)
            .expect("encryption failed");

        // Build MIRAGE frame
        let mut frame = Vec::with_capacity(7 + ciphertext.len());
        frame.push(frame_type);
        frame.extend_from_slice(&((ciphertext.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ciphertext);

        frame
    }

    pub fn decrypt_server(&mut self, frame: &[u8]) -> Result<(u8, Vec<u8>), ()> {
        if frame.len() < 7 {
            return Err(());
        }

        let frame_type = frame[0];
        let length = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        let seq = u32::from_be_bytes([frame[3], frame[4], frame[5], frame[6]]);

        if seq != self.server_seq {
            return Err(()); // Sequence number mismatch
        }
        self.server_seq += 1;

        let cipher = ChaCha20Poly1305::new(&self.server_write_key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = Vec::with_capacity(7);
        aad.push(frame_type);
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(&seq.to_be_bytes());

        let ciphertext = &frame[7..7 + length];
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| ())?;

        Ok((frame_type, plaintext))
    }

    pub fn needs_rotation(&self) -> bool {
        self.client_seq > 0xFFFF_FF00 || self.server_seq > 0xFFFF_FF00
    }
}

fn current_timestamp() -> u64 {
    // Use WASI clock_time_get for current time
    unsafe {
        let mut time: u64 = 0;
        // wasi::clock_time_get returns nanoseconds
        // We want seconds
        wasi::clock_time_get(wasi::CLOCKID_REALTIME, 1_000_000_000)
            .map(|t| t / 1_000_000_000)
            .unwrap_or(0)
    }
}
```

### 12.7 Build Process

```bash
# Install the target
rustup target add wasm32-wasip1

# Build the WATM module
cargo build --release --target wasm32-wasip1

# Optimize the WASM binary
wasm-opt -Os -o mirage-opt.wasm target/wasm32-wasip1/release/mirage_watm.wasm

# Verify exports
wasm-tools print mirage-opt.wasm | grep "export"

# Test with wasmtime
wasmtime run mirage-opt.wasm
```

---

## 13. Security Analysis

### 13.1 Analysis Against Known Detection Techniques

| Detection Technique                    | MIRAGE Defense                            | Residual Risk |
|----------------------------------------|-------------------------------------------|---------------|
| **TLS SNI inspection**                 | SNI points to CDN hostname (allowed)      | Low: CDN might be blocked entirely |
| **TLS fingerprinting (JA3/JA4)**       | Platform native TLS stack (matches browser) | Negligible |
| **JARM server fingerprinting**         | CDN's TLS stack responds                  | Negligible |
| **Post-handshake analysis (Aparecium)**| CDN handles all TLS post-handshake        | None |
| **Encapsulated TLS fingerprinting**    | No inner TLS handshake exists             | None |
| **Cross-layer RTT fingerprinting**     | CDN edge equalizes RTTs                   | Low: CDN adds natural variance |
| **Entropy analysis**                   | Traffic is valid HTTP/2 (structured)      | Negligible |
| **Protocol fingerprinting (DPI)**      | All traffic is standard HTTPS/HTTP2       | Negligible |
| **Active probing (replay)**            | Timestamp + nonce prevents replay         | Negligible |
| **Active probing (crafted)**           | Cover site serves legitimate responses    | Negligible |
| **Active probing (partial handshake)** | CDN handles TLS negotiation               | None |
| **ML traffic classification**          | Traffic morphing matches real profiles     | Low-Moderate |
| **Port forwarding detection**          | No port forwarding; direct CDN connection | None |
| **Traffic volume analysis**            | Traffic shaping limits burst sizes         | Low |
| **IP reputation**                      | CDN anycast IPs are shared infrastructure | Negligible |
| **Protocol whitelisting (Iran)**       | Traffic is genuine HTTPS on port 443      | Negligible |
| **DNS poisoning**                      | Hardcoded CDN IPs as fallback             | Low |
| **Behavioral profiling**              | Session duration/pattern randomization    | Moderate |

### 13.2 Formal Security Properties

**Claim 1 (Unobservability)**: Given a TLS-encrypted HTTP/2 connection from client C
to CDN edge E, a passive observer cannot distinguish between (a) C browsing a website
hosted behind E, and (b) C using MIRAGE to proxy traffic through an origin behind E,
with advantage better than epsilon, where epsilon is bounded by the statistical
distance between MIRAGE's shaped traffic and real browsing traffic.

**Justification**: The observer sees only TLS records. The TLS is identical in both
cases (same CDN, same certificate, same TLS stack). The HTTP/2 content is encrypted.
Traffic shaping reduces statistical differences. The remaining distinguisher is the
traffic volume and timing distributions, which are bounded by the traffic morphing
fidelity.

**Claim 2 (Active Probing Resistance)**: No polynomial-time active prober can
distinguish the MIRAGE endpoint from a legitimate website endpoint with advantage
better than negligible, assuming the cover site is correctly configured.

**Justification**: The prober interacts only with (a) the CDN's TLS stack and (b)
the cover website's HTTP responses. Both are real, legitimate services. The MIRAGE
handler is never invoked for unauthenticated requests, so there is no protocol-
specific behavior to detect.

**Claim 3 (Replay Resistance)**: A replayed authentication token is rejected with
probability 1 - 2^{-128}.

**Justification**: Replay attempts fail because (a) the timestamp becomes stale
after 120 seconds, and (b) the nonce is stored in a server-side cache for 240
seconds. The combination ensures that within the validity window, a replayed nonce
is detected, and after the window, the timestamp check rejects it.

**Claim 4 (Forward Secrecy)**: Compromise of the server's long-term X25519 key and
PSK does not reveal session keys for past sessions.

**Justification**: Each session uses ephemeral X25519 keys. The session keys are
derived from the ephemeral DH result. Recovering past session keys requires the
ephemeral private keys, which are erased after key derivation.

### 13.3 Known Limitations

1. **CDN dependency**: MIRAGE in CDN-fronted mode requires a cooperating CDN. If all
   suitable CDNs are blocked or compelled to cooperate with censors, this mode fails.
   Mitigation: Mode B (direct TLS) provides a fallback.

2. **CDN cost**: CDN-fronted operation incurs bandwidth costs. This limits MIRAGE's
   use for high-bandwidth applications. Mitigation: Traffic profiles can target
   low-bandwidth patterns; CDN free tiers may suffice for light usage.

3. **Latency overhead**: CDN routing adds latency (typically 10-50ms). For
   latency-sensitive applications (gaming, VoIP), this may be unacceptable.
   Mitigation: Mode C (QUIC) reduces latency; CDN edge proximity minimizes hop count.

4. **Traffic analysis at scale**: If a censor observes large numbers of connections
   to a specific CDN-hosted origin, they may become suspicious and block the origin's
   specific CDN route (not the CDN entirely). Mitigation: Use multiple origin servers
   and rotate them; use CDN configurations that make origin identification difficult.

5. **Behavioral analysis**: Long-term patterns of usage (always connected, high data
   volume, unusual hours) could signal circumvention even if individual sessions are
   undetectable. Mitigation: Session duration randomization; traffic profiles that
   match expected usage.

6. **HTTP/2 fingerprinting within TLS**: While the censor cannot read HTTP/2 content,
   TLS record sizes may partially reveal HTTP/2 frame boundaries. Mitigation: TLS
   record padding (supported in TLS 1.3); this is handled by the platform TLS stack,
   not by MIRAGE directly.

---

## 14. Comparison with Existing Protocols

### 14.1 Comparison Matrix

| Feature                          | MIRAGE    | REALITY   | naiveproxy | SS-2022   | Trojan    | Hysteria2 | ShadowTLS v3 |
|----------------------------------|-----------|-----------|------------|-----------|-----------|-----------|--------------|
| **Outer layer**                  | Real CDN TLS | Stolen TLS cert | Chrome HTTPS | Raw encrypted | TLS 1.3 | QUIC/HTTP3 | Real TLS handshake |
| **Inner protocol**               | HTTP/2    | Custom    | HTTP/2 CONNECT | Custom AEAD | Custom | Custom QUIC | Custom |
| **TLS fingerprint**             | Native    | uTLS (impersonation) | Chrome | N/A (no TLS) | Library TLS | QUIC | Real handshake |
| **Active probing resistance**    | Cover site via CDN | Fail-open to real site | Application fronting | Drops invalid | Drops invalid | Drops invalid | Forward to real site |
| **Encapsulated TLS detection**   | Immune    | Immune    | Vulnerable | N/A | Vulnerable | N/A (QUIC) | Immune |
| **Cross-layer RTT detection**    | Resistant (CDN) | Vulnerable | Partially resistant | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| **Post-handshake detection**     | Immune    | Vulnerable (Aparecium) | N/A | N/A | N/A | N/A | Vulnerable (Aparecium) |
| **ML traffic classification**    | Resistant (shaping) | Limited | Moderate | Weak (random bytes) | Moderate | Moderate | Limited |
| **Protocol whitelisting**        | Passes (real HTTPS) | Passes (looks like TLS) | Passes | Fails | Passes | May fail (QUIC blocking) | Passes |
| **Port forwarding detection**    | N/A       | Vulnerable | N/A | N/A | N/A | N/A | Vulnerable |
| **CDN fronting**                 | Native    | Not supported | Possible | Not possible | Not designed for | Not possible | Not supported |
| **UDP support**                  | Via HTTP/2 tunnel | No | No | Yes | No | Native QUIC | No |
| **WATER/WASM compatible**        | Designed for | No | No | Possible | No | No | No |
| **Dynamic transport updates**    | Yes (WATER) | No | No | No | No | No | No |
| **Forward secrecy**              | Yes (ephemeral X25519) | Yes | Yes (TLS) | Yes (per-session salt) | Yes (TLS) | Yes (QUIC) | Partial |
| **Iran whitelister resistance**  | Yes       | Yes       | Yes | No (not TLS) | Yes | Partial (QUIC) | Yes |
| **Russia TSPU resistance**       | Yes       | Partial   | Yes | Partial | Partial | Partial | Partial |
| **GFW resistance (2025)**        | Yes       | Under pressure | Yes | Partially blocked | Partially blocked | Under pressure (QUIC SNI) | Partially blocked |

### 14.2 Protocol-Specific Comparisons

#### vs. REALITY

REALITY "steals" a real server's TLS certificate by acting as a man-in-the-middle
for the TLS handshake with a legitimate server. This was a significant innovation
but has several weaknesses that MIRAGE addresses:

1. **Port forwarding detection**: The GFW can detect that REALITY servers forward
   the TLS handshake, exposing the proxy. MIRAGE has no port forwarding.

2. **Aparecium vulnerability**: REALITY fails to send TLS 1.3 NewSessionTicket
   messages when impersonating OpenSSL servers. MIRAGE's TLS is handled entirely
   by the CDN.

3. **Active probing surface**: A censor can connect to a REALITY server and observe
   that the "real" server behind it behaves slightly differently from the actual
   server at that IP. MIRAGE's cover site IS the origin server.

4. **Traffic volume triggers**: REALITY in Iran was blocked based on traffic volume
   thresholds. MIRAGE benefits from CDN's shared IP space, making per-origin volume
   analysis harder.

#### vs. naiveproxy

naiveproxy reuses Chrome's network stack, making its TLS fingerprint identical to
Chrome. This is excellent but has limitations:

1. **Deployment complexity**: Requires building from Chromium source. MIRAGE uses
   standard Rust crates.

2. **Encapsulated TLS**: naiveproxy still creates a TLS-inside-TLS tunnel for
   CONNECT proxying, making it vulnerable to the USENIX Security 2024 detection
   technique. MIRAGE operates at the HTTP/2 layer, avoiding nested TLS.

3. **RST_STREAM anomaly**: naiveproxy sends atypical RST_STREAM frames that can
   fingerprint it. MIRAGE uses standard HTTP/2 stream management.

4. **WATER incompatibility**: naiveproxy requires Chrome's network stack, which
   cannot be compiled to WASM. MIRAGE is designed for WATER from the start.

#### vs. Shadowsocks-2022

Shadowsocks-2022 improved replay resistance with AEAD-2022 ciphers and timestamp-
based replay filters, but:

1. **Random byte entropy**: Shadowsocks traffic appears as a random byte stream,
   which can be distinguished from structured protocols by entropy analysis. MIRAGE
   uses real HTTP/2 framing.

2. **No TLS wrapper by default**: Without an additional TLS layer, Shadowsocks fails
   Iran's protocol whitelister. Adding TLS creates the encapsulated TLS problem.
   MIRAGE's TLS is the CDN's real TLS.

3. **Active probing**: While Shadowsocks-2022 rejects invalid connections silently,
   the lack of any response is itself a fingerprint (legitimate servers respond to
   connection attempts). MIRAGE's cover site always responds.

#### vs. Hysteria2

Hysteria2 leverages QUIC for high performance and censorship resistance, but faces
growing challenges:

1. **QUIC censorship**: Since April 2024, the GFW censors QUIC by decrypting Initial
   packets. Iran periodically blocks all QUIC. MIRAGE's primary mode uses TCP/HTTPS,
   which is more universally allowed.

2. **Protocol identification**: While Hysteria2 masquerades as HTTP/3, the specific
   QUIC behaviors may differ from real browser HTTP/3 implementations. MIRAGE's
   HTTP/2 traffic is validated by the CDN itself.

3. **No CDN fronting**: Hysteria2 cannot easily operate behind CDN infrastructure
   (most CDNs do not support arbitrary QUIC proxying). MIRAGE is CDN-native.

### 14.3 What MIRAGE Does Differently: Summary

1. **Eliminates the TLS camouflage problem entirely** by using real CDN-terminated
   TLS instead of impersonating it.

2. **Eliminates the encapsulated TLS problem** by operating at the HTTP/2 application
   layer within the CDN's TLS session, not tunneling TLS inside TLS.

3. **Neutralizes cross-layer RTT fingerprinting** by leveraging the CDN's edge
   servers as natural relay points that equalize RTT profiles.

4. **Achieves perfect active probing resistance** through architectural separation:
   unauthenticated traffic never reaches the MIRAGE handler.

5. **Supports dynamic transport updates** via WATER WASM, enabling rapid response
   to new detection techniques.

6. **Provides adaptive traffic morphing** based on real browsing session profiles,
   addressing the ML classifier threat with statistically grounded countermeasures.

---

## 15. References

### Academic Papers

1. Xue, D., Kallitsis, M., Houmansadr, A., Ensafi, R. "Fingerprinting Obfuscated
   Proxy Traffic with Encapsulated TLS Handshakes." USENIX Security 2024.
   https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting

2. Xue, D. et al. "The Discriminative Power of Cross-layer RTTs in Fingerprinting
   Proxy Traffic." NDSS 2025.
   https://www.ndss-symposium.org/ndss-paper/the-discriminative-power-of-cross-layer-rtts-in-fingerprinting-proxy-traffic/

3. "Just add WATER: WebAssembly-based Circumvention Transports." FOCI 2024.
   https://water.refraction.network/

4. Niere, N. "Encrypted Client Hello (ECH) in Censorship Circumvention." FOCI 2025.
   https://petsymposium.org/foci/2025/foci-2025-0016.php

5. Alice et al. "How China Detects and Blocks Shadowsocks." GFW Report / IMC 2020.
   https://gfw.report/blog/gfw_shadowsocks/

6. Zohaib et al. "Exposing and Circumventing SNI-based QUIC Censorship of the GFW."
   USENIX Security 2025.
   https://gfw.report/publications/usenixsecurity25/en/

7. "On Precisely Detecting Censorship Circumvention in Real-World Networks." NDSS 2024.
   https://github.com/net4people/bbs/issues/312

8. "A Comprehensive Survey of Website Fingerprinting Attacks and Defenses in Tor."
   arXiv 2024. https://arxiv.org/abs/2510.11804

9. "Rethinking the Role of Network Stacks for Website Fingerprinting Defenses."
   HotNets 2025.
   https://conferences.sigcomm.org/hotnets/2025/papers/hotnets25-final494.pdf

10. "A Case for Machine-Checked Verification of Circumvention Protocols." FOCI 2025.
    https://www.petsymposium.org/foci/2025/foci-2025-0013.pdf

### Technical Reports and Analysis

11. GFW Report. "Analysis of the GFW's Unconditional Port 443 Block on August 20,
    2025." https://gfw.report/blog/gfw_unconditional_rst_20250820/en/

12. GFW Report. "Geedge & MESA Leak: Analyzing the Great Firewall's Largest Document
    Leak." https://gfw.report/blog/geedge_and_mesa_leak/en/

13. Geneva Project (UMD). "Iran: A New Model for Censorship."
    https://geneva.cs.umd.edu/posts/iran-whitelister/

14. Aparecium: Detect ShadowTLS v3 & REALITY TLS Camouflage.
    https://github.com/net4people/bbs/issues/481

15. VPN Guild. "Report on VPN Censorship in Russia, January 2025."
    https://files.rks.global/vpn-block-report_01.25.pdf

### Protocol Documentation

16. REALITY Protocol. https://github.com/XTLS/REALITY
17. ShadowTLS v3 Protocol. https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md
18. Shadowsocks SIP022 AEAD-2022. https://shadowsocks.org/doc/sip022.html
19. Hysteria2 Protocol. https://v2.hysteria.network/docs/developers/Protocol/
20. NaiveProxy. https://github.com/klzgrad/naiveproxy

### Frameworks

21. WATER Runtime. https://github.com/refraction-networking/water
22. WATER-rs (Rust implementation). https://github.com/refraction-networking/water-rs
23. WATM v1 Specification. https://water.refraction.network/transport-module/spec/v1.html
24. WebAssembly Transport Modules. https://github.com/refraction-networking/watm

### Community Resources

25. net4people/bbs. https://github.com/net4people/bbs
26. GFW Report. https://gfw.report/en/
27. Censored Planet. https://censoredplanet.org/

---

## Appendix A: Traffic Profile Example

A sample traffic profile for mimicking browsing of a news website:

```json
{
  "profile_name": "news_site_browsing",
  "streams_per_session": {
    "distribution": "log_normal",
    "mu": 2.5,
    "sigma": 1.2,
    "min": 1,
    "max": 50
  },
  "stream_open_interval_ms": {
    "distribution": "exponential",
    "lambda": 0.01,
    "min": 10,
    "max": 5000
  },
  "request_sizes": {
    "distribution": "mixture",
    "components": [
      {"weight": 0.7, "distribution": "normal", "mu": 500, "sigma": 200},
      {"weight": 0.3, "distribution": "normal", "mu": 2000, "sigma": 500}
    ]
  },
  "response_size_buckets": [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072],
  "response_size_weights": [0.05, 0.1, 0.15, 0.2, 0.2, 0.15, 0.08, 0.04, 0.02, 0.01],
  "think_time_ms": {
    "distribution": "log_normal",
    "mu": 8.5,
    "sigma": 1.5,
    "min": 1000,
    "max": 300000
  },
  "upload_download_ratio": {
    "distribution": "log_normal",
    "mu": -2.3,
    "sigma": 0.8
  },
  "session_duration_s": {
    "distribution": "log_normal",
    "mu": 6.0,
    "sigma": 1.5,
    "min": 30,
    "max": 7200
  }
}
```

## Appendix B: WASM Binary Verification

To verify that a MIRAGE WASM module exports the correct WATM v1 interface:

```bash
# Check exported functions
wasm-tools print mirage.wasm | grep "(export"

# Expected output:
#   (export "watm_init_v1" (func $watm_init_v1))
#   (export "watm_ctrlpipe_v1" (func $watm_ctrlpipe_v1))
#   (export "watm_dial_v1" (func $watm_dial_v1))
#   (export "watm_accept_v1" (func $watm_accept_v1))
#   (export "watm_associate_v1" (func $watm_associate_v1))
#   (export "watm_start_v1" (func $watm_start_v1))
#   (export "memory" (memory $memory))

# Verify WASI imports
wasm-tools print mirage.wasm | grep "(import"

# Expected: imports from "wasi_snapshot_preview1" and "env" (WATER host)
```

## Appendix C: Deployment Checklist

1. [ ] Register CDN account (Cloudflare recommended)
2. [ ] Deploy cover website on origin server
3. [ ] Configure CDN routing (Cloudflare Worker or Tunnel)
4. [ ] Generate server X25519 keypair and PSK
5. [ ] Build MIRAGE WATM module (`cargo build --release --target wasm32-wasip1`)
6. [ ] Optimize WASM binary (`wasm-opt -Os`)
7. [ ] Configure MIRAGE origin handler on server
8. [ ] Generate client configuration (public key, PSK, CDN hostname, traffic profile)
9. [ ] Distribute WASM module and config to clients via WATER
10. [ ] Test with active probing simulation
11. [ ] Test with traffic analysis tools
12. [ ] Monitor for detection and prepare profile/module updates
