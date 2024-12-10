[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

<p align="center">
    <img src="logo.png" alt="Logo" align="center">
</p>

# Eisenbahn (Deprecated)

**⚠️ Important Notice:** Eisenbahn has been **superseded** by [**Hexgate**](https://github.com/alexdesander/hexgate). Please refer to Hexgate for the latest updates, continued development, and new features.

----

A fully UDP-based client-server game networking system developed in Rust.

## Features (Eisenbahn)

- **Encryption Options:**
  - None
  - AES128-GCM
  - AES256-GCM
  - ChaCha8Poly1305
  - ChaCha20Poly1305
- **Flexible Client Authentication:**
  - Username only
  - Username and password
  - ed25519 public/private key (ed25519 signature)
  - Central Authority (for most commercial use)
- **Optional Server Authentication:**
  - Based on ed25519 signatures
- **Connection Management:**
  - Rejection based on client version
  - User-defined connection rejection (e.g., player bans)
- **API Interface:**
  - Poll-based and blocking
- **System Performance:**
  - Runs on a dedicated thread
  - Latency (Ping) discovery
  - Timeout detection
- **Messaging System:**
  - 4 virtual reliable ordered message channels
  - Unreliable unordered messages **NOT YET IMPLEMENTED**
  - Bypassing congestion control for ultra-low latency **NOT YET IMPLEMENTED**
  - Decaying unreliable unordered messages **NOT YET IMPLEMENTED**
- **Efficiency:**
  - Thread efficiency in idle state (the network thread does not poll at fixed intervals) **NOT YET IMPLEMENTED**
- **Safety:**
  - 100% safe Rust (excluding dependencies)

## Contribution

Contributions to Eisenbahn are no longer accepted as the project has been superseded by [Hexgate](https://github.com/alexdesander/hexgate). If you'd like to contribute, please consider contributing to Hexgate instead.

**License:** Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be under the terms and conditions of the BSD-3-Clause License, without any additional terms or conditions.
