# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-07

### Added
- X3DH key agreement with mandatory signed pre-key verification
- Double Ratchet with forward secrecy and post-compromise security
- Sealed Sender for metadata protection (sender anonymity)
- Sender Keys for efficient group E2EE with Ed25519 authentication
- PQXDH hybrid key agreement (X25519 + Kyber-768) with policy modes
- Safety Number generation (60-digit numeric fingerprint)
- Message padding (fixed bucket sizes for traffic analysis resistance)
- LSB steganography for covert communication
- Session auto-reset with rate limiting
- FFI-based secure memory zeroing (Android/iOS)
- 200+ tests covering protocol correctness and adversarial scenarios

### Security
- Ed25519 asymmetric signatures for Sender Key authentication (prevents recipient forgery)
- Mandatory signed pre-key verification (no downgrade path)
- PQXDH policy enforcement (require_pq, prefer_pq, classical_only)
- Constant-time HMAC comparison for chain key operations
