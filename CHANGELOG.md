# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-04-07

### Added
- SecurityEventBus: stream-based pub/sub for 13 security event types
- Anti-replay state persistence: `receivedMessages` in RatchetState (cap 2000, persisted via JSON)
- Anti-downgrade enforcement: tracks peer PQXDH capability, detects classical-only regression
- Kyber key rotation: periodic ML-KEM-768 rotation (default 7 days)
- `rotateKyberKeyIfNeeded()` and `rotateKeysIfNeeded()` convenience methods
- OTP low-watermark raised to 25 with event bus emissions
- Production telemetry integration guide (`docs/OPERATIONAL_RUNBOOK.md`)
- Release signing controls and semver policy for crypto libraries
- Incident drill procedures (quarterly schedule with pass criteria)
- Memory safety model documentation (`docs/MEMORY_SAFETY.md`)

### Changed
- [SECURITY] Skipped message key cap raised from 100 to 2000 for realistic offline gaps
- [SECURITY] OTP exhaustion threshold raised from 10 to 25 (earlier warnings)
- CI pipeline: enforced 80% coverage threshold, SAST scan, dependency vulnerability audit, changelog gate

### Fixed
- [SECURITY] `SecretKey` by-reference corruption from `SecureMemory.zeroBytes()` — defensive `List<int>.from()` copies
- SECURITY.md: corrected skipped key cap documentation (was 100, now 2000)

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
- 357+ tests covering protocol correctness, adversarial, fuzz, and memory hygiene scenarios

### Security
- Ed25519 asymmetric signatures for Sender Key authentication (prevents recipient forgery)
- Mandatory signed pre-key verification (no downgrade path)
- PQXDH policy enforcement (require_pq, prefer_pq, classical_only)
- Constant-time HMAC comparison for chain key operations
