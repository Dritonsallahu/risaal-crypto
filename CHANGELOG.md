# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-18

### Security Fixes (from external security analysis)

- **[BREAKING] AES-256-CBC → AES-256-GCM** for Sender Key group encryption. Old CBC messages (v1) can still be decrypted for backward compatibility. New messages always use GCM (v2). Eliminates unauthenticated CBC and non-constant-time PKCS7 padding.
- **[BREAKING] `seenNonces` now required** in `SealedSenderEnvelope.unseal()`. Prevents nonce replay attacks. Callers must supply a persistent `Set<String>`.
- **[BREAKING] `RatchetState` keys migrated from `String` to `Uint8List`**. Enables genuine memory zeroing via `SecureMemory.zeroBytes()`. Stored sessions auto-migrate on first load.
- **[BREAKING] `CryptoSecureStorage` now requires `securityLevel` getter**. Implementations must declare `StorageSecurityLevel.hardwareBacked`, `.softwareEncrypted`, or `.insecure`.
- **Pinned `pqcrypto`** to exact version (pre-release, unaudited FFI binding).
- **First-session Kyber downgrade protection**: `requirePq` policy now blocks first-contact sessions without Kyber; `preferPq` emits `firstSessionNoPqxdh` warning.
- **Message number cap**: `messageNumber` and `previousChainLength` reject values > 100,000.

### Documentation

- Corrected deniability claims: group messages are non-deniable by design (Ed25519 signatures). 1-to-1 remains deniable.
- Updated crypto primitives: group encryption is AES-256-GCM (not CBC).

### Added

- `SecurityEventType.firstSessionNoPqxdh` event type
- `SecurityEventType.insecureStorageWarning` event type
- `StorageSecurityLevel` enum
- `CryptoStorage.saveSeenNonces()` / `loadSeenNonces()` for nonce persistence
- Negative test vectors (malformed keys, truncated ciphertext, invalid nonces)

## [0.2.1] - 2026-04-07

### Fixed
- [SECURITY] PQXDH anti-downgrade now **refuses** session establishment when a peer's bundle loses its Kyber key (previously only logged a warning). Prevents MITM from silently stripping the post-quantum layer. `PqxdhPolicy.classicalOnly` override preserved for explicit user confirmation.

### Added
- `PqxdhDowngradeError` exception for anti-downgrade enforcement
- 8 new tests: anti-downgrade blocking, override bypass, event emission, edge cases (392 total)
- Dependency patching policy (72h SLA) documented in `SECURITY.md`
- GPG-signed tag release procedure documented in `BRANCH_PROTECTION.md`

## [0.2.0] - 2026-04-07

### Added
- **CI: Per-file coverage enforcement** — 85% global threshold, 95% for critical crypto files (x3dh, double_ratchet, sender_key, sealed_sender), 90% for protocol orchestration files. Enforced via `scripts/check_coverage.sh`
- **CI: OSV-Scanner vulnerability scanning** — scans `pubspec.lock` against OSV database, blocks merge on unexcepted vulnerabilities
- **CI: Dependabot configuration** — weekly scans for both `pub` and `github-actions` ecosystems
- **CI: Known vulnerability exception file** — `security/known-vulns.yaml` with mandatory expiry dates (max 90 days), automated expiry enforcement in CI
- **CI: Semgrep SAST** — 9 custom crypto-focused rules (insecure RNG, MD5, SHA-1, ECB, CBC without auth, static IV, hardcoded secrets, print in production, unsafe deserialization) with SARIF upload to GitHub Security tab
- **CI: Signed release workflow** — `release.yml` with version verification, changelog extraction, source archives, SHA256SUMS checksums, GitHub Attestations build provenance, pub.dev publish
- **CI: CODEOWNERS** — all `lib/src/` crypto files require explicit review from @Dritonsallahu
- **Ops: SLO definitions** — 6 stability SLOs (decrypt failure < 0.1%, session reset < 0.5%, replay rejection < 0.01%, OTP exhaustion < 1%, X3DH success > 99.5%, Sender Key success > 99%) and 6 security SLOs (MAC failure < 0.01%, signature failure < 0.01%, PQ downgrade block 100%, replay rejection 100%, key cap enforcement 100%, key rotation compliance 100%)
- **Ops: Telemetry integration guide** — privacy-safe counter architecture, client collection, server aggregation, Prometheus-style alert rules, Grafana dashboard panels
- **Ops: Canary deployment strategy** — 4-stage rollout (1% internal → 5% beta → 25% progressive → 100%), statistical significance methodology, rollback triggers, version-specific requirements
- **Ops: 4 security runbooks** — `runbook-key-compromise.md`, `runbook-replay-spike.md`, `runbook-session-reset-storm.md`, `runbook-critical-dependency-cve.md` with triage checklists, containment actions, recovery steps, and communication templates
- **Ops: Incident drill procedures** — monthly tabletop exercises (12-scenario annual rotation), quarterly live simulations with event injection, annual full simulations with scoring criteria
- **Docs: Branch protection policy** — required CI checks, CODEOWNERS, signed commits, linear history, emergency bypass procedure

### Changed
- [SECURITY] CI coverage threshold raised from 80% to 85% global, with per-file enforcement
- CI pipeline expanded from 7 to 8 jobs (added Semgrep SAST)
- CI dependency audit now includes OSV-Scanner and known-vulns expiry enforcement

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
