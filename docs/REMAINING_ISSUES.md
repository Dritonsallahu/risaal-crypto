# Remaining Security Issues — risaal_crypto 0.3.0

Last updated: 2026-04-19

This document tracks known security gaps that remain after the 0.3.0 security remediation. Each item includes severity, current status, and planned resolution.

---

## 1. No Third-Party Security Audit

**Severity:** High
**Status:** Planned for Q4 2026
**Impact:** The Signal Protocol design is well-vetted, but our Dart implementation has not been formally reviewed by an independent security firm. Implementation bugs (off-by-one in ratchet logic, subtle key reuse, incorrect nonce handling) would only be found by expert review.

**Mitigation:**
- Comprehensive test suite (440+ tests including fuzzing, adversarial, and memory hygiene tests)
- `docs/AUDIT_SCOPE.md` defines the scope for a future audit engagement
- All cryptographic operations follow Signal Protocol reference closely

**Resolution:** Engage NCC Group, Trail of Bits, or Cure53 for a formal audit of the core protocol implementation (`lib/src/`).

---

## 2. pqcrypto 0.1.0 — Unaudited FFI Binding

**Severity:** Medium
**Status:** Monitoring upstream
**Impact:** The `pqcrypto` package provides Kyber-768 (ML-KEM-768) via FFI to liboqs. It is research-grade and has not been production-audited. Potential risks include side-channel leaks in the C code and FFI memory handling bugs.

**Mitigation:**
- Kyber is used in **hybrid mode** with X25519 — if Kyber is broken, X25519 still provides classical security
- Version pinned to exactly `0.1.0` (not `^0.1.0`) to prevent untested updates
- Post-quantum layer is additive, not replacing classical security

**Resolution:** Track liboqs audit progress. Consider switching to NIST-certified ML-KEM implementation when available in Dart ecosystem.

---

## 3. dhSendingKeyPair Wipe Structurally Incomplete

**Severity:** Medium
**Status:** Documented, no fix available
**Impact:** During `_dhRatchetStep`, a new X25519 key pair is generated. The `KeyPair.privateKey` field is a base64-encoded Dart `String`. Since Dart `String` is immutable, the private key bytes cannot be zeroed — they persist on the Dart heap until garbage collection reclaims the memory page. The serialized `Uint8List` copy IS zeroed, but the original `String` representation is structurally unwipeable.

**Mitigation:**
- Key pair lifetime is minimized (generated, serialized to `Uint8List`, and the reference dropped immediately)
- The `Uint8List` serialization is zeroed via `SecureMemory.zeroBytes()`
- Documented in `docs/MEMORY_SAFETY.md` residual risks table

**Resolution:** Requires upstream `cryptography` package to expose raw `Uint8List` key pairs instead of base64 `String`. Filed as a known limitation — will adopt when upstream support is available.

---

## 4. Storage Security Warning Not Blocking

**Severity:** Low
**Status:** Fixed in 0.3.0 (console warning added)
**Impact:** When a developer passes an insecure `CryptoSecureStorage` implementation (one returning `StorageSecurityLevel.insecure`), the library previously only emitted an event bus event. Developers without the event bus wired up would never see the warning.

**Mitigation (0.3.0):**
- Constructor-time `print()` warning added — developers now see a clear console message during `initialize()` even without event bus integration
- Event bus emission retained for app-level handling
- `CryptoDebugLogger` warning retained for structured logging

**Potential future enhancement:** Add an `assert()` in debug mode or a `strict` constructor parameter that throws on insecure storage, forcing developers to acknowledge the risk explicitly.

---

## Priority Matrix

| Issue | Severity | Effort | Timeline |
|-------|----------|--------|----------|
| Third-party audit | High | High (external) | Q4 2026 |
| pqcrypto audit status | Medium | Low (monitoring) | Ongoing |
| dhSendingKeyPair String residue | Medium | Blocked (upstream) | When upstream supports Uint8List keys |
| Storage warning enhancement | Low | Low | Optional future release |

---

## Score Progression

| Version | Score | Key Changes |
|---------|-------|-------------|
| 0.2.x | 5.2/10 | CBC encryption, no signatures, incomplete deniability claims, no memory safety tests |
| 0.3.0 | 7.6/10 | AES-256-GCM, Ed25519 group signatures, corrected deniability docs, memory hygiene tests, constructor-time storage warning, version table updated |
| Post-audit | Target 9.0+ | Third-party validation, certified PQ implementation |
