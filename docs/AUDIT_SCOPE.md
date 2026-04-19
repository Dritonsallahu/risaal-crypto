# Third-Party Security Audit — Scope Document

## Overview

This document defines the scope for a formal security audit of the `risaal_crypto` package — a pure Dart implementation of the Signal Protocol with post-quantum extensions.

## Audit Objectives

1. Verify cryptographic protocol correctness against published specifications
2. Identify implementation vulnerabilities (side channels, state management, error handling)
3. Assess post-quantum (PQXDH) hybrid construction security
4. Review key management lifecycle and memory hygiene
5. Evaluate resistance to adversarial scenarios (replay, forgery, downgrade)

## In-Scope Components

| Component | File | Priority | Specification |
|-----------|------|----------|---------------|
| X3DH + PQXDH | `lib/src/x3dh.dart` | Critical | [X3DH Spec](https://signal.org/docs/specifications/x3dh/), [PQXDH](https://eprint.iacr.org/2024/131) |
| Double Ratchet | `lib/src/double_ratchet.dart` | Critical | [DR Spec](https://signal.org/docs/specifications/doubleratchet/) |
| Sender Keys | `lib/src/sender_key.dart` | Critical | [Signal Group v2](https://signal.org/docs/specifications/group-v2/) |
| Sealed Sender | `lib/src/sealed_sender.dart` | High | [Signal Blog](https://signal.org/blog/sealed-sender/) |
| Key Storage | `lib/src/crypto_storage.dart` | High | N/A (custom) |
| Key Generation | `lib/src/key_helper.dart` | High | RFC 7748, FIPS 203 |
| Safety Numbers | `lib/src/safety_number.dart` | Medium | [Signal Fingerprint](https://signal.org/docs/specifications/fingerprint/) |
| Message Padding | `lib/src/message_padding.dart` | Medium | Custom (PKCS#7 variant) |
| Secure Memory | `lib/src/secure_memory.dart` | Medium | N/A (platform FFI) |
| Steganography | `lib/src/stego_service.dart` | Low | Custom (LSB embedding) |

## Out of Scope

- Server-side code (`risaal-server/`)
- Flutter app integration code (`risaal-app/`)
- Admin panel (`risaal-admin/`)
- UI/UX components
- Network transport layer

## Key Models

| File | Purpose |
|------|---------|
| `lib/src/models/signal_keys.dart` | Key pair types, PreKeyBundle, signed/one-time pre-keys |
| `lib/src/models/session_state.dart` | Double Ratchet session state persistence |

## Cryptographic Dependencies

| Library | Version | Usage | Notes |
|---------|---------|-------|-------|
| `cryptography` | ^2.7.0 | X25519, Ed25519, AES-GCM, HKDF, HMAC | Pure Dart, well-maintained |
| `crypto` | ^3.0.5 | SHA-256, SHA-512 | Dart team maintained |
| `pqcrypto` | ^0.1.0 | Kyber-768 (ML-KEM) | FFI bindings, NOT audited |

## Test Suite

The package includes 200+ tests across 14 test files. The auditor should:
1. Review test coverage for critical paths
2. Identify untested edge cases
3. Verify adversarial test scenarios match real-world attack vectors
4. Assess whether deterministic test vectors match reference implementations

## Specific Areas of Concern

1. **Kyber-768 FFI bindings**: The `pqcrypto` package wraps a C implementation. The bindings have not been independently verified.
2. **Dart VM non-constant-time operations**: The Dart VM does not guarantee constant-time execution. Side-channel resistance depends on the `cryptography` package internals.
3. **GC-related key exposure**: Despite FFI-based `SecureMemory.zeroBytes()`, the Dart GC may create copies of key material during compaction. `SecureBuffer` mitigates this for long-lived keys.
4. **Session auto-reset**: The rate-limited auto-reset mechanism is custom (not in Signal spec). Verify it doesn't introduce attack vectors.

## Deliverables

1. Vulnerability report with severity ratings (Critical/High/Medium/Low/Informational)
2. Code-level findings with file paths and line numbers
3. Recommendations for each finding
4. Assessment of overall cryptographic design soundness
5. Comparison with reference Signal Protocol implementation (libsignal)

## Estimated Effort

Based on similar Signal Protocol audits:
- **Minimum**: 2 auditors, 2 weeks (protocol review + code audit)
- **Recommended**: 2 auditors, 4 weeks (includes fuzzing, side-channel analysis)

## Review Schedule

| Type | Frequency | Scope | Responsibility |
|------|-----------|-------|---------------|
| Peer review | Every PR | All `lib/src/` changes | @Dritonsallahu (CODEOWNERS) |
| Informal review | Every 3–6 months | Full package, focus on recent changes | Trusted peer / security-savvy reviewer |
| Formal audit | Annually (target) | Full protocol + code audit | Third-party security firm |
| Incident-triggered | On discovery | Affected component only | Maintainer + reviewer |

### Review Triggers (outside scheduled cadence)

A review MUST be requested when:
- A new cryptographic primitive is added or replaced
- The session auto-reset or key rotation logic changes
- The PQXDH hybrid construction is modified
- More than 500 lines of `lib/src/` change in a single release
- A security vulnerability is reported and patched

### Audit History

| Date | Type | Reviewer | Outcome |
|------|------|----------|---------|
| 2026-04 | Informal peer review | — | In progress (this review) |


### Publication & Re-Audit Policy

- Full audit reports (or maximum-detail public summaries when legal constraints apply) MUST be published after remediation planning.
- Every finding must have a tracked remediation item and closure evidence in CHANGELOG/release notes.
- A re-audit MUST be scheduled when:
  - protocol wire formats change,
  - core key agreement/ratchet primitives are modified, or
  - a high/critical cryptographic vulnerability is fixed.

### Next Milestones

- **Q2 2026:** Complete informal peer review, address all findings
- **Q3 2026:** Issue RFP for formal third-party audit
- **Q4 2026:** First formal audit (target)

## Contact

Report findings to: security@risaal.org (PGP key available on request)
