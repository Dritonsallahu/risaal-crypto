# Security Policy

## Reporting Security Vulnerabilities

**This is a cryptographic library. Security vulnerabilities have serious consequences.**

If you discover a security vulnerability in `risaal_crypto`, please report it responsibly:

- **Email:** security@risaal.org
- **DO NOT** open public GitHub issues for security vulnerabilities
- **Expected response time:** 72 hours
- **Responsible disclosure:** We request a 90-day window before public disclosure to allow time for fixes and coordinated release
- **PGP key:** Available at https://risaal.org/security.txt for encrypted reports

### What to Include in Your Report

- Clear description of the vulnerability
- Reproduction steps (proof-of-concept code if applicable)
- Affected versions (check `pubspec.yaml` version)
- Potential impact and attack scenarios
- Any suggested mitigations or fixes

We take all security reports seriously and will acknowledge receipt within 72 hours.

### Escalation for Active Attacks (P0)

If a vulnerability is being **actively exploited**:

1. **Email** security@risaal.org — include "P0 ACTIVE EXPLOIT" in subject
2. **If you receive no acknowledgement within 72 hours:** escalate to hello@risaal.org
3. **If vulnerability affects >1% of users:** trigger emergency patch release (bypass standard review, require single maintainer sign-off)
4. **If key material is compromised server-side:** push remote key rotation to all clients immediately

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.4.x   | Yes                | Current |
| 0.3.x   | No — upgrade required (RISAAL-CRYPTO-2026-001) | End of Life |
| < 0.3   | No                 | End of Life |

Only the latest 0.4.x version receives full updates. All prior versions are end-of-life and affected by RISAAL-CRYPTO-2026-001. Please upgrade before reporting issues.

### Security Advisories

Published advisories are in [`docs/security/advisories/`](docs/security/advisories/). See [RISAAL-CRYPTO-2026-001](docs/security/advisories/RISAAL-CRYPTO-2026-001.md) for the transactional-decrypt vulnerability fixed in 0.4.0.

## Threat Model

### What We Protect Against

**Network-Level Attacks:**
- **Passive eavesdroppers:** All messages encrypted end-to-end with AES-256-GCM on top of TLS
- **Active network attackers:** Message authentication prevents tampering
- **Message replay attacks:** Message numbers and timestamp verification prevent replay
- **Traffic analysis (partial):** Message padding to fixed bucket sizes (256B, 1KB, 4KB, 16KB, 64KB, 256KB) obscures true length

**Server Compromise:**
- **Compromised server:** Server never sees plaintext, private keys, or sender identity (Sealed Sender)
- **Metadata leakage:** Sealed Sender hides sender from server; only recipient knows who sent the message
- **Message interception:** Server can only relay encrypted envelopes, cannot decrypt

**Key Compromise:**
- **Compromised past messages:** Forward secrecy via Diffie-Hellman ratchet ensures past messages unreadable after key compromise
- **Future message compromise:** Post-compromise security via DH ratchet ensures future messages protected after key recovery
- **Quantum computer attacks on key exchange:** Kyber-768 (ML-KEM-768) hybrid key agreement provides post-quantum resistance

**Device Forensics:**
- **Memory forensics (partial):** Best-effort zeroing of key copies owned by this package (`SecureMemory.zeroBytes()`, Dart heap); the `cryptography`/`pqcrypto` libraries' internal copies are not overwritten and GC copies may persist (see `docs/MEMORY_SAFETY.md`)
- **Key extraction:** Private keys stored in platform secure storage (Keychain/Keystore), never in plaintext files

### What We Do NOT Protect Against

**Device Compromise:**
- **Malware on device:** If malicious code runs on the device with app privileges, encryption cannot protect you
- **Keyloggers:** Physical or software keyloggers can capture messages before encryption
- **Screen capture:** Malware with screen recording permissions can capture decrypted messages

**Implementation Limitations:**
- **Side-channel attacks on Dart VM:** Dart does not guarantee constant-time operations; timing attacks may be possible
- **Bugs in underlying crypto libraries:** We depend on `cryptography`, `crypto`, and `pqcrypto` implementations
- **Dart VM memory safety:** Dart's garbage collector may leave copies of sensitive data in memory

**Operational Security:**
- **Rubber hose cryptanalysis:** Physical coercion to reveal keys or messages
- **Traffic analysis beyond message size:** Timing patterns, message frequency, and conversation graphs may leak metadata
- **Social engineering:** Attackers impersonating contacts to trick users

**Cryptographic Limitations:**
- **Group metadata:** Group membership is visible to server (though message content is still encrypted via Sender Keys)
- **Contact discovery:** Phone number hashing for contact discovery is susceptible to rainbow table attacks
- **Sealed Sender nonce set:** Nonce deduplication is the primary replay guard; the timestamp window is 30 days to cover realistic offline gaps. The persistent nonce set is trimmed to the newest 10,000 entries.

## Security Invariants

These invariants MUST hold at all times. Violations are security bugs:

1. **Private keys never leave secure storage:** All private keys stored via `CryptoSecureStorage`, never serialized to disk or logs
2. **Package-owned DH/HKDF outputs are zeroed:** Every DH/HKDF output the package owns is copied once into a mutable buffer (`SecureMemory.ownedCopy()`) and zeroed via `SecureMemory.zeroBytes()` after use (verified by `test/secure_memory_zeroing_sites_test.dart`). Library-internal copies are out of reach and are not zeroed
3. **No plaintext ever logged:** `CryptoDebugLogger` only logs key prefixes (first 8 chars) in debug builds, stripped from release
4. **Sealed Sender replay protection:** Envelopes carry a persistent nonce set (trimmed to 10,000 entries) as the primary guard; the timestamp window is 30 days to cover realistic offline gaps
5. **Skipped message key cap:** Maximum 2000 skipped message keys per session to prevent DoS memory exhaustion
6. **Sender Key chain advance cap:** Maximum 2000 iterations when advancing chain to prevent DoS CPU exhaustion
7. **Message number monotonicity:** Message numbers must strictly increase within a session (prevents replay and reordering)
8. **AES-256-GCM authentication:** All ciphertexts verified before decryption (prevents tampering)

## Cryptographic Dependencies

| Library | Version | Algorithms | Audit Status |
|---------|---------|-----------|-------------|
| `cryptography` | ^2.7.0 | X25519, Ed25519, AES-256-GCM, HKDF-SHA256, HMAC-SHA256 | Community-reviewed, widely used |
| `crypto` | ^3.0.3 | SHA-256, SHA-512 | Maintained by Dart team |
| `pqcrypto` | 0.4.0 | ML-KEM-768 (Kyber-768, FIPS 203) — pure Dart | Pure-Dart reference implementation; no native/FFI dependency |

### Dependency Security Notes

- **cryptography:** Actively maintained, used in production by thousands of projects
- **crypto:** Official Dart package, stable API since 2019
- **pqcrypto:** Pure-Dart FIPS 203 (ML-KEM-768) implementation; no native/FFI dependency. Not yet independently audited. The hybrid design ensures X25519 alone provides classical security if the ML-KEM component is broken.

We pin exact versions in `pubspec.lock` and review all dependency updates for security implications.

### Dependency Patching Policy

| Severity | SLA | Details |
|----------|-----|---------|
| P0 — Critical, actively exploited | 4h assess, 24h patch | Emergency bypass allowed |
| P1 — Critical or crypto-relevant | 4h assess, 24h patch | All crypto deps (`cryptography`, `crypto`, `pqcrypto`) are P1 minimum |
| P2 — High, exploitable in context | 7 days | Standard PR workflow |
| P3 — Medium/Low | Next release cycle | Standard PR workflow |

**Blanket rule:** All security-relevant dependency patches MUST ship within 72 hours of a fix being available. See `docs/security/runbook-critical-dependency-cve.md` for the full response playbook.

## Known Limitations

### No Formal Security Audit

**This library has NOT undergone a formal third-party security audit.** While the Signal Protocol design is well-vetted, our implementation may contain bugs. Use in production at your own risk.

### Post-Quantum Implementation Status

The `pqcrypto` 0.4.0 dependency is a **pure-Dart** FIPS 203 (ML-KEM-768) implementation with no native or FFI component. It has not undergone independent audit. We use ML-KEM as a **hybrid** with X25519, so even if ML-KEM is broken, X25519 still provides classical security.

### Dart VM Limitations

- **No constant-time guarantees:** Dart VM does not guarantee constant-time execution for cryptographic operations
- **Garbage collection:** GC may leave copies of sensitive data in memory despite zeroing attempts
- **JIT compilation:** Timing variations from JIT may leak information via side channels

These are inherent Dart platform limitations. For maximum security, consider a native implementation.

**Mitigations implemented:** best-effort Dart-heap zeroing of the DH/HKDF/chain-key copies this package owns (`SecureMemory.zeroBytes()`, no `volatile` guarantee), native-heap isolation with `volatile` zeroing on dispose for host-chosen long-lived keys (`SecureBuffer`), defensive copies so zeroing never corrupts a key still in use. **Not wiped:** the `cryptography`/`pqcrypto` libraries' internal key copies (e.g. `SensitiveBytes` in `cryptography` 2.9.0), GC compaction copies, and base64 `String` private keys. See `docs/MEMORY_SAFETY.md` for the complete memory safety model and residual risk analysis.

## Security Best Practices for Users

1. **Verify safety numbers:** Always verify safety numbers out-of-band before sensitive conversations
2. **Keep devices updated:** Security patches are only effective if you update regularly
3. **Use strong PINs/passwords:** Protect device unlock and app lock with strong credentials
4. **Enable disappearing messages:** Reduces forensic attack surface
5. **Verify contact identity:** Confirm you're talking to the right person before sharing sensitive information
6. **Don't screenshot:** Screenshots bypass disappearing messages and create forensic evidence

## Changelog

Security-relevant changes are documented in `CHANGELOG.md` with a `[SECURITY]` prefix. Always review the changelog when updating.

## Contact

- **General inquiries:** hello@risaal.org
- **Security reports:** security@risaal.org (PGP key at https://risaal.org/security.txt)
- **GitHub Issues:** For non-security bugs and feature requests only

## Related Documentation

### Core Security Docs
- **[docs/REMAINING_ISSUES.md](docs/REMAINING_ISSUES.md)** — Known security gaps, severity, status, and planned resolutions
- **[docs/MEMORY_SAFETY.md](docs/MEMORY_SAFETY.md)** — Complete memory safety model, Dart GC constraints, FFI mitigations, residual risks
- **[docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md)** — Key compromise playbook, protocol bug response, coordinated disclosure
- **[docs/OPERATIONAL_RUNBOOK.md](docs/OPERATIONAL_RUNBOOK.md)** — Production telemetry integration, release signing controls, incident drill procedures
- **[docs/AUDIT_SCOPE.md](docs/AUDIT_SCOPE.md)** — Scope document for third-party security audit
- **[docs/SECURITY_GOALS.md](docs/SECURITY_GOALS.md)** — Measurable security goals and acceptance criteria
- **[docs/PROTOCOL_COMPATIBILITY.md](docs/PROTOCOL_COMPATIBILITY.md)** — Protocol versioning and compatibility rules
- **[docs/METADATA_PRIVACY_MODEL.md](docs/METADATA_PRIVACY_MODEL.md)** — Explicit metadata guarantees, leakage model, and roadmap
- **[docs/ASSURANCE_SCORECARD.md](docs/ASSURANCE_SCORECARD.md)** — Objective scoring matrix and benchmark tracking
- **[docs/BUG_BOUNTY.md](docs/BUG_BOUNTY.md)** — Vulnerability disclosure policy (no paid bounty during pre-release)
- **[docs/TRANSPARENCY_REPORT_TEMPLATE.md](docs/TRANSPARENCY_REPORT_TEMPLATE.md)** — Quarterly transparency report template

### Operational Security
- **[docs/security/SLO_DEFINITIONS.md](docs/security/SLO_DEFINITIONS.md)** — Stability and security SLOs with measurement methodology and breach escalation
- **[docs/security/TELEMETRY_INTEGRATION.md](docs/security/TELEMETRY_INTEGRATION.md)** — Privacy-safe telemetry architecture, client/server integration, alert rules
- **[docs/security/CANARY_DEPLOYMENT.md](docs/security/CANARY_DEPLOYMENT.md)** — 4-stage canary rollout strategy with statistical comparison and rollback triggers
- **[docs/security/BRANCH_PROTECTION.md](docs/security/BRANCH_PROTECTION.md)** — Branch protection policy, CODEOWNERS, CI gate requirements

### Security Runbooks
- **[docs/security/runbook-key-compromise.md](docs/security/runbook-key-compromise.md)** — Key compromise detection, triage, containment, and recovery
- **[docs/security/runbook-replay-spike.md](docs/security/runbook-replay-spike.md)** — Replay attack spike diagnosis and response
- **[docs/security/runbook-session-reset-storm.md](docs/security/runbook-session-reset-storm.md)** — Mass session reset diagnosis and containment
- **[docs/security/runbook-critical-dependency-cve.md](docs/security/runbook-critical-dependency-cve.md)** — Critical dependency vulnerability response
- **[docs/security/INCIDENT_DRILL_PROCEDURES.md](docs/security/INCIDENT_DRILL_PROCEDURES.md)** — Monthly/quarterly/annual drill schedule and evaluation criteria

Thank you for helping keep Risaal secure.
