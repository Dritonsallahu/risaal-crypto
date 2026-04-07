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

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.1.x   | Yes                | Current |
| < 0.1   | No                 | Pre-release |

Only the latest 0.1.x version receives security updates. Please upgrade to the latest version before reporting issues.

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
- **Memory forensics:** FFI-based secure memory zeroing (`SecureMemory.zeroBytes()`) clears sensitive data from RAM
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
- **Sealed Sender window:** 5-minute replay window exists for Sealed Sender envelopes

## Security Invariants

These invariants MUST hold at all times. Violations are security bugs:

1. **Private keys never leave secure storage:** All private keys stored via `CryptoSecureStorage`, never serialized to disk or logs
2. **All DH intermediaries are zeroed:** Shared secrets from X25519 operations must be zeroed via `SecureMemory.zeroBytes()` after use
3. **No plaintext ever logged:** `CryptoDebugLogger` only logs key prefixes (first 8 chars) in debug builds, stripped from release
4. **Sealed Sender replay protection:** Envelopes have 5-minute maximum replay window, enforced via timestamp validation
5. **Skipped message key cap:** Maximum 2000 skipped message keys per session to prevent DoS memory exhaustion
6. **Sender Key chain advance cap:** Maximum 2000 iterations when advancing chain to prevent DoS CPU exhaustion
7. **Message number monotonicity:** Message numbers must strictly increase within a session (prevents replay and reordering)
8. **AES-256-GCM authentication:** All ciphertexts verified before decryption (prevents tampering)

## Cryptographic Dependencies

| Library | Version | Algorithms | Audit Status |
|---------|---------|-----------|-------------|
| `cryptography` | ^2.7.0 | X25519, Ed25519, AES-256-GCM, HKDF-SHA256, HMAC-SHA256 | Community-reviewed, widely used |
| `crypto` | ^3.0.3 | SHA-256, SHA-512 | Maintained by Dart team |
| `pqcrypto` | ^0.1.0 | ML-KEM-768 (Kyber-768) via FFI | Research-grade, not production-audited |

### Dependency Security Notes

- **cryptography:** Actively maintained, used in production by thousands of projects
- **crypto:** Official Dart package, stable API since 2019
- **pqcrypto:** Experimental FFI bindings to liboqs; USE AT YOUR OWN RISK for post-quantum features

We pin exact versions in `pubspec.lock` and review all dependency updates for security implications.

## Known Limitations

### No Formal Security Audit

**This library has NOT undergone a formal third-party security audit.** While the Signal Protocol design is well-vetted, our implementation may contain bugs. Use in production at your own risk.

### Post-Quantum Implementation Status

The `pqcrypto` FFI bindings are **research-grade**, not production-audited. The Kyber-768 implementation:
- Uses liboqs (Open Quantum Safe) via FFI
- Has not been formally verified
- May have side-channel vulnerabilities
- Should be considered experimental

We use Kyber as a **hybrid** with X25519, so even if Kyber is broken, X25519 still provides classical security.

### Dart VM Limitations

- **No constant-time guarantees:** Dart VM does not guarantee constant-time execution for cryptographic operations
- **Garbage collection:** GC may leave copies of sensitive data in memory despite zeroing attempts
- **JIT compilation:** Timing variations from JIT may leak information via side channels

These are inherent Dart platform limitations. For maximum security, consider a native implementation.

**Mitigations implemented:** FFI-based volatile memory zeroing (`SecureMemory`), native heap isolation (`SecureBuffer`), defensive byte copies to prevent library corruption, immediate zeroing after every DH operation. See `docs/MEMORY_SAFETY.md` for the complete memory safety model and residual risk analysis.

### Steganography is NOT Security

The `StegoService` LSB steganography feature provides **obscurity, not security:**
- It hides encrypted data inside images, making it less obvious
- The underlying security still comes from AES-256-GCM encryption
- Steganography can be defeated by simple statistical analysis
- DO NOT rely on steganography as your primary security mechanism

Steganography is an additional layer on top of proper encryption, not a replacement.

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

- **[docs/MEMORY_SAFETY.md](docs/MEMORY_SAFETY.md)** — Complete memory safety model, Dart GC constraints, FFI mitigations, residual risks
- **[docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md)** — Key compromise playbook, protocol bug response, coordinated disclosure
- **[docs/OPERATIONAL_RUNBOOK.md](docs/OPERATIONAL_RUNBOOK.md)** — Production telemetry integration, release signing controls, incident drill procedures
- **[docs/AUDIT_SCOPE.md](docs/AUDIT_SCOPE.md)** — Scope document for third-party security audit

Thank you for helping keep Risaal secure.
