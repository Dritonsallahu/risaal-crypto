# Incident Response Playbook — risaal_crypto

This document covers response procedures for cryptographic incidents in the Risaal crypto package.

---

## 1. Key Compromise Response

### Detection Signals
- `SecurityEventType.signatureVerificationFailed` — possible identity key compromise
- `SecurityEventType.antiDowngradeTriggered` — peer's keys may have been replaced
- `SecurityEventType.replayRejected` — attacker replaying intercepted messages
- User reports safety number change they didn't initiate

### Immediate Actions (0–15 minutes)
1. **Quarantine the affected session** — stop all message send/receive on the compromised session
2. **Notify the user** — display a clear, non-dismissible warning that the session may be compromised
3. **Trigger key rotation** — call `rotateKeysIfNeeded(signedPreKeyMaxAge: Duration.zero, kyberKeyMaxAge: Duration.zero)` to force immediate rotation of signed pre-key and Kyber key
4. **Generate new one-time pre-keys** — call `generateOneTimePreKeys(50)` to replenish pool
5. **Upload new bundle to server** — push the rotated key bundle to the key server

### Recovery Steps (15 min – 1 hour)
1. **Re-establish sessions** — for each active peer, fetch their new bundle and create a fresh session via `createSession()`
2. **Invalidate old sessions** — call `removeSession()` on all sessions established before the compromise was detected
3. **Audit skipped keys** — examine `RatchetState.skippedKeys` for unexpectedly large gaps
4. **Verify safety numbers** — prompt both users to verify safety numbers through an out-of-band channel

### Post-Incident (1–24 hours)
1. **Collect security events** — review all `SecurityEvent` emissions from the event bus for the 48 hours before detection
2. **Determine blast radius** — identify all sessions that used the compromised key material
3. **Notify affected users** — if server-side compromise, notify all users who exchanged messages during the window
4. **Update peer capabilities** — clear stored PQXDH capabilities to allow fresh capability detection

---

## 2. Protocol Bug Response

### Severity Classification
| Level | Description | Response Time |
|-------|-------------|---------------|
| P0 | Message content can be decrypted by attacker | Immediate (< 1 hour) |
| P1 | Authentication bypass, impersonation possible | < 4 hours |
| P2 | Forward secrecy broken for specific scenarios | < 24 hours |
| P3 | Metadata leakage, timing side-channel | < 1 week |

### Response Procedure
1. **Reproduce with test vectors** — write a failing test in `test/test_vectors_test.dart` that demonstrates the bug
2. **Fix in isolation** — develop the fix on a separate branch, run full adversarial test suite
3. **Verify no regression** — run the complete test suite (`flutter test`), adversarial tests, and fuzz tests
4. **Publish patch release** — bump patch version, update CHANGELOG.md, push to repository
5. **Coordinate client update** — the Risaal app must update `risaal_crypto` dependency and re-deploy

### Communication Template
```
RISAAL SECURITY ADVISORY — [YYYY-MM-DD]

Severity: P[0-3]
Affected versions: X.Y.Z – X.Y.Z
Fixed in: X.Y.Z

Summary: [One sentence description]
Impact: [What an attacker could achieve]
Mitigation: [Steps users can take before updating]
Fix: [Brief technical description of the fix]
```

---

## 3. Remote Key Rotation Procedure

### When to Rotate
- Signed pre-key age exceeds 7 days (`signedPreKeyAge()` > 7 days)
- Kyber key age exceeds 7 days
- OTP pool drops below watermark (25 keys)
- After a suspected compromise
- After app update that changes crypto parameters

### Rotation Procedure
```dart
// 1. Check if rotation is needed
final signedAge = await manager.signedPreKeyAge();
final kyberResult = await manager.rotateKyberKeyIfNeeded();
final signedResult = await manager.rotateSignedPreKeyIfNeeded();

// 2. Generate fresh OTPs if pool is low
if (await manager.isPreKeyExhaustionNear()) {
  final newKeys = await manager.generateOneTimePreKeys(50);
  // Upload to server
}

// 3. Upload new bundle to server
final bundle = await manager.generateKeyBundle();
// POST to /api/keys/bundle

// 4. Verify upload succeeded before proceeding
```

### Rotation Invariants
- The new signed pre-key ID MUST be strictly greater than the old one
- The new Kyber encapsulation key MUST be a fresh ML-KEM-768 keypair
- Old key material MUST be wiped from memory after upload confirmation
- Sessions established with old keys continue to work (Double Ratchet is independent)

---

## 4. Coordinated Disclosure Process

### If We Discover a Vulnerability
1. **Document** — write a private report with reproduction steps, impact analysis, and proposed fix
2. **Fix** — develop and test the fix privately
3. **Release** — publish the patched version
4. **Disclose** — after 90 days or when ≥95% of clients have updated, publish the full advisory

### If a Vulnerability Is Reported to Us
1. **Acknowledge** — respond within 24 hours confirming receipt
2. **Validate** — reproduce the issue within 72 hours
3. **Prioritize** — classify severity (P0–P3) and assign response timeline
4. **Fix** — develop, test, and release patch within the response timeline
5. **Credit** — credit the reporter in the security advisory (unless they prefer anonymity)
6. **Publish** — release full advisory after patch deployment

### Contact
Security issues should be reported to: security@risaal.org

---

## 5. Anti-Replay Incident

### Detection
- `SecurityEventType.replayRejected` fires on duplicate message ID
- Multiple rejections from the same session in short timeframe = active attack

### Response
1. **Log the event** (metadata only — never message content)
2. **Count occurrences** — 3+ replays in 60 seconds = escalate to user notification
3. **Consider session reset** — if replay attempts persist, the session may be corrupted
4. **Verify network** — confirm the user is not on a compromised or MITM'd network

---

## 6. Anti-Downgrade Incident

### Detection
- `SecurityEventType.antiDowngradeTriggered` fires when a peer who previously supported PQXDH presents a bundle without Kyber keys

### Response
1. **Warn the user** — "This contact's security level has decreased. Their device may have been replaced or compromised."
2. **Allow explicit override** — user can choose to proceed with classical-only security
3. **Log the event** — track which peers triggered downgrades for pattern detection
4. **Verify identity** — prompt users to re-verify safety numbers

---

## 7. Session State Corruption

### Detection
- Decryption fails with `SecretBoxAuthenticationError` on a previously working session
- `SecurityEventType.sessionReset` fires after auto-renegotiation
- `SecurityEventType.sessionUnstable` fires after repeated reset attempts

### Response
1. **Automatic retry** — the session auto-renegotiation system will attempt to re-establish
2. **If unstable** — after 3 failed reset attempts within 60 seconds, stop auto-reset
3. **Manual intervention** — user should verify safety numbers and manually re-establish if needed
4. **Data preservation** — undelivered messages should be queued, not dropped
