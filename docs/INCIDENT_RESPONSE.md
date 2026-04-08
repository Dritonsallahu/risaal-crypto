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
3. **Trigger key rotation** — call `forceKeyRotationNow()` to force immediate rotation of signed pre-key and Kyber key
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
3. **Verify no regression** — run the verification checklist below
4. **Publish patch release** — bump patch version, update CHANGELOG.md with `[SECURITY]` prefix, push to repository
5. **Coordinate client update** — the Risaal app must update `risaal_crypto` dependency and re-deploy

### Verification Checklist (before merge)
```
- [ ] Regression test written in test/test_vectors_test.dart
- [ ] All tests pass: flutter test
- [ ] Adversarial test suite passes: flutter test test/adversarial_crypto_test.dart
- [ ] dart analyze --fatal-infos reports 0 issues
- [ ] dart format --set-exit-if-changed reports 0 changes
- [ ] Coverage ≥ 95% for affected files, ≥ 85% global
- [ ] CHANGELOG.md updated with [SECURITY] prefix
- [ ] If P0/P1: canary rollout Stage 1 verified before full release
```

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

### Routine Rotation (periodic, e.g. on app foreground)
```dart
// Rotates signed pre-key and Kyber key if older than 7 days
final bundle = await manager.rotateKeysIfNeeded();
if (bundle != null) {
  // Upload new bundle to server — POST /api/keys/bundle
}

// Replenish OTPs if pool is low
if (await manager.isPreKeyExhaustionNear()) {
  final newKeys = await manager.generateOneTimePreKeys(50);
  // Upload to server
}
```

### Emergency Rotation (incident response — key compromise suspected)
```dart
// Force immediate rotation — bypasses age checks
final bundle = await manager.forceKeyRotationNow();
// Upload to server IMMEDIATELY — this is time-critical
await uploadKeyBundle(bundle);

// Also replenish OTPs
final newKeys = await manager.generateOneTimePreKeys(100);
await uploadOneTimePreKeys(newKeys);
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

### Post-Disclosure Retrospective (after advisory is published)
1. **Analyze** — review whether exploitation was observed in the wild
2. **Lessons learned** — document what could have prevented the vulnerability
3. **Update threat model** — add the new attack vector to SECURITY.md if applicable
4. **Update runbooks** — revise incident response procedures based on what worked or didn't
5. **Add regression test** — ensure the specific vulnerability class is covered by adversarial tests
6. **Credit reporter** — update advisory with credit (unless anonymous preference)

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
2. **Block the session** — do NOT allow messaging until user explicitly acknowledges the downgrade
3. **15-minute verification deadline** — if user cannot verify safety numbers via an out-of-band channel within 15 minutes, keep the session blocked
4. **Allow explicit override** — user can choose to proceed with classical-only security after verification
5. **Log the event** — track which peers triggered downgrades for pattern detection
6. **Verify identity** — prompt users to re-verify safety numbers

### Escalation
- **Single peer downgrade:** follow steps above (user-level response)
- **10+ simultaneous downgrades from different peers:** escalate to network attack hypothesis — notify ops team and consider pausing all session establishment
- **Same peer triggers downgrade for multiple users:** possible identity key compromise on that peer's device — recommend that peer factory-reset and re-register

---

## 7. OTP Pool Exhaustion During Crisis

### Detection
- `SecurityEventType.otpPoolExhausted` fires when pool reaches zero
- `SecurityEventType.otpPoolLow` fires at 25 keys remaining

### Response
1. **Stop accepting new sessions** — do not attempt session establishment with zero OTPs
2. **Attempt upload of fresh batch** — call `generateOneTimePreKeys(100)` and upload to server (up to 3 retries with exponential backoff)
3. **If upload fails** — emit `otpPoolExhausted`, notify user that new conversations are temporarily unavailable
4. **NEVER downgrade to insecure fallback** — no OTPs means no new sessions, not insecure sessions
5. **Existing sessions unaffected** — Double Ratchet sessions that are already established continue to work

### If Server Is Compromised
If OTP upload fails because the server is unreachable or compromised:
1. Queue outgoing messages locally
2. Retry upload on next network change
3. Alert user if condition persists > 1 hour
4. Existing sessions remain operational via Double Ratchet

---

## 8. Session State Corruption

### Detection
- Decryption fails with `SecretBoxAuthenticationError` on a previously working session
- `SecurityEventType.sessionReset` fires after auto-renegotiation
- `SecurityEventType.sessionUnstable` fires after repeated reset attempts

### Response
1. **Automatic retry** — the session auto-renegotiation system will attempt to re-establish
2. **If unstable** — after 3 failed reset attempts within 60 seconds, stop auto-reset
3. **Manual intervention** — user should verify safety numbers and manually re-establish if needed
4. **Data preservation** — undelivered messages should be queued, not dropped
