# Operational Runbook — risaal_crypto

Production telemetry, release controls, and incident drill procedures.

---

## 1. Production Telemetry & Alerts

### SecurityEventBus Integration

The `SecurityEventBus` emits typed events for all security-critical operations. The host app must subscribe and route these to its alerting pipeline.

#### Required Integration (App Layer)

```dart
final eventBus = SecurityEventBus();
final manager = SignalProtocolManager(
  secureStorage: storage,
  securityEventBus: eventBus,
);

// Subscribe to all security events
eventBus.events.listen((event) {
  // Route to your telemetry backend
  _handleSecurityEvent(event);
});

void _handleSecurityEvent(SecurityEvent event) {
  switch (event.type) {
    // ── P0 Alerts (immediate notification to user + ops) ──
    case SecurityEventType.signatureVerificationFailed:
    case SecurityEventType.antiDowngradeTriggered:
    case SecurityEventType.replayRejected:
      _alertCritical(event);
      break;

    // ── P1 Alerts (log + periodic review) ──
    case SecurityEventType.sessionReset:
    case SecurityEventType.sessionUnstable:
    case SecurityEventType.resetRateLimitHit:
    case SecurityEventType.skippedKeyCapReached:
      _alertWarning(event);
      break;

    // ── P2 Metrics (aggregate for dashboards) ──
    case SecurityEventType.keyRotationCompleted:
    case SecurityEventType.keyExpired:
    case SecurityEventType.otpPoolLow:
    case SecurityEventType.otpPoolExhausted:
    case SecurityEventType.preKeyReplenishmentNeeded:
      _recordMetric(event);
      break;
  }
}
```

#### Alert Routing Rules

| Event Type | Severity | Action | Escalation |
|-----------|----------|--------|------------|
| `signatureVerificationFailed` | P0 | Block message, warn user | Immediate |
| `antiDowngradeTriggered` | P0 | Warn user, require manual override | Immediate |
| `replayRejected` | P0 | Drop message, log attempt | 3+ in 60s → notify user |
| `sessionReset` | P1 | Log, auto-recover | 3+ in 60s → mark unstable |
| `sessionUnstable` | P1 | Pause auto-reset, prompt user | Manual review required |
| `resetRateLimitHit` | P1 | Log rate limit activation | Review if persistent |
| `skippedKeyCapReached` | P1 | Log, consider session reset | Manual review |
| `keyRotationCompleted` | P2 | Metric: key_rotations_total++ | Weekly dashboard review |
| `keyExpired` | P2 | Trigger rotation | Should not happen in normal operation |
| `otpPoolLow` | P2 | Trigger replenishment upload | Monitor refill success |
| `otpPoolExhausted` | P2 | Critical: no OTPs for new sessions | Immediate replenishment |
| `preKeyReplenishmentNeeded` | P2 | Upload new OTPs to server | Verify upload succeeded |

#### Telemetry Guidelines

**Never log:**
- Message content, plaintext, or ciphertext
- Private keys, chain keys, or root keys
- User identifiers that could deanonymize sessions
- Safety numbers or identity key fingerprints

**Safe to log:**
- Event type and timestamp
- Session ID (opaque hash, not user-identifiable)
- Aggregate counts (events per hour, per type)
- Error categories (not stack traces with key material)

#### Health Dashboard Metrics

```
# Key rotation freshness
risaal_signed_prekey_age_hours     gauge    "Age of current signed pre-key"
risaal_kyber_key_age_hours         gauge    "Age of current Kyber key"

# OTP pool health
risaal_otp_pool_size               gauge    "Remaining one-time pre-keys"
risaal_otp_replenishments_total    counter  "OTP refill uploads"

# Session health
risaal_active_sessions             gauge    "Active Double Ratchet sessions"
risaal_session_resets_total        counter  "Auto-reset events"
risaal_session_unstable_total      counter  "Sessions marked unstable"

# Security events
risaal_replay_rejections_total     counter  "Replay attempts blocked"
risaal_downgrade_detections_total  counter  "Anti-downgrade triggers"
risaal_signature_failures_total    counter  "Signature verification failures"
```

---

## 2. Release Signing & Controls

### Version Release Checklist

Every release of `risaal_crypto` must follow this process:

#### Pre-Release Gates

- [ ] All tests pass: `flutter test` (357+ tests, 0 failures)
- [ ] Static analysis clean: `flutter analyze --fatal-warnings` (0 warnings)
- [ ] Format check: `dart format --set-exit-if-changed .` (0 changes)
- [ ] Coverage meets threshold: ≥80% line coverage
- [ ] SAST scan passes: no hardcoded secrets, no unsafe crypto patterns
- [ ] Dependency audit: `flutter pub outdated` reviewed, no known vulnerabilities
- [ ] CHANGELOG.md updated with all changes (prefix security changes with `[SECURITY]`)
- [ ] Version bumped in `pubspec.yaml` following semver

#### Semver Policy for Crypto Libraries

| Change Type | Version Bump | Examples |
|-------------|-------------|---------|
| Security fix (no API change) | PATCH (0.1.x) | Fix replay window, fix memory leak |
| New security feature | MINOR (0.x.0) | Add anti-downgrade, add event bus |
| Breaking API change | MAJOR (x.0.0) | Change constructor signature, remove method |
| Protocol parameter change | MINOR + `[SECURITY]` | Change skipped key cap, OTP threshold |

#### Release Process

```bash
# 1. Ensure clean working tree
git status  # must be clean

# 2. Run full verification
flutter test
flutter analyze --fatal-warnings --no-fatal-infos
dart format --set-exit-if-changed .

# 3. Bump version
# Edit pubspec.yaml version field

# 4. Update CHANGELOG.md
# Add entry under new version header

# 5. Commit and tag
git add pubspec.yaml CHANGELOG.md
git commit -m "release: v0.1.1"
git tag -s v0.1.1 -m "v0.1.1: <summary>"

# 6. Push with tag
git push origin main --tags
```

#### Git Tag Signing

All release tags MUST be signed:

```bash
# Verify tag is signed
git tag -v v0.1.1

# If signing key not configured:
git config user.signingkey <GPG-KEY-ID>
git config tag.gpgSign true
```

#### Post-Release Verification

- [ ] Tag exists on GitHub: `git ls-remote --tags origin | grep v0.1.1`
- [ ] CI passes on the tagged commit
- [ ] Downstream app (`risaal-app`) can resolve the new version
- [ ] Smoke test: app builds and basic encrypt/decrypt works

---

## 3. Incident Drill Procedures

### Purpose

Quarterly drills ensure the team can execute incident response procedures under pressure. Each drill simulates a specific attack scenario and measures response time and correctness.

### Drill Schedule

| Quarter | Drill | Scenario |
|---------|-------|----------|
| Q1 | Key Compromise Drill | Simulate compromised identity key |
| Q2 | Protocol Bug Drill | Simulate discovered decryption flaw |
| Q3 | Downgrade Attack Drill | Simulate PQXDH downgrade attempt |
| Q4 | Full Incident Drill | Combined scenario with disclosure |

---

### Drill 1: Key Compromise Response

**Scenario:** Bob's identity private key has been exfiltrated via a device backup.

**Steps to execute:**

1. **Detection** (target: < 5 minutes)
   ```dart
   // Simulate: SecurityEventBus emits signatureVerificationFailed
   eventBus.emitType(SecurityEventType.signatureVerificationFailed,
     sessionId: 'bob-session-001',
     metadata: {'reason': 'drill'});
   ```

2. **Quarantine** (target: < 2 minutes)
   - Stop sending messages to Bob's session
   - Queue outgoing messages

3. **Key rotation** (target: < 5 minutes)
   ```dart
   await manager.rotateKeysIfNeeded(
     signedPreKeyMaxAge: Duration.zero,
     kyberKeyMaxAge: Duration.zero,
   );
   await manager.generateOneTimePreKeys(50);
   // Upload new bundle
   ```

4. **Session re-establishment** (target: < 10 minutes)
   - Fetch Bob's new pre-key bundle
   - Create fresh session
   - Verify safety numbers changed

5. **Post-drill review**
   - Was response within target times?
   - Were all event bus emissions correct?
   - Was the user notified appropriately?

**Pass criteria:** All steps completed within 22 minutes total.

---

### Drill 2: Protocol Bug Response

**Scenario:** A researcher reports that messages with `messageNumber > 1000` in a single chain can be decrypted without the correct chain key.

**Steps to execute:**

1. **Reproduce** (target: < 30 minutes)
   ```dart
   // Write a failing test that demonstrates the bug
   test('regression: high message numbers decrypt correctly', () async {
     // ... reproduce the reported issue
   });
   ```

2. **Classify severity** — determine P0-P3 based on exploitability

3. **Fix and verify** (target: < 2 hours for P0)
   - Develop fix on branch
   - Run full test suite including adversarial tests
   - Verify the regression test now passes

4. **Release** — follow release process above

5. **Communicate** — draft advisory using template in INCIDENT_RESPONSE.md

**Pass criteria:** Regression test written and fix verified within target time.

---

### Drill 3: Downgrade Attack Response

**Scenario:** Alice notices her conversation with Bob lost the "post-quantum" indicator. Bob's new bundle only has classical X25519, no Kyber.

**Steps to execute:**

1. **Detection** (target: automatic via event bus)
   ```dart
   // SecurityEventBus should emit antiDowngradeTriggered
   // Verify the event fires when Bob's bundle lacks Kyber
   ```

2. **User notification** (target: < 1 minute)
   - Verify the app shows a non-dismissible warning
   - Verify the session is NOT auto-established (requires manual override)

3. **Investigation** (target: < 15 minutes)
   - Check if Bob genuinely reinstalled (new device)
   - Verify Bob's identity key changed (safety number check)
   - Confirm via out-of-band channel

4. **Resolution**
   - If legitimate: user accepts downgrade, session proceeds
   - If suspicious: session blocked, peer reported

**Pass criteria:** Downgrade detected automatically, user warned before any message sent.

---

### Drill 4: Full Incident with Coordinated Disclosure

**Scenario:** An external researcher emails security@risaal.org reporting that the sealed sender replay window allows message injection.

**Steps to execute:**

1. **Acknowledge** within 24 hours (simulate email response)
2. **Validate** — reproduce within 72 hours
3. **Classify** severity (P0 if message content affected)
4. **Fix** — develop, test, release within severity timeline
5. **Draft advisory** using INCIDENT_RESPONSE.md template
6. **Coordinate** with reporter on disclosure timeline
7. **Publish** advisory after patch deployment

**Pass criteria:** Full process completed within severity deadline. Advisory is clear and complete.

---

### Drill Tracking

After each drill, record:

| Field | Value |
|-------|-------|
| Date | YYYY-MM-DD |
| Drill type | Key Compromise / Protocol Bug / Downgrade / Full |
| Participants | Names |
| Detection time | mm:ss |
| Response time | mm:ss |
| Total time | mm:ss |
| Pass/Fail | Pass or Fail with reason |
| Action items | What to improve |

Store drill records in `docs/drill-records/YYYY-QN-drill.md`.
