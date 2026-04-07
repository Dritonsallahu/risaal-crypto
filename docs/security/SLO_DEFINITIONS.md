# Service Level Objectives (SLOs) — risaal_crypto

This document defines measurable stability and security SLOs for the cryptographic layer. These SLOs are measured via the `SecurityEventBus` telemetry stream and reported in the operational dashboard.

---

## Stability SLOs

| SLO ID | Metric | Target | Measurement Window | Alert Threshold |
|--------|--------|--------|-------------------|-----------------|
| S-001 | Decrypt failure rate | < 0.1% of all decrypt attempts | Rolling 24 hours | > 0.05% (early warning) |
| S-002 | Session reset rate | < 0.5% of active sessions per day | Rolling 24 hours | > 0.25% (early warning) |
| S-003 | Replay rejection baseline | < 0.01% of inbound messages | Rolling 24 hours | > 0.005% |
| S-004 | OTP exhaustion rate | < 1% of active sessions | Rolling 7 days | > 0.5% |
| S-005 | X3DH handshake success rate | > 99.5% | Rolling 24 hours | < 99.75% |
| S-006 | Sender Key distribution success rate | > 99% | Rolling 24 hours | < 99.5% |

## Security SLOs

| SLO ID | Metric | Target | Measurement Window | Alert Threshold |
|--------|--------|--------|-------------------|-----------------|
| SEC-001 | MAC verification failure rate | < 0.01% of messages | Rolling 24 hours | > 0.005% (immediate) |
| SEC-002 | Signature verification failure rate | < 0.01% of messages | Rolling 24 hours | > 0.005% (immediate) |
| SEC-003 | PQ downgrade block rate | 100% of downgrade attempts blocked | Continuous | Any unblocked downgrade |
| SEC-004 | Sealed Sender replay rejection rate | 100% of replayed envelopes rejected | Continuous | Any accepted replay |
| SEC-005 | Skipped message key cap enforcement | 100% of cap violations rejected | Continuous | Any cap bypass |
| SEC-006 | Key rotation compliance | 100% of Kyber keys rotated within policy window | Rolling 7 days | Any expired key |

---

## Metric Definitions

### S-001: Decrypt Failure Rate

**What:** Percentage of `DoubleRatchet.decrypt()` calls that throw `SecretBoxAuthenticationError` or any decryption exception, excluding legitimate replay rejections.

**How to measure:**
```dart
// From SecurityEventBus
final decryptAttempts = eventBus.events
    .where((e) => e.type == SecurityEventType.messageDecrypted ||
                  e.type == SecurityEventType.decryptionFailed)
    .length;
final failures = eventBus.events
    .where((e) => e.type == SecurityEventType.decryptionFailed)
    .length;
final rate = failures / decryptAttempts;
```

**Exclusions:** Replay rejections (these are correct behavior, not failures).

**Breach response:** See `runbook-session-reset-storm.md` — decrypt failures above 0.1% indicate corrupted sessions or protocol bugs.

### S-002: Session Reset Rate

**What:** Percentage of active sessions that require automatic re-negotiation (X3DH re-initiation) per day.

**How to measure:**
```dart
final resets = eventBus.events
    .where((e) => e.type == SecurityEventType.sessionReset)
    .length;
final activeSessions = storage.getActiveSessionCount();
final rate = resets / activeSessions;
```

**Breach response:** See `runbook-session-reset-storm.md`.

### S-003: Replay Rejection Baseline

**What:** Percentage of inbound messages rejected as replays (duplicate message number in `receivedMessages` set).

**How to measure:**
```dart
final replays = eventBus.events
    .where((e) => e.type == SecurityEventType.replayDetected)
    .length;
final totalInbound = eventBus.events
    .where((e) => e.type == SecurityEventType.messageDecrypted ||
                  e.type == SecurityEventType.replayDetected)
    .length;
final rate = replays / totalInbound;
```

**Breach response:** See `runbook-replay-spike.md` — spikes indicate active attack or broken sender.

### S-004: OTP Exhaustion Rate

**What:** Percentage of sessions where one-time pre-keys (OTPs) drop below the low-watermark threshold (25).

**How to measure:**
```dart
final otpWarnings = eventBus.events
    .where((e) => e.type == SecurityEventType.otpLowWatermark)
    .length;
```

**Breach response:** Trigger automatic OTP upload to server. Alert if exhaustion occurs (no OTPs remaining).

### SEC-001: MAC Verification Failure Rate

**What:** Percentage of messages where AES-256-GCM authentication tag verification fails.

**Impact:** MAC failures indicate message tampering or corrupted ciphertext. Even a single failure is suspicious.

**Breach response:** See `runbook-key-compromise.md` — MAC failures at scale indicate active MITM or compromised session keys.

### SEC-003: PQ Downgrade Block Rate

**What:** Percentage of attempts to downgrade from PQXDH (hybrid quantum-resistant) to classical-only X3DH that are blocked by the anti-downgrade enforcement.

**Target:** 100% — no downgrades should succeed once PQXDH is established.

**Breach response:** Any unblocked downgrade is a critical security bug. See `runbook-key-compromise.md`.

---

## Measurement Infrastructure

### Privacy-Safe Counters

All telemetry counters are **privacy-safe** — they contain no message content, user identifiers, or key material. Only event type and timestamp are recorded.

```dart
/// Counter format emitted by SecurityEventBus
class TelemetryCounter {
  final SecurityEventType type;  // Enum, not a string
  final DateTime timestamp;      // When it happened
  final int count;               // How many since last emit
}
```

**What is NOT collected:**
- Message content (plaintext or ciphertext)
- User identifiers (phone numbers, UUIDs)
- Key material (public keys, private keys, shared secrets)
- IP addresses or device identifiers
- Conversation identifiers

### Dashboard Integration

SLO metrics should be aggregated server-side from client telemetry reports:

1. Clients emit privacy-safe counters via `SecurityEventBus`
2. Counters are batched and sent to the analytics endpoint every 15 minutes
3. Server aggregates into per-metric time series
4. Dashboard displays rolling windows with alert thresholds

See `TELEMETRY_INTEGRATION.md` for the full integration guide.

---

## SLO Review Schedule

| Frequency | Action |
|-----------|--------|
| Daily | Automated SLO dashboard check (alerts if any threshold breached) |
| Weekly | Review trending metrics for emerging patterns |
| Monthly | SLO review meeting — adjust thresholds based on observed baselines |
| Quarterly | Full SLO audit — validate measurement methodology, update targets |

## SLO Breach Escalation

| Severity | Condition | Response Time | Escalation |
|----------|-----------|---------------|------------|
| P0 — Critical | SEC-003 or SEC-004 breached (security invariant violated) | 15 minutes | Immediate incident, all hands |
| P1 — High | SEC-001 or SEC-002 above threshold | 1 hour | On-call engineer + security lead |
| P2 — Medium | S-001 or S-002 above early warning | 4 hours | On-call engineer |
| P3 — Low | S-003, S-004, S-005, S-006 above threshold | 24 hours | Next business day |
