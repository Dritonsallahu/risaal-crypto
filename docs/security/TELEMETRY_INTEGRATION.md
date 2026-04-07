# Security Telemetry Integration Guide — risaal_crypto

This document describes how to integrate `SecurityEventBus` telemetry into a production monitoring stack while preserving user privacy.

---

## Architecture Overview

```
┌─────────────────────┐
│   risaal_crypto      │
│                     │
│  SecurityEventBus   │──▶ Privacy-safe counters
│  (in-process stream)│
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Client App Layer   │
│                     │
│  TelemetryCollector │──▶ Batch + aggregate
│  (15-min intervals) │
└────────┬────────────┘
         │ HTTPS POST
         ▼
┌─────────────────────┐
│   Server             │
│                     │
│  /api/telemetry     │──▶ Aggregate across clients
│  (rate-limited)     │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Dashboard          │
│                     │
│  SLO monitoring     │
│  Alert triggers     │
│  Trend analysis     │
└─────────────────────┘
```

## Client-Side Integration

### Step 1: Subscribe to SecurityEventBus

```dart
import 'package:risaal_crypto/risaal_crypto.dart';

class TelemetryCollector {
  final Map<SecurityEventType, int> _counters = {};
  late final StreamSubscription _sub;

  TelemetryCollector() {
    _sub = SecurityEventBus.instance.events.listen(_onEvent);
  }

  void _onEvent(SecurityEvent event) {
    _counters[event.type] = (_counters[event.type] ?? 0) + 1;
  }

  /// Returns and resets all counters. Call every 15 minutes.
  Map<SecurityEventType, int> flush() {
    final snapshot = Map<SecurityEventType, int>.from(_counters);
    _counters.clear();
    return snapshot;
  }

  void dispose() => _sub.cancel();
}
```

### Step 2: Batch and Report

```dart
class TelemetryReporter {
  final TelemetryCollector _collector;
  Timer? _timer;

  TelemetryReporter(this._collector);

  void start() {
    _timer = Timer.periodic(
      const Duration(minutes: 15),
      (_) => _report(),
    );
  }

  Future<void> _report() async {
    final counters = _collector.flush();
    if (counters.isEmpty) return;

    // Convert to privacy-safe payload
    final payload = {
      'timestamp': DateTime.now().toUtc().toIso8601String(),
      'window_minutes': 15,
      'counters': counters.map(
        (type, count) => MapEntry(type.name, count),
      ),
    };

    // Send to server (no user ID, no device ID)
    await apiClient.post('/api/telemetry', body: payload);
  }

  void stop() => _timer?.cancel();
}
```

### Privacy Guarantee

The telemetry payload contains ONLY:
- Timestamp (when the batch was collected)
- Window duration (15 minutes)
- Counter map: `{ eventTypeName: count }`

**It does NOT contain:** user IDs, device IDs, message content, key material, conversation IDs, IP addresses (handled at transport level, not application level).

## Server-Side Aggregation

### Endpoint Schema

```typescript
// POST /api/telemetry
interface TelemetryPayload {
  timestamp: string;          // ISO 8601
  window_minutes: number;     // Always 15
  counters: {
    [eventType: string]: number;
  };
}
```

### Aggregation Strategy

```typescript
// Aggregate into per-metric time series (5-minute buckets)
interface MetricBucket {
  metric: string;        // e.g., "decryptionFailed"
  bucket: Date;          // 5-minute aligned timestamp
  sum: number;           // Total count across all clients
  clientCount: number;   // How many clients reported
}
```

### SLO Computation

```typescript
// Example: Compute S-001 (Decrypt failure rate)
function computeDecryptFailureRate(window: Date): number {
  const failures = sumMetric('decryptionFailed', window);
  const successes = sumMetric('messageDecrypted', window);
  const total = failures + successes;
  return total === 0 ? 0 : failures / total;
}
```

## SecurityEventBus Event Types

| Event Type | SLO | Description |
|-----------|-----|-------------|
| `messageEncrypted` | — | Successful encryption (baseline counter) |
| `messageDecrypted` | S-001 | Successful decryption |
| `decryptionFailed` | S-001 | Decryption failure (MAC error, corrupted ciphertext) |
| `sessionReset` | S-002 | Session required re-negotiation |
| `replayDetected` | S-003 | Duplicate message number rejected |
| `otpLowWatermark` | S-004 | OTP count below threshold (25) |
| `otpExhausted` | S-004 | No OTPs remaining |
| `macVerificationFailed` | SEC-001 | AES-GCM auth tag failed |
| `signatureVerificationFailed` | SEC-002 | Ed25519 signature failed |
| `pqDowngradeBlocked` | SEC-003 | Classical-only downgrade attempt blocked |
| `sealedSenderReplayRejected` | SEC-004 | Sealed Sender envelope replayed |
| `keyRotationCompleted` | SEC-006 | Kyber key rotation succeeded |
| `keyRotationOverdue` | SEC-006 | Kyber key past rotation deadline |

## Alert Configuration

### Alert Rules

```yaml
# Prometheus-style alert rules (adapt to your monitoring stack)
groups:
  - name: risaal_crypto_slos
    rules:
      - alert: HighDecryptFailureRate
        expr: rate(crypto_decrypt_failures[1h]) / rate(crypto_decrypt_total[1h]) > 0.001
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Decrypt failure rate above 0.1%"
          runbook: "docs/security/runbook-session-reset-storm.md"

      - alert: HighSessionResetRate
        expr: rate(crypto_session_resets[1h]) / crypto_active_sessions > 0.005
        for: 10m
        labels:
          severity: medium
        annotations:
          summary: "Session reset rate above 0.5%"
          runbook: "docs/security/runbook-session-reset-storm.md"

      - alert: ReplaySpike
        expr: rate(crypto_replay_rejections[15m]) > 10
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Unusual replay rejection spike"
          runbook: "docs/security/runbook-replay-spike.md"

      - alert: PQDowngradeAttempt
        expr: increase(crypto_pq_downgrade_blocked[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "PQ downgrade attempt detected and blocked"
          runbook: "docs/security/runbook-key-compromise.md"

      - alert: MACFailureSpike
        expr: increase(crypto_mac_failures[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "MAC verification failure — possible tampering"
          runbook: "docs/security/runbook-key-compromise.md"
```

## Dashboard Panels

### Recommended Grafana Panels

| Panel | Visualization | Query |
|-------|---------------|-------|
| Decrypt Success Rate | Gauge (green > 99.9%) | `1 - rate(failures) / rate(total)` |
| Session Reset Rate | Time series | `rate(session_resets) / active_sessions` |
| Replay Rejections | Time series with anomaly band | `rate(replay_rejections)` |
| OTP Health | Gauge per session bucket | `sessions_with_healthy_otp / total_sessions` |
| Security Events (critical) | Event log table | Filter on MAC/sig/PQ events |
| 30/60/90 Day Trends | Multi-line time series | Rolling averages for all S-* SLOs |

### Canary Deployment Monitoring

During canary rollouts, split dashboards by version:

| Metric | Canary (new version) | Stable (current version) |
|--------|---------------------|--------------------------|
| Decrypt failure rate | Must be <= stable | Baseline |
| Session reset rate | Must be <= stable | Baseline |
| Replay rejections | Must be comparable | Baseline |

**Canary promotion criteria:** After 24-48 hours, if canary metrics are within 10% of stable baseline, promote to full rollout. If any SLO is worse by > 10%, roll back.

See `CANARY_DEPLOYMENT.md` for the full canary strategy.
