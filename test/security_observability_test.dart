import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/security_anomaly_detector.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';

void main() {
  // ── SecurityAnomalyDetector ───────────────────────────────────────────

  group('SecurityAnomalyDetector', () {
    late SecurityEventBus bus;
    late SecurityAnomalyDetector detector;

    setUp(() {
      bus = SecurityEventBus();
    });

    tearDown(() {
      detector.dispose();
      bus.dispose();
    });

    test('emits anomaly on signature failure spike exceeding threshold', () async {
      detector = SecurityAnomalyDetector(
        eventBus: bus,
        signatureFailureThreshold: 3,
        signatureFailureWindow: const Duration(minutes: 10),
      );

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      // Emit 3 signature failures (meets threshold)
      for (var i = 0; i < 3; i++) {
        bus.emitType(SecurityEventType.signatureVerificationFailed);
        await Future<void>.delayed(Duration.zero);
      }
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));
      expect(anomalies.first.metadata['pattern'], 'signature_failure_spike');
      expect(anomalies.first.metadata['severity'], 'high');
    });

    test('does not emit anomaly below threshold', () async {
      detector = SecurityAnomalyDetector(
        eventBus: bus,
        signatureFailureThreshold: 5,
      );

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      for (var i = 0; i < 4; i++) {
        bus.emitType(SecurityEventType.signatureVerificationFailed);
        await Future<void>.delayed(Duration.zero);
      }
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, isEmpty);
    });

    test('emits anomaly on session reset spike', () async {
      detector = SecurityAnomalyDetector(
        eventBus: bus,
        resetSpikeThreshold: 3,
      );

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      for (var i = 0; i < 3; i++) {
        bus.emitType(SecurityEventType.sessionReset);
        await Future<void>.delayed(Duration.zero);
      }
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));
      expect(anomalies.first.metadata['pattern'], 'session_reset_spike');
    });

    test('emits anomaly on replay rejection spike', () async {
      detector = SecurityAnomalyDetector(
        eventBus: bus,
        replaySpikeThreshold: 3,
      );

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      for (var i = 0; i < 3; i++) {
        bus.emitType(SecurityEventType.replayRejected);
        await Future<void>.delayed(Duration.zero);
      }
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));
      expect(anomalies.first.metadata['pattern'], 'replay_spike');
    });

    test('emits anomaly immediately on OTP pool exhaustion', () async {
      detector = SecurityAnomalyDetector(eventBus: bus);

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      bus.emitType(SecurityEventType.otpPoolExhausted);
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));
      expect(anomalies.first.metadata['pattern'], 'otp_pool_exhausted');
      expect(anomalies.first.metadata['severity'], 'high');
    });

    test('emits anomaly immediately on downgrade attempt', () async {
      detector = SecurityAnomalyDetector(eventBus: bus);

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      bus.emitType(SecurityEventType.antiDowngradeTriggered);
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));
      expect(anomalies.first.metadata['pattern'], 'downgrade_attempt');
      expect(anomalies.first.metadata['severity'], 'critical');
    });

    test('resets window after anomaly fires to avoid repeated alerts', () async {
      detector = SecurityAnomalyDetector(
        eventBus: bus,
        signatureFailureThreshold: 2,
      );

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      // First spike: 2 events triggers anomaly
      bus.emitType(SecurityEventType.signatureVerificationFailed);
      await Future<void>.delayed(Duration.zero);
      bus.emitType(SecurityEventType.signatureVerificationFailed);
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));

      // One more event should NOT trigger — window was cleared
      bus.emitType(SecurityEventType.signatureVerificationFailed);
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, hasLength(1));
    });

    test('dispose stops listening', () async {
      detector = SecurityAnomalyDetector(
        eventBus: bus,
        signatureFailureThreshold: 1,
      );

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      detector.dispose();

      bus.emitType(SecurityEventType.signatureVerificationFailed);
      await Future<void>.delayed(Duration.zero);

      // Re-create so tearDown doesn't double-dispose
      detector = SecurityAnomalyDetector(eventBus: bus);

      expect(anomalies, isEmpty);
    });

    test('ignores non-monitored event types', () async {
      detector = SecurityAnomalyDetector(eventBus: bus);

      final anomalies = <SecurityEvent>[];
      bus.events
          .where((e) => e.type == SecurityEventType.anomalyDetected)
          .listen(anomalies.add);

      bus.emitType(SecurityEventType.keyRotationCompleted);
      bus.emitType(SecurityEventType.preKeyReplenishmentNeeded);
      await Future<void>.delayed(Duration.zero);

      expect(anomalies, isEmpty);
    });
  });

  // ── Event type completeness ───────────────────────────────────────────

  group('SecurityEventType', () {
    test('has all required event types from spec', () {
      final requiredTypes = [
        SecurityEventType.sessionReset,
        SecurityEventType.signatureVerificationFailed,
        SecurityEventType.replayRejected,
        SecurityEventType.antiDowngradeTriggered,
        SecurityEventType.otpPoolLow,
        SecurityEventType.keyRotationCompleted,
        SecurityEventType.keyExpired,
        SecurityEventType.resetRateLimitHit,
        SecurityEventType.anomalyDetected,
      ];

      for (final type in requiredTypes) {
        expect(SecurityEventType.values.contains(type), isTrue,
            reason: '$type must exist');
      }
    });

    test('anomalyDetected is a valid event type', () {
      expect(SecurityEventType.anomalyDetected, isNotNull);
    });
  });

  // ── SecurityEvent never contains sensitive data ──────────────────────

  group('SecurityEvent metadata safety', () {
    test('metadata is an empty map by default', () {
      final event = SecurityEvent(type: SecurityEventType.sessionReset);
      expect(event.metadata, isEmpty);
    });

    test('sessionId defaults to empty string', () {
      final event = SecurityEvent(type: SecurityEventType.sessionReset);
      expect(event.sessionId, '');
    });

    test('timestamp defaults to now', () {
      final before = DateTime.now();
      final event = SecurityEvent(type: SecurityEventType.sessionReset);
      final after = DateTime.now();
      expect(event.timestamp.isAfter(before) || event.timestamp == before,
          isTrue);
      expect(
          event.timestamp.isBefore(after) || event.timestamp == after, isTrue);
    });
  });

  // ── SecurityEventBus ─────────────────────────────────────────────────

  group('SecurityEventBus', () {
    test('emitType convenience method creates event correctly', () async {
      final bus = SecurityEventBus();
      SecurityEvent? received;
      bus.events.listen((e) => received = e);

      bus.emitType(
        SecurityEventType.replayRejected,
        sessionId: 'alice:device1',
        metadata: {'source': 'double_ratchet'},
      );
      await Future<void>.delayed(Duration.zero);

      expect(received, isNotNull);
      expect(received!.type, SecurityEventType.replayRejected);
      expect(received!.sessionId, 'alice:device1');
      expect(received!.metadata['source'], 'double_ratchet');

      bus.dispose();
    });

    test('does not throw when emitting after dispose', () {
      final bus = SecurityEventBus();
      bus.dispose();
      // Should silently drop — no error
      bus.emitType(SecurityEventType.sessionReset);
    });

    test('broadcast stream supports multiple listeners', () async {
      final bus = SecurityEventBus();
      final a = <SecurityEventType>[];
      final b = <SecurityEventType>[];

      bus.events.listen((e) => a.add(e.type));
      bus.events.listen((e) => b.add(e.type));

      bus.emitType(SecurityEventType.keyRotationCompleted);
      await Future<void>.delayed(Duration.zero);

      expect(a, [SecurityEventType.keyRotationCompleted]);
      expect(b, [SecurityEventType.keyRotationCompleted]);

      bus.dispose();
    });
  });
}
