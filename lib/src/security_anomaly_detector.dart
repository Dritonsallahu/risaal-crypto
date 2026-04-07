import 'dart:async';

import 'security_event_bus.dart';

/// Sliding-window anomaly detector for crypto security events.
///
/// Subscribes to a [SecurityEventBus] and tracks event frequencies using
/// configurable sliding windows. When a threshold is exceeded, emits
/// [SecurityEventType.anomalyDetected] with a `pattern` metadata key
/// describing the threat.
///
/// The crypto package emits raw events; this detector identifies patterns.
/// The host app decides how to respond (UI warning, telemetry, lockout).
///
/// Detected patterns:
///   - **Signature failure spike** (>5 in 10 min) — possible MITM
///   - **Session reset spike** (>5 in 10 min) — possible replay/DoS
///   - **OTP pool depletion** — possible session enumeration
///   - **Downgrade attempt** — possible active attacker
///
/// Example:
/// ```dart
/// final bus = SecurityEventBus();
/// final detector = SecurityAnomalyDetector(eventBus: bus);
///
/// bus.events
///     .where((e) => e.type == SecurityEventType.anomalyDetected)
///     .listen((e) {
///   showSecurityWarning(e.metadata['pattern']);
/// });
/// ```
class SecurityAnomalyDetector {
  final SecurityEventBus _eventBus;
  final Map<SecurityEventType, List<DateTime>> _windows = {};
  StreamSubscription<SecurityEvent>? _subscription;

  /// Signature failures exceeding this count within [signatureFailureWindow]
  /// trigger an anomaly. Default: 5.
  final int signatureFailureThreshold;

  /// Sliding window for signature failure spike detection. Default: 10 min.
  final Duration signatureFailureWindow;

  /// Session resets exceeding this count within [resetSpikeWindow]
  /// trigger an anomaly. Default: 5.
  final int resetSpikeThreshold;

  /// Sliding window for session reset spike detection. Default: 10 min.
  final Duration resetSpikeWindow;

  /// Replay rejections exceeding this count within [replaySpikeWindow]
  /// trigger an anomaly. Default: 5.
  final int replaySpikeThreshold;

  /// Sliding window for replay spike detection. Default: 10 min.
  final Duration replaySpikeWindow;

  SecurityAnomalyDetector({
    required SecurityEventBus eventBus,
    this.signatureFailureThreshold = 5,
    this.signatureFailureWindow = const Duration(minutes: 10),
    this.resetSpikeThreshold = 5,
    this.resetSpikeWindow = const Duration(minutes: 10),
    this.replaySpikeThreshold = 5,
    this.replaySpikeWindow = const Duration(minutes: 10),
  }) : _eventBus = eventBus {
    _subscription = _eventBus.events.listen(_onEvent);
  }

  void _onEvent(SecurityEvent event) {
    switch (event.type) {
      case SecurityEventType.signatureVerificationFailed:
        _trackAndCheck(
          event.type,
          signatureFailureThreshold,
          signatureFailureWindow,
          'signature_failure_spike',
          'Possible MITM attack — multiple signature failures',
        );

      case SecurityEventType.sessionReset:
        _trackAndCheck(
          event.type,
          resetSpikeThreshold,
          resetSpikeWindow,
          'session_reset_spike',
          'Possible replay/DoS attack — excessive session resets',
        );

      case SecurityEventType.replayRejected:
        _trackAndCheck(
          event.type,
          replaySpikeThreshold,
          replaySpikeWindow,
          'replay_spike',
          'Possible replay attack — multiple replay rejections',
        );

      case SecurityEventType.otpPoolExhausted:
        _eventBus.emitType(
          SecurityEventType.anomalyDetected,
          metadata: {
            'pattern': 'otp_pool_exhausted',
            'severity': 'high',
            'description': 'Possible session enumeration — OTP pool depleted',
          },
        );

      case SecurityEventType.antiDowngradeTriggered:
        _eventBus.emitType(
          SecurityEventType.anomalyDetected,
          metadata: {
            'pattern': 'downgrade_attempt',
            'severity': 'critical',
            'description':
                'Possible active attacker — PQXDH downgrade detected',
          },
        );

      default:
        break;
    }
  }

  void _trackAndCheck(
    SecurityEventType type,
    int threshold,
    Duration window,
    String pattern,
    String description,
  ) {
    final now = DateTime.now();
    final cutoff = now.subtract(window);

    final timestamps = _windows.putIfAbsent(type, () => []);
    timestamps.add(now);

    // Evict entries outside the sliding window
    timestamps.removeWhere((t) => t.isBefore(cutoff));

    if (timestamps.length >= threshold) {
      _eventBus.emitType(
        SecurityEventType.anomalyDetected,
        metadata: {
          'pattern': pattern,
          'count': timestamps.length,
          'windowMinutes': window.inMinutes,
          'severity': 'high',
          'description': description,
        },
      );
      // Reset window after firing to avoid repeated alerts
      timestamps.clear();
    }
  }

  /// Stop listening to the event bus.
  void dispose() {
    _subscription?.cancel();
    _subscription = null;
    _windows.clear();
  }
}
