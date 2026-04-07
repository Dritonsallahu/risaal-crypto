import 'dart:async';

/// Types of security-relevant events emitted by the crypto layer.
///
/// The host app subscribes to these via [SecurityEventBus.events] to
/// drive UI warnings, anonymous telemetry, or local logging. The crypto
/// package never persists or transmits events — it only emits them.
enum SecurityEventType {
  /// A broken session was auto-reset (AES-GCM MAC failure).
  sessionReset,

  /// Auto-reset was blocked because the rate limit was exceeded.
  resetRateLimitHit,

  /// Ed25519 or HMAC signature verification failed.
  signatureVerificationFailed,

  /// A replayed message was rejected (duplicate message number).
  replayRejected,

  /// A peer's PQXDH capability downgraded (previously supported, now absent).
  antiDowngradeTriggered,

  /// One-time pre-key pool dropped below the low-watermark threshold.
  otpPoolLow,

  /// One-time pre-key pool is completely empty.
  otpPoolExhausted,

  /// Signed pre-key (or Kyber key) was rotated successfully.
  keyRotationCompleted,

  /// A key exceeded its maximum lifetime and was force-rotated.
  keyExpired,

  /// The skipped-message-key cap was reached (possible DoS).
  skippedKeyCapReached,

  /// A session was flagged as unstable (too many resets).
  sessionUnstable,

  /// Pre-key replenishment is needed (OTP consumed during session setup).
  preKeyReplenishmentNeeded,
}

/// A single security event emitted by the crypto layer.
///
/// Events carry only non-sensitive metadata: event type, a hashed or
/// opaque conversation identifier, a timestamp, and optional context.
/// Events **never** contain key material, plaintext, phone numbers,
/// or user IDs in cleartext.
///
/// Example:
/// ```dart
/// bus.events.listen((event) {
///   if (event.type == SecurityEventType.otpPoolLow) {
///     uploadMorePreKeys();
///   }
/// });
/// ```
class SecurityEvent {
  /// The category of this security event.
  final SecurityEventType type;

  /// Opaque session/conversation identifier (e.g. "userId:deviceId").
  ///
  /// Intentionally not a raw user ID — the host app can hash or map this
  /// to a conversation before logging. May be empty for global events
  /// (e.g. key rotation that isn't tied to one session).
  final String sessionId;

  /// When the event occurred (monotonic-safe: uses [DateTime.now]).
  final DateTime timestamp;

  /// Optional structured context. Keys and values must not contain
  /// key material or plaintext.
  ///
  /// Common keys:
  ///   - `"resetCount"`: number of resets in the current window
  ///   - `"remaining"`: remaining OTP count
  ///   - `"keyType"`: which key was rotated (e.g. "signedPreKey", "kyber")
  ///   - `"reason"`: human-readable reason string
  final Map<String, dynamic> metadata;

  SecurityEvent({
    required this.type,
    this.sessionId = '',
    DateTime? timestamp,
    Map<String, dynamic>? metadata,
  })  : timestamp = timestamp ?? DateTime.now(),
        metadata = metadata ?? const {};

  @override
  String toString() =>
      'SecurityEvent($type, session=$sessionId, meta=$metadata)';
}

/// Stream-based bus for security events from the crypto layer.
///
/// Usage:
/// ```dart
/// final bus = SecurityEventBus();
/// final manager = SignalProtocolManager(
///   secureStorage: storage,
///   securityEventBus: bus,
/// );
///
/// bus.events.listen((event) {
///   switch (event.type) {
///     case SecurityEventType.otpPoolLow:
///       uploadMorePreKeys();
///     case SecurityEventType.sessionReset:
///       showSessionResetWarning(event.sessionId);
///     default:
///       logSecurityEvent(event);
///   }
/// });
/// ```
///
/// The bus uses a broadcast [StreamController] so multiple listeners
/// can subscribe independently. Events are fire-and-forget — if no
/// listener is attached, emitted events are silently dropped.
class SecurityEventBus {
  final StreamController<SecurityEvent> _controller =
      StreamController<SecurityEvent>.broadcast();

  /// The event stream. Subscribe to receive security events.
  Stream<SecurityEvent> get events => _controller.stream;

  /// Emit a security event to all listeners.
  void emit(SecurityEvent event) {
    if (!_controller.isClosed) {
      _controller.add(event);
    }
  }

  /// Convenience: emit an event by type with optional metadata.
  void emitType(
    SecurityEventType type, {
    String sessionId = '',
    Map<String, dynamic>? metadata,
  }) {
    emit(SecurityEvent(
      type: type,
      sessionId: sessionId,
      metadata: metadata,
    ));
  }

  /// Close the bus. After this, no more events can be emitted.
  void dispose() {
    _controller.close();
  }
}
