import 'dart:developer' as dev;

/// Runtime-safe crypto diagnostics. Every value maps to a fixed code and tag;
/// no caller-controlled string is part of the emitted event.
enum CryptoDiagnosticEvent { decryptSucceeded }

/// Security-hardened debug logger for the crypto pipeline.
///
/// Every log call is wrapped in `assert(() { ... return true; }())` so the
/// Dart AOT compiler strips them entirely from release builds. No strings,
/// no function bodies, no log infrastructure survives tree-shaking.
///
/// There is intentionally NO in-memory log history — a memory dump of a
/// release binary must yield zero crypto diagnostics.
class CryptoDebugLogger {
  CryptoDebugLogger._();

  /// Optional runtime sink for explicitly enabled BETA diagnostics.
  ///
  /// Only [event] may invoke this callback. Generic debug methods accept
  /// arbitrary caller strings and therefore never cross the runtime boundary.
  /// The host app must still validate both fixed values at its buffer boundary.
  static void Function(String tag, String eventCode)? _sink;

  /// Setter-only bridge: callers may install or clear a sink but cannot read or
  /// wrap a previously installed callback.
  static set sink(void Function(String tag, String eventCode)? value) {
    _sink = value;
  }

  static void log(String tag, String message) {
    _debugEvent('crypto_debug_event');
  }

  static void logKeyInfo(String tag, String label, String base64Key) {
    _debugEvent('key_state_event');
  }

  static void logRatchetState(
    String tag,
    String label,
    Map<String, dynamic> state,
  ) {
    _debugEvent('ratchet_state_event');
  }

  static void logError(String tag, String message, Object error) {
    _debugEvent('crypto_operation_failed');
  }

  static void logSessionInfo(
    String tag,
    String label,
    Map<String, dynamic> info,
  ) {
    _debugEvent('session_state_event');
  }

  static void _debugEvent(String eventCode) {
    assert(() {
      dev.log(eventCode, name: 'RISAAL_CRYPTO');
      return true;
    }());
  }

  static void event(CryptoDiagnosticEvent event) {
    switch (event) {
      case CryptoDiagnosticEvent.decryptSucceeded:
        assert(() {
          dev.log('decrypt_succeeded', name: 'RISAAL_CRYPTO');
          return true;
        }());
        try {
          _sink?.call('DECRYPT_MSG', 'decrypt_succeeded');
        } catch (_) {
          // Diagnostics must never alter crypto control flow or turn a
          // successful state transition into an application-level failure.
          assert(() {
            dev.log('diagnostic_sink_failed', name: 'RISAAL_CRYPTO');
            return true;
          }());
        }
    }
  }
}
