import 'dart:convert';
import 'dart:developer' as dev;

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

  static void log(String tag, String message) {
    assert(() {
      final timestamp = DateTime.now().toIso8601String();
      dev.log('[$timestamp] [$tag] $message', name: 'RISAAL_CRYPTO');
      return true;
    }());
  }

  static void logKeyInfo(String tag, String label, String base64Key) {
    assert(() {
      final bytes = base64Decode(base64Key);
      final preview = base64Key.substring(
        0,
        base64Key.length > 8 ? 8 : base64Key.length,
      );
      final timestamp = DateTime.now().toIso8601String();
      dev.log(
        '[$timestamp] [$tag] $label: ${bytes.length} bytes, first4=$preview...',
        name: 'RISAAL_CRYPTO',
      );
      return true;
    }());
  }

  static void logRatchetState(
    String tag,
    String label,
    Map<String, dynamic> state,
  ) {
    assert(() {
      final sendN = state['sendMessageNumber'] ?? '?';
      final recvN = state['receiveMessageNumber'] ?? '?';
      final prevChain = state['previousChainLength'] ?? '?';
      final skipped = (state['skippedKeys'] as Map?)?.length ?? 0;
      final hasRecvChain =
          (state['receivingChainKey'] as String?)?.isNotEmpty ?? false;
      final hasSendChain =
          (state['sendingChainKey'] as String?)?.isNotEmpty ?? false;
      final dhRecvKey = state['dhReceivingKey'] as String? ?? '';

      final dhPreview = dhRecvKey.isEmpty
          ? '(empty)'
          : '${dhRecvKey.substring(0, dhRecvKey.length > 8 ? 8 : dhRecvKey.length)}...';

      final timestamp = DateTime.now().toIso8601String();
      dev.log(
        '[$timestamp] [$tag] $label: sendN=$sendN recvN=$recvN '
        'prevChain=$prevChain skipped=$skipped '
        'hasSendChain=$hasSendChain hasRecvChain=$hasRecvChain '
        'dhRecvKey=$dhPreview',
        name: 'RISAAL_CRYPTO',
      );
      return true;
    }());
  }

  static void logError(String tag, String message, Object error) {
    assert(() {
      final timestamp = DateTime.now().toIso8601String();
      dev.log(
        '[$timestamp] [$tag] ERROR: $message — $error',
        name: 'RISAAL_CRYPTO',
      );
      return true;
    }());
  }

  static void logSessionInfo(
    String tag,
    String label,
    Map<String, dynamic> info,
  ) {
    assert(() {
      final timestamp = DateTime.now().toIso8601String();
      final buffer = StringBuffer('[$timestamp] [$tag] $label:');
      for (final entry in info.entries) {
        buffer.write(' ${entry.key}=${entry.value}');
      }
      dev.log(buffer.toString(), name: 'RISAAL_CRYPTO');
      return true;
    }());
  }
}
