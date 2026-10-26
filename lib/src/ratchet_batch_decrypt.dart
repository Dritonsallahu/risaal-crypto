import 'double_ratchet.dart';
import 'message_padding.dart';

/// Off-main-thread batch decryption of a backlog of NORMAL (type-2) Double
/// Ratchet messages from a SINGLE session.
///
/// Why this exists (audit 2026-06 performance): on chat open the app decrypts a
/// whole backlog of messages on the MAIN isolate, and each `ratchet.decrypt()`
/// is a chain of AES-GCM / HKDF / (occasionally) X25519 operations that can
/// stall the UI ~50–200 ms per message. `DoubleRatchet.decrypt()` is a PURE
/// function of (state, ciphertext) and its state is fully JSON-serialisable, so
/// the whole backlog can be handed to a background isolate via `compute()` and
/// decrypted there while the UI thread keeps painting.
///
/// CORRECTNESS — `DoubleRatchet.decrypt()` advances a candidate copy and commits
/// only after authentication. This batch additionally snapshots after every
/// success, so a later failure returns the last authenticated state and index.
///
/// This function is a top-level, side-effect-free function so it can be passed
/// directly to Flutter's `compute()`. It touches NO storage and NO platform
/// channels (the `cryptography` primitives are pure Dart).

/// Input for [ratchetBatchDecrypt]. [stateJson] is `DoubleRatchet.toJson()` of
/// the loaded session; [messages] are the inner `EncryptedMessage` JSON maps
/// (i.e. `envelope['message']`) in delivery order.
class RatchetBatchRequest {
  const RatchetBatchRequest({
    required this.stateJson,
    required this.messages,
    this.localIdentityKey,
  });

  final Map<String, dynamic> stateJson;
  final List<Map<String, dynamic>> messages;

  /// The local base64 identity public key a v3 message binds (R4-L1). Without
  /// it a v3 message in the batch fails and is left to the inline path.
  final String? localIdentityKey;
}

/// Result of [ratchetBatchDecrypt].
///
/// [plaintexts] holds the successfully-decrypted strings in order (length ==
/// number of messages decrypted before any failure). [finalStateJson] is the
/// ratchet state AFTER the last successful decrypt — safe to persist. If
/// [failedIndex] is >= 0, decryption stopped at that message and the caller must
/// resume from it inline; [failedError] carries the thrown error's string.
class RatchetBatchResult {
  const RatchetBatchResult({
    required this.plaintexts,
    required this.finalStateJson,
    required this.failedIndex,
    this.failedError,
  });

  final List<String> plaintexts;
  final Map<String, dynamic> finalStateJson;
  final int failedIndex;
  final String? failedError;

  bool get hadFailure => failedIndex >= 0;
}

/// Decrypt a backlog of normal messages from one session. See file docs.
Future<RatchetBatchResult> ratchetBatchDecrypt(
  RatchetBatchRequest request,
) async {
  // Preflight the entire batch before parsing the session or returning any
  // plaintext. A legacy/future entry at index N must not partially decrypt and
  // expose entries 0..N-1 under the epoch-2 public API.
  final messages = request.messages
      .map(EncryptedMessage.fromJson)
      .toList(growable: false);
  for (final message in messages) {
    message.requireCurrentWireVersion();
  }

  final ratchet = DoubleRatchet.fromJson(request.stateJson);
  final plaintexts = <String>[];

  // Last state we are sure is good. Starts at the input (before any decrypt) so
  // that a failure on the very first message returns the untouched session.
  Map<String, dynamic> lastGoodState = request.stateJson;

  for (var i = 0; i < messages.length; i++) {
    try {
      final plainBytes = await ratchet.decrypt(
        messages[i],
        localIdentityKey: request.localIdentityKey,
      );
      plaintexts.add(MessagePadding.unpadString(plainBytes));
      // Commit ONLY after a fully successful decrypt — decrypt() mutates state
      // before it can throw, so this snapshot is the only safe rollback point.
      lastGoodState = ratchet.toJson();
    } catch (e) {
      return RatchetBatchResult(
        plaintexts: plaintexts,
        finalStateJson: lastGoodState,
        failedIndex: i,
        failedError: e.toString(),
      );
    }
  }

  return RatchetBatchResult(
    plaintexts: plaintexts,
    finalStateJson: lastGoodState,
    failedIndex: -1,
  );
}
