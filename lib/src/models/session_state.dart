import 'dart:convert';
import 'dart:typed_data';

import 'signal_keys.dart';
import '../secure_memory.dart';

/// Mutable state for the Double Ratchet between two parties.
///
/// The Double Ratchet algorithm maintains two types of ratchets:
///   1. **Symmetric ratchet**: Chain keys advance with each message (forward secrecy)
///   2. **DH ratchet**: Ephemeral DH keys rotate when the other party replies (post-compromise security)
///
/// This state is updated in-place during encrypt/decrypt operations and must be
/// persisted after every change. If the state is lost or corrupted, the session
/// cannot decrypt future messages.
///
/// Field lifecycle:
///   - **Root key**: Derived from X3DH shared secret, ratcheted with each DH step
///   - **Chain keys**: Derived from root key, ratcheted with each message
///   - **DH keys**: Generated fresh for each sending turn, received from peer
///   - **Skipped keys**: Stored when messages arrive out-of-order (up to 2000)
///
/// All key fields are stored as [Uint8List] (mutable bytes) so that
/// [SecureMemory.zeroBytes] can overwrite them in-place during [wipe].
/// Base64 encoding/decoding happens only at the serialization boundary
/// ([toJson] / [fromJson]).
///
/// The state is JSON-serializable for storage via [CryptoStorage].
///
/// See also:
///   - [DoubleRatchet] which owns and mutates this state
///   - [SignalSession] which wraps this for persistence
class RatchetState {
  /// Raw bytes of the JSON-encoded [KeyPair] for the current sending DH ratchet key.
  ///
  /// This is the local party's ephemeral X25519 key pair. The public portion
  /// is sent in the header of every outgoing message so the recipient can
  /// perform a DH ratchet step.
  ///
  /// Stored as UTF-8 bytes of the JSON string (e.g. `{"publicKey":"...","privateKey":"..."}`).
  Uint8List dhSendingKeyPair;

  /// Raw 32-byte X25519 public key of the remote party's current DH ratchet key.
  ///
  /// Updated when receiving a message with a new DH public key in the header.
  /// Used to derive the receiving chain key via DH(localPrivate, remotePub).
  /// Empty [Uint8List(0)] when uninitialized.
  Uint8List dhReceivingKey;

  /// Raw 32-byte root key.
  ///
  /// The root key is ratcheted forward with each DH step using HKDF:
  /// `(newRootKey, chainKey) = HKDF(oldRootKey, DH_output)`.
  /// Never used directly for encryption -- only for deriving chain keys.
  Uint8List rootKey;

  /// Raw 32-byte sending chain key.
  ///
  /// Ratcheted forward with each outgoing message using HMAC:
  /// `(nextChainKey, messageKey) = HMAC(chainKey, constants)`.
  /// The message key is used once to encrypt the current message, then discarded.
  /// Empty [Uint8List(0)] when uninitialized.
  Uint8List sendingChainKey;

  /// Raw 32-byte receiving chain key.
  ///
  /// Ratcheted forward with each incoming message. Derived from the root key
  /// after a DH ratchet step. Used to decrypt messages from the remote party.
  /// Empty [Uint8List(0)] when uninitialized.
  Uint8List receivingChainKey;

  /// Number of messages sent in the current sending chain.
  ///
  /// Incremented after each encrypt operation. Reset to 0 when a DH ratchet
  /// step occurs (i.e., when we receive a reply with a new DH key).
  int sendMessageNumber;

  /// Number of messages received in the current receiving chain.
  ///
  /// Incremented after each decrypt operation. Reset to 0 when a DH ratchet
  /// step occurs (i.e., when we receive a message with a new DH key).
  int receiveMessageNumber;

  /// Length of the previous sending chain.
  ///
  /// Sent in the header of the first message after a DH ratchet step. Tells
  /// the recipient how many messages were sent in the old chain so they can
  /// skip ahead and store the correct message keys.
  int previousChainLength;

  /// Stored message keys for out-of-order decryption.
  ///
  /// Format: `"<dhPublicKey>:<messageNumber>" -> <raw message key bytes>`.
  /// When a message arrives with a higher number than expected, the chain key
  /// is advanced and intermediate message keys are stored here. If the missing
  /// messages arrive later, they're decrypted using the stored keys.
  ///
  /// Limited to 100 entries to prevent DoS attacks that force unbounded storage.
  Map<String, Uint8List> skippedKeys;

  /// Set of received message identifiers ("dhPublicKey:messageNumber")
  /// for explicit anti-replay protection. Persisted across app restarts.
  ///
  /// When a message is successfully decrypted, its identifier is added
  /// here. If the same identifier arrives again, decryption is rejected
  /// as a replay. Capped at [DoubleRatchet.maxReceivedTracked] entries,
  /// pruning oldest when exceeded.
  Set<String> receivedMessages;

  RatchetState({
    required this.dhSendingKeyPair,
    required this.dhReceivingKey,
    required this.rootKey,
    required this.sendingChainKey,
    required this.receivingChainKey,
    this.sendMessageNumber = 0,
    this.receiveMessageNumber = 0,
    this.previousChainLength = 0,
    Map<String, Uint8List>? skippedKeys,
    Set<String>? receivedMessages,
  })  : skippedKeys = skippedKeys ?? {},
        receivedMessages = receivedMessages ?? {};

  /// Serialize to JSON, encoding all [Uint8List] fields to base64 strings.
  ///
  /// The output is backward-compatible with the v1 format (all values are
  /// base64 strings). A `v` field is added so [fromJson] can distinguish
  /// formats in the future.
  Map<String, dynamic> toJson() => {
        'v': 2,
        'dhSendingKeyPair': base64Encode(dhSendingKeyPair),
        'dhReceivingKey': base64Encode(dhReceivingKey),
        'rootKey': base64Encode(rootKey),
        'sendingChainKey': base64Encode(sendingChainKey),
        'receivingChainKey': base64Encode(receivingChainKey),
        'sendMessageNumber': sendMessageNumber,
        'receiveMessageNumber': receiveMessageNumber,
        'previousChainLength': previousChainLength,
        'skippedKeys': skippedKeys.map((k, v) => MapEntry(k, base64Encode(v))),
        'receivedMessages': receivedMessages.toList(),
      };

  /// Deserialize from JSON, decoding base64 strings to [Uint8List].
  ///
  /// Handles both v1 (legacy String fields) and v2 (base64 in JSON) since
  /// both store base64 strings in the JSON.
  factory RatchetState.fromJson(Map<String, dynamic> json) => RatchetState(
        dhSendingKeyPair: _decodeField(json['dhSendingKeyPair']),
        dhReceivingKey: _decodeField(json['dhReceivingKey']),
        rootKey: _decodeField(json['rootKey']),
        sendingChainKey: _decodeField(json['sendingChainKey']),
        receivingChainKey: _decodeField(json['receivingChainKey']),
        sendMessageNumber: json['sendMessageNumber'] as int,
        receiveMessageNumber: json['receiveMessageNumber'] as int,
        previousChainLength: json['previousChainLength'] as int,
        skippedKeys: (json['skippedKeys'] as Map<String, dynamic>?)
                ?.map((k, v) => MapEntry(k, _decodeField(v))) ??
            {},
        receivedMessages: (json['receivedMessages'] as List<dynamic>?)
                ?.cast<String>()
                .toSet() ??
            {},
      );

  /// Decode a single field from its stored representation (base64 string)
  /// to raw bytes.
  static Uint8List _decodeField(dynamic value) {
    if (value is String) {
      if (value.isEmpty) return Uint8List(0);
      return Uint8List.fromList(base64Decode(value));
    }
    throw FormatException('Expected base64 string, got ${value.runtimeType}');
  }

  /// Zero all cryptographic key material in this ratchet state.
  ///
  /// Called during panic wipe to destroy session state and prevent forensic
  /// recovery of past message keys. Uses [SecureMemory.zeroBytes] to
  /// overwrite the mutable [Uint8List] bytes in-place, then clears the
  /// skipped keys map.
  ///
  /// After calling this method, the session is unusable and should be deleted
  /// from storage.
  void wipe() {
    SecureMemory.zeroBytes(dhSendingKeyPair);
    SecureMemory.zeroBytes(dhReceivingKey);
    SecureMemory.zeroBytes(rootKey);
    SecureMemory.zeroBytes(sendingChainKey);
    SecureMemory.zeroBytes(receivingChainKey);
    for (final key in skippedKeys.values) {
      SecureMemory.zeroBytes(key);
    }
    skippedKeys.clear();
    receivedMessages.clear();
    sendMessageNumber = 0;
    receiveMessageNumber = 0;
    previousChainLength = 0;
  }
}

/// A complete session record between the local user and one remote device.
///
/// Wraps a [RatchetState] with recipient identifiers for persistence. Each
/// user can have multiple devices, so sessions are keyed by `userId:deviceId`.
///
/// The session is created during X3DH (either as initiator via [createSession]
/// or as responder via [processPreKeyMessage]) and persisted to storage after
/// every encrypt/decrypt operation.
///
/// See also:
///   - [SignalProtocolManager] which manages the session lifecycle
///   - [CryptoStorage.saveSession] which persists this to secure storage
class SignalSession {
  /// The remote user's ID (UUID from the server).
  final String recipientId;

  /// The remote device's ID (UUID from the server).
  ///
  /// Users can have multiple devices (phone, tablet, desktop). Each device
  /// has its own identity key and sessions.
  final String recipientDeviceId;

  /// The mutable Double Ratchet state for this session.
  ///
  /// Updated in-place during encrypt/decrypt operations.
  RatchetState ratchetState;

  SignalSession({
    required this.recipientId,
    required this.recipientDeviceId,
    required this.ratchetState,
  });

  Map<String, dynamic> toJson() => {
        'recipientId': recipientId,
        'recipientDeviceId': recipientDeviceId,
        'ratchetState': ratchetState.toJson(),
      };

  factory SignalSession.fromJson(Map<String, dynamic> json) => SignalSession(
        recipientId: json['recipientId'] as String,
        recipientDeviceId: json['recipientDeviceId'] as String,
        ratchetState: RatchetState.fromJson(
          json['ratchetState'] as Map<String, dynamic>,
        ),
      );
}
