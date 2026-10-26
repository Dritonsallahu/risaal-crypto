import 'dart:convert';
import 'dart:typed_data';

import '../crypto_protocol.dart';
import '../secure_memory.dart';
import 'signal_keys.dart';

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

  /// When each entry of [skippedKeys] was stored, as Unix milliseconds
  /// (R4-L2). [DoubleRatchet] purges keys older than
  /// [DoubleRatchet.skippedKeyTtl] at the start of every decrypt. Local
  /// storage only; never on the wire.
  Map<String, int> skippedKeyAges;

  /// Set of received message identifiers ("dhPublicKey:messageNumber")
  /// for explicit anti-replay protection. Persisted across app restarts.
  ///
  /// When a message is successfully decrypted, its identifier is added
  /// here. If the same identifier arrives again, decryption is rejected
  /// as a replay. Capped at [DoubleRatchet.maxReceivedTracked] entries,
  /// pruning oldest when exceeded.
  Set<String> receivedMessages;

  /// Canonical base64 identity public key of the remote party this session was
  /// established with (R4-PKG-SESSION-PIN-CHECK). `null` only for a record
  /// written before this field existed; [SignalProtocolManager] stamps such a
  /// record on first load. Every encrypt and decrypt refuses the session when
  /// this disagrees with the identity pinned for the peer. Local storage only;
  /// never on the wire.
  String? remoteIdentityKey;

  /// The peer has sent a valid Double Ratchet v3 message on this session, or
  /// the session was created with PQXDH transcript 2 (R4-L1). From then on a
  /// v2 message on this session is refused (L1-I1). Local storage only.
  bool peerSpeaksV3;

  /// This session sends Double Ratchet v3 (R4-L1). Set by the first v3 send,
  /// or at creation with PQXDH transcript 2, and never cleared: the peer
  /// refuses v2 from a session that has sent v3. Local storage only.
  bool sendV3;

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
    Map<String, int>? skippedKeyAges,
    Set<String>? receivedMessages,
    this.remoteIdentityKey,
    this.peerSpeaksV3 = false,
    this.sendV3 = false,
  }) : skippedKeys = skippedKeys ?? {},
       skippedKeyAges = skippedKeyAges ?? {},
       receivedMessages = receivedMessages ?? {};

  /// Serialize to JSON, encoding all [Uint8List] fields to base64 strings.
  ///
  /// Epoch-2 storage is explicitly marked. Legacy/unversioned state belongs in
  /// the quarantined pre-cutover namespace and is never accepted here.
  Map<String, dynamic> toJson() => {
    'v': 2,
    'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
    'dhSendingKeyPair': base64Encode(dhSendingKeyPair),
    'dhReceivingKey': base64Encode(dhReceivingKey),
    'rootKey': base64Encode(rootKey),
    'sendingChainKey': base64Encode(sendingChainKey),
    'receivingChainKey': base64Encode(receivingChainKey),
    'sendMessageNumber': sendMessageNumber,
    'receiveMessageNumber': receiveMessageNumber,
    'previousChainLength': previousChainLength,
    'skippedKeys': skippedKeys.map((k, v) => MapEntry(k, base64Encode(v))),
    'skippedKeyAges': Map<String, int>.of(skippedKeyAges),
    'receivedMessages': receivedMessages.toList(),
    if (remoteIdentityKey != null) 'remoteIdentityKey': remoteIdentityKey,
    // R4-L1: written only once set, so a v2-only record is byte-identical to
    // the pre-R4-L1 format.
    if (peerSpeaksV3) 'peerSpeaksV3': true,
    if (sendV3) 'sendV3': true,
  };

  /// Deserialize from JSON, decoding base64 strings to [Uint8List].
  ///
  /// Only the exact epoch-2 storage schema is accepted by the exported live
  /// API. Offline migration tools must use a separately named legacy parser.
  factory RatchetState.fromJson(Map<String, dynamic> json) {
    if (json['v'] != 2 ||
        json['cryptoProtocolEpoch'] !=
            RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException(
        'Unsupported or legacy Double Ratchet storage state',
      );
    }
    final skippedKeys =
        (json['skippedKeys'] as Map<String, dynamic>?)?.map(
          (k, v) => MapEntry(k, _decodeField(v)),
        ) ??
        <String, Uint8List>{};
    // Backward compatible (R4-L2): a key without a stored age (legacy state
    // or a missing entry) is stamped with the load time, never dropped.
    final storedAges = json['skippedKeyAges'] as Map<String, dynamic>?;
    final loadTime = DateTime.now().millisecondsSinceEpoch;
    // Backward compatible (R4-PKG-SESSION-PIN-CHECK): absent on older records.
    final remoteIdentityKey = json['remoteIdentityKey'];
    if (remoteIdentityKey != null && remoteIdentityKey is! String) {
      throw const FormatException('Invalid session remote identity key');
    }
    final skippedKeyAges = <String, int>{
      for (final k in skippedKeys.keys) k: (storedAges?[k] as int?) ?? loadTime,
    };
    // R4-L1: absent on records written before identity binding (false).
    final peerSpeaksV3 = json['peerSpeaksV3'] ?? false;
    final sendV3 = json['sendV3'] ?? false;
    if (peerSpeaksV3 is! bool || sendV3 is! bool) {
      throw const FormatException('Invalid session identity-binding flags');
    }
    return RatchetState(
      dhSendingKeyPair: _decodeField(json['dhSendingKeyPair']),
      dhReceivingKey: _decodeField(json['dhReceivingKey']),
      rootKey: _decodeField(json['rootKey']),
      sendingChainKey: _decodeField(json['sendingChainKey']),
      receivingChainKey: _decodeField(json['receivingChainKey']),
      sendMessageNumber: json['sendMessageNumber'] as int,
      receiveMessageNumber: json['receiveMessageNumber'] as int,
      previousChainLength: json['previousChainLength'] as int,
      skippedKeys: skippedKeys,
      skippedKeyAges: skippedKeyAges,
      receivedMessages:
          (json['receivedMessages'] as List<dynamic>?)
              ?.cast<String>()
              .toSet() ??
          {},
      remoteIdentityKey: remoteIdentityKey as String?,
      peerSpeaksV3: peerSpeaksV3,
      sendV3: sendV3,
    );
  }

  /// Decode a single field from its stored representation to raw bytes.
  ///
  /// Epoch-2 stores every byte field as strict base64.
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
    skippedKeyAges.clear();
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
