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
///   - **Skipped keys**: Stored when messages arrive out-of-order (up to 100)
///
/// The state is JSON-serializable for storage via [CryptoStorage].
///
/// See also:
///   - [DoubleRatchet] which owns and mutates this state
///   - [SignalSession] which wraps this for persistence
class RatchetState {
  /// JSON-encoded [KeyPair] for the current sending DH ratchet key.
  ///
  /// This is the local party's ephemeral X25519 key pair. The public portion
  /// is sent in the header of every outgoing message so the recipient can
  /// perform a DH ratchet step.
  String dhSendingKeyPair;

  /// Base64-encoded public key of the remote party's current DH ratchet key.
  ///
  /// Updated when receiving a message with a new DH public key in the header.
  /// Used to derive the receiving chain key via DH(localPrivate, remotePub).
  String dhReceivingKey;

  /// Base64-encoded 32-byte root key.
  ///
  /// The root key is ratcheted forward with each DH step using HKDF:
  /// `(newRootKey, chainKey) = HKDF(oldRootKey, DH_output)`.
  /// Never used directly for encryption — only for deriving chain keys.
  String rootKey;

  /// Base64-encoded 32-byte sending chain key.
  ///
  /// Ratcheted forward with each outgoing message using HMAC:
  /// `(nextChainKey, messageKey) = HMAC(chainKey, constants)`.
  /// The message key is used once to encrypt the current message, then discarded.
  String sendingChainKey;

  /// Base64-encoded 32-byte receiving chain key.
  ///
  /// Ratcheted forward with each incoming message. Derived from the root key
  /// after a DH ratchet step. Used to decrypt messages from the remote party.
  String receivingChainKey;

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
  /// Format: `"<dhPublicKey>:<messageNumber>" -> <base64MessageKey>`.
  /// When a message arrives with a higher number than expected, the chain key
  /// is advanced and intermediate message keys are stored here. If the missing
  /// messages arrive later, they're decrypted using the stored keys.
  ///
  /// Limited to 100 entries to prevent DoS attacks that force unbounded storage.
  Map<String, String> skippedKeys;

  RatchetState({
    required this.dhSendingKeyPair,
    required this.dhReceivingKey,
    required this.rootKey,
    required this.sendingChainKey,
    required this.receivingChainKey,
    this.sendMessageNumber = 0,
    this.receiveMessageNumber = 0,
    this.previousChainLength = 0,
    Map<String, String>? skippedKeys,
  }) : skippedKeys = skippedKeys ?? {};

  Map<String, dynamic> toJson() => {
        'dhSendingKeyPair': dhSendingKeyPair,
        'dhReceivingKey': dhReceivingKey,
        'rootKey': rootKey,
        'sendingChainKey': sendingChainKey,
        'receivingChainKey': receivingChainKey,
        'sendMessageNumber': sendMessageNumber,
        'receiveMessageNumber': receiveMessageNumber,
        'previousChainLength': previousChainLength,
        'skippedKeys': skippedKeys,
      };

  factory RatchetState.fromJson(Map<String, dynamic> json) => RatchetState(
        dhSendingKeyPair: json['dhSendingKeyPair'] as String,
        dhReceivingKey: json['dhReceivingKey'] as String,
        rootKey: json['rootKey'] as String,
        sendingChainKey: json['sendingChainKey'] as String,
        receivingChainKey: json['receivingChainKey'] as String,
        sendMessageNumber: json['sendMessageNumber'] as int,
        receiveMessageNumber: json['receiveMessageNumber'] as int,
        previousChainLength: json['previousChainLength'] as int,
        skippedKeys: (json['skippedKeys'] as Map<String, dynamic>?)
                ?.map((k, v) => MapEntry(k, v as String)) ??
            {},
      );

  /// Zero all cryptographic key material in this ratchet state.
  ///
  /// Called during panic wipe to destroy session state and prevent forensic
  /// recovery of past message keys. Overwrites all key strings with empty
  /// values (allowing the Dart GC to reclaim the original base64 strings)
  /// and clears the skipped keys map.
  ///
  /// This is a best-effort operation — Dart's GC may have already copied
  /// the strings elsewhere in memory during compaction. For maximum security,
  /// use [SecureMemory.zeroBytes] on the raw key bytes before they're
  /// base64-encoded.
  ///
  /// After calling this method, the session is unusable and should be deleted
  /// from storage.
  void wipe() {
    dhSendingKeyPair = '';
    dhReceivingKey = '';
    rootKey = '';
    sendingChainKey = '';
    receivingChainKey = '';
    skippedKeys.clear();
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
