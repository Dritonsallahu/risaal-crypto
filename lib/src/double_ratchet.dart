import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'secure_memory.dart';
import 'crypto_debug_logger.dart';
import 'key_helper.dart';
import 'models/signal_keys.dart';
import 'models/session_state.dart';

/// Wire-format encrypted message produced by the Double Ratchet.
///
/// Contains all metadata needed for the receiver to decrypt and advance their
/// ratchet state. This structure is embedded in PreKey messages (type 1) and
/// normal messages (type 2).
///
/// Wire format (JSON):
/// ```json
/// {
///   "dhPublicKey": "<base64 X25519 public key>",
///   "messageNumber": 5,
///   "previousChainLength": 3,
///   "ciphertext": "<base64 AES-256-GCM ciphertext + MAC>",
///   "nonce": "<base64 12-byte nonce>"
/// }
/// ```
///
/// The receiver uses [dhPublicKey] to detect if a DH ratchet step is needed
/// (i.e., the sender's ratchet key changed). If so, they skip [previousChainLength]
/// messages in the old receiving chain and perform a new DH to derive the new
/// receiving chain key. Then they skip ahead to [messageNumber] in the new chain.
class EncryptedMessage {
  /// Base64-encoded X25519 public key of the sender's current ratchet key pair.
  ///
  /// Changes when the sender performs a DH ratchet step (i.e., when they receive
  /// a reply after sending one or more messages). The receiver compares this to
  /// their stored [RatchetState.dhReceivingKey] to detect ratchet steps.
  final String dhPublicKey;

  /// Message number within the current sending chain (0-indexed).
  ///
  /// Incremented for each message sent with the same DH ratchet key. Reset to 0
  /// when the sender performs a DH ratchet step.
  final int messageNumber;

  /// Length of the sender's previous sending chain.
  ///
  /// Used by the receiver to skip messages in the old receiving chain before
  /// performing a DH ratchet step. If the sender sent 3 messages, then received
  /// a reply, the first message of their new chain has `previousChainLength: 3`.
  final int previousChainLength;

  /// Base64-encoded AES-256-GCM ciphertext concatenated with the 16-byte MAC.
  ///
  /// Total length: `(paddedPlaintext.length + 16)` bytes (before base64).
  /// The last 16 bytes are the GCM authentication tag.
  final String ciphertext;

  /// Base64-encoded 12-byte AES-GCM nonce (randomly generated per message).
  final String nonce;

  const EncryptedMessage({
    required this.dhPublicKey,
    required this.messageNumber,
    required this.previousChainLength,
    required this.ciphertext,
    required this.nonce,
  });

  Map<String, dynamic> toJson() => {
        'dhPublicKey': dhPublicKey,
        'messageNumber': messageNumber,
        'previousChainLength': previousChainLength,
        'ciphertext': ciphertext,
        'nonce': nonce,
      };

  factory EncryptedMessage.fromJson(Map<String, dynamic> json) {
    final dhKey = json['dhPublicKey'] as String?;
    final msgNum = json['messageNumber'] as int?;
    final prevLen = json['previousChainLength'] as int?;
    final ct = json['ciphertext'] as String?;
    final nonce = json['nonce'] as String?;

    if (dhKey == null || dhKey.isEmpty)
      throw const FormatException('Missing dhPublicKey');
    if (msgNum == null || msgNum < 0)
      throw const FormatException('Invalid messageNumber');
    if (msgNum > 100000)
      throw FormatException('Message number exceeds maximum: $msgNum');
    if (prevLen == null || prevLen < 0)
      throw const FormatException('Invalid previousChainLength');
    if (prevLen > 100000)
      throw FormatException('Previous chain length exceeds maximum: $prevLen');
    if (ct == null || ct.isEmpty)
      throw const FormatException('Missing ciphertext');
    if (nonce == null || nonce.isEmpty)
      throw const FormatException('Missing nonce');

    return EncryptedMessage(
      dhPublicKey: dhKey,
      messageNumber: msgNum,
      previousChainLength: prevLen,
      ciphertext: ct,
      nonce: nonce,
    );
  }
}

/// Signal Double Ratchet algorithm -- symmetric ratchet + DH ratchet.
///
/// Implements the core encryption algorithm of the Signal Protocol, providing:
///   - **Forward secrecy**: Past messages cannot be decrypted if current keys are compromised
///   - **Post-compromise security**: Future messages are secure even after a key compromise
///   - **Out-of-order delivery**: Messages can arrive in any order
///
/// How it works:
///   1. **Symmetric ratchet**: Chain keys are derived via HMAC and advance with every message.
///      Message keys are derived from chain keys and used once, then deleted.
///   2. **DH ratchet**: When Alice receives a reply from Bob, she performs a DH exchange
///      with his new ephemeral public key, deriving a new root key and new chain keys.
///      This rotates the encryption keys even if an attacker has the current chain key.
///
/// Each instance represents one session between two devices. The [RatchetState]
/// is mutable and must be persisted after every encrypt/decrypt operation.
///
/// Initialization:
///   - **Sender** (Alice): Call [initSender] with X3DH shared secret and Bob's signed pre-key public
///   - **Receiver** (Bob): Call [initReceiver] with X3DH shared secret and his signed pre-key pair
///
/// Out-of-order messages:
///   - If message N+5 arrives before N+1, the chain key advances 4 times and the intermediate
///     message keys are stored in [RatchetState.skippedKeys] (up to [_maxSkippedKeys]).
///   - When N+1 arrives later, its stored key is used for decryption.
///
/// See also:
///   - [X3DH] for initial key agreement
///   - [RatchetState] for the mutable session state
class DoubleRatchet {
  /// Maximum number of skipped message keys to store (DoS protection).
  ///
  /// If an attacker sends message number 10000 when we're at message 5, we'd
  /// try to store 9995 skipped keys. This limit prevents unbounded memory usage.
  static const _maxSkippedKeys = 2000;

  /// Maximum number of received message IDs to track for anti-replay.
  static const maxReceivedTracked = 2000;
  static const _ratchetInfo = 'Risaal_Ratchet';

  static final _x25519 = X25519();
  static final _hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 64);
  static final _hmac = Hmac.sha256();
  static final _aesGcm = AesGcm.with256bits();

  RatchetState _state;

  /// Async mutex to prevent concurrent decrypt() from causing TOCTOU races
  /// on skipped message keys.
  Completer<void>? _decryptLock;

  DoubleRatchet._(this._state);

  // -- Factory: Sender (Alice after X3DH) --------------------------------

  /// Initialize as the sender (Alice role after X3DH).
  ///
  /// Called by the session initiator after performing X3DH key agreement.
  /// The [sharedSecret] comes from X3DH (32 bytes). Alice generates her first
  /// ephemeral DH ratchet key pair and performs the initial DH exchange with
  /// Bob's [recipientPublicKey] (his signed pre-key public).
  ///
  /// This produces the initial root key and sending chain key. The receiving
  /// chain key is empty until Alice receives Bob's first reply.
  ///
  /// Parameters:
  ///   - [sharedSecret]: 32-byte shared secret from X3DH
  ///   - [recipientPublicKey]: Base64-encoded X25519 public key (Bob's signed pre-key)
  ///
  /// Returns a [DoubleRatchet] ready to encrypt messages.
  static Future<DoubleRatchet> initSender({
    required List<int> sharedSecret,
    required String recipientPublicKey,
  }) async {
    final sendingKeyPair = await SignalKeyHelper.generateX25519KeyPair();

    // First DH ratchet step: DH(sendingKP, recipientPub)
    final dhOutput = await _performDH(sendingKeyPair, recipientPublicKey);

    // KDF_RK to get new root key + sending chain key
    final (newRootKey, newChainKey) = await _kdfRK(sharedSecret, dhOutput);

    final state = RatchetState(
      dhSendingKeyPair: Uint8List.fromList(
          utf8.encode(jsonEncode(sendingKeyPair.toJson()))),
      dhReceivingKey: Uint8List.fromList(base64Decode(recipientPublicKey)),
      rootKey: Uint8List.fromList(newRootKey),
      sendingChainKey: Uint8List.fromList(newChainKey),
      receivingChainKey: Uint8List(0), // no receiving chain until we get a reply
    );

    // Zero DH intermediaries -- must not persist in RAM
    SecureMemory.zeroBytes(dhOutput);
    SecureMemory.zeroBytes(newRootKey);
    SecureMemory.zeroBytes(newChainKey);

    return DoubleRatchet._(state);
  }

  // -- Factory: Receiver (Bob after X3DH) --------------------------------

  /// Initialize as the receiver (Bob role after X3DH).
  ///
  /// Called by the session responder after performing X3DH key agreement.
  /// The [sharedSecret] comes from X3DH (32 bytes). Bob uses his signed pre-key
  /// pair ([dhKeyPair]) as the initial DH ratchet key.
  ///
  /// The root key is initialized from the shared secret. The chain keys are empty
  /// until Bob receives Alice's first message (which triggers the first DH ratchet
  /// step and derives the receiving chain key).
  ///
  /// Parameters:
  ///   - [sharedSecret]: 32-byte shared secret from X3DH
  ///   - [dhKeyPair]: Bob's signed pre-key pair (X25519, used for initial ratchet)
  ///
  /// Returns a [DoubleRatchet] ready to decrypt Alice's first message.
  static Future<DoubleRatchet> initReceiver({
    required List<int> sharedSecret,
    required KeyPair dhKeyPair,
  }) async {
    final state = RatchetState(
      dhSendingKeyPair: Uint8List.fromList(
          utf8.encode(jsonEncode(dhKeyPair.toJson()))),
      dhReceivingKey: Uint8List(0), // filled on first received message
      rootKey: Uint8List.fromList(sharedSecret),
      sendingChainKey: Uint8List(0),
      receivingChainKey: Uint8List(0),
    );

    return DoubleRatchet._(state);
  }

  // -- Encrypt ------------------------------------------------------------

  /// Encrypt plaintext and advance the sending chain.
  ///
  /// Derives a message key from the current sending chain key via HMAC:
  /// ```
  /// messageKey = HMAC(sendingChainKey, 0x01)
  /// nextChainKey = HMAC(sendingChainKey, 0x02)
  /// ```
  ///
  /// Encrypts [plaintext] with AES-256-GCM using the message key, then wipes
  /// the message key from memory (forward secrecy). The sending chain key is
  /// advanced and the message number incremented.
  ///
  /// The [plaintext] should already be padded (via [MessagePadding.pad]) before
  /// calling this method.
  ///
  /// Returns an [EncryptedMessage] ready for wire transmission.
  Future<EncryptedMessage> encrypt(List<int> plaintext) async {
    // Derive message key from sending chain key
    final chainKey = List<int>.from(_state.sendingChainKey);
    final (newChainKey, messageKey) = await _kdfCK(chainKey);
    _state.sendingChainKey = Uint8List.fromList(newChainKey);

    // Encrypt with AES-256-GCM -- copy bytes so zeroBytes() below
    // doesn't corrupt the key inside the cryptography package's internals
    final secretKey = SecretKey(List<int>.from(messageKey));
    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: secretKey,
    );

    // Wipe ephemeral key material from RAM
    SecureMemory.zeroBytes(chainKey);
    SecureMemory.zeroBytes(newChainKey);
    SecureMemory.zeroBytes(messageKey);

    // Extract the current sending public key
    final sendingKP = KeyPair.fromJson(
      jsonDecode(utf8.decode(_state.dhSendingKeyPair)) as Map<String, dynamic>,
    );

    final message = EncryptedMessage(
      dhPublicKey: sendingKP.publicKey,
      messageNumber: _state.sendMessageNumber,
      previousChainLength: _state.previousChainLength,
      ciphertext: base64Encode(secretBox.cipherText + secretBox.mac.bytes),
      nonce: base64Encode(secretBox.nonce),
    );

    _state.sendMessageNumber++;

    return message;
  }

  // -- Decrypt ------------------------------------------------------------

  /// Decrypt a received message and advance the receiving chain.
  ///
  /// Process:
  ///   1. Check if message key is in [RatchetState.skippedKeys] (out-of-order delivery)
  ///   2. If [message.dhPublicKey] changed, perform DH ratchet step:
  ///      - Skip remaining messages in old receiving chain
  ///      - Derive new receiving chain key via `DH(localKey, newRemoteKey)`
  ///      - Generate new sending key pair and derive new sending chain key
  ///   3. Skip ahead to [message.messageNumber] in receiving chain
  ///   4. Derive message key and decrypt with AES-256-GCM
  ///   5. Verify MAC (throws if authentication fails)
  ///   6. Wipe message key from memory
  ///
  /// This method is protected by an async mutex to prevent TOCTOU races when
  /// multiple messages arrive concurrently and try to update [skippedKeys].
  ///
  /// Returns the decrypted plaintext bytes (still padded -- caller must unpad).
  ///
  /// Throws [StateError] if MAC verification fails or too many keys skipped.
  Future<List<int>> decrypt(EncryptedMessage message) async {
    // Acquire async mutex to prevent TOCTOU race on skipped keys
    while (_decryptLock != null) {
      await _decryptLock!.future;
    }
    _decryptLock = Completer<void>();
    try {
      return await _decryptInner(message);
    } finally {
      final lock = _decryptLock;
      _decryptLock = null;
      lock?.complete();
    }
  }

  Future<List<int>> _decryptInner(EncryptedMessage message) async {
    CryptoDebugLogger.log('RATCHET_D',
        'decrypt: msgNum=${message.messageNumber} prevChain=${message.previousChainLength}');
    CryptoDebugLogger.log('RATCHET_D',
        'state: sendN=${_state.sendMessageNumber} recvN=${_state.receiveMessageNumber} skipped=${_state.skippedKeys.length}');

    // -- Anti-replay check ------------------------------------------------
    final messageId = '${message.dhPublicKey}:${message.messageNumber}';
    if (_state.receivedMessages.contains(messageId)) {
      CryptoDebugLogger.log('RATCHET_D', 'REPLAY REJECTED: $messageId');
      throw StateError(
        'Replay attack detected: message $messageId already received',
      );
    }

    // Check skipped keys first
    final skipKey = '${message.dhPublicKey}:${message.messageNumber}';
    if (_state.skippedKeys.containsKey(skipKey)) {
      CryptoDebugLogger.log(
          'RATCHET_D', 'Found in SKIPPED KEYS -- decrypting with stored key');
      final messageKey = List<int>.from(_state.skippedKeys[skipKey]!);
      _state.skippedKeys.remove(skipKey);
      final result = await _decryptWithKey(messageKey, message);
      _recordReceivedMessage(messageId);
      return result;
    }

    // If the DH ratchet key changed, perform a DH ratchet step
    final stateReceivingKeyBase64 = base64Encode(_state.dhReceivingKey);
    final dhKeyChanged = message.dhPublicKey != stateReceivingKeyBase64;
    CryptoDebugLogger.log('RATCHET_D',
        'DH key changed: $dhKeyChanged (msg=${message.dhPublicKey.substring(0, 8)}... state=${_state.dhReceivingKey.isEmpty ? "(empty)" : "${stateReceivingKeyBase64.substring(0, 8)}..."})');

    if (dhKeyChanged) {
      // Skip any remaining messages in the old receiving chain
      if (_state.receivingChainKey.isNotEmpty) {
        CryptoDebugLogger.log('RATCHET_D',
            'Skipping old chain messages up to ${message.previousChainLength}');
        await _skipMessageKeys(
          stateReceivingKeyBase64,
          message.previousChainLength,
        );
      }

      // DH ratchet step
      CryptoDebugLogger.log('RATCHET_D', 'Performing DH ratchet step');
      await _dhRatchetStep(message.dhPublicKey);
      CryptoDebugLogger.log('RATCHET_D',
          'DH ratchet step complete. recvN=${_state.receiveMessageNumber} sendN=${_state.sendMessageNumber}');
    }

    // Skip ahead to the correct message number in the receiving chain
    if (message.messageNumber > _state.receiveMessageNumber) {
      CryptoDebugLogger.log('RATCHET_D',
          'Skipping ahead from recvN=${_state.receiveMessageNumber} to msgNum=${message.messageNumber}');
    }
    await _skipMessageKeys(
      base64Encode(_state.dhReceivingKey),
      message.messageNumber,
    );

    // Derive the message key
    CryptoDebugLogger.log('RATCHET_D',
        'Deriving message key at recvN=${_state.receiveMessageNumber}');
    final chainKey = List<int>.from(_state.receivingChainKey);
    final (newChainKey, messageKey) = await _kdfCK(chainKey);
    _state.receivingChainKey = Uint8List.fromList(newChainKey);
    _state.receiveMessageNumber++;

    // Wipe chain key intermediaries
    SecureMemory.zeroBytes(chainKey);
    SecureMemory.zeroBytes(newChainKey);

    CryptoDebugLogger.log('RATCHET_D',
        'Decrypting with derived key. New recvN=${_state.receiveMessageNumber}');
    final result = await _decryptWithKey(messageKey, message);
    _recordReceivedMessage(messageId);
    return result;
  }

  /// Record a successfully-decrypted message for anti-replay.
  /// Caps the set at [maxReceivedTracked] to prevent unbounded growth.
  void _recordReceivedMessage(String messageId) {
    _state.receivedMessages.add(messageId);
    if (_state.receivedMessages.length > maxReceivedTracked) {
      // Remove oldest entries (set has no ordering, so convert to list)
      final list = _state.receivedMessages.toList();
      _state.receivedMessages =
          list.sublist(list.length - maxReceivedTracked).toSet();
    }
  }

  // -- State Serialisation ------------------------------------------------

  Map<String, dynamic> toJson() => _state.toJson();

  factory DoubleRatchet.fromJson(Map<String, dynamic> json) =>
      DoubleRatchet._(RatchetState.fromJson(json));

  /// Expose state for storage.
  RatchetState get state => _state;

  // -- Private: DH Ratchet Step -------------------------------------------

  /// Perform a DH ratchet step: update receiving chain, generate new
  /// sending key pair, update sending chain.
  Future<void> _dhRatchetStep(String newRemotePublicKey) async {
    _state.previousChainLength = _state.sendMessageNumber;
    _state.sendMessageNumber = 0;
    _state.receiveMessageNumber = 0;
    _state.dhReceivingKey =
        Uint8List.fromList(base64Decode(newRemotePublicKey));

    // Receiving chain: DH(currentSendingKP, newRemotePub)
    final currentKP = KeyPair.fromJson(
      jsonDecode(utf8.decode(_state.dhSendingKeyPair)) as Map<String, dynamic>,
    );
    final dhOutput = await _performDH(currentKP, newRemotePublicKey);
    final rootKey = List<int>.from(_state.rootKey);
    final (newRootKey1, recvChainKey) = await _kdfRK(rootKey, dhOutput);
    _state.rootKey = Uint8List.fromList(newRootKey1);
    _state.receivingChainKey = Uint8List.fromList(recvChainKey);

    // Zero DH output and old root key -- must not persist in RAM
    SecureMemory.zeroBytes(dhOutput);
    SecureMemory.zeroBytes(rootKey);
    SecureMemory.zeroBytes(recvChainKey);

    // Sending chain: generate new DH key pair
    final newSendingKP = await SignalKeyHelper.generateX25519KeyPair();
    _state.dhSendingKeyPair =
        Uint8List.fromList(utf8.encode(jsonEncode(newSendingKP.toJson())));

    final dhOutput2 = await _performDH(newSendingKP, newRemotePublicKey);
    final (newRootKey2, sendChainKey) = await _kdfRK(newRootKey1, dhOutput2);
    _state.rootKey = Uint8List.fromList(newRootKey2);
    _state.sendingChainKey = Uint8List.fromList(sendChainKey);

    // Zero second DH output and intermediate key material
    SecureMemory.zeroBytes(dhOutput2);
    SecureMemory.zeroBytes(newRootKey1);
    SecureMemory.zeroBytes(newRootKey2);
    SecureMemory.zeroBytes(sendChainKey);
  }

  // -- Private: Skip Message Keys -----------------------------------------

  /// Advance the receiving chain and store skipped message keys up to
  /// [untilNumber]. Throws if too many keys would be skipped.
  Future<void> _skipMessageKeys(
    String dhPublicKey,
    int untilNumber,
  ) async {
    if (_state.receivingChainKey.isEmpty) return;

    final toSkip = untilNumber - _state.receiveMessageNumber;
    if (toSkip < 0) return;
    if (_state.skippedKeys.length + toSkip > _maxSkippedKeys) {
      throw StateError(
        'Too many skipped message keys (max $_maxSkippedKeys). '
        'Possible DoS attempt.',
      );
    }

    List<int> chainKey = List<int>.from(_state.receivingChainKey);
    for (var i = _state.receiveMessageNumber; i < untilNumber; i++) {
      final (newChainKey, messageKey) = await _kdfCK(chainKey);
      _state.skippedKeys['$dhPublicKey:$i'] = Uint8List.fromList(messageKey);
      // Zero old chain key and message key copy after storing
      SecureMemory.zeroBytes(chainKey);
      SecureMemory.zeroBytes(messageKey);
      chainKey = newChainKey;
    }
    _state.receivingChainKey = Uint8List.fromList(chainKey);
    SecureMemory.zeroBytes(chainKey);
  }

  // -- Private: AES-256-GCM Decryption ------------------------------------

  Future<List<int>> _decryptWithKey(
    List<int> messageKey,
    EncryptedMessage message,
  ) async {
    final secretKey = SecretKey(List<int>.from(messageKey));
    final nonce = base64Decode(message.nonce);
    final combined = base64Decode(message.ciphertext);

    // Last 16 bytes are the GCM MAC tag
    final ciphertext = combined.sublist(0, combined.length - 16);
    final mac = Mac(combined.sublist(combined.length - 16));

    final secretBox = SecretBox(
      ciphertext,
      nonce: nonce,
      mac: mac,
    );

    final plaintext = await _aesGcm.decrypt(secretBox, secretKey: secretKey);

    // Wipe message key after use -- it must not persist in RAM
    SecureMemory.zeroBytes(messageKey);

    return plaintext;
  }

  // -- Private: KDF_RK -- Root Key Derivation -----------------------------

  /// Derive (newRootKey, newChainKey) from the current root key and a
  /// DH output using HKDF-SHA256.
  static Future<(List<int>, List<int>)> _kdfRK(
    List<int> rootKey,
    List<int> dhOutput,
  ) async {
    final derived = await _hkdf.deriveKey(
      secretKey: SecretKey(List<int>.from(dhOutput)),
      info: _ratchetInfo.codeUnits,
      nonce: rootKey,
    );
    final bytes = await derived.extractBytes();
    // First 32 bytes = new root key, last 32 bytes = new chain key
    return (bytes.sublist(0, 32), bytes.sublist(32, 64));
  }

  // -- Private: KDF_CK -- Chain Key Derivation ----------------------------

  /// Derive (newChainKey, messageKey) from the current chain key using
  /// HMAC-SHA256. Message key = HMAC(ck, 0x01), new chain key = HMAC(ck, 0x02).
  static Future<(List<int>, List<int>)> _kdfCK(List<int> chainKey) async {
    final ck = SecretKey(List<int>.from(chainKey));

    final messageKeyMac = await _hmac.calculateMac(
      [0x01],
      secretKey: ck,
    );
    final newChainKeyMac = await _hmac.calculateMac(
      [0x02],
      secretKey: ck,
    );

    return (newChainKeyMac.bytes, messageKeyMac.bytes);
  }

  // -- Private: X25519 DH -------------------------------------------------

  /// Perform an X25519 DH exchange between a local key pair and a
  /// remote base64 public key.
  static Future<List<int>> _performDH(
    KeyPair localKeyPair,
    String remotePublicKeyBase64,
  ) async {
    final privateBytes = base64Decode(localKeyPair.privateKey);
    final publicBytes = base64Decode(localKeyPair.publicKey);
    final remoteBytes = base64Decode(remotePublicKeyBase64);

    final kp = SimpleKeyPairData(
      privateBytes,
      publicKey: SimplePublicKey(publicBytes, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
    final remotePub = SimplePublicKey(remoteBytes, type: KeyPairType.x25519);

    final secret = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: remotePub,
    );
    return secret.extractBytes();
  }
}
