import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'crypto_debug_logger.dart';
import 'crypto_storage.dart';
import 'key_helper.dart';
import 'message_padding.dart';

/// Mutable state of a Sender Key for a specific group and sender.
///
/// Each group member generates their own Sender Key (one per group) and
/// distributes it to all other members via 1-to-1 encrypted sessions. When
/// Alice sends a group message, she encrypts it once with her Sender Key
/// (AES-256-CBC + Ed25519 signature) and broadcasts the same ciphertext to all
/// members. Everyone who has Alice's Sender Key can decrypt.
///
/// The chain key ratchets forward after each message (forward secrecy within
/// the group). The Ed25519 signing key is static for the lifetime of the
/// Sender Key.
///
/// Authentication uses **asymmetric Ed25519 signatures** rather than shared
/// HMAC. Only the sender holds the private signing key and can produce
/// signatures. Recipients hold only the public key and can verify, but
/// cannot forge messages on behalf of the sender.
///
/// State lifecycle:
///   - Created by [SenderKeyManager.generateSenderKey]
///   - Distributed via [SenderKeyDistribution] to all group members
///   - Mutated by [SenderKeyManager.encrypt] (sender) and [decrypt] (receivers)
///   - Persisted to storage after every operation
///
/// See also:
///   - [SenderKeyDistribution] for the wire format sent to members
///   - [SenderKeyMessage] for encrypted group message wire format
class SenderKeyState {
  final String groupId;
  final String senderId;
  int iteration;
  List<int> chainKey; // 32 bytes
  final String signingPublicKey;   // Ed25519 public key (base64)
  final String? signingPrivateKey; // Ed25519 private key (base64) — only for OUR OWN sender key

  SenderKeyState({
    required this.groupId,
    required this.senderId,
    required this.iteration,
    required this.chainKey,
    required this.signingPublicKey,
    this.signingPrivateKey,
  });

  Map<String, dynamic> toJson() => {
    'groupId': groupId,
    'senderId': senderId,
    'iteration': iteration,
    'chainKey': base64Encode(chainKey),
    'signingPublicKey': signingPublicKey,
    if (signingPrivateKey != null) 'signingPrivateKey': signingPrivateKey,
  };

  factory SenderKeyState.fromJson(Map<String, dynamic> json) {
    // Migration: detect legacy format (shared HMAC key) vs new Ed25519 format
    if (json.containsKey('signingPublicKey')) {
      // New Ed25519 format
      return SenderKeyState(
        groupId: json['groupId'] as String,
        senderId: json['senderId'] as String,
        iteration: json['iteration'] as int,
        chainKey: base64Decode(json['chainKey'] as String),
        signingPublicKey: json['signingPublicKey'] as String,
        signingPrivateKey: json['signingPrivateKey'] as String?,
      );
    } else {
      // Legacy format: 'signingKey' was a shared HMAC key.
      // Treat as public-only (cannot sign — forces sender key regeneration).
      return SenderKeyState(
        groupId: json['groupId'] as String,
        senderId: json['senderId'] as String,
        iteration: json['iteration'] as int,
        chainKey: base64Decode(json['chainKey'] as String),
        signingPublicKey: json['signingKey'] as String,
        signingPrivateKey: null,
      );
    }
  }
}

/// Distribution message sent to each group member via 1-to-1 encrypted sessions.
///
/// Contains everything a recipient needs to decrypt future messages from this
/// sender in the group. The distribution is sent once when a member joins or
/// when the sender rotates their key.
///
/// Wire format (encrypted with recipient's 1-to-1 session):
/// ```json
/// {
///   "groupId": "group-uuid",
///   "senderId": "alice-uuid",
///   "iteration": 0,
///   "chainKey": "<base64 32-byte AES chain key>",
///   "signingKey": "<base64 Ed25519 public key>"
/// }
/// ```
///
/// The `signingKey` field contains the sender's Ed25519 **public** key only.
/// Recipients use it to verify message signatures but cannot forge messages.
/// The sender's private signing key never leaves the sender's device.
///
/// After receiving this, the recipient can decrypt and verify all future
/// messages from this sender in this group.
///
/// See also:
///   - [SenderKeyManager.generateSenderKey] which creates this distribution
///   - [SenderKeyManager.processSenderKeyDistribution] which stores it
class SenderKeyDistribution {
  final String groupId;
  final String senderId;
  final int iteration;
  final String chainKey; // base64
  final String signingKey; // base64 — Ed25519 PUBLIC KEY ONLY

  const SenderKeyDistribution({
    required this.groupId,
    required this.senderId,
    required this.iteration,
    required this.chainKey,
    required this.signingKey,
  });

  Map<String, dynamic> toJson() => {
    'groupId': groupId,
    'senderId': senderId,
    'iteration': iteration,
    'chainKey': chainKey,
    'signingKey': signingKey,
  };

  factory SenderKeyDistribution.fromJson(Map<String, dynamic> json) =>
      SenderKeyDistribution(
        groupId: json['groupId'] as String,
        senderId: json['senderId'] as String,
        iteration: json['iteration'] as int,
        chainKey: json['chainKey'] as String,
        signingKey: json['signingKey'] as String,
      );
}

/// Wire-format of a Sender Key encrypted group message.
///
/// Broadcast to all group members. Recipients who have the sender's Sender Key
/// can decrypt using [SenderKeyManager.decrypt].
///
/// Wire format (JSON):
/// ```json
/// {
///   "iteration": 5,
///   "ciphertext": "<base64 AES-256-CBC ciphertext>",
///   "iv": "<base64 16-byte IV>",
///   "signature": "<base64 Ed25519 signature>"
/// }
/// ```
///
/// The [iteration] allows recipients to fast-forward their chain key if they
/// missed messages (e.g., iteration jumps from 3 to 7 — derive chain key 4 times).
///
/// The [signature] is an Ed25519 signature over (IV || ciphertext || iteration),
/// produced by the sender's private signing key. Only the sender can produce
/// valid signatures; recipients verify using the sender's public key.
///
/// See also:
///   - [SenderKeyManager.encrypt] which produces this message
///   - [SenderKeyManager.decrypt] which consumes it
class SenderKeyMessage {
  final int iteration;
  final String ciphertext; // base64 AES-256-CBC ciphertext
  final String iv; // base64 16-byte IV
  final String signature; // base64 Ed25519 signature

  const SenderKeyMessage({
    required this.iteration,
    required this.ciphertext,
    required this.iv,
    required this.signature,
  });

  Map<String, dynamic> toJson() => {
    'iteration': iteration,
    'ciphertext': ciphertext,
    'iv': iv,
    'signature': signature,
  };

  factory SenderKeyMessage.fromJson(Map<String, dynamic> json) =>
      SenderKeyMessage(
        iteration: json['iteration'] as int,
        ciphertext: json['ciphertext'] as String,
        iv: json['iv'] as String,
        signature: json['signature'] as String,
      );
}

/// Manages Sender Key operations for group E2EE (encrypt-once, decrypt-many).
///
/// Implements Signal's Sender Key protocol for efficient group messaging.
/// Instead of encrypting N times (once per member) with N 1-to-1 sessions,
/// the sender encrypts once and broadcasts the same ciphertext to all members.
///
/// Protocol overview:
///   1. Each group member generates a Sender Key (chain key + Ed25519 signing key pair)
///   2. The Sender Key distribution (chain key + Ed25519 **public** key) is sent
///      to all members via 1-to-1 encrypted sessions
///   3. When sending to the group, encrypt with AES-256-CBC using a key derived from the chain key
///   4. Authenticate the ciphertext with Ed25519 signature using the sender's **private** key
///   5. Broadcast the same ciphertext to all members
///   6. The chain key ratchets forward after each message (forward secrecy)
///
/// Each member has:
///   - **One sender key they generated** (with Ed25519 private key — for signing)
///   - **N sender keys from other members** (with Ed25519 public key only — for verifying)
///
/// Chain key derivation:
///   - `nextChainKey = HMAC(chainKey, 0x01)`
///   - `messageKey = HMAC(chainKey, 0x02)`
///
/// Out-of-order delivery:
///   - Messages include an iteration number
///   - If iteration jumps (e.g., 3 → 7), the chain key is advanced 4 times
///   - Limited to 256 skipped iterations (DoS protection)
///
/// Security properties:
///   - Forward secrecy: Chain key is deleted after deriving the next one
///   - Sender authentication: Ed25519 signatures prevent forgery by recipients
///   - Anti-forgery: Recipients hold only the public key and CANNOT sign on behalf of the sender
///   - No post-compromise security: If signing key is leaked, all future messages are compromised
///     (unlike Double Ratchet which has DH ratchet steps)
///
/// See also:
///   - [SignalProtocolManager.generateGroupSenderKey] for the high-level API
///   - [SenderKeyDistribution] for the distribution wire format
///   - [SenderKeyMessage] for the encrypted message wire format
class SenderKeyManager {
  final CryptoStorage _cryptoStorage;

  static final _hmac = Hmac.sha256();
  static final _random = Random.secure();

  /// Maximum number of skipped iterations we'll try to fast-forward through
  /// when receiving an out-of-order message.
  static const _maxSkipIterations = 256;

  /// Per-key async mutex to prevent concurrent decrypt() from causing
  /// TOCTOU races on the chain key state.
  final Map<String, Completer<void>?> _decryptLocks = {};

  SenderKeyManager({required CryptoStorage cryptoStorage})
    : _cryptoStorage = cryptoStorage;

  // ── Storage Helpers ─────────────────────────────────────────────

  Future<void> _saveSenderKey(
    String groupId,
    String senderId,
    SenderKeyState state,
  ) => _cryptoStorage.saveSenderKeyRaw(groupId, senderId, state.toJson());

  Future<SenderKeyState?> _loadSenderKey(
    String groupId,
    String senderId,
  ) async {
    final json = await _cryptoStorage.getSenderKeyRaw(groupId, senderId);
    if (json == null) return null;
    return SenderKeyState.fromJson(json);
  }

  // ── Generate ──────────────────────────────────────────────────────

  /// Generate a new Sender Key for a group. Returns a distribution
  /// message that should be encrypted with each member's 1-to-1 session
  /// and sent to them.
  Future<SenderKeyDistribution> generateSenderKey(String groupId) async {
    final senderId = await _cryptoStorage.readRaw('user_id') ?? '';
    CryptoDebugLogger.log('SENDER_KEY', '═══ Generating Sender Key ═══');
    CryptoDebugLogger.log('SENDER_KEY', 'groupId=$groupId senderId=$senderId');

    // Generate 32-byte random chain key
    final chainKey = _generateRandomBytes(32);
    // Generate Ed25519 key pair for asymmetric signing
    final signingKeyPair = await SignalKeyHelper.generateSigningKeyPair();

    final state = SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      iteration: 0,
      chainKey: chainKey,
      signingPublicKey: signingKeyPair.publicKey,
      signingPrivateKey: signingKeyPair.privateKey, // Keep private!
    );

    // Persist our own sender key (includes private signing key)
    await _saveSenderKey(groupId, senderId, state);

    CryptoDebugLogger.log('SENDER_KEY', '═══ Sender Key generated ═══');

    // Distribute ONLY the public signing key
    return SenderKeyDistribution(
      groupId: groupId,
      senderId: senderId,
      iteration: 0,
      chainKey: base64Encode(chainKey),
      signingKey: signingKeyPair.publicKey, // Public only!
    );
  }

  // ── Process Distribution ──────────────────────────────────────────

  /// Process a received Sender Key distribution message. Stores the
  /// sender's key so we can decrypt their future group messages.
  Future<void> processSenderKeyDistribution(
    String groupId,
    String senderId,
    SenderKeyDistribution distribution,
  ) async {
    CryptoDebugLogger.log(
      'SENDER_KEY',
      '═══ Processing Sender Key distribution ═══',
    );
    CryptoDebugLogger.log(
      'SENDER_KEY',
      'groupId=$groupId senderId=$senderId iteration=${distribution.iteration}',
    );

    final state = SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      iteration: distribution.iteration,
      chainKey: base64Decode(distribution.chainKey),
      signingPublicKey: distribution.signingKey, // Public key only
      signingPrivateKey: null, // We don't have sender's private key
    );

    await _saveSenderKey(groupId, senderId, state);

    CryptoDebugLogger.log('SENDER_KEY', '═══ Sender Key stored ═══');
  }

  // ── Encrypt ───────────────────────────────────────────────────────

  /// Encrypt a message for the group using our Sender Key.
  ///
  /// The plaintext is padded with [MessagePadding] before encryption.
  /// After encryption, the chain key ratchets forward.
  Future<SenderKeyMessage> encrypt(String groupId, List<int> plaintext) async {
    final senderId = await _cryptoStorage.readRaw('user_id') ?? '';
    CryptoDebugLogger.log('SENDER_KEY', '═══ Encrypting group message ═══');
    CryptoDebugLogger.log('SENDER_KEY', 'groupId=$groupId senderId=$senderId');

    final state = await _loadSenderKey(groupId, senderId);
    if (state == null) {
      throw StateError(
        'No Sender Key found for group $groupId. '
        'Call generateSenderKey() first.',
      );
    }

    // Derive message key from current chain key
    final messageKey = await _deriveMessageKey(state.chainKey);

    // Generate random 16-byte IV for AES-256-CBC
    final iv = _generateRandomBytes(16);

    // Encrypt with AES-256-CBC
    final ciphertext = await _aes256CbcEncrypt(plaintext, messageKey, iv);

    // Ed25519 signature over the ciphertext for authentication
    final signatureInput = <int>[
      ...iv,
      ...ciphertext,
      ..._intToBytes(state.iteration),
    ];

    if (state.signingPrivateKey == null) {
      throw StateError(
        'Cannot encrypt — no signing private key. '
        'This is a received sender key, not our own. '
        'Call generateSenderKey() to create your own sender key.',
      );
    }
    final signature = await SignalKeyHelper.sign(
      state.signingPrivateKey!,
      signatureInput,
    );

    final currentIteration = state.iteration;

    // Ratchet the chain key forward — zero old key for forward secrecy
    final oldChainKey = state.chainKey;
    state.chainKey = await _deriveNextChainKey(oldChainKey);
    state.iteration++;
    // Zero old chain key so a memory dump can't recover previous keys
    for (var i = 0; i < oldChainKey.length; i++) {
      oldChainKey[i] = 0;
    }

    // Persist updated state
    await _saveSenderKey(groupId, senderId, state);

    CryptoDebugLogger.log(
      'SENDER_KEY',
      'Encrypted at iteration=$currentIteration, new iteration=${state.iteration}',
    );
    CryptoDebugLogger.log('SENDER_KEY', '═══ Group message encrypted ═══');

    return SenderKeyMessage(
      iteration: currentIteration,
      ciphertext: base64Encode(ciphertext),
      iv: base64Encode(iv),
      signature: signature, // Already base64 from SignalKeyHelper.sign
    );
  }

  // ── Decrypt ───────────────────────────────────────────────────────

  /// Decrypt a group message from a specific sender.
  ///
  /// If the message iteration is ahead of our stored state, we
  /// fast-forward the chain key to catch up (up to [_maxSkipIterations]).
  ///
  /// Uses a per-key async mutex to prevent concurrent calls for the same
  /// group+sender from corrupting the chain key state.
  Future<List<int>> decrypt(
    String groupId,
    String senderId,
    SenderKeyMessage message,
  ) async {
    final lockKey = '$groupId:$senderId';

    // Wait for any in-flight decrypt on the same sender key
    while (_decryptLocks[lockKey] != null) {
      await _decryptLocks[lockKey]!.future;
    }
    _decryptLocks[lockKey] = Completer<void>();

    try {
      return await _decryptInner(groupId, senderId, message);
    } finally {
      final lock = _decryptLocks[lockKey];
      _decryptLocks.remove(lockKey);
      lock?.complete();
    }
  }

  /// Inner decrypt logic, protected by the per-key mutex in [decrypt].
  Future<List<int>> _decryptInner(
    String groupId,
    String senderId,
    SenderKeyMessage message,
  ) async {
    CryptoDebugLogger.log('SENDER_KEY', '═══ Decrypting group message ═══');
    CryptoDebugLogger.log(
      'SENDER_KEY',
      'groupId=$groupId senderId=$senderId msgIteration=${message.iteration}',
    );

    final state = await _loadSenderKey(groupId, senderId);
    if (state == null) {
      throw StateError(
        'No Sender Key found for $senderId in group $groupId. '
        'Waiting for Sender Key distribution.',
      );
    }

    CryptoDebugLogger.log('SENDER_KEY', 'Stored iteration=${state.iteration}');

    if (message.iteration < state.iteration) {
      throw StateError(
        'Sender Key message iteration ${message.iteration} is behind '
        'stored iteration ${state.iteration}. Possible replay attack.',
      );
    }

    // Fast-forward chain key to the message's iteration
    final skip = message.iteration - state.iteration;
    if (skip > _maxSkipIterations) {
      throw StateError(
        'Too many skipped iterations ($skip > $_maxSkipIterations). '
        'Possible DoS attempt.',
      );
    }

    // Use a copy of the chain key for derivation so we can advance
    // the state to iteration+1 after successful decryption
    List<int> chainKey = List<int>.from(state.chainKey);
    for (var i = 0; i < skip; i++) {
      final oldKey = chainKey;
      chainKey = await _deriveNextChainKey(oldKey);
      // Zero intermediate chain keys for forward secrecy
      for (var j = 0; j < oldKey.length; j++) {
        oldKey[j] = 0;
      }
    }

    // Derive the message key at the target iteration
    final messageKey = await _deriveMessageKey(chainKey);

    // Verify Ed25519 signature
    final iv = base64Decode(message.iv);
    final ciphertext = base64Decode(message.ciphertext);

    final signatureInput = <int>[
      ...iv,
      ...ciphertext,
      ..._intToBytes(message.iteration),
    ];

    final signatureValid = await SignalKeyHelper.verify(
      state.signingPublicKey,
      signatureInput,
      message.signature,
    );
    if (!signatureValid) {
      throw StateError(
        'Sender Key Ed25519 signature verification failed. '
        'Message tampered or forged.',
      );
    }

    // Decrypt with AES-256-CBC
    final plaintext = await _aes256CbcDecrypt(ciphertext, messageKey, iv);

    // Advance the stored state past this message — zero old keys
    final oldStateChainKey = state.chainKey;
    state.chainKey = await _deriveNextChainKey(chainKey);
    state.iteration = message.iteration + 1;
    await _saveSenderKey(groupId, senderId, state);
    // Zero old chain keys for forward secrecy
    for (var i = 0; i < oldStateChainKey.length; i++) {
      oldStateChainKey[i] = 0;
    }
    for (var i = 0; i < chainKey.length; i++) {
      chainKey[i] = 0;
    }

    CryptoDebugLogger.log(
      'SENDER_KEY',
      'Decrypted successfully, new stored iteration=${state.iteration}',
    );
    CryptoDebugLogger.log('SENDER_KEY', '═══ Group message decrypted ═══');

    return plaintext;
  }

  // ── Queries ───────────────────────────────────────────────────────

  /// Check if we have our own sender key for a group (i.e., we've
  /// already generated and can encrypt).
  Future<bool> hasOwnSenderKey(String groupId) async {
    final senderId = await _cryptoStorage.readRaw('user_id') ?? '';
    final state = await _loadSenderKey(groupId, senderId);
    return state != null;
  }

  /// Check if we have a sender key for a specific member of a group.
  Future<bool> hasSenderKeyFor(String groupId, String senderId) async {
    final state = await _loadSenderKey(groupId, senderId);
    return state != null;
  }

  // ── Private: Chain Key Derivation ─────────────────────────────────

  /// Derive the next chain key: HMAC-SHA256(chainKey, 0x01)
  static Future<List<int>> _deriveNextChainKey(List<int> chainKey) async {
    final mac = await _hmac.calculateMac([
      0x01,
    ], secretKey: SecretKey(chainKey));
    return mac.bytes;
  }

  /// Derive a message key from the current chain key: HMAC-SHA256(chainKey, 0x02)
  static Future<List<int>> _deriveMessageKey(List<int> chainKey) async {
    final mac = await _hmac.calculateMac([
      0x02,
    ], secretKey: SecretKey(chainKey));
    return mac.bytes;
  }

  // ── Private: AES-256-CBC ──────────────────────────────────────────

  /// AES-256-CBC encryption using the `cryptography` package's AesCbc.
  static Future<List<int>> _aes256CbcEncrypt(
    List<int> plaintext,
    List<int> key,
    List<int> iv,
  ) async {
    final algorithm = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);
    final secretKey = SecretKey(key);
    // Pad plaintext to AES block size (PKCS7)
    final padded = _pkcs7Pad(plaintext, 16);
    final secretBox = await algorithm.encrypt(
      padded,
      secretKey: secretKey,
      nonce: iv,
    );
    return secretBox.cipherText;
  }

  /// AES-256-CBC decryption.
  static Future<List<int>> _aes256CbcDecrypt(
    List<int> ciphertext,
    List<int> key,
    List<int> iv,
  ) async {
    final algorithm = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);
    final secretKey = SecretKey(key);
    final secretBox = SecretBox(ciphertext, nonce: iv, mac: Mac.empty);
    final padded = await algorithm.decrypt(secretBox, secretKey: secretKey);
    return _pkcs7Unpad(padded);
  }

  // ── Private: PKCS7 Padding ────────────────────────────────────────

  static Uint8List _pkcs7Pad(List<int> data, int blockSize) {
    final padLen = blockSize - (data.length % blockSize);
    final padded = Uint8List(data.length + padLen);
    padded.setRange(0, data.length, data);
    for (var i = data.length; i < padded.length; i++) {
      padded[i] = padLen;
    }
    return padded;
  }

  static List<int> _pkcs7Unpad(List<int> data) {
    if (data.isEmpty) throw const FormatException('Empty PKCS7 data');
    final padLen = data.last;
    if (padLen < 1 || padLen > 16 || padLen > data.length) {
      throw FormatException('Invalid PKCS7 padding: $padLen');
    }
    // Verify all padding bytes are correct
    for (var i = data.length - padLen; i < data.length; i++) {
      if (data[i] != padLen) {
        throw FormatException('Invalid PKCS7 padding byte at $i');
      }
    }
    return data.sublist(0, data.length - padLen);
  }

  // ── Private: Utilities ────────────────────────────────────────────

  static List<int> _generateRandomBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  /// Convert an integer to a 4-byte big-endian representation.
  static List<int> _intToBytes(int value) {
    return [
      (value >> 24) & 0xFF,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF,
    ];
  }

}
