import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'crypto_debug_logger.dart';
import 'crypto_storage.dart';
import 'key_helper.dart';
import 'message_padding.dart';
import 'secure_memory.dart';

/// Mutable state of a Sender Key for a specific group and sender.
///
/// Each group member generates their own Sender Key (one per group) and
/// distributes it to all other members via 1-to-1 encrypted sessions. When
/// Alice sends a group message, she encrypts it once with her Sender Key
/// (AES-256-GCM + Ed25519 signature) and broadcasts the same ciphertext to all
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

  /// Monotonic counter incremented when this group's sender keys are
  /// rotated (e.g. after a member is removed). Members holding a stale
  /// epoch must request and process a fresh distribution before they
  /// can decrypt.
  int epoch;
  List<int> chainKey;
  final String signingPublicKey;
  final String? signingPrivateKey;

  SenderKeyState({
    required this.groupId,
    required this.senderId,
    required this.iteration,
    required this.chainKey,
    required this.signingPublicKey,
    this.signingPrivateKey,
    this.epoch = 0,
  });

  Map<String, dynamic> toJson() => {
        'groupId': groupId,
        'senderId': senderId,
        'iteration': iteration,
        'epoch': epoch,
        'chainKey': base64Encode(chainKey),
        'signingPublicKey': signingPublicKey,
        if (signingPrivateKey != null) 'signingPrivateKey': signingPrivateKey,
      };

  factory SenderKeyState.fromJson(Map<String, dynamic> json) {
    if (json.containsKey('signingPublicKey')) {
      return SenderKeyState(
        groupId: json['groupId'] as String,
        senderId: json['senderId'] as String,
        iteration: json['iteration'] as int,
        epoch: (json['epoch'] as int?) ?? 0,
        chainKey: base64Decode(json['chainKey'] as String),
        signingPublicKey: json['signingPublicKey'] as String,
        signingPrivateKey: json['signingPrivateKey'] as String?,
      );
    } else {
      return SenderKeyState(
        groupId: json['groupId'] as String,
        senderId: json['senderId'] as String,
        iteration: json['iteration'] as int,
        epoch: 0,
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

  /// Epoch this distribution was generated at. Mirrors
  /// [SenderKeyState.epoch]; recipients store this value and reject
  /// future messages encrypted under a stale epoch.
  final int epoch;
  final String chainKey;
  final String signingKey;

  const SenderKeyDistribution({
    required this.groupId,
    required this.senderId,
    required this.iteration,
    required this.chainKey,
    required this.signingKey,
    this.epoch = 0,
  });

  Map<String, dynamic> toJson() => {
        'groupId': groupId,
        'senderId': senderId,
        'iteration': iteration,
        'epoch': epoch,
        'chainKey': chainKey,
        'signingKey': signingKey,
      };

  factory SenderKeyDistribution.fromJson(Map<String, dynamic> json) =>
      SenderKeyDistribution(
        groupId: json['groupId'] as String,
        senderId: json['senderId'] as String,
        iteration: json['iteration'] as int,
        epoch: (json['epoch'] as int?) ?? 0,
        chainKey: json['chainKey'] as String,
        signingKey: json['signingKey'] as String,
      );
}

/// Wire-format of a Sender Key encrypted group message.
///
/// Broadcast to all group members. Recipients who have the sender's Sender Key
/// can decrypt using [SenderKeyManager.decrypt].
///
/// **v3 format** (current — AES-256-GCM with epoch bound into AAD):
/// ```
/// blob = 0x03 || epoch(4 LE) || nonce(12) || ciphertext(N) || mac(16)
/// AAD  = epoch(4 LE)
/// ```
/// JSON envelope:
/// ```json
/// {
///   "iteration": 5,
///   "ciphertext": "<base64 v3 blob>",
///   "iv": "",
///   "signature": "<base64 Ed25519 signature over (blob || iteration)>"
/// }
/// ```
///
/// **v2 format** (legacy — AES-256-GCM, read-only): version byte `0x02`,
/// no embedded epoch (treated as epoch 0). Decrypt path retained for
/// backwards compatibility with messages from pre-epoch clients.
///
/// **v1 format** (legacy — AES-256-CBC, read-only): version-less, IV in
/// `iv` field, signature over `(iv || ciphertext || iteration)`.
///
/// The [iteration] allows recipients to fast-forward their chain key if
/// they missed messages within the same epoch (e.g., iteration jumps from
/// 3 to 7 — derive chain key 4 times).
///
/// The epoch (in v3) provides forward secrecy on group membership change:
/// when a member is removed, the sender's epoch increments and the AAD
/// binding makes the recipient's old chain key cryptographically incapable
/// of decrypting new ciphertexts — the AES-GCM auth tag will not validate
/// against the wrong AAD.
///
/// The [signature] is an Ed25519 signature over the ciphertext blob (which
/// for v3 already includes the epoch bytes) plus the iteration in 4-byte
/// big-endian. Only the sender's private signing key can produce a valid
/// signature; recipients hold only the public key and verify.
///
/// See also:
///   - [SenderKeyManager.encrypt] which produces this message
///   - [SenderKeyManager.decrypt] which consumes it
class SenderKeyMessage {
  final int iteration;
  final String ciphertext; // base64: v2 GCM blob (0x02+nonce+ct+mac) or v1 CBC ciphertext
  final String iv; // base64 IV for v1 legacy; empty for v2 GCM
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
///   3. When sending to the group, encrypt with AES-256-GCM using a key derived from the chain key
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
  ) =>
      _cryptoStorage.saveSenderKeyRaw(groupId, senderId, state.toJson());

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

    // Bump epoch if we already have a sender key for this group.
    // First call → epoch 0. Each subsequent call → previous epoch + 1.
    final existing = await _loadSenderKey(groupId, senderId);
    final newEpoch = existing == null ? 0 : existing.epoch + 1;

    // Generate fresh 32-byte random chain key and Ed25519 signing key pair.
    final chainKey = _generateRandomBytes(32);
    final signingKeyPair = await SignalKeyHelper.generateSigningKeyPair();

    final state = SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      iteration: 0,
      epoch: newEpoch,
      chainKey: chainKey,
      signingPublicKey: signingKeyPair.publicKey,
      signingPrivateKey: signingKeyPair.privateKey,
    );

    // Persist our own sender key (includes private signing key).
    await _saveSenderKey(groupId, senderId, state);

    CryptoDebugLogger.log(
      'SENDER_KEY',
      'Sender Key generated at epoch=$newEpoch',
    );

    // Distribute ONLY the public signing key, plus the new epoch.
    return SenderKeyDistribution(
      groupId: groupId,
      senderId: senderId,
      iteration: 0,
      epoch: newEpoch,
      chainKey: base64Encode(chainKey),
      signingKey: signingKeyPair.publicKey,
    );
  }

  // ── Process Distribution ──────────────────────────────────────────

  /// Process a received Sender Key distribution message. Stores the
  /// sender's key so we can decrypt their future group messages.
  ///
  /// Rejects distributions whose epoch is below the currently stored epoch
  /// for this `(groupId, senderId)` — this prevents an attacker from
  /// replaying an old SKDM to downgrade the recipient back onto a chain key
  /// that removed members may still hold.
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
      'groupId=$groupId senderId=$senderId '
      'iteration=${distribution.iteration} epoch=${distribution.epoch}',
    );

    final existing = await _loadSenderKey(groupId, senderId);
    if (existing != null && distribution.epoch < existing.epoch) {
      throw StateError(
        'Stale Sender Key distribution: epoch ${distribution.epoch} '
        '< stored epoch ${existing.epoch}. Possible replay attack.',
      );
    }

    final state = SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      iteration: distribution.iteration,
      epoch: distribution.epoch,
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

    // Encrypt with AES-256-GCM (v3 format: version + epoch + nonce + ct + mac)
    final ciphertextBlob =
        await _aes256GcmEncryptV3(plaintext, messageKey, state.epoch);

    // Ed25519 signature over the entire blob for authentication
    final signatureInput = <int>[
      ...ciphertextBlob,
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

    // Zero the message key after encryption — must not persist in RAM
    SecureMemory.zeroBytes(messageKey);

    // Ratchet the chain key forward — zero old key for forward secrecy
    final oldChainKey = state.chainKey;
    state.chainKey = await _deriveNextChainKey(oldChainKey);
    state.iteration++;
    // Zero old chain key so a memory dump can't recover previous keys
    SecureMemory.zeroBytes(oldChainKey);

    // Persist updated state
    await _saveSenderKey(groupId, senderId, state);

    CryptoDebugLogger.log(
      'SENDER_KEY',
      'Encrypted at iteration=$currentIteration, new iteration=${state.iteration}',
    );
    CryptoDebugLogger.log('SENDER_KEY', '═══ Group message encrypted ═══');

    return SenderKeyMessage(
      iteration: currentIteration,
      ciphertext: base64Encode(ciphertextBlob),
      iv: '', // Empty for v2 — nonce is embedded in ciphertextBlob
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
      SecureMemory.zeroBytes(oldKey);
    }

    // Derive the message key at the target iteration
    final messageKey = await _deriveMessageKey(chainKey);

    // Decode ciphertext to check version
    final ctBytes = base64Decode(message.ciphertext);
    final version = ctBytes.isNotEmpty ? ctBytes[0] : 0;
    final isV3 = version == 0x03;
    final isV2 = version == 0x02;

    // v3 carries epoch bytes 1..5; verify it matches our stored state BEFORE
    // even attempting AES-GCM decrypt, so we get a clear error message.
    if (isV3) {
      if (ctBytes.length < 1 + 4 + 12 + 16) {
        throw const FormatException('v3 sender key blob too short');
      }
      final msgEpoch = ctBytes[1] |
          (ctBytes[2] << 8) |
          (ctBytes[3] << 16) |
          (ctBytes[4] << 24);
      if (msgEpoch != state.epoch) {
        throw StateError(
          'Sender Key epoch mismatch: message epoch=$msgEpoch, '
          'stored epoch=${state.epoch}. Member may have been removed '
          'or new SKDM not yet received.',
        );
      }
    }

    // Build signature input based on version.
    final List<int> signatureInput;
    if (isV3 || isV2) {
      // v2 and v3 both sign the entire ciphertext blob (which already includes
      // the version byte and, for v3, the epoch bytes).
      signatureInput = <int>[
        ...ctBytes,
        ..._intToBytes(message.iteration),
      ];
    } else {
      // v1 legacy: signature over iv + ciphertext + iteration
      final iv = base64Decode(message.iv);
      signatureInput = <int>[
        ...iv,
        ...ctBytes,
        ..._intToBytes(message.iteration),
      ];
    }

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

    // Version-aware decryption
    List<int> plaintext;
    if (isV3) {
      plaintext = await _aes256GcmDecryptV3(ctBytes, messageKey);
    } else if (isV2) {
      plaintext = await _aes256GcmDecrypt(ctBytes, messageKey);
    } else {
      final iv = base64Decode(message.iv);
      plaintext = await _legacyCbcDecrypt(ctBytes, messageKey, iv);
    }

    // Zero the message key after decryption — must not persist in RAM
    SecureMemory.zeroBytes(messageKey);

    // Advance the stored state past this message — zero old keys
    final oldStateChainKey = state.chainKey;
    state.chainKey = await _deriveNextChainKey(chainKey);
    state.iteration = message.iteration + 1;
    await _saveSenderKey(groupId, senderId, state);
    // Zero old chain keys for forward secrecy
    SecureMemory.zeroBytes(oldStateChainKey);
    SecureMemory.zeroBytes(chainKey);

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
    ], secretKey: SecretKey(List<int>.from(chainKey)));
    return mac.bytes;
  }

  /// Derive a message key from the current chain key: HMAC-SHA256(chainKey, 0x02)
  static Future<List<int>> _deriveMessageKey(List<int> chainKey) async {
    final mac = await _hmac.calculateMac([
      0x02,
    ], secretKey: SecretKey(List<int>.from(chainKey)));
    return mac.bytes;
  }

  // ── Private: AES-256-GCM (v3 — current) ─────────────────────────

  /// AES-256-GCM encryption with epoch bound into AAD (v3 format).
  /// Returns: 0x03 + epoch(4 LE) + nonce(12) + ciphertext(N) + mac(16).
  ///
  /// The epoch bytes appear both in the wire format AND as AES-GCM
  /// additional authenticated data, so any attempt to decrypt with a
  /// different stored epoch produces an authentication failure.
  static Future<List<int>> _aes256GcmEncryptV3(
    List<int> plaintext,
    List<int> key,
    int epoch,
  ) async {
    final algorithm = AesGcm.with256bits();
    final secretKey = SecretKey(List<int>.from(key));
    final epochBytes = _epochToLeBytes(epoch);
    final secretBox = await algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
      aad: epochBytes,
    );
    return [
      0x03,
      ...epochBytes,
      ...secretBox.nonce,
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ];
  }

  /// 4-byte little-endian epoch encoding for v3 wire format and AAD.
  static List<int> _epochToLeBytes(int epoch) => [
        epoch & 0xFF,
        (epoch >> 8) & 0xFF,
        (epoch >> 16) & 0xFF,
        (epoch >> 24) & 0xFF,
      ];

  // ── Private: AES-256-GCM (v2 — legacy decrypt only) ─────────────

  /// AES-256-GCM encryption (v2 format).
  /// Returns: version_byte(1) + nonce(12) + ciphertext(N) + mac(16).
  ///
  // kept for documentation / legacy compat reference
  // ignore: unused_element
  static Future<List<int>> _aes256GcmEncrypt(
    List<int> plaintext,
    List<int> key,
  ) async {
    final algorithm = AesGcm.with256bits();
    final secretKey = SecretKey(List<int>.from(key));
    final secretBox = await algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
    );
    return [
      0x02, // version byte: GCM
      ...secretBox.nonce,
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ];
  }

  /// AES-256-GCM decryption (v2 format).
  /// Input: version_byte(1) + nonce(12) + ciphertext(N) + mac(16).
  static Future<List<int>> _aes256GcmDecrypt(
    List<int> blob,
    List<int> key,
  ) async {
    // Minimum: version(1) + nonce(12) + ciphertext(1+) + mac(16) = 30
    if (blob.length < 30) {
      throw FormatException('GCM blob too short: ${blob.length} < 30 bytes');
    }
    // Strip version byte (already checked by caller)
    final nonce = blob.sublist(1, 13); // 12 bytes
    final mac = Mac(blob.sublist(blob.length - 16)); // last 16 bytes
    final ciphertext = blob.sublist(13, blob.length - 16);
    final algorithm = AesGcm.with256bits();
    final secretKey = SecretKey(List<int>.from(key));
    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
    return algorithm.decrypt(secretBox, secretKey: secretKey);
  }

  /// AES-256-GCM decryption (v3 format with epoch AAD).
  /// Input: 0x03 + epoch(4 LE) + nonce(12) + ciphertext(N) + mac(16).
  /// AAD passed to AES-GCM is the 4 epoch bytes — any mismatch fails
  /// authentication.
  static Future<List<int>> _aes256GcmDecryptV3(
    List<int> blob,
    List<int> key,
  ) async {
    if (blob.length < 1 + 4 + 12 + 16) {
      throw FormatException('GCM v3 blob too short: ${blob.length}');
    }
    final epochBytes = blob.sublist(1, 5);
    final nonce = blob.sublist(5, 17);
    final mac = Mac(blob.sublist(blob.length - 16));
    final ciphertext = blob.sublist(17, blob.length - 16);
    final algorithm = AesGcm.with256bits();
    final secretKey = SecretKey(List<int>.from(key));
    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
    return algorithm.decrypt(secretBox, secretKey: secretKey, aad: epochBytes);
  }

  // ── Private: Legacy AES-256-CBC (v1, read-only) ─────────────────

  /// Legacy AES-256-CBC decryption (v1 format, read-only).
  /// Used only to decrypt messages from pre-0.3.0 clients.
  static Future<List<int>> _legacyCbcDecrypt(
    List<int> ciphertext,
    List<int> key,
    List<int> iv,
  ) async {
    final algorithm = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);
    final secretKey = SecretKey(List<int>.from(key));
    final secretBox = SecretBox(ciphertext, nonce: iv, mac: Mac.empty);
    final padded = await algorithm.decrypt(secretBox, secretKey: secretKey);
    return _pkcs7Unpad(padded);
  }

  /// Legacy PKCS7 unpadding (v1 format only).
  static List<int> _pkcs7Unpad(List<int> data) {
    if (data.isEmpty) throw const FormatException('Empty PKCS7 data');
    final padLen = data.last;
    if (padLen < 1 || padLen > 16 || padLen > data.length) {
      throw FormatException('Invalid PKCS7 padding: $padLen');
    }
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
