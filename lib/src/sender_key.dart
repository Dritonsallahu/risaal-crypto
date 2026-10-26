import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'crypto_debug_logger.dart';
import 'crypto_protocol.dart';
import 'crypto_storage.dart';
import 'key_helper.dart';
import 'message_padding.dart';
import 'secure_memory.dart';

enum SenderKeyDependencyCode {
  missingKey,
  keyStateMismatch,
  epochMismatch,
  iterationGap,
  messageOutsideWindow,
}

/// A group message could not be decrypted because this device's SenderKey
/// state is missing or no longer matches the sender's authenticated state.
///
/// Callers may request the current distribution and retry the exact ciphertext.
/// Extending [StateError] keeps older callers fail-closed while giving current
/// callers a stable machine-readable code instead of parsing exception text.
class SenderKeyDependencyError extends StateError {
  final SenderKeyDependencyCode code;

  SenderKeyDependencyError(this.code, String message) : super(message);
}

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
  static const int currentStorageVersion = 2;

  final String groupId;
  final String senderId;
  final int cryptoProtocolEpoch;
  int iteration;

  /// Monotonic counter incremented when this group's sender keys are
  /// rotated (e.g. after a member is removed). Members holding a stale
  /// epoch must request and process a fresh distribution before they
  /// can decrypt.
  int epoch;
  List<int> chainKey;
  final String signingPublicKey;
  final String? signingPrivateKey;

  /// Message keys for iterations that were skipped over, by iteration.
  ///
  /// Sender-key decryption used to fast-forward the chain and zero every
  /// intermediate key, keeping nothing. Since the relay decides what order
  /// group messages arrive in — the realtime lane decrypts each frame as it
  /// lands, and the history lane sorts on a relay-authored `createdAt` — it
  /// could deliver a later message first and permanently destroy every earlier
  /// one on the recipient's device. Not delay: destroy. The chain had moved and
  /// the KDF only runs forward, so no redelivery, reinstall or resync could
  /// ever recover them, and the resulting error triggered no re-request.
  ///
  /// Retaining the skipped keys makes out-of-order delivery survivable, which
  /// is what the Double Ratchet already does for 1:1. The store is bounded, so
  /// a peer cannot make this grow without limit.
  final Map<int, List<int>> skippedMessageKeys;

  /// When each retained key was stored, so age can bound them as well as count.
  ///
  /// A count bound alone means a store that fills up and then goes quiet holds
  /// 2000 message keys for the life of the install — for messages this device
  /// never received and may never receive. On the device-seizure surface this
  /// product exists to survive, that is a forward-secrecy regression: before
  /// the store existed those keys were derived, used for nothing and zeroed.
  final Map<int, int> skippedMessageKeyAges;

  static const int maxSkippedMessageKeys = 2000;

  /// How long a retained key may outlive the message it was kept for.
  static const Duration skippedMessageKeyLifetime = Duration(days: 14);

  SenderKeyState({
    required this.groupId,
    required this.senderId,
    required this.cryptoProtocolEpoch,
    required this.iteration,
    required this.chainKey,
    required this.signingPublicKey,
    this.signingPrivateKey,
    required this.epoch,
    Map<int, List<int>>? skippedMessageKeys,
    Map<int, int>? skippedMessageKeyAges,
  }) : skippedMessageKeys = skippedMessageKeys ?? <int, List<int>>{},
       skippedMessageKeyAges = skippedMessageKeyAges ?? <int, int>{};

  Map<String, dynamic> toJson() => {
    'storageVersion': currentStorageVersion,
    'cryptoProtocolEpoch': cryptoProtocolEpoch,
    'groupId': groupId,
    'senderId': senderId,
    'iteration': iteration,
    'epoch': epoch,
    'chainKey': base64Encode(chainKey),
    'signingPublicKey': signingPublicKey,
    if (signingPrivateKey != null) 'signingPrivateKey': signingPrivateKey,
    if (skippedMessageKeys.isNotEmpty)
      'skippedMessageKeys': {
        for (final entry in skippedMessageKeys.entries)
          '${entry.key}': base64Encode(entry.value),
      },
    if (skippedMessageKeyAges.isNotEmpty)
      'skippedMessageKeyAges': {
        for (final entry in skippedMessageKeyAges.entries)
          '${entry.key}': entry.value,
      },
  };

  /// Decode the skipped-key store, discarding anything malformed rather than
  /// failing the whole state: a bad entry costs one unreadable message, while
  /// refusing the state costs the entire conversation.
  static Map<int, int> _decodeSkippedAges(Object? raw) {
    final out = <int, int>{};
    if (raw is! Map) return out;
    for (final entry in raw.entries) {
      final iteration = int.tryParse('${entry.key}');
      final at = entry.value;
      if (iteration == null || at is! int) continue;
      out[iteration] = at;
    }
    return out;
  }

  static Map<int, List<int>> _decodeSkippedKeys(Object? raw) {
    final out = <int, List<int>>{};
    if (raw is! Map) return out;
    for (final entry in raw.entries) {
      final iteration = int.tryParse('${entry.key}');
      if (iteration == null || iteration < 0) continue;
      final value = entry.value;
      if (value is! String) continue;
      try {
        final key = base64Decode(value);
        if (key.length != 32) continue;
        out[iteration] = key;
      } on FormatException {
        continue;
      }
      if (out.length >= maxSkippedMessageKeys) break;
    }
    return out;
  }

  factory SenderKeyState.fromJson(Map<String, dynamic> json) {
    final storageVersion = json['storageVersion'];
    final protocolEpoch = json['cryptoProtocolEpoch'];
    final groupId = json['groupId'];
    final senderId = json['senderId'];
    final iteration = json['iteration'];
    final epoch = json['epoch'];
    final chainKey = json['chainKey'];
    final signingPublicKey = json['signingPublicKey'];
    final signingPrivateKey = json['signingPrivateKey'];
    if (storageVersion != currentStorageVersion ||
        protocolEpoch != RisaalCryptoProtocol.cryptoProtocolEpoch ||
        groupId is! String ||
        groupId.isEmpty ||
        senderId is! String ||
        senderId.isEmpty ||
        iteration is! int ||
        iteration < 0 ||
        epoch is! int ||
        epoch < 0 ||
        chainKey is! String ||
        signingPublicKey is! String ||
        (signingPrivateKey != null && signingPrivateKey is! String)) {
      throw const FormatException('Unsupported or invalid Sender Key state');
    }
    try {
      final privateKeyLength = signingPrivateKey == null
          ? null
          : base64Decode(signingPrivateKey as String).length;
      if (base64Decode(chainKey).length != 32 ||
          base64Decode(signingPublicKey).length != 32 ||
          (privateKeyLength != null &&
              privateKeyLength != 32 &&
              privateKeyLength != 64)) {
        throw const FormatException();
      }
    } catch (_) {
      throw const FormatException('Invalid Sender Key state key material');
    }
    final skippedKeys = _decodeSkippedKeys(json['skippedMessageKeys']);
    final skippedAges = _decodeSkippedAges(json['skippedMessageKeyAges'])
      ..removeWhere((iteration, _) => !skippedKeys.containsKey(iteration));
    return SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      cryptoProtocolEpoch: protocolEpoch,
      iteration: iteration,
      epoch: epoch,
      skippedMessageKeys: skippedKeys,
      skippedMessageKeyAges: skippedAges,
      chainKey: base64Decode(chainKey),
      signingPublicKey: signingPublicKey,
      signingPrivateKey: signingPrivateKey as String?,
    );
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
  final int cryptoProtocolEpoch;
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
    required this.cryptoProtocolEpoch,
    required this.groupId,
    required this.senderId,
    required this.iteration,
    required this.chainKey,
    required this.signingKey,
    required this.epoch,
  });

  Map<String, dynamic> toJson() => {
    'cryptoProtocolEpoch': cryptoProtocolEpoch,
    'groupId': groupId,
    'senderId': senderId,
    'iteration': iteration,
    'epoch': epoch,
    'chainKey': chainKey,
    'signingKey': signingKey,
  };

  factory SenderKeyDistribution.fromJson(Map<String, dynamic> json) =>
      _fromJson(json);

  static SenderKeyDistribution _fromJson(Map<String, dynamic> json) {
    if (!json.containsKey('epoch')) {
      throw const FormatException('Missing Sender Key distribution epoch');
    }
    final protocolEpoch = json['cryptoProtocolEpoch'];
    final groupId = json['groupId'];
    final senderId = json['senderId'];
    final iteration = json['iteration'];
    final epoch = json['epoch'];
    final chainKey = json['chainKey'];
    final signingKey = json['signingKey'];
    if (protocolEpoch != RisaalCryptoProtocol.cryptoProtocolEpoch ||
        groupId is! String ||
        groupId.isEmpty ||
        senderId is! String ||
        senderId.isEmpty ||
        iteration is! int ||
        iteration < 0 ||
        epoch is! int ||
        epoch < 0 ||
        chainKey is! String ||
        signingKey is! String) {
      throw const FormatException('Invalid Sender Key distribution');
    }
    try {
      if (base64Decode(chainKey).length != 32 ||
          base64Decode(signingKey).length != 32) {
        throw const FormatException();
      }
    } catch (_) {
      throw const FormatException('Invalid Sender Key distribution key');
    }
    return SenderKeyDistribution(
      cryptoProtocolEpoch: protocolEpoch as int,
      groupId: groupId,
      senderId: senderId,
      iteration: iteration,
      epoch: epoch,
      chainKey: chainKey,
      signingKey: signingKey,
    );
  }
}

/// Durable candidate for one group SenderKey epoch rotation.
///
/// The candidate contains the public distribution only. Its private signing
/// key and chain state stay in secure storage until [SenderKeyManager]
/// commits or aborts the exact [rotationId].
class SenderKeyRotationProposal {
  static const int currentVersion = 1;

  final String rotationId;
  final SenderKeyDistribution distribution;

  const SenderKeyRotationProposal({
    required this.rotationId,
    required this.distribution,
  });

  Map<String, dynamic> toJson() => <String, dynamic>{
    'version': currentVersion,
    'rotationId': rotationId,
    'distribution': distribution.toJson(),
  };
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
/// Legacy v2 GCM and v1 CBC blobs are rejected by the live epoch-2 API before
/// sender-key state is loaded or advanced.
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
  static const int currentBlobVersion = 0x03;
  final int iteration;
  final String
  ciphertext; // base64: v2 GCM blob (0x02+nonce+ct+mac) or v1 CBC ciphertext
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

  factory SenderKeyMessage.fromJson(Map<String, dynamic> json) {
    final iteration = json['iteration'];
    final ciphertext = json['ciphertext'];
    final iv = json['iv'];
    final signature = json['signature'];
    if (iteration is! int ||
        iteration < 0 ||
        ciphertext is! String ||
        iv is! String ||
        signature is! String ||
        signature.isEmpty) {
      throw const FormatException('Invalid Sender Key message');
    }
    final message = SenderKeyMessage(
      iteration: iteration,
      ciphertext: ciphertext,
      iv: iv,
      signature: signature,
    );
    message.requireCurrentWireVersion();
    return message;
  }

  void requireCurrentWireVersion() {
    try {
      final bytes = base64Decode(ciphertext);
      final signatureBytes = base64Decode(signature);
      if (bytes.length < 1 + 4 + 12 + 16 ||
          bytes.first != currentBlobVersion ||
          iv.isNotEmpty ||
          signatureBytes.length != 64) {
        throw const FormatException();
      }
    } catch (_) {
      throw const FormatException('Unsupported Sender Key wire version');
    }
  }
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
  /// How far a single message may be ahead of the stored chain position.
  ///
  /// This is a denial-of-service bound on key derivation, not a protocol
  /// limit — each skipped iteration costs one HKDF step and one retained
  /// message key. It was 256, which is a normal week in an active group: a
  /// member who came back after that hit "Too many skipped iterations", and
  /// the only recovery available then was a fresh distribution, which the
  /// roll-forward guard correctly refuses. The result was a member who could
  /// never read that sender again. 2000 matches the retained-key bound, so the
  /// worst case is the same amount of state either way.
  /// How far a single AUTHENTICATED message may be ahead of the stored chain.
  ///
  /// This is a work bound, and its value only matters now that authentication
  /// happens first: a forged frame cannot reach it at all, so it no longer
  /// bounds attacker-triggered work — it bounds how far a genuine sender can
  /// run ahead of a recipient who was offline.
  ///
  /// At 256, and then at 2000, a member who missed enough traffic hit "too many
  /// skipped iterations", asked for a fresh distribution, and was answered with
  /// a same-epoch one that the roll-forward guard correctly refuses — a
  /// permanent lockout with no way back. Since the recipient can derive the gap
  /// from its own chain, the only thing standing between them and recovery was
  /// this number. Retention stays bounded independently, by count and by age.
  static const _maxSkipIterations = 50000;

  /// Per-key async mutex over EVERY operation that reads-then-writes a sender
  /// key state: decrypt, encrypt, generate and process-distribution.
  ///
  /// It used to cover decrypt only, which was enough while rotation could be
  /// started only by the same bloc the user was sending from. Rotation now runs
  /// from a socket-lifetime service, at a moment the relay chooses, on a device
  /// with no chat open — concurrently with a send. Both paths load the state,
  /// await several crypto operations, and only then write it back, so either
  /// order silently discards the other: a lost rotation leaves the ejected
  /// member holding a live key AND makes every later message from this device
  /// unreadable to the group, and a lost send ships an envelope under an epoch
  /// nobody holds any more.
  final Map<String, Completer<void>?> _stateLocks = {};

  Future<T> _withStateLock<T>(
    String groupId,
    String senderId,
    Future<T> Function() action,
  ) async {
    final lockKey = '$groupId:$senderId';
    while (_stateLocks[lockKey] != null) {
      await _stateLocks[lockKey]!.future;
    }
    _stateLocks[lockKey] = Completer<void>();
    try {
      return await action();
    } finally {
      final lock = _stateLocks[lockKey];
      _stateLocks.remove(lockKey);
      lock?.complete();
    }
  }

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
    final state = SenderKeyState.fromJson(json);
    // Expire here, so the bound applies on every read rather than only on a
    // successful decrypt. Its stated purpose is the sender who has gone quiet
    // — and a quiet sender produces no decrypt, so the only call site it had
    // never ran in the one case it was written for. Persist immediately: the
    // decrypt that follows may well throw, and every throw between here and
    // the success path used to discard the expiry.
    if (_expireSkippedKeys(state)) {
      await _saveSenderKey(groupId, senderId, state);
    }
    return state;
  }

  // ── Generate ──────────────────────────────────────────────────────

  /// Generate a new Sender Key for a group. Returns a distribution
  /// message that should be encrypted with each member's 1-to-1 session
  /// and sent to them.
  Future<SenderKeyDistribution> generateSenderKey(String groupId) async {
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    return _withStateLock(
      groupId,
      senderId,
      () => _generateSenderKeyUnlocked(groupId, senderId),
    );
  }

  Future<SenderKeyDistribution> _generateSenderKeyUnlocked(
    String groupId,
    String senderId,
  ) async {
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
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
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
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
      groupId: groupId,
      senderId: senderId,
      iteration: 0,
      epoch: newEpoch,
      chainKey: base64Encode(chainKey),
      signingKey: signingKeyPair.publicKey,
    );
  }

  /// Prepare exactly one durable candidate epoch without activating it.
  ///
  /// Repeating the same [rotationId] after a restart returns byte-identical
  /// public material. A different id while a candidate exists fails closed.
  Future<SenderKeyRotationProposal> prepareSenderKeyRotation(
    String groupId, {
    required String rotationId,
  }) async {
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    return _withStateLock(groupId, senderId, () async {
      _validateRotationId(rotationId);
      final pending = await _loadPendingRotation(groupId, senderId);
      if (pending != null) {
        if (pending.rotationId != rotationId) {
          throw StateError('A different Sender Key rotation is pending');
        }
        return pending.proposal;
      }

      final active = await _loadSenderKey(groupId, senderId);
      if (active == null || active.signingPrivateKey == null) {
        throw StateError('No active local Sender Key exists to rotate');
      }
      final signingKeyPair = await SignalKeyHelper.generateSigningKeyPair();
      final candidate = SenderKeyState(
        groupId: groupId,
        senderId: senderId,
        cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
        iteration: 0,
        epoch: active.epoch + 1,
        chainKey: _generateRandomBytes(32),
        signingPublicKey: signingKeyPair.publicKey,
        signingPrivateKey: signingKeyPair.privateKey,
      );
      final row = _PendingSenderKeyRotation(
        rotationId: rotationId,
        state: candidate,
      );
      await _cryptoStorage.savePendingSenderKeyRotationRaw(
        groupId,
        senderId,
        row.toJson(),
      );
      return row.proposal;
    });
  }

  Future<SenderKeyRotationProposal?> pendingSenderKeyRotation(
    String groupId,
  ) async {
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    return _withStateLock(
      groupId,
      senderId,
      () async => (await _loadPendingRotation(groupId, senderId))?.proposal,
    );
  }

  /// Atomically promote the exact prepared candidate to the active send key.
  ///
  /// Saving the active state precedes deletion of the candidate. A crash in
  /// between is recovered idempotently because the active state then exactly
  /// matches the pending candidate.
  Future<void> commitSenderKeyRotation(
    String groupId, {
    required String rotationId,
  }) async {
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    await _withStateLock(groupId, senderId, () async {
      _validateRotationId(rotationId);
      final pending = await _loadPendingRotation(groupId, senderId);
      if (pending == null || pending.rotationId != rotationId) {
        throw StateError('Exact pending Sender Key rotation not found');
      }
      final active = await _loadSenderKey(groupId, senderId);
      if (active == null ||
          (active.epoch != pending.state.epoch - 1 &&
              !_sameSenderKeyState(active, pending.state))) {
        throw StateError('Sender Key rotation active-state drift');
      }
      if (!_sameSenderKeyState(active, pending.state)) {
        await _saveSenderKey(groupId, senderId, pending.state);
      }
      await _cryptoStorage.deletePendingSenderKeyRotation(groupId, senderId);
    });
  }

  /// Delete an unactivated candidate while preserving the active epoch.
  Future<void> abortSenderKeyRotation(
    String groupId, {
    required String rotationId,
  }) async {
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    await _withStateLock(groupId, senderId, () async {
      _validateRotationId(rotationId);
      final pending = await _loadPendingRotation(groupId, senderId);
      if (pending == null) return;
      if (pending.rotationId != rotationId) {
        throw StateError('Sender Key rotation id does not match');
      }
      await _cryptoStorage.deletePendingSenderKeyRotation(groupId, senderId);
    });
  }

  Future<_PendingSenderKeyRotation?> _loadPendingRotation(
    String groupId,
    String senderId,
  ) async {
    final raw = await _cryptoStorage.getPendingSenderKeyRotationRaw(
      groupId,
      senderId,
    );
    if (raw == null) return null;
    final row = _PendingSenderKeyRotation.fromJson(raw);
    if (row.state.groupId != groupId || row.state.senderId != senderId) {
      throw const FormatException('Pending Sender Key rotation identity drift');
    }
    return row;
  }

  static void _validateRotationId(String rotationId) {
    if (rotationId.isEmpty || rotationId.length > 128) {
      throw const FormatException('Invalid Sender Key rotation id');
    }
  }

  static bool _sameSenderKeyState(SenderKeyState a, SenderKeyState b) =>
      jsonEncode(a.toJson()) == jsonEncode(b.toJson());

  /// The distribution for the sender key we ALREADY hold for [groupId], or
  /// null if this device has never generated one.
  ///
  /// [generateSenderKey] is not idempotent — it mints a fresh chain key and
  /// bumps the epoch every single time — so using it to answer a member's
  /// "I am missing your sender key" request rotated the whole group off this
  /// device's chain and then handed the new chain to that one member. Every
  /// other member kept decrypting at the old epoch and got a hard mismatch,
  /// with no recovery path, for every subsequent message. An unauthenticated
  /// relay frame could trigger that at will.
  ///
  /// Answering a request must therefore share what exists, never re-key. The
  /// distribution carries the CURRENT iteration, so the recipient can read
  /// from now on but not retroactively — which is the correct property for a
  /// member who joined late or lost their copy.
  Future<SenderKeyDistribution?> currentSenderKeyDistribution(
    String groupId,
  ) async {
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    final existing = await _loadSenderKey(groupId, senderId);
    if (existing == null) return null;
    return SenderKeyDistribution(
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
      groupId: groupId,
      senderId: senderId,
      iteration: existing.iteration,
      epoch: existing.epoch,
      chainKey: base64Encode(existing.chainKey),
      signingKey: existing.signingPublicKey,
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
  ) => _withStateLock(
    groupId,
    senderId,
    () =>
        _processSenderKeyDistributionUnlocked(groupId, senderId, distribution),
  );

  Future<void> _processSenderKeyDistributionUnlocked(
    String groupId,
    String senderId,
    SenderKeyDistribution distribution,
  ) async {
    CryptoDebugLogger.log(
      'SENDER_KEY',
      '═══ Processing Sender Key distribution ═══',
    );

    if (distribution.groupId != groupId || distribution.senderId != senderId) {
      throw const FormatException(
        'Sender Key distribution identity does not match its transport',
      );
    }
    if (distribution.cryptoProtocolEpoch !=
        RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException(
        'Unsupported Sender Key distribution protocol',
      );
    }
    if (distribution.iteration < 0 || distribution.epoch < 0) {
      throw const FormatException('Invalid Sender Key distribution counters');
    }
    try {
      if (base64Decode(distribution.chainKey).length != 32 ||
          base64Decode(distribution.signingKey).length != 32) {
        throw const FormatException();
      }
    } catch (_) {
      throw const FormatException('Invalid Sender Key distribution key');
    }
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
    // A LIVE chain may only ever be replaced by a higher epoch — never rolled
    // forward within its own epoch.
    //
    // The epoch guard alone was not enough. A same-epoch distribution at a
    // higher iteration overwrote the stored chain key, and the superseded key
    // cannot be re-derived (the KDF only moves forward), so every message
    // between the two iterations became permanently undecryptable — silently,
    // for that one member. An unauthenticated `senderkey:request` frame naming
    // a real member was enough to make an honest sender produce exactly that
    // distribution while the relay withheld the messages in between.
    //
    // Accepting an EQUAL iteration is harmless (it is the same state) and keeps
    // a genuine retransmission idempotent.
    if (existing != null &&
        distribution.epoch == existing.epoch &&
        distribution.iteration > existing.iteration) {
      throw StateError(
        'Sender Key roll-forward refused: iteration ${distribution.iteration} '
        '> stored iteration ${existing.iteration} at the same epoch. '
        'A live chain may only be replaced by a higher epoch.',
      );
    }

    // Our own chain is the only one holding a private signing key; a
    // distribution naming us would overwrite it with a public-only state and
    // silently end our ability to send to the group.
    final localUserId = await _cryptoStorage.getLocalUserId();
    if (localUserId != null &&
        localUserId.isNotEmpty &&
        senderId == localUserId) {
      throw StateError('Refusing to process our own Sender Key distribution');
    }

    // The same chain arriving again (same epoch, same signer) must never move
    // the stored state BACKWARDS. Rewinding the iteration re-enabled every
    // message already consumed and rejected as a replay, and dropped the
    // cached skipped keys. A redelivery of a chain we already hold is a no-op.
    //
    // A different signing key at the same epoch is a new chain (a sender that
    // reinstalled restarts at epoch 0) and still replaces the stored one:
    // messages signed under the old key cannot verify against the new key, so
    // that replacement opens no replay.
    if (existing != null &&
        distribution.epoch == existing.epoch &&
        distribution.signingKey == existing.signingPublicKey) {
      if (distribution.iteration == existing.iteration &&
          !_constantTimeEquals(
            base64Decode(distribution.chainKey),
            existing.chainKey,
          )) {
        throw StateError(
          'Conflicting Sender Key distribution: same epoch, signer and '
          'iteration but a different chain key.',
        );
      }
      CryptoDebugLogger.log(
        'SENDER_KEY',
        'Same-chain distribution ignored (iteration ${distribution.iteration} '
            '<= stored ${existing.iteration})',
      );
      return;
    }

    final state = SenderKeyState(
      groupId: groupId,
      senderId: senderId,
      cryptoProtocolEpoch: distribution.cryptoProtocolEpoch,
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
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
    return _withStateLock(
      groupId,
      senderId,
      () => _encryptUnlocked(groupId, senderId, plaintext),
    );
  }

  Future<SenderKeyMessage> _encryptUnlocked(
    String groupId,
    String senderId,
    List<int> plaintext,
  ) async {
    CryptoDebugLogger.log('SENDER_KEY', '═══ Encrypting group message ═══');
    CryptoDebugLogger.log('SENDER_KEY', 'groupId=$groupId senderId=$senderId');

    if (await _loadPendingRotation(groupId, senderId) != null) {
      throw StateError(
        'Group sending is paused until the pending Sender Key rotation '
        'commits or aborts',
      );
    }

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
    final ciphertextBlob = await _aes256GcmEncryptV3(
      plaintext,
      messageKey,
      state.epoch,
    );

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
    return _withStateLock(
      groupId,
      senderId,
      () => _decryptInner(groupId, senderId, message),
    );
  }

  /// Drop retained keys that have outlived their usefulness.
  ///
  /// Bounding the store by count alone left up to 2000 message keys on disk
  /// indefinitely whenever a sender went quiet — keys for messages this device
  /// never received, which a seized device plus the relay's copy of the
  /// withheld ciphertexts would decrypt.
  bool _expireSkippedKeys(SenderKeyState state) {
    if (state.skippedMessageKeys.isEmpty) return false;
    final cutoff = DateTime.now()
        .subtract(SenderKeyState.skippedMessageKeyLifetime)
        .millisecondsSinceEpoch;
    final stale = <int>[];
    for (final iteration in state.skippedMessageKeys.keys) {
      final storedAt = state.skippedMessageKeyAges[iteration];
      // An entry with no recorded age predates this bound; treat it as stale
      // rather than immortal.
      if (storedAt == null || storedAt < cutoff) stale.add(iteration);
    }
    for (final iteration in stale) {
      final expired = state.skippedMessageKeys.remove(iteration);
      state.skippedMessageKeyAges.remove(iteration);
      if (expired != null) SecureMemory.zeroBytes(expired);
    }
    return stale.isNotEmpty;
  }

  /// Verify a group message really came from [state]'s owner, and belongs to
  /// the epoch this device holds — before any key material is derived.
  ///
  /// Order matters twice over. Deriving first meant a forged frame could make
  /// the device do thousands of HMAC operations on unauthenticated input. And
  /// checking the epoch first meant a forged frame could raise "epoch
  /// mismatch", which the receive lanes turn into an automatic key re-request
  /// — so the relay could make a victim ask for a fresh distribution on demand.
  Future<void> _requireAuthenticSenderKeyMessage(
    SenderKeyState state,
    SenderKeyMessage message,
  ) async {
    final ctBytes = base64Decode(message.ciphertext);
    final version = ctBytes.isNotEmpty ? ctBytes[0] : 0;
    final isV3 = version == 0x03;
    final isV2 = version == 0x02;

    if (isV3 && ctBytes.length < 1 + 4 + 12 + 16) {
      throw const FormatException('v3 sender key blob too short');
    }

    final List<int> signatureInput;
    if (isV3 || isV2) {
      // v2 and v3 both sign the entire ciphertext blob (which already includes
      // the version byte and, for v3, the epoch bytes).
      signatureInput = <int>[...ctBytes, ..._intToBytes(message.iteration)];
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
      throw SenderKeyDependencyError(
        SenderKeyDependencyCode.keyStateMismatch,
        'Sender Key Ed25519 signature verification failed. '
        'Message tampered or forged.',
      );
    }

    if (isV3) {
      final msgEpoch =
          ctBytes[1] |
          (ctBytes[2] << 8) |
          (ctBytes[3] << 16) |
          (ctBytes[4] << 24);
      if (msgEpoch != state.epoch) {
        throw SenderKeyDependencyError(
          SenderKeyDependencyCode.epochMismatch,
          'Sender Key epoch mismatch: message epoch=$msgEpoch, '
          'stored epoch=${state.epoch}. Member may have been removed '
          'or new SKDM not yet received.',
        );
      }
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

    // Reject v1/v2/future blobs before loading or mutating Sender Key state.
    message.requireCurrentWireVersion();

    final state = await _loadSenderKey(groupId, senderId);
    if (state == null) {
      throw SenderKeyDependencyError(
        SenderKeyDependencyCode.missingKey,
        'No Sender Key found for $senderId in group $groupId. '
        'Waiting for Sender Key distribution.',
      );
    }

    CryptoDebugLogger.log('SENDER_KEY', 'Stored iteration=${state.iteration}');

    // Authenticate FIRST. Everything below derives key material, and the
    // amount of it is chosen by the sender of the frame: a forged message
    // claiming an iteration far ahead used to make this device run thousands
    // of HMAC operations, on the UI isolate, holding the sender-key lock,
    // before the signature was ever checked — at whatever rate the relay
    // chose to emit. An unauthenticated frame now costs one Ed25519 verify.
    await _requireAuthenticSenderKeyMessage(state, message);

    // A message from BEFORE the current chain position is an out-of-order
    // delivery, not necessarily a replay — and the relay decides delivery
    // order. Its key was retained when the chain skipped past it; using it
    // once and removing it keeps exactly-once, which is what the replay check
    // was really protecting.
    List<int>? chainKey;
    List<int>? messageKey;
    var usedSkippedKey = false;
    if (message.iteration < state.iteration) {
      final retained = state.skippedMessageKeys[message.iteration];
      if (retained == null) {
        throw SenderKeyDependencyError(
          SenderKeyDependencyCode.messageOutsideWindow,
          'Sender Key message iteration ${message.iteration} is behind '
          'stored iteration ${state.iteration} and its key was not retained. '
          'Either it was already read, or it fell outside the retention '
          'window. Possible replay attack.',
        );
      }
      messageKey = List<int>.from(retained);
      usedSkippedKey = true;
    } else {
      // Fast-forward chain key to the message's iteration
      final skip = message.iteration - state.iteration;
      if (skip > _maxSkipIterations) {
        throw SenderKeyDependencyError(
          SenderKeyDependencyCode.iterationGap,
          'Too many skipped iterations ($skip > $_maxSkipIterations). '
          'Possible DoS attempt.',
        );
      }

      // Use a copy of the chain key for derivation so we can advance
      // the state to iteration+1 after successful decryption
      var forward = List<int>.from(state.chainKey);
      int? oldestRetained;
      for (var i = 0; i < skip; i++) {
        // Retain the message key for each iteration being skipped over, so a
        // message the relay chose to deliver later is still readable. Without
        // this the intermediate keys were derived, used for nothing, and
        // zeroed — destroying the messages rather than merely delaying them.
        final skippedIteration = state.iteration + i;
        // Evict the OLDEST retained key when full, rather than silently
        // declining to retain the newest.
        //
        // Skipping retention while still advancing the chain restored exactly
        // the destruction this store was added to prevent: once full, every
        // out-of-order message became permanently unreadable, with no error
        // that triggers a re-request. The oldest entries are also the ones
        // least likely ever to arrive, so they are the right ones to drop.
        while (state.skippedMessageKeys.length >=
            SenderKeyState.maxSkippedMessageKeys) {
          // The oldest retained iteration is tracked rather than rescanned.
          // `keys.reduce` inside the skip loop made a long fast-forward
          // quadratic — order 10^8 comparisons at the top of the range, on the
          // UI isolate, holding the sender-key lock.
          oldestRetained ??= state.skippedMessageKeys.keys.reduce(
            (a, b) => a < b ? a : b,
          );
          final evicted = state.skippedMessageKeys.remove(oldestRetained);
          state.skippedMessageKeyAges.remove(oldestRetained);
          if (evicted != null) SecureMemory.zeroBytes(evicted);
          oldestRetained = state.skippedMessageKeys.isEmpty
              ? null
              : oldestRetained + 1;
        }
        state.skippedMessageKeys[skippedIteration] = await _deriveMessageKey(
          forward,
        );
        state.skippedMessageKeyAges[skippedIteration] =
            DateTime.now().millisecondsSinceEpoch;
        final oldKey = forward;
        forward = await _deriveNextChainKey(oldKey);
        // Zero intermediate chain keys for forward secrecy
        SecureMemory.zeroBytes(oldKey);
      }
      chainKey = forward;

      // Derive the message key at the target iteration
      messageKey = await _deriveMessageKey(forward);
    }

    // Already authenticated above, before any derivation. Re-decode only the
    // few fields the decryption step needs.
    final ctBytes = base64Decode(message.ciphertext);
    final version = ctBytes.isNotEmpty ? ctBytes[0] : 0;
    final isV3 = version == 0x03;
    final isV2 = version == 0x02;

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

    if (usedSkippedKey) {
      // Consume it. Retaining a key for an out-of-order message is what makes
      // the message readable; retaining it AFTER the message is read would
      // make it replayable, which is precisely what the iteration check
      // existed to prevent.
      state.skippedMessageKeyAges.remove(message.iteration);
      final consumed = state.skippedMessageKeys.remove(message.iteration);
      if (consumed != null) SecureMemory.zeroBytes(consumed);
      await _saveSenderKey(groupId, senderId, state);
    } else {
      // Advance the stored state past this message — zero old keys
      final oldStateChainKey = state.chainKey;
      state.chainKey = await _deriveNextChainKey(chainKey!);
      state.iteration = message.iteration + 1;
      await _saveSenderKey(groupId, senderId, state);
      // Zero old chain keys for forward secrecy
      SecureMemory.zeroBytes(oldStateChainKey);
      SecureMemory.zeroBytes(chainKey);
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
    final senderId = await _cryptoStorage.getLocalUserId() ?? '';
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
    final secretBox = await algorithm.encrypt(plaintext, secretKey: secretKey);
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

class _PendingSenderKeyRotation {
  static const int currentVersion = 1;

  final String rotationId;
  final SenderKeyState state;

  const _PendingSenderKeyRotation({
    required this.rotationId,
    required this.state,
  });

  SenderKeyRotationProposal get proposal => SenderKeyRotationProposal(
    rotationId: rotationId,
    distribution: SenderKeyDistribution(
      cryptoProtocolEpoch: state.cryptoProtocolEpoch,
      groupId: state.groupId,
      senderId: state.senderId,
      iteration: state.iteration,
      chainKey: base64Encode(state.chainKey),
      signingKey: state.signingPublicKey,
      epoch: state.epoch,
    ),
  );

  Map<String, dynamic> toJson() => <String, dynamic>{
    'version': currentVersion,
    'rotationId': rotationId,
    'state': state.toJson(),
  };

  factory _PendingSenderKeyRotation.fromJson(Map<String, dynamic> json) {
    if (json['version'] != currentVersion ||
        json['rotationId'] is! String ||
        json['state'] is! Map) {
      throw const FormatException('Invalid pending Sender Key rotation');
    }
    final rotationId = json['rotationId'] as String;
    SenderKeyManager._validateRotationId(rotationId);
    return _PendingSenderKeyRotation(
      rotationId: rotationId,
      state: SenderKeyState.fromJson(
        Map<String, dynamic>.from(json['state'] as Map),
      ),
    );
  }
}

bool _constantTimeEquals(List<int> left, List<int> right) {
  var difference = left.length ^ right.length;
  final shared = left.length < right.length ? left.length : right.length;
  for (var i = 0; i < shared; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference == 0;
}
