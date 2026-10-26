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
  /// v2: canonical header AAD without identity binding. Still the default
  /// send format until R4-L1 Part C.
  static const int currentWireVersion = 2;

  /// v3 (R4-L1): the v2 header AAD plus `AD = IK_lo ‖ IK_hi`.
  static const int identityBoundWireVersion = 3;

  /// Every version the live API accepts (R4-L1 Part A). Part D narrows this
  /// to {3}.
  static const Set<int> acceptedWireVersions = <int>{
    currentWireVersion,
    identityBoundWireVersion,
  };

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

  /// Envelope format version (PR-SEC-004).
  ///
  ///   - **v1 (legacy):** recognized by the wire parser only so callers can
  ///     quarantine it. Exported encrypt/decrypt APIs reject it before state.
  ///   - **v2 (current default):** the canonical header (version + dhPublicKey +
  ///     messageNumber + previousChainLength) is bound into the AES-GCM AAD via
  ///     [DoubleRatchet.canonicalHeaderAad]. Tampering any bound header field
  ///     causes AEAD authentication to fail.
  ///   - **v3 (R4-L1):** the v2 header plus both identity keys
  ///     ([DoubleRatchet.identityAssociatedData]) under a new AAD domain.
  ///
  /// An absent `version` parses as v1 for classification, then the live API
  /// fails closed. The v2 version is itself authenticated in the AAD.
  final int version;

  const EncryptedMessage({
    required this.dhPublicKey,
    required this.messageNumber,
    required this.previousChainLength,
    required this.ciphertext,
    required this.nonce,
    this.version = 2,
  });

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'dhPublicKey': dhPublicKey,
      'messageNumber': messageNumber,
      'previousChainLength': previousChainLength,
      'ciphertext': ciphertext,
      'nonce': nonce,
    };
    // Byte-compat: v1 envelopes omit the version field entirely so their wire
    // JSON is identical to the pre-versioning format. v2+ carry it explicitly.
    if (version >= 2) {
      json['version'] = version;
    }
    return json;
  }

  factory EncryptedMessage.fromJson(Map<String, dynamic> json) {
    final dhKey = json['dhPublicKey'] as String?;
    final msgNum = json['messageNumber'] as int?;
    final prevLen = json['previousChainLength'] as int?;
    final ct = json['ciphertext'] as String?;
    final nonce = json['nonce'] as String?;
    // Absent version ⇒ legacy v1 (no AAD). A present value is trusted only for
    // routing/AAD reconstruction — its integrity is enforced by the AEAD tag
    // (v2 binds the version into the AAD), so a tampered version fails auth.
    final version = json['version'] as int? ?? 1;

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
    if (version < 1)
      throw FormatException('Invalid envelope version: $version');

    return EncryptedMessage(
      dhPublicKey: dhKey,
      messageNumber: msgNum,
      previousChainLength: prevLen,
      ciphertext: ct,
      nonce: nonce,
      version: version,
    );
  }

  /// Enforce the epoch-2 application boundary while preserving the low-level
  /// parser for explicit offline migration/quarantine tooling.
  void requireCurrentWireVersion() {
    if (!acceptedWireVersions.contains(version)) {
      throw FormatException(
        'Unsupported Double Ratchet wire version: $version',
      );
    }
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

  /// How long a skipped message key is kept (R4-L2). Matches the relay's
  /// 30-day retention of undelivered messages: an older key can no longer
  /// decrypt anything that still exists, so it is purged and zeroed.
  static const skippedKeyTtl = Duration(days: 30);

  /// Time source for skipped-key ages and expiry. Overridable for tests only.
  DateTime Function() clock = DateTime.now;

  /// Maximum number of received message IDs to track for anti-replay.
  static const maxReceivedTracked = 2000;
  static const _ratchetInfo = 'Risaal_Ratchet';

  static final _x25519 = X25519();
  static final _hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 64);
  static final _hmac = Hmac.sha256();
  static final _aesGcm = AesGcm.with256bits();

  RatchetState _state;

  /// Async mutex shared by [encrypt] and [decrypt] (R4-M5). It serializes
  /// every mutation of [_state]: concurrent decrypts would race on skipped
  /// message keys, and an encrypt interleaved with a transactional decrypt
  /// would have its sending-chain advance discarded by the decrypt commit.
  Completer<void>? _stateLock;

  DoubleRatchet._(this._state);

  /// Run [body] while holding [_stateLock].
  Future<T> _withStateLock<T>(Future<T> Function() body) async {
    while (_stateLock != null) {
      await _stateLock!.future;
    }
    _stateLock = Completer<void>();
    try {
      return await body();
    } finally {
      final lock = _stateLock;
      _stateLock = null;
      lock?.complete();
    }
  }

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
        utf8.encode(jsonEncode(sendingKeyPair.toJson())),
      ),
      dhReceivingKey: Uint8List.fromList(base64Decode(recipientPublicKey)),
      rootKey: Uint8List.fromList(newRootKey),
      sendingChainKey: Uint8List.fromList(newChainKey),
      receivingChainKey: Uint8List(
        0,
      ), // no receiving chain until we get a reply
    );

    // Zero package-owned DH intermediaries (best-effort, Dart heap).
    // Non-short-circuit `&`: every buffer is zeroed, also in release builds.
    final wiped =
        SecureMemory.zeroBytes(dhOutput) &
        SecureMemory.zeroBytes(newRootKey) &
        SecureMemory.zeroBytes(newChainKey);
    assert(wiped, 'ratchet intermediaries must be package-owned and zeroable');

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
        utf8.encode(jsonEncode(dhKeyPair.toJson())),
      ),
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
  ///
  /// [version] is one of [EncryptedMessage.acceptedWireVersions]; legacy or
  /// future formats must use separate offline migration tooling. Version 3
  /// (R4-L1) needs [localIdentityKey] and [RatchetState.remoteIdentityKey]
  /// and marks the session [RatchetState.sendV3]; after that, version 2 is
  /// refused on this session, because its peer refuses it (L1-I1).
  Future<EncryptedMessage> encrypt(
    List<int> plaintext, {
    int version = 2,
    String? localIdentityKey,
  }) async {
    if (!EncryptedMessage.acceptedWireVersions.contains(version)) {
      throw FormatException(
        'Unsupported Double Ratchet wire version: $version',
      );
    }
    return _withStateLock(
      () => _encryptInner(plaintext, version, localIdentityKey),
    );
  }

  Future<EncryptedMessage> _encryptInner(
    List<int> plaintext,
    int version,
    String? localIdentityKey,
  ) async {
    // R4-L1: resolve the identity binding before any chain step, so a refusal
    // leaves the session untouched.
    final identityBound = version == EncryptedMessage.identityBoundWireVersion;
    if (!identityBound && _state.sendV3) {
      throw StateError(
        'Double Ratchet v$version refused: this session sends v3 (R4-L1)',
      );
    }
    final remoteIdentityKey = _state.remoteIdentityKey;
    if (identityBound &&
        (localIdentityKey == null || remoteIdentityKey == null)) {
      throw StateError(
        'Double Ratchet v3 needs both identity keys; re-establish the session',
      );
    }
    final identityAd = identityBound
        ? identityAssociatedData(
            localIdentityKey: localIdentityKey!,
            remoteIdentityKey: remoteIdentityKey!,
          )
        : null;

    // Derive message key from sending chain key
    final chainKey = List<int>.from(_state.sendingChainKey);
    final (newChainKey, messageKey) = await _kdfCK(chainKey);
    _state.sendingChainKey = Uint8List.fromList(newChainKey);

    // Extract the current sending public key (part of the canonical header).
    final sendingKP = KeyPair.fromJson(
      jsonDecode(utf8.decode(_state.dhSendingKeyPair)) as Map<String, dynamic>,
    );

    // v2 binds the canonical header into the AEAD AAD so any header tamper
    // (version/dhPublicKey/N/PN) fails authentication; v3 adds both identity
    // keys. v1 uses no AAD.
    final aad = version >= 2
        ? canonicalHeaderAad(
            version: version,
            dhPublicKey: sendingKP.publicKey,
            messageNumber: _state.sendMessageNumber,
            previousChainLength: _state.previousChainLength,
            identityAd: identityAd,
          )
        : const <int>[];

    // Encrypt with AES-256-GCM -- copy bytes so zeroBytes() below
    // doesn't corrupt the key inside the cryptography package's internals
    final secretKey = SecretKey(List<int>.from(messageKey));
    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: secretKey,
      aad: aad,
    );

    // Wipe ephemeral key material from RAM
    SecureMemory.zeroBytes(chainKey);
    SecureMemory.zeroBytes(newChainKey);
    SecureMemory.zeroBytes(messageKey);

    final message = EncryptedMessage(
      dhPublicKey: sendingKP.publicKey,
      messageNumber: _state.sendMessageNumber,
      previousChainLength: _state.previousChainLength,
      ciphertext: base64Encode(secretBox.cipherText + secretBox.mac.bytes),
      nonce: base64Encode(secretBox.nonce),
      version: version,
    );

    _state.sendMessageNumber++;
    if (identityBound) _state.sendV3 = true;

    return message;
  }

  // -- Canonical header AAD (PR-SEC-004) ----------------------------------

  /// Domain-separation tag for the Double Ratchet header AAD. Prevents the
  /// serialized header from ever colliding with another AEAD use in the app.
  static const _aadDomain = 'RISAAL_DR_HDRv1';

  /// Domain of the v3 identity-bound layout (R4-L1, L1-I3).
  static const _aadDomainV2 = 'RISAAL_DR_HDRv2';

  /// Deterministic, collision-free serialization of the canonical Double
  /// Ratchet header, used as the AES-GCM AAD for v2+ envelopes.
  ///
  /// Layout (all integers big-endian, fixed 4-byte width; every variable-length
  /// field is length-prefixed, so two distinct header tuples can never map to
  /// the same byte string):
  /// ```
  ///   u32(len(domain))  || domain
  ///   u32(version)
  ///   u32(len(dhKeyBytes)) || dhKeyBytes    (raw X25519 key, not base64)
  ///   u32(messageNumber)
  ///   u32(previousChainLength)
  /// ```
  /// The raw (base64-decoded) public key is bound rather than its textual
  /// encoding, so a benign re-encoding never breaks a genuine message while any
  /// change to the actual key material is detected.
  ///
  /// v3 (R4-L1) uses the domain `RISAAL_DR_HDRv2` and inserts
  /// `u32(len(AD)) || AD` after it, where [identityAd] is
  /// [identityAssociatedData]; it is required for v3 and refused otherwise.
  static List<int> canonicalHeaderAad({
    required int version,
    required String dhPublicKey,
    required int messageNumber,
    required int previousChainLength,
    List<int>? identityAd,
  }) {
    final identityBound = version == EncryptedMessage.identityBoundWireVersion;
    if (identityBound != (identityAd != null)) {
      throw const FormatException(
        'Double Ratchet v3 AAD needs the identity AD, and only v3 takes it',
      );
    }
    final domain = utf8.encode(identityBound ? _aadDomainV2 : _aadDomain);
    final dhBytes = base64Decode(dhPublicKey);
    final out = BytesBuilder(copy: false);
    _appendU32(out, domain.length);
    out.add(domain);
    if (identityBound) {
      _appendU32(out, identityAd!.length);
      out.add(identityAd);
    }
    _appendU32(out, version);
    _appendU32(out, dhBytes.length);
    out.add(dhBytes);
    _appendU32(out, messageNumber);
    _appendU32(out, previousChainLength);
    return out.toBytes();
  }

  /// `AD = IK_lo ‖ IK_hi` (R4-L1): both raw X25519 identity keys in
  /// byte-lexicographic order, so both sides build the same bytes without
  /// knowing who initiated.
  static Uint8List identityAssociatedData({
    required String localIdentityKey,
    required String remoteIdentityKey,
  }) {
    final local = _rawIdentityKey(localIdentityKey);
    final remote = _rawIdentityKey(remoteIdentityKey);
    var localFirst = true;
    for (var i = 0; i < local.length; i++) {
      if (local[i] != remote[i]) {
        localFirst = local[i] < remote[i];
        break;
      }
    }
    return Uint8List.fromList(
      localFirst ? <int>[...local, ...remote] : <int>[...remote, ...local],
    );
  }

  static Uint8List _rawIdentityKey(String identityKey) {
    final Uint8List raw;
    try {
      raw = base64Decode(identityKey);
    } on FormatException {
      throw const FormatException('Invalid Double Ratchet identity key');
    }
    if (raw.length != 32) {
      throw const FormatException('Invalid Double Ratchet identity key');
    }
    return raw;
  }

  /// Append [value] as a 4-byte big-endian unsigned integer.
  static void _appendU32(BytesBuilder b, int value) {
    b.add([
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ]);
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
  /// Decryption is TRANSACTIONAL (PR-SEC-004): the ratchet state is advanced
  /// on a candidate copy and only committed after AEAD authentication passes,
  /// so a tampered or forged message throws without mutating [_state].
  ///
  /// Returns the decrypted plaintext bytes (still padded -- caller must unpad).
  ///
  /// Throws [SecretBoxAuthenticationError] if AEAD authentication fails
  /// (tampered header/ciphertext/nonce), or [StateError] on replay / too many
  /// skipped keys. Throws [FormatException] before any state change when R4-L1
  /// refuses the version for this session: v2 after the peer spoke v3, or v3
  /// without [localIdentityKey] and [RatchetState.remoteIdentityKey].
  Future<List<int>> decrypt(
    EncryptedMessage message, {
    String? localIdentityKey,
  }) async {
    // This exported low-level surface must enforce the same hard-cutover
    // boundary as SignalProtocolManager. Do it before the mutex/state clone so
    // an unsupported wire version cannot touch ratchet state.
    message.requireCurrentWireVersion();

    // Shared with encrypt(): no other mutation may interleave between the
    // candidate clone and its commit (R4-M5).
    return _withStateLock(() => _decryptInner(message, localIdentityKey));
  }

  /// Transactional decrypt (PR-SEC-004).
  ///
  /// All ratchet advancement (chain steps, skipped-key add/remove, DH ratchet,
  /// anti-replay tracking) runs against a deep-cloned CANDIDATE state. The
  /// candidate is committed to [_state] ONLY after AEAD authentication
  /// succeeds. Therefore any failure — tampered header/ciphertext/nonce, a
  /// replay, or a DoS skip overflow — throws with [_state] (including
  /// [RatchetState.skippedKeys]) byte-identical to before the call, so a
  /// forged message can never desynchronise or corrupt the session.
  Future<List<int>> _decryptInner(
    EncryptedMessage message,
    String? localIdentityKey,
  ) async {
    // R4-L1 version gate, before any state is touched (expiry included).
    final identityAd = _receiveIdentityAd(_state, message, localIdentityKey);
    // Expiry is time-based, not input-driven, so it is applied to the live
    // state and holds even when this message later fails to authenticate.
    _purgeExpiredSkippedKeys(_state);
    // Deep clone via the public JSON round-trip (no touch to session_state.dart).
    final candidate = RatchetState.fromJson(_state.toJson());
    final plaintext = await _decryptOnState(candidate, message, identityAd);
    // The first authenticated v3 message pins the session to v3 (L1-I1).
    if (identityAd != null) candidate.peerSpeaksV3 = true;
    // AEAD authentication passed — commit atomically.
    _state = candidate;
    return plaintext;
  }

  /// The identity AD a receive of [message] binds, or `null` for v2.
  ///
  ///  * L1-I1: once the peer has spoken v3 on this session, v2 is refused.
  ///  * L1-I2: v3 needs both identity keys; there is no fallback to an AAD
  ///    without AD. Such a session can only be re-established.
  static List<int>? _receiveIdentityAd(
    RatchetState state,
    EncryptedMessage message,
    String? localIdentityKey,
  ) {
    if (message.version != EncryptedMessage.identityBoundWireVersion) {
      if (state.peerSpeaksV3) {
        throw FormatException(
          'Double Ratchet v${message.version} refused: the peer already '
          'speaks v3 on this session (R4-L1)',
        );
      }
      return null;
    }
    final remoteIdentityKey = state.remoteIdentityKey;
    if (localIdentityKey == null || remoteIdentityKey == null) {
      throw const FormatException(
        'Double Ratchet v3 needs both identity keys; re-establish the session',
      );
    }
    return identityAssociatedData(
      localIdentityKey: localIdentityKey,
      remoteIdentityKey: remoteIdentityKey,
    );
  }

  /// Perform the decrypt against [state] (a candidate) without touching
  /// [_state]. Throws before returning if authentication fails.
  Future<List<int>> _decryptOnState(
    RatchetState state,
    EncryptedMessage message,
    List<int>? identityAd,
  ) async {
    CryptoDebugLogger.log(
      'RATCHET_D',
      'decrypt: msgNum=${message.messageNumber} prevChain=${message.previousChainLength} v=${message.version}',
    );
    CryptoDebugLogger.log(
      'RATCHET_D',
      'state: sendN=${state.sendMessageNumber} recvN=${state.receiveMessageNumber} skipped=${state.skippedKeys.length}',
    );

    // -- Anti-replay check ------------------------------------------------
    final messageId = '${message.dhPublicKey}:${message.messageNumber}';
    if (state.receivedMessages.contains(messageId)) {
      CryptoDebugLogger.log('RATCHET_D', 'REPLAY REJECTED: $messageId');
      throw StateError(
        'Replay attack detected: message $messageId already received',
      );
    }

    // Check skipped keys first
    final skipKey = '${message.dhPublicKey}:${message.messageNumber}';
    if (state.skippedKeys.containsKey(skipKey)) {
      CryptoDebugLogger.log(
        'RATCHET_D',
        'Found in SKIPPED KEYS -- decrypting with stored key',
      );
      final messageKey = List<int>.from(state.skippedKeys[skipKey]!);
      state.skippedKeys.remove(skipKey);
      state.skippedKeyAges.remove(skipKey);
      final result = await _decryptWithKey(messageKey, message, identityAd);
      _recordReceivedMessage(state, messageId);
      return result;
    }

    // If the DH ratchet key changed, perform a DH ratchet step
    final stateReceivingKeyBase64 = base64Encode(state.dhReceivingKey);
    final dhKeyChanged = message.dhPublicKey != stateReceivingKeyBase64;
    CryptoDebugLogger.log(
      'RATCHET_D',
      'DH key changed: $dhKeyChanged (msg=${message.dhPublicKey.substring(0, 8)}... state=${state.dhReceivingKey.isEmpty ? "(empty)" : "${stateReceivingKeyBase64.substring(0, 8)}..."})',
    );

    if (dhKeyChanged) {
      // Skip any remaining messages in the old receiving chain
      if (state.receivingChainKey.isNotEmpty) {
        CryptoDebugLogger.log(
          'RATCHET_D',
          'Skipping old chain messages up to ${message.previousChainLength}',
        );
        await _skipMessageKeys(
          state,
          stateReceivingKeyBase64,
          message.previousChainLength,
        );
      }

      // DH ratchet step
      CryptoDebugLogger.log('RATCHET_D', 'Performing DH ratchet step');
      await _dhRatchetStep(state, message.dhPublicKey);
      CryptoDebugLogger.log(
        'RATCHET_D',
        'DH ratchet step complete. recvN=${state.receiveMessageNumber} sendN=${state.sendMessageNumber}',
      );
    }

    // Skip ahead to the correct message number in the receiving chain
    if (message.messageNumber > state.receiveMessageNumber) {
      CryptoDebugLogger.log(
        'RATCHET_D',
        'Skipping ahead from recvN=${state.receiveMessageNumber} to msgNum=${message.messageNumber}',
      );
    }
    await _skipMessageKeys(
      state,
      base64Encode(state.dhReceivingKey),
      message.messageNumber,
    );

    // Derive the message key
    CryptoDebugLogger.log(
      'RATCHET_D',
      'Deriving message key at recvN=${state.receiveMessageNumber}',
    );
    final chainKey = List<int>.from(state.receivingChainKey);
    final (newChainKey, messageKey) = await _kdfCK(chainKey);
    state.receivingChainKey = Uint8List.fromList(newChainKey);
    state.receiveMessageNumber++;

    // Wipe chain key intermediaries
    SecureMemory.zeroBytes(chainKey);
    SecureMemory.zeroBytes(newChainKey);

    CryptoDebugLogger.log(
      'RATCHET_D',
      'Decrypting with derived key. New recvN=${state.receiveMessageNumber}',
    );
    final result = await _decryptWithKey(messageKey, message, identityAd);
    _recordReceivedMessage(state, messageId);
    return result;
  }

  /// Record a successfully-decrypted message for anti-replay on [state].
  /// Caps the set at [maxReceivedTracked] to prevent unbounded growth.
  void _recordReceivedMessage(RatchetState state, String messageId) {
    state.receivedMessages.add(messageId);
    if (state.receivedMessages.length > maxReceivedTracked) {
      // Remove oldest entries (set has no ordering, so convert to list)
      final list = state.receivedMessages.toList();
      state.receivedMessages = list
          .sublist(list.length - maxReceivedTracked)
          .toSet();
    }
  }

  // -- State Serialisation ------------------------------------------------

  Map<String, dynamic> toJson() => _state.toJson();

  factory DoubleRatchet.fromJson(Map<String, dynamic> json) =>
      DoubleRatchet._(RatchetState.fromJson(json));

  /// Expose state for storage.
  RatchetState get state => _state;

  // -- Private: DH Ratchet Step -------------------------------------------

  /// Perform a DH ratchet step on [state]: update receiving chain, generate new
  /// sending key pair, update sending chain.
  Future<void> _dhRatchetStep(
    RatchetState state,
    String newRemotePublicKey,
  ) async {
    state.previousChainLength = state.sendMessageNumber;
    state.sendMessageNumber = 0;
    state.receiveMessageNumber = 0;
    state.dhReceivingKey = Uint8List.fromList(base64Decode(newRemotePublicKey));

    // Receiving chain: DH(currentSendingKP, newRemotePub)
    final currentKP = KeyPair.fromJson(
      jsonDecode(utf8.decode(state.dhSendingKeyPair)) as Map<String, dynamic>,
    );
    final dhOutput = await _performDH(currentKP, newRemotePublicKey);
    final rootKey = List<int>.from(state.rootKey);
    final (newRootKey1, recvChainKey) = await _kdfRK(rootKey, dhOutput);
    state.rootKey = Uint8List.fromList(newRootKey1);
    state.receivingChainKey = Uint8List.fromList(recvChainKey);

    // Zero DH output and old root key (best-effort, Dart heap).
    final wiped1 =
        SecureMemory.zeroBytes(dhOutput) &
        SecureMemory.zeroBytes(rootKey) &
        SecureMemory.zeroBytes(recvChainKey);
    assert(wiped1, 'ratchet intermediaries must be package-owned and zeroable');

    // Sending chain: generate new DH key pair
    final newSendingKP = await SignalKeyHelper.generateX25519KeyPair();
    state.dhSendingKeyPair = Uint8List.fromList(
      utf8.encode(jsonEncode(newSendingKP.toJson())),
    );

    final dhOutput2 = await _performDH(newSendingKP, newRemotePublicKey);
    final (newRootKey2, sendChainKey) = await _kdfRK(newRootKey1, dhOutput2);
    state.rootKey = Uint8List.fromList(newRootKey2);
    state.sendingChainKey = Uint8List.fromList(sendChainKey);

    // Zero second DH output and intermediate key material
    final wiped2 =
        SecureMemory.zeroBytes(dhOutput2) &
        SecureMemory.zeroBytes(newRootKey1) &
        SecureMemory.zeroBytes(newRootKey2) &
        SecureMemory.zeroBytes(sendChainKey);
    assert(wiped2, 'ratchet intermediaries must be package-owned and zeroable');
  }

  // -- Private: Skip Message Keys -----------------------------------------

  /// Advance [state]'s receiving chain and store skipped message keys up to
  /// [untilNumber]. Throws if too many keys would be skipped.
  Future<void> _skipMessageKeys(
    RatchetState state,
    String dhPublicKey,
    int untilNumber,
  ) async {
    if (state.receivingChainKey.isEmpty) return;

    final toSkip = untilNumber - state.receiveMessageNumber;
    if (toSkip < 0) return;
    if (state.skippedKeys.length + toSkip > _maxSkippedKeys) {
      throw StateError(
        'Too many skipped message keys (max $_maxSkippedKeys). '
        'Possible DoS attempt.',
      );
    }

    final storedAt = clock().millisecondsSinceEpoch;
    List<int> chainKey = List<int>.from(state.receivingChainKey);
    for (var i = state.receiveMessageNumber; i < untilNumber; i++) {
      final (newChainKey, messageKey) = await _kdfCK(chainKey);
      state.skippedKeys['$dhPublicKey:$i'] = Uint8List.fromList(messageKey);
      state.skippedKeyAges['$dhPublicKey:$i'] = storedAt;
      // Zero old chain key and message key copy after storing
      SecureMemory.zeroBytes(chainKey);
      SecureMemory.zeroBytes(messageKey);
      chainKey = newChainKey;
    }
    state.receivingChainKey = Uint8List.fromList(chainKey);
    SecureMemory.zeroBytes(chainKey);
  }

  /// Zero and remove every skipped key in [state] older than [skippedKeyTtl]
  /// (R4-L2). A key without an age is treated as stored now.
  void _purgeExpiredSkippedKeys(RatchetState state) {
    final cutoff =
        clock().millisecondsSinceEpoch - skippedKeyTtl.inMilliseconds;
    final expired = <String>[
      for (final k in state.skippedKeys.keys)
        if ((state.skippedKeyAges[k] ?? cutoff + 1) < cutoff) k,
    ];
    for (final k in expired) {
      SecureMemory.zeroBytes(state.skippedKeys.remove(k)!);
      state.skippedKeyAges.remove(k);
    }
    state.skippedKeyAges.removeWhere(
      (k, _) => !state.skippedKeys.containsKey(k),
    );
  }

  // -- Private: AES-256-GCM Decryption ------------------------------------

  /// Decrypt one message with [messageKey]. For v2+ envelopes the canonical
  /// header is reconstructed and passed as the AEAD AAD, so any tampered header
  /// field (version/dhPublicKey/N/PN) fails authentication and throws
  /// [SecretBoxAuthenticationError]. v1 envelopes use no AAD (legacy). v3
  /// also binds [identityAd] (R4-L1).
  Future<List<int>> _decryptWithKey(
    List<int> messageKey,
    EncryptedMessage message,
    List<int>? identityAd,
  ) async {
    final secretKey = SecretKey(List<int>.from(messageKey));
    final nonce = base64Decode(message.nonce);
    final combined = base64Decode(message.ciphertext);

    // Reconstruct the AAD from the parsed header. If any bound field was
    // tampered on the wire, the reconstructed AAD differs from the one used at
    // encrypt time and AES-GCM authentication fails.
    final aad = message.version >= 2
        ? canonicalHeaderAad(
            version: message.version,
            dhPublicKey: message.dhPublicKey,
            messageNumber: message.messageNumber,
            previousChainLength: message.previousChainLength,
            identityAd: identityAd,
          )
        : const <int>[];

    // Last 16 bytes are the GCM MAC tag
    final ciphertext = combined.sublist(0, combined.length - 16);
    final mac = Mac(combined.sublist(combined.length - 16));

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);

    final plaintext = await _aesGcm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
    );

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
    final ikm = List<int>.from(dhOutput);
    final derived = await _hkdf.deriveKey(
      secretKey: SecretKey(ikm),
      info: _ratchetInfo.codeUnits,
      nonce: rootKey,
    );
    final bytes = SecureMemory.ownedCopy(await derived.extractBytes());
    derived.destroy();
    SecureMemory.zeroBytes(ikm);
    // First 32 bytes = new root key, last 32 bytes = new chain key.
    // sublist() returns fresh mutable copies the callers zero.
    final out = (bytes.sublist(0, 32), bytes.sublist(32, 64));
    SecureMemory.zeroBytes(bytes);
    return out;
  }

  // -- Private: KDF_CK -- Chain Key Derivation ----------------------------

  /// Derive (newChainKey, messageKey) from the current chain key using
  /// HMAC-SHA256. Message key = HMAC(ck, 0x01), new chain key = HMAC(ck, 0x02).
  static Future<(List<int>, List<int>)> _kdfCK(List<int> chainKey) async {
    final ck = SecretKey(List<int>.from(chainKey));

    final messageKeyMac = await _hmac.calculateMac([0x01], secretKey: ck);
    final newChainKeyMac = await _hmac.calculateMac([0x02], secretKey: ck);

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
    final out = SecureMemory.ownedCopy(await secret.extractBytes());
    secret.destroy();
    SignalKeyHelper.requireContributoryX25519(out);
    return out;
  }
}
