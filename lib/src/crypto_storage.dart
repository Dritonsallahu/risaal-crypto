import 'dart:convert';

import 'crypto_protocol.dart';
import 'crypto_secure_storage.dart';
import 'key_bundle_replacement.dart';
import 'key_helper.dart';
import 'models/session_state.dart';
import 'models/signal_keys.dart';
import 'transfer/transfer_archive.dart';
import 'transfer/transfer_crypto_store.dart';

/// Persists all Signal Protocol key material in [CryptoSecureStorage].
///
/// Every key is prefixed to avoid collisions with non-crypto storage
/// entries. All values are JSON- or base64-encoded strings.
class CryptoStorage {
  final CryptoSecureStorage _secureStorage;

  CryptoStorage({required CryptoSecureStorage secureStorage})
    : _secureStorage = secureStorage;

  // ── Storage Key Prefixes ──────────────────────────────────────────
  // Epoch-2 derived/session material lives in a new namespace. This makes
  // legacy v0.1 ratchets, pending handshakes, sender keys and KEM keys
  // unreachable after upgrade without requiring insecure key enumeration.
  static const _epoch2Prefix = 'crypto_e2_';
  static const _keyIdentityKP = 'crypto_identity_key_pair';
  static const _keySigningKP = 'crypto_signing_key_pair';
  static const _keySignedPreKey = 'crypto_signed_pre_key';
  static const _keySignedPreKeyCreatedAt = 'crypto_signed_prekey_created_at';
  static const _keyOneTimePreKeys = 'crypto_one_time_pre_keys';
  static const _keySessionPrefix = '${_epoch2Prefix}session_';
  static const _keyKyberKP = '${_epoch2Prefix}kyber_key_pair';
  static const _keyKyberCreatedAt = '${_epoch2Prefix}kyber_created_at';
  static const _keyNextPreKeyId = 'crypto_next_pre_key_id';
  static const _keyOneTimePreKeyRecovery =
      '${_epoch2Prefix}one_time_pre_key_recovery';
  static const _keyNextSignedPreKeyId =
      '${_epoch2Prefix}next_signed_pre_key_id';
  static const _keyPeerCapPrefix = '${_epoch2Prefix}peer_cap_';
  static const _keyProtocolMarker = '${_epoch2Prefix}protocol';
  static const _keyBundleUploadPending =
      '${_epoch2Prefix}bundle_upload_pending';
  static const _keyServerBundleRevision =
      '${_epoch2Prefix}server_bundle_revision';
  static const _keyLastAcceptedBundleGeneration =
      '${_epoch2Prefix}last_accepted_bundle_generation';
  static const _keyNextKyberKeyId = '${_epoch2Prefix}next_kyber_key_id';
  static const _keyBundleReplacementJournal =
      '${_epoch2Prefix}bundle_replacement_journal_v1';
  static const _keyInitialRegistrationIntent =
      '${_epoch2Prefix}initial_registration_intent_v1';

  Future<void> _markInitialRegistrationIntent() => _secureStorage.write(
    key: _keyInitialRegistrationIntent,
    value: RisaalCryptoProtocol.clientProtocol,
  );

  Future<bool> hasInitialRegistrationIntent() async =>
      await _secureStorage.read(key: _keyInitialRegistrationIntent) ==
      RisaalCryptoProtocol.clientProtocol;

  Future<void> clearInitialRegistrationIntent() =>
      _secureStorage.delete(key: _keyInitialRegistrationIntent);

  Future<KeyBundleReplacementJournal?> _readKeyBundleReplacementJournal({
    required bool validateAllPrivateMaterial,
  }) async {
    final raw = await _secureStorage.read(key: _keyBundleReplacementJournal);
    if (raw == null) return null;
    try {
      if (utf8.encode(raw).length >
          KeyBundleReplacementJournal.maxEncodedBytes) {
        throw const FormatException('Oversized key-bundle journal');
      }
      final decoded = jsonDecode(raw);
      if (decoded is! Map) {
        throw const FormatException('Corrupt key-bundle journal');
      }
      final journal = KeyBundleReplacementJournal.fromJson(
        Map<String, dynamic>.from(decoded),
      );
      if (validateAllPrivateMaterial) {
        await validateKeyBundleReplacementJournal(journal);
      }
      return journal;
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Corrupt key-bundle journal');
    }
  }

  /// Full private-material audit used by startup and lifecycle persistence.
  /// Exact inbound hot paths validate only their routed generation.
  Future<void> validateKeyBundleReplacementJournal(
    KeyBundleReplacementJournal journal,
  ) async {
    journal.requireValid();
    if (journal.generations.isEmpty) return;
    final localIdentity = await getIdentityKeyPair();
    final localSigning = await getSigningKeyPair();
    if (localIdentity == null ||
        localSigning == null ||
        !await SignalKeyHelper.isValidX25519KeyPair(localIdentity) ||
        !await SignalKeyHelper.isValidEd25519KeyPair(localSigning)) {
      throw const FormatException('Invalid journal identity material');
    }

    final x25519Pairs = <KeyPair>[localIdentity];
    for (final generation in journal.generations) {
      x25519Pairs.add(generation.signedPreKey!.keyPair);
      x25519Pairs.addAll(generation.oneTimePreKeys.map((key) => key.keyPair));
    }
    if (!await SignalKeyHelper.areValidX25519KeyPairs(x25519Pairs)) {
      throw const FormatException('Invalid journal X25519 material');
    }

    for (final generation in journal.generations) {
      final signedPreKey = generation.signedPreKey!;
      final kyberKeyPair = generation.kyberKeyPair!;
      if (generation.identityKey != localIdentity.publicKey ||
          generation.identitySigningKey != localSigning.publicKey ||
          !SignalKeyHelper.isValidKyberKeyPair(kyberKeyPair)) {
        throw const FormatException('Invalid journal generation secrets');
      }
      try {
        if (!await SignalKeyHelper.verify(
              localSigning.publicKey,
              base64Decode(signedPreKey.keyPair.publicKey),
              signedPreKey.signature,
            ) ||
            !await SignalKeyHelper.verify(
              localSigning.publicKey,
              RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
                keyId: kyberKeyPair.keyId!,
                publicKey: kyberKeyPair.publicKey,
              ),
              generation.kemSignature,
            )) {
          throw const FormatException('Invalid journal generation signature');
        }
      } on ArgumentError {
        throw const FormatException('Invalid journal generation signature');
      }
    }
  }

  Future<int> getAcceptedGenerationOneTimePreKeyCount() async {
    final journal = await _readKeyBundleReplacementJournal(
      validateAllPrivateMaterial: false,
    );
    final receipt = journal?.acceptedReceipt;
    if (receipt == null) {
      throw StateError('No authenticated accepted OPK generation');
    }
    final matches = journal!.generations.where(
      (entry) =>
          entry.opkGeneration == receipt.opkGeneration &&
          entry.role == OpkGenerationRole.acceptedLookupOnly &&
          entry.acceptedReceipt == receipt,
    );
    if (matches.length != 1) {
      throw const FormatException('Accepted OPK generation is unavailable');
    }
    return matches.single.oneTimePreKeys.length;
  }

  Future<bool> hasCurrentProtocolMarker() async =>
      await _secureStorage.read(key: _keyProtocolMarker) ==
      RisaalCryptoProtocol.clientProtocol;

  Future<void> saveCurrentProtocolMarker() => _secureStorage.write(
    key: _keyProtocolMarker,
    value: RisaalCryptoProtocol.clientProtocol,
  );

  Future<bool> isKeyBundleUploadPending() async =>
      await _secureStorage.read(key: _keyBundleUploadPending) != null;

  Future<KeyBundleGeneration?> getPendingKeyBundleGeneration() async {
    final raw = await _secureStorage.read(key: _keyBundleUploadPending);
    if (raw == null || raw == 'true') return null;
    try {
      final generation = KeyBundleGeneration.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );
      generation.requireCurrent(requirePublicMaterialDigest: true);
      return generation;
    } on Object {
      throw const FormatException('Corrupt pending key-bundle generation');
    }
  }

  Future<void> markKeyBundleUploadPending(KeyBundleGeneration generation) {
    generation.requireCurrent(requirePublicMaterialDigest: true);
    return _secureStorage.write(
      key: _keyBundleUploadPending,
      value: jsonEncode(generation.toJson()),
    );
  }

  Future<void> clearPendingKeyBundleGeneration() =>
      _secureStorage.delete(key: _keyBundleUploadPending);

  Future<bool> isOneTimePreKeyRecoveryPending() async =>
      await _secureStorage.read(key: _keyOneTimePreKeyRecovery) != null;

  Future<KeyBundleGeneration?> getOneTimePreKeyRecoveryTarget() async {
    final raw = await _secureStorage.read(key: _keyOneTimePreKeyRecovery);
    if (raw == null || raw == 'requested') return null;
    try {
      final generation = KeyBundleGeneration.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );
      generation.requireCurrent(requirePublicMaterialDigest: true);
      return generation;
    } on Object {
      throw const FormatException('Corrupt one-time pre-key recovery target');
    }
  }

  Future<void> markOneTimePreKeyRecoveryRequested() =>
      _secureStorage.write(key: _keyOneTimePreKeyRecovery, value: 'requested');

  Future<void> saveOneTimePreKeyRecoveryTarget(KeyBundleGeneration generation) {
    generation.requireCurrent(requirePublicMaterialDigest: true);
    return _secureStorage.write(
      key: _keyOneTimePreKeyRecovery,
      value: jsonEncode(generation.toJson()),
    );
  }

  Future<void> clearOneTimePreKeyRecovery() =>
      _secureStorage.delete(key: _keyOneTimePreKeyRecovery);

  Future<int> getServerBundleRevision() async {
    final raw = await _secureStorage.read(key: _keyServerBundleRevision);
    if (raw == null) return 0;
    final revision = int.tryParse(raw);
    if (revision == null || revision < 0) {
      throw const FormatException('Corrupt server bundle revision');
    }
    return revision;
  }

  Future<void> saveServerBundleRevision(int revision) {
    if (revision <= 0) {
      throw ArgumentError.value(revision, 'revision', 'must be positive');
    }
    return _secureStorage.write(
      key: _keyServerBundleRevision,
      value: revision.toString(),
    );
  }

  Future<KeyBundleGeneration?> getLastAcceptedKeyBundleGeneration() async {
    final raw = await _secureStorage.read(
      key: _keyLastAcceptedBundleGeneration,
    );
    if (raw == null) return null;
    try {
      final generation = KeyBundleGeneration.fromJson(
        jsonDecode(raw) as Map<String, dynamic>,
      );
      generation.requireCurrent(requirePublicMaterialDigest: true);
      return generation;
    } on Object {
      throw const FormatException('Corrupt accepted key-bundle generation');
    }
  }

  Future<void> saveLastAcceptedKeyBundleGeneration(
    KeyBundleGeneration generation,
  ) {
    generation.requireCurrent(requirePublicMaterialDigest: true);
    return _secureStorage.write(
      key: _keyLastAcceptedBundleGeneration,
      value: jsonEncode(generation.toJson()),
    );
  }

  /// Reserve the next positive per-device KEM key id.
  Future<int> reserveNextKyberKeyId() async {
    final raw = await _secureStorage.read(key: _keyNextKyberKeyId);
    var next = int.tryParse(raw ?? '') ?? 1;

    // Recover safely if a counter write was lost/restored. Never issue an ID
    // that aliases either current or retained previous key material.
    final currentId = (await getKyberKeyPair())?.keyId;
    final previousId = (await getPreviousKyberKeyPair())?.keyId;
    for (final existingId in <int?>[currentId, previousId]) {
      if (existingId != null && next <= existingId) next = existingId + 1;
    }

    if (next <= 0 || next > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('Invalid ML-KEM key id counter');
    }
    await _secureStorage.write(
      key: _keyNextKyberKeyId,
      value: (next + 1).toString(),
    );
    return next;
  }

  /// Reserve the next positive signed-pre-key id without aliasing retained
  /// current/previous material.
  Future<int> reserveNextSignedPreKeyId() async {
    final raw = await _secureStorage.read(key: _keyNextSignedPreKeyId);
    var next = int.tryParse(raw ?? '') ?? 1;
    final currentId = (await getSignedPreKey())?.keyId;
    final previousId = (await getPreviousSignedPreKey())?.keyId;
    for (final existingId in <int?>[currentId, previousId]) {
      if (existingId != null && next <= existingId) next = existingId + 1;
    }
    if (next <= 0 || next > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('Invalid signed pre-key id counter');
    }
    await _secureStorage.write(
      key: _keyNextSignedPreKeyId,
      value: (next + 1).toString(),
    );
    return next;
  }

  /// Seed monotonic local counters from an authenticated server generation.
  Future<void> advanceKeyIdCountersPast(KeyBundleGeneration generation) async {
    generation.requireCurrent();
    if (generation.signedPreKeyId >= RisaalCryptoProtocol.maxKeyId ||
        generation.kemKeyId >= RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('Server key id space exhausted');
    }

    Future<void> advance(String key, int observed) async {
      final raw = await _secureStorage.read(key: key);
      final current = int.tryParse(raw ?? '') ?? 1;
      if (current <= observed) {
        await _secureStorage.write(key: key, value: (observed + 1).toString());
      }
    }

    await advance(_keyNextSignedPreKeyId, generation.signedPreKeyId);
    await advance(_keyNextKyberKeyId, generation.kemKeyId);
  }

  // ── Identity Key Pair ─────────────────────────────────────────────

  Future<void> saveIdentityKeyPair(KeyPair keyPair) => _secureStorage.write(
    key: _keyIdentityKP,
    value: jsonEncode(keyPair.toJson()),
  );

  Future<KeyPair?> getIdentityKeyPair() async {
    final raw = await _secureStorage.read(key: _keyIdentityKP);
    if (raw == null) return null;
    return KeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Signing Key Pair (Ed25519) ──────────────────────────────────

  Future<void> saveSigningKeyPair(KeyPair keyPair) => _secureStorage.write(
    key: _keySigningKP,
    value: jsonEncode(keyPair.toJson()),
  );

  Future<KeyPair?> getSigningKeyPair() async {
    final raw = await _secureStorage.read(key: _keySigningKP);
    if (raw == null) return null;
    return KeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Signed Pre-Key ────────────────────────────────────────────────

  Future<void> saveSignedPreKey(SignedPreKey key) => _secureStorage.write(
    key: _keySignedPreKey,
    value: jsonEncode(key.toJson()),
  );

  Future<SignedPreKey?> getSignedPreKey() async {
    final raw = await _secureStorage.read(key: _keySignedPreKey);
    if (raw == null) return null;
    return SignedPreKey.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Signed Pre-Key Creation Timestamp ────────────────────────────

  Future<void> saveSignedPreKeyCreatedAt(int epochMs) => _secureStorage.write(
    key: _keySignedPreKeyCreatedAt,
    value: epochMs.toString(),
  );

  Future<int?> getSignedPreKeyCreatedAt() async {
    final raw = await _secureStorage.read(key: _keySignedPreKeyCreatedAt);
    if (raw == null) return null;
    return int.tryParse(raw);
  }

  // ── One-Time Pre-Keys ─────────────────────────────────────────────

  Future<void> saveOneTimePreKeys(List<OneTimePreKey> keys) =>
      _secureStorage.write(
        key: _keyOneTimePreKeys,
        value: jsonEncode(keys.map((k) => k.toJson()).toList()),
      );

  Future<List<OneTimePreKey>> getOneTimePreKeys() async {
    final raw = await _secureStorage.read(key: _keyOneTimePreKeys);
    if (raw == null) return [];
    final list = jsonDecode(raw) as List<dynamic>;
    return list
        .map((e) => OneTimePreKey.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<int> _greatestValidatedOneTimePreKeyId(
    List<OneTimePreKey> keys,
  ) async {
    final seenIds = <int>{};
    final seenPublicKeys = <String>{};
    final seenPrivateKeys = <String>{};
    var greatestStoredId = 0;
    for (final key in keys) {
      final keyId = key.keyId;
      if (keyId <= 0 || keyId > RisaalCryptoProtocol.maxKeyId) {
        throw const FormatException('Invalid stored one-time pre-key id');
      }
      if (!seenIds.add(keyId)) {
        throw const FormatException('Duplicate stored one-time pre-key id');
      }
      try {
        final publicBytes = base64Decode(key.keyPair.publicKey);
        final privateBytes = base64Decode(key.keyPair.privateKey);
        final canonicalPublic = base64Encode(publicBytes);
        final canonicalPrivate = base64Encode(privateBytes);
        if (publicBytes.length != 32 ||
            privateBytes.length != 32 ||
            canonicalPublic != key.keyPair.publicKey ||
            canonicalPrivate != key.keyPair.privateKey ||
            !seenPublicKeys.add(canonicalPublic) ||
            !seenPrivateKeys.add(canonicalPrivate) ||
            !await SignalKeyHelper.isValidX25519KeyPair(key.keyPair)) {
          throw const FormatException('Invalid one-time pre-key material');
        }
      } on FormatException {
        throw const FormatException('Invalid one-time pre-key material');
      }
      if (keyId > greatestStoredId) greatestStoredId = keyId;
    }
    return greatestStoredId;
  }

  Future<void> validateOneTimePreKeyPool() async {
    await _greatestValidatedOneTimePreKeyId(await getOneTimePreKeys());
  }

  Future<void> removeOneTimePreKey(int keyId) async {
    final keys = await getOneTimePreKeys();
    keys.removeWhere((k) => k.keyId == keyId);
    await saveOneTimePreKeys(keys);
  }

  // ── Kyber Key Pair (ML-KEM-768) ──────────────────────────────────

  Future<void> saveKyberKeyPair(KyberKeyPair keyPair) {
    if (!keyPair.isCurrentProtocol) {
      throw const FormatException('Refusing to store legacy ML-KEM key');
    }
    return _secureStorage.write(
      key: _keyKyberKP,
      value: jsonEncode(keyPair.toJson()),
    );
  }

  Future<KyberKeyPair?> getKyberKeyPair() async {
    final raw = await _secureStorage.read(key: _keyKyberKP);
    if (raw == null) return null;
    return KyberKeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Kyber Key Creation Timestamp ─────────────────────────────────

  Future<void> saveKyberCreatedAt(int epochMs) =>
      _secureStorage.write(key: _keyKyberCreatedAt, value: epochMs.toString());

  Future<int?> getKyberCreatedAt() async {
    final raw = await _secureStorage.read(key: _keyKyberCreatedAt);
    if (raw == null) return null;
    return int.tryParse(raw);
  }

  // ── Previous Signed Pre-Key (48h overlap) ──────────────────────

  static const _keyPreviousSignedPreKey =
      '${_epoch2Prefix}previous_signed_pre_key';
  static const _keyPreviousSpkExpiry = '${_epoch2Prefix}previous_spk_expiry';

  Future<void> savePreviousSignedPreKey(
    SignedPreKey key,
    int expiryEpochMs,
  ) async {
    await _secureStorage.write(
      key: _keyPreviousSignedPreKey,
      value: jsonEncode(key.toJson()),
    );
    await _secureStorage.write(
      key: _keyPreviousSpkExpiry,
      value: expiryEpochMs.toString(),
    );
  }

  Future<SignedPreKey?> getPreviousSignedPreKey() async {
    final raw = await _secureStorage.read(key: _keyPreviousSignedPreKey);
    if (raw == null) return null;
    return SignedPreKey.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  Future<int?> getPreviousSpkExpiry() async {
    final raw = await _secureStorage.read(key: _keyPreviousSpkExpiry);
    if (raw == null) return null;
    return int.tryParse(raw);
  }

  Future<void> deletePreviousSignedPreKey() async {
    await _secureStorage.delete(key: _keyPreviousSignedPreKey);
    await _secureStorage.delete(key: _keyPreviousSpkExpiry);
  }

  /// Resolve the exact signed pre-key selected by a PreKey envelope.
  Future<SignedPreKey?> getSignedPreKeyById(int keyId) async {
    if (keyId <= 0) return null;
    final current = await getSignedPreKey();
    if (current?.keyId == keyId) return current;

    final expiry = await getPreviousSpkExpiry();
    if (expiry == null || DateTime.now().millisecondsSinceEpoch >= expiry) {
      if (expiry != null) await deletePreviousSignedPreKey();
      return null;
    }
    final previous = await getPreviousSignedPreKey();
    return previous?.keyId == keyId ? previous : null;
  }

  // ── Previous Kyber Key (48h overlap) ───────────────────────────

  static const _keyPreviousKyberKP = '${_epoch2Prefix}previous_kyber_key_pair';
  static const _keyPreviousKyberExpiry =
      '${_epoch2Prefix}previous_kyber_expiry';

  Future<void> savePreviousKyberKeyPair(
    KyberKeyPair keyPair,
    int expiryEpochMs,
  ) async {
    if (!keyPair.isCurrentProtocol) {
      throw const FormatException(
        'Refusing to retain a legacy ML-KEM key in the epoch-2 key ring',
      );
    }
    await _secureStorage.write(
      key: _keyPreviousKyberKP,
      value: jsonEncode(keyPair.toJson()),
    );
    await _secureStorage.write(
      key: _keyPreviousKyberExpiry,
      value: expiryEpochMs.toString(),
    );
  }

  Future<KyberKeyPair?> getPreviousKyberKeyPair() async {
    final raw = await _secureStorage.read(key: _keyPreviousKyberKP);
    if (raw == null) return null;
    return KyberKeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  Future<int?> getPreviousKyberExpiry() async {
    final raw = await _secureStorage.read(key: _keyPreviousKyberExpiry);
    if (raw == null) return null;
    return int.tryParse(raw);
  }

  Future<void> deletePreviousKyberKeyPair() async {
    await _secureStorage.delete(key: _keyPreviousKyberKP);
    await _secureStorage.delete(key: _keyPreviousKyberExpiry);
  }

  /// Resolve the exact current/previous key selected by an envelope.
  Future<KyberKeyPair?> getKyberKeyPairById(int keyId) async {
    if (keyId <= 0) return null;
    final current = await getKyberKeyPair();
    if (current?.isCurrentProtocol == true && current!.keyId == keyId) {
      return current;
    }

    final expiry = await getPreviousKyberExpiry();
    if (expiry == null || DateTime.now().millisecondsSinceEpoch >= expiry) {
      if (expiry != null) await deletePreviousKyberKeyPair();
      return null;
    }
    final previous = await getPreviousKyberKeyPair();
    if (previous?.isCurrentProtocol == true && previous!.keyId == keyId) {
      return previous;
    }
    return null;
  }

  // ── Peer Identity Key Tracking (reinstall / MITM detection) ───────

  static const _keyPeerIdentityPrefix = '${_epoch2Prefix}peer_identity_';

  /// Reserved words that name a namespace segment inside another key template.
  ///
  /// P0-B: `crypto_e2_session_<id>_<dev>` and `crypto_e2_session_ik_<id>_<dev>`
  /// and `crypto_e2_session_devices_<id>` share a prefix, so an identifier
  /// equal to `ik` or `devices` makes one template's key collide with
  /// another's. A charset alone cannot separate templates of differing arity.
  static const Set<String> _reservedIdSegments = <String>{'ik', 'devices'};

  static final RegExp _safeIdPattern = RegExp(r'^[A-Za-z0-9-]{1,64}$');

  /// P0-C: validation belongs here, in key construction, so no caller can
  /// bypass it. Identifiers reaching these builders come from untrusted
  /// envelopes; real ones are UUID v4 device ids and hex account ids, so this
  /// makes the `<id>_<dev>` join unambiguous without any stored-data migration.
  static String _safeId(String value, String field) {
    if (!_safeIdPattern.hasMatch(value) ||
        _reservedIdSegments.contains(value)) {
      throw FormatException('Invalid $field for a storage key');
    }
    return value;
  }

  String _peerIdentityKey(String userId, String deviceId) =>
      '$_keyPeerIdentityPrefix${_safeId(userId, 'user id')}_'
      '${_safeId(deviceId, 'device id')}';

  /// Save the peer's identity public key for change detection.
  Future<void> savePeerIdentityKey(
    String userId,
    String deviceId,
    String identityPublicKey,
  ) => _secureStorage.write(
    key: _peerIdentityKey(userId, deviceId),
    value: identityPublicKey,
  );

  /// Get the peer's previously stored identity public key.
  /// Returns null if we've never stored a key for this peer.
  Future<String?> getPeerIdentityKey(String userId, String deviceId) =>
      _secureStorage.read(key: _peerIdentityKey(userId, deviceId));

  /// Delete the peer's stored identity key (e.g. on session deletion).
  Future<void> deletePeerIdentityKey(String userId, String deviceId) =>
      _secureStorage.delete(key: _peerIdentityKey(userId, deviceId));

  // ── Peer Capability Tracking (anti-downgrade) ─────────────────────

  String _peerCapKey(String userId, String deviceId) =>
      '$_keyPeerCapPrefix${_safeId(userId, 'user id')}_'
      '${_safeId(deviceId, 'device id')}';

  /// Save the peer's known PQXDH capability.
  Future<void> savePeerPqxdhCapability(
    String userId,
    String deviceId,
    bool supportsPqxdh,
  ) => _secureStorage.write(
    key: _peerCapKey(userId, deviceId),
    value: jsonEncode({
      'supportsPqxdh': supportsPqxdh,
      'lastSeen': DateTime.now().millisecondsSinceEpoch,
    }),
  );

  /// Get the peer's last known PQXDH capability.
  /// Returns null if we've never established a session with this peer.
  Future<bool?> getPeerPqxdhCapability(String userId, String deviceId) async {
    final raw = await _secureStorage.read(key: _peerCapKey(userId, deviceId));
    if (raw == null) return null;
    final json = jsonDecode(raw) as Map<String, dynamic>;
    return json['supportsPqxdh'] as bool?;
  }

  /// Delete peer capability record (e.g. on session deletion).
  Future<void> deletePeerCapability(String userId, String deviceId) =>
      _secureStorage.delete(key: _peerCapKey(userId, deviceId));

  // ── Anti-Replay State Persistence ──────────────────────────────────

  static const _keyReplayPrefix = '${_epoch2Prefix}replay_';

  String _replayKey(String userId, String deviceId) =>
      '$_keyReplayPrefix${_safeId(userId, 'user id')}_'
      '${_safeId(deviceId, 'device id')}';

  /// Save the set of received message numbers for anti-replay.
  /// Stores as JSON list of "dhKey:msgNum" strings.
  Future<void> saveReceivedMessageNumbers(
    String userId,
    String deviceId,
    Set<String> messageIds,
  ) async {
    // Only persist the most recent entries to bound storage size.
    final list = messageIds.toList();
    final trimmed = list.length > 2000
        ? list.sublist(list.length - 2000)
        : list;
    await _secureStorage.write(
      key: _replayKey(userId, deviceId),
      value: jsonEncode(trimmed),
    );
  }

  /// Load persisted received message numbers for anti-replay.
  Future<Set<String>> loadReceivedMessageNumbers(
    String userId,
    String deviceId,
  ) async {
    final raw = await _secureStorage.read(key: _replayKey(userId, deviceId));
    if (raw == null || raw.isEmpty) return {};
    final list = jsonDecode(raw) as List<dynamic>;
    return list.cast<String>().toSet();
  }

  /// Clear anti-replay state for a session (e.g. on session deletion).
  Future<void> clearReceivedMessageNumbers(String userId, String deviceId) =>
      _secureStorage.delete(key: _replayKey(userId, deviceId));

  // ── Session State ─────────────────────────────────────────────────

  String _sessionKey(String recipientId, String deviceId) =>
      '$_keySessionPrefix${_safeId(recipientId, 'recipient id')}_'
      '${_safeId(deviceId, 'device id')}';

  Future<void> saveSession(
    String recipientId,
    String deviceId,
    RatchetState state,
  ) => _secureStorage.write(
    key: _sessionKey(recipientId, deviceId),
    value: jsonEncode(state.toJson()),
  );

  Future<RatchetState?> getSession(String recipientId, String deviceId) async {
    final raw = await _secureStorage.read(
      key: _sessionKey(recipientId, deviceId),
    );
    if (raw == null) return null;
    return RatchetState.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  Future<void> deleteSession(String recipientId, String deviceId) =>
      _secureStorage.delete(key: _sessionKey(recipientId, deviceId));

  // ── Session Identity Key (remote party's identity key at session creation)

  String _sessionIkKey(String userId, String deviceId) =>
      '${_epoch2Prefix}session_ik_${_safeId(userId, 'user id')}_'
      '${_safeId(deviceId, 'device id')}';

  Future<void> saveSessionIdentityKey(
    String userId,
    String deviceId,
    String identityKey,
  ) => _secureStorage.write(
    key: _sessionIkKey(userId, deviceId),
    value: identityKey,
  );

  Future<String?> getSessionIdentityKey(String userId, String deviceId) =>
      _secureStorage.read(key: _sessionIkKey(userId, deviceId));

  Future<void> deleteSessionIdentityKey(String userId, String deviceId) =>
      _secureStorage.delete(key: _sessionIkKey(userId, deviceId));

  // ── Peer Signing Key Pin (R4-C3: certified Ed25519 key of a sender device)

  String _peerSigningKey(String userId, String deviceId) =>
      '${_epoch2Prefix}peer_signing_${_safeId(userId, 'user id')}_'
      '${_safeId(deviceId, 'device id')}';

  /// Pin the Ed25519 signing public key a verified sender certificate bound to
  /// [userId]/[deviceId]. Lives and dies with the session identity pin.
  Future<void> savePeerSigningKey(
    String userId,
    String deviceId,
    String signingKey,
  ) => _secureStorage.write(
    key: _peerSigningKey(userId, deviceId),
    value: signingKey,
  );

  Future<String?> getPeerSigningKey(String userId, String deviceId) =>
      _secureStorage.read(key: _peerSigningKey(userId, deviceId));

  Future<void> deletePeerSigningKey(String userId, String deviceId) =>
      _secureStorage.delete(key: _peerSigningKey(userId, deviceId));

  // ── Session Device Tracking (for clearing all sessions for a user)

  String _sessionDevicesKey(String userId) =>
      '${_epoch2Prefix}session_devices_${_safeId(userId, 'user id')}';

  Future<void> trackSessionDevice(String userId, String deviceId) async {
    final key = _sessionDevicesKey(userId);
    final existing = await _secureStorage.read(key: key) ?? '';
    final devices = existing.isEmpty ? <String>{} : existing.split(',').toSet();
    devices.add(deviceId);
    await _secureStorage.write(key: key, value: devices.join(','));
  }

  /// Replace the tracked device list for [userId] with exactly [deviceIds] in
  /// ONE storage write, so no interruption can leave a pinned device untracked
  /// (an untracked pin is invisible to the per-contact identity checks).
  Future<void> replaceSessionDevices(String userId, List<String> deviceIds) =>
      _secureStorage.write(
        key: _sessionDevicesKey(userId),
        value: deviceIds.map((d) => _safeId(d, 'device id')).toSet().join(','),
      );

  /// Device IDs that currently have an established session with [userId].
  /// Used to look up the identity key actually pinned by the ratchet (e.g. for
  /// safety-number verification), instead of trusting a server-supplied key.
  Future<List<String>> getSessionDevices(String userId) async {
    final existing =
        await _secureStorage.read(key: _sessionDevicesKey(userId)) ?? '';
    if (existing.isEmpty) return const <String>[];
    return existing.split(',').where((d) => d.isNotEmpty).toList();
  }

  /// Delete the ratchet sessions for a peer, **keeping the identity pins**.
  ///
  /// A pinned identity key is a trust anchor, not session state. Deleting it
  /// alongside the session silently downgraded the contact back to
  /// trust-on-first-use, and that is exactly how the PreKey-takeover defence
  /// was bypassed: rather than trying to overwrite a pin — which the inbound
  /// guards refuse — an attacker only had to get the pin deleted, after which
  /// every one of those guards passes because there is nothing left to compare
  /// against. Destroying the device list made it worse, because the per-contact
  /// fallback scan then found no other pinned device either.
  ///
  /// Sessions are disposable and re-establish safely. Pins must survive, and
  /// are cleared only by [forgetPeerIdentity], which exists for the one case
  /// where a user deliberately re-verifies a contact.
  Future<void> deleteAllSessionsForUser(String userId) async {
    final key = _sessionDevicesKey(userId);
    final existing = await _secureStorage.read(key: key) ?? '';
    if (existing.isEmpty) return;
    for (final deviceId in existing.split(',')) {
      await deleteSession(userId, deviceId);
      await clearPendingPreKeyInfo(userId, deviceId);
    }
    // The device list is deliberately retained: it is what lets a later inbound
    // handshake find a sibling device's pin and refuse an impostor.
  }

  /// Explicitly forget a peer's pinned identity.
  ///
  /// This is a deliberate act of un-trusting a contact and must only ever be
  /// reached from a user-initiated flow — never from a server-supplied event.
  Future<void> forgetPeerIdentity(String userId) async {
    final existing =
        await _secureStorage.read(key: _sessionDevicesKey(userId)) ?? '';
    for (final deviceId in existing.split(',')) {
      if (deviceId.isEmpty) continue;
      await deleteSession(userId, deviceId);
      await deleteSessionIdentityKey(userId, deviceId);
      await deletePeerSigningKey(userId, deviceId);
      await clearPendingPreKeyInfo(userId, deviceId);
    }
    await _secureStorage.delete(key: _sessionDevicesKey(userId));
  }

  // ── Pending PreKey Info (for first message in new sessions) ──────

  static const _keyPendingPreKeyPrefix = '${_epoch2Prefix}pending_prekey_';

  String _pendingPreKeyKey(String recipientId, String deviceId) =>
      '$_keyPendingPreKeyPrefix${_safeId(recipientId, 'recipient id')}_'
      '${_safeId(deviceId, 'device id')}';

  Future<void> savePendingPreKeyInfo(
    String recipientId,
    String deviceId,
    String ephemeralPublicKey, {
    required String kyberCiphertext,
    required PreKeyHandshakeRouting routing,
  }) {
    routing.requireCurrent();
    if (kyberCiphertext.isEmpty) {
      throw const FormatException('Missing pending ML-KEM ciphertext');
    }
    return _secureStorage.write(
      key: _pendingPreKeyKey(recipientId, deviceId),
      value: jsonEncode({
        'ephemeralPublicKey': ephemeralPublicKey,
        'kyberCiphertext': kyberCiphertext,
        ...routing.toEnvelopeJson(),
      }),
    );
  }

  Future<Map<String, dynamic>?> getPendingPreKeyInfo(
    String recipientId,
    String deviceId,
  ) async {
    final raw = await _secureStorage.read(
      key: _pendingPreKeyKey(recipientId, deviceId),
    );
    if (raw == null) return null;
    return jsonDecode(raw) as Map<String, dynamic>;
  }

  Future<void> clearPendingPreKeyInfo(String recipientId, String deviceId) =>
      _secureStorage.delete(key: _pendingPreKeyKey(recipientId, deviceId));

  // ── Pre-Key Counter ───────────────────────────────────────────────

  Future<int> getNextPreKeyId() async {
    final raw = await _secureStorage.read(key: _keyNextPreKeyId);
    if (raw == null) return 1;
    final parsed = int.tryParse(raw);
    if (parsed == null) {
      throw const FormatException('Corrupt one-time pre-key counter');
    }
    if (parsed < 0) {
      throw const FormatException('Corrupt one-time pre-key counter');
    }
    // Epoch 2 reserves zero as invalid. Exactly legacy zero is advanced once
    // during the hard cutover instead of ever being uploaded again.
    return parsed == 0 ? 1 : parsed;
  }

  /// Durably reserve a positive, non-overlapping range of one-time pre-key
  /// ids before any corresponding private key material is generated.
  ///
  /// Persisting the counter first makes interruption create harmless gaps
  /// instead of allowing a retry to store different keys under an id already
  /// exposed to the server. The stored pool is also treated as authoritative
  /// when repairing a lost or restored counter.
  Future<int> reserveOneTimePreKeyRange(
    int count, {
    int minimumExclusive = 0,
  }) async {
    if (count <= 0) {
      throw ArgumentError.value(count, 'count', 'must be positive');
    }

    final greatestStoredId = await _greatestValidatedOneTimePreKeyId(
      await getOneTimePreKeys(),
    );

    var startId = await getNextPreKeyId();
    if (startId <= greatestStoredId) startId = greatestStoredId + 1;
    if (startId <= minimumExclusive) startId = minimumExclusive + 1;
    final nextId = startId + count;
    if (startId <= 0 ||
        startId > RisaalCryptoProtocol.maxKeyId ||
        nextId <= startId ||
        nextId > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('One-time pre-key id space exhausted');
    }

    // This write intentionally precedes key generation/list persistence.
    // A crash after it consumes ids but can never alias key material.
    await setNextPreKeyId(nextId);
    return startId;
  }

  Future<void> setNextPreKeyId(int id) {
    if (id <= 0 || id > RisaalCryptoProtocol.maxKeyId) {
      throw ArgumentError.value(id, 'id', 'must be a positive epoch-2 key id');
    }
    return _secureStorage.write(key: _keyNextPreKeyId, value: id.toString());
  }

  // ── Sender Keys (Group E2EE) ─────────────────────────────────────

  static const _keySenderKeyPrefix = '${_epoch2Prefix}sender_key_';
  static const _keySenderKeyRotationPrefix =
      '${_epoch2Prefix}sender_key_rotation_';

  String _senderKeyKey(String groupId, String senderId) =>
      '$_keySenderKeyPrefix${_safeId(groupId, 'group id')}_'
      '${_safeId(senderId, 'sender id')}';

  String _senderKeyRotationKey(String groupId, String senderId) =>
      '$_keySenderKeyRotationPrefix${_safeId(groupId, 'group id')}_'
      '${_safeId(senderId, 'sender id')}';

  Future<void> saveSenderKeyRaw(
    String groupId,
    String senderId,
    Map<String, dynamic> stateJson,
  ) => _secureStorage.write(
    key: _senderKeyKey(groupId, senderId),
    value: jsonEncode(stateJson),
  );

  Future<Map<String, dynamic>?> getSenderKeyRaw(
    String groupId,
    String senderId,
  ) async {
    final raw = await _secureStorage.read(
      key: _senderKeyKey(groupId, senderId),
    );
    if (raw == null) return null;
    return jsonDecode(raw) as Map<String, dynamic>;
  }

  Future<void> deleteSenderKey(String groupId, String senderId) =>
      _secureStorage.delete(key: _senderKeyKey(groupId, senderId));

  Future<void> savePendingSenderKeyRotationRaw(
    String groupId,
    String senderId,
    Map<String, dynamic> rotationJson,
  ) => _secureStorage.write(
    key: _senderKeyRotationKey(groupId, senderId),
    value: jsonEncode(rotationJson),
  );

  Future<Map<String, dynamic>?> getPendingSenderKeyRotationRaw(
    String groupId,
    String senderId,
  ) async {
    final raw = await _secureStorage.read(
      key: _senderKeyRotationKey(groupId, senderId),
    );
    if (raw == null) return null;
    final decoded = jsonDecode(raw);
    if (decoded is! Map) {
      throw const FormatException('Invalid pending Sender Key rotation');
    }
    return Map<String, dynamic>.from(decoded);
  }

  Future<void> deletePendingSenderKeyRotation(
    String groupId,
    String senderId,
  ) => _secureStorage.delete(key: _senderKeyRotationKey(groupId, senderId));

  /// Delete all sender keys for a group. Since we can't enumerate
  /// secure storage keys, we accept a list of known member IDs.
  Future<void> deleteSenderKeysForGroup(
    String groupId,
    List<String> memberIds,
  ) async {
    for (final memberId in memberIds) {
      await _secureStorage.delete(key: _senderKeyKey(groupId, memberId));
    }
  }

  // ── Session Reset Tracking ──────────────────────────────────────

  static const _keyResetPrefix = '${_epoch2Prefix}session_resets_';

  String _resetKey(String userId, String deviceId) =>
      '$_keyResetPrefix${_safeId(userId, 'user id')}_'
      '${_safeId(deviceId, 'device id')}';

  /// Load the list of reset timestamps (epoch ms) for a session pair.
  Future<List<int>> loadResetTimestamps(String userId, String deviceId) async {
    final raw = await _secureStorage.read(key: _resetKey(userId, deviceId));
    if (raw == null || raw.isEmpty) return [];
    final list = jsonDecode(raw) as List<dynamic>;
    return list.cast<int>();
  }

  /// Save the list of reset timestamps for a session pair.
  /// Trims to the last 10 entries to prevent unbounded growth.
  Future<void> saveResetTimestamps(
    String userId,
    String deviceId,
    List<int> timestamps,
  ) async {
    final trimmed = timestamps.length > 10
        ? timestamps.sublist(timestamps.length - 10)
        : timestamps;
    await _secureStorage.write(
      key: _resetKey(userId, deviceId),
      value: jsonEncode(trimmed),
    );
  }

  /// Clear all reset timestamps for a session pair.
  /// Called on manual "Reset Encryption" or after 24h cooldown.
  Future<void> clearResetTimestamps(String userId, String deviceId) =>
      _secureStorage.delete(key: _resetKey(userId, deviceId));

  // ── Exact non-crypto account routing reads ──────────────────────

  /// Read only the local account identifier used in authenticated routing.
  /// A generic raw-key reader is intentionally not exposed because it would
  /// also make private crypto journal records caller-readable.
  Future<String?> getLocalUserId() => _secureStorage.read(key: 'user_id');

  /// Read only the local device identifier used in authenticated routing.
  Future<String?> getLocalDeviceId() => _secureStorage.read(key: 'device_id');

  // ── Sealed Sender Nonce Deduplication ────────────────────────────

  static const _keySeenNonces = '${_epoch2Prefix}seen_nonces';

  /// Save the sealed sender nonce deduplication set.
  /// Bounded to most recent 10,000 entries.
  Future<void> saveSeenNonces(Set<String> nonces) async {
    final list = nonces.toList();
    final trimmed = list.length > 10000
        ? list.sublist(list.length - 10000)
        : list;
    await _secureStorage.write(key: _keySeenNonces, value: jsonEncode(trimmed));
  }

  /// Load persisted sealed sender nonces for replay protection.
  Future<Set<String>> loadSeenNonces() async {
    final raw = await _secureStorage.read(key: _keySeenNonces);
    if (raw == null || raw.isEmpty) return {};
    final list = jsonDecode(raw) as List<dynamic>;
    return list.cast<String>().toSet();
  }

  // ── Panic Wipe ────────────────────────────────────────────────────

  /// Erase all crypto material from secure storage.
  Future<void> wipeAll() => _secureStorage.clearAll();

  /// Surgical wipe for a fresh registration on the same device.
  ///
  /// Deletes every account-scoped value through the storage backend's atomic
  /// delete-all + whitelist-restore boundary. This includes dynamic
  /// per-recipient sessions, peer identities/capabilities, replay state,
  /// sender keys, pending pre-keys and reset counters. Leaving those records
  /// reachable across accounts can load a prior account's ratchet when
  /// user/device identifiers collide.
  ///
  /// Call this *before* [SignalProtocolManager.initialize] when the user
  /// is creating a new account so [initialize] regenerates a fresh
  /// 20-key bundle instead of replaying accumulated state from a
  /// previous account on the same device.
  Future<void> wipeForFreshRegistration() async {
    await _secureStorage.clearAccountScopedValues();
    await _markInitialRegistrationIntent();
  }

  // ── Device transfer (R4-M37) ──────────────────────────────────────

  /// Every crypto key this package owns, as `crypto_store` archive entries
  /// in key order: identity and signing keys, SPK and KEM generations, the
  /// OPK pool and the key-bundle journal, sessions and their identity pins,
  /// peer signing pins and capabilities, pending PreKey state, sender keys
  /// and rotations, replay sets, handshake tombstones, seen sealed-sender
  /// nonces and the commit journals' completed receipts.
  ///
  /// Read through the storage only; the storage must implement
  /// [TransferKeyListing]. Never exported: app keys (tokens, PINs, the PIN
  /// vault, KT, rosters, the sender certificate), legacy keys, diagnostics.
  /// Throws [TransferExportBlocked] (nothing exported) for a storage that
  /// cannot list its keys, an unaccepted registration, a missing identity, a
  /// pending send or receive commit, or a store that changed during export.
  /// Call it in transfer mode, with sends and receives held.
  Future<List<TransferArchiveEntry>> exportForTransfer() =>
      exportCryptoStoreForTransfer(_secureStorage);

  /// Install the archive's `crypto_store` entries into [staging], never into
  /// this storage: the app commits [staging] afterwards (like registration
  /// staging), so nothing is live until then.
  ///
  /// Validates everything before the first write: only package keys, strict
  /// UTF-8, an identity, signing key and key-bundle journal that belong
  /// together, no pending commit. [staging] must be empty and must not be
  /// this storage. Throws [FormatException] for a refused archive,
  /// [ArgumentError] when [staging] is this storage and [StateError] when it
  /// is not empty. On any throw, discard [staging].
  Future<void> importForTransfer(
    TransferArchive archive, {
    required CryptoSecureStorage staging,
  }) => importCryptoStoreForTransfer(
    archive: archive,
    live: _secureStorage,
    staging: staging,
  );
}
