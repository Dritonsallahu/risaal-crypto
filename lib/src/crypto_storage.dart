import 'dart:convert';

import 'crypto_secure_storage.dart';
import 'models/session_state.dart';
import 'models/signal_keys.dart';

/// Persists all Signal Protocol key material in [CryptoSecureStorage].
///
/// Every key is prefixed to avoid collisions with non-crypto storage
/// entries. All values are JSON- or base64-encoded strings.
class CryptoStorage {
  final CryptoSecureStorage _secureStorage;

  CryptoStorage({required CryptoSecureStorage secureStorage})
      : _secureStorage = secureStorage;

  // ── Storage Key Prefixes ──────────────────────────────────────────
  static const _keyIdentityKP = 'crypto_identity_key_pair';
  static const _keySigningKP = 'crypto_signing_key_pair';
  static const _keySignedPreKey = 'crypto_signed_pre_key';
  static const _keyOneTimePreKeys = 'crypto_one_time_pre_keys';
  static const _keySessionPrefix = 'crypto_session_';
  static const _keyKyberKP = 'crypto_kyber_key_pair';
  static const _keyNextPreKeyId = 'crypto_next_pre_key_id';

  // ── Identity Key Pair ─────────────────────────────────────────────

  Future<void> saveIdentityKeyPair(KeyPair keyPair) =>
      _secureStorage.write(
        key: _keyIdentityKP,
        value: jsonEncode(keyPair.toJson()),
      );

  Future<KeyPair?> getIdentityKeyPair() async {
    final raw = await _secureStorage.read(key: _keyIdentityKP);
    if (raw == null) return null;
    return KeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Signing Key Pair (Ed25519) ──────────────────────────────────

  Future<void> saveSigningKeyPair(KeyPair keyPair) =>
      _secureStorage.write(
        key: _keySigningKP,
        value: jsonEncode(keyPair.toJson()),
      );

  Future<KeyPair?> getSigningKeyPair() async {
    final raw = await _secureStorage.read(key: _keySigningKP);
    if (raw == null) return null;
    return KeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Signed Pre-Key ────────────────────────────────────────────────

  Future<void> saveSignedPreKey(SignedPreKey key) =>
      _secureStorage.write(
        key: _keySignedPreKey,
        value: jsonEncode(key.toJson()),
      );

  Future<SignedPreKey?> getSignedPreKey() async {
    final raw = await _secureStorage.read(key: _keySignedPreKey);
    if (raw == null) return null;
    return SignedPreKey.fromJson(jsonDecode(raw) as Map<String, dynamic>);
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

  Future<void> removeOneTimePreKey(int keyId) async {
    final keys = await getOneTimePreKeys();
    keys.removeWhere((k) => k.keyId == keyId);
    await saveOneTimePreKeys(keys);
  }

  // ── Kyber Key Pair (ML-KEM-768) ──────────────────────────────────

  Future<void> saveKyberKeyPair(KyberKeyPair keyPair) =>
      _secureStorage.write(
        key: _keyKyberKP,
        value: jsonEncode(keyPair.toJson()),
      );

  Future<KyberKeyPair?> getKyberKeyPair() async {
    final raw = await _secureStorage.read(key: _keyKyberKP);
    if (raw == null) return null;
    return KyberKeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Session State ─────────────────────────────────────────────────

  String _sessionKey(String recipientId, String deviceId) =>
      '$_keySessionPrefix${recipientId}_$deviceId';

  Future<void> saveSession(
    String recipientId,
    String deviceId,
    RatchetState state,
  ) =>
      _secureStorage.write(
        key: _sessionKey(recipientId, deviceId),
        value: jsonEncode(state.toJson()),
      );

  Future<RatchetState?> getSession(
    String recipientId,
    String deviceId,
  ) async {
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
      'crypto_session_ik_${userId}_$deviceId';

  Future<void> saveSessionIdentityKey(
    String userId,
    String deviceId,
    String identityKey,
  ) =>
      _secureStorage.write(
        key: _sessionIkKey(userId, deviceId),
        value: identityKey,
      );

  Future<String?> getSessionIdentityKey(String userId, String deviceId) =>
      _secureStorage.read(key: _sessionIkKey(userId, deviceId));

  Future<void> deleteSessionIdentityKey(String userId, String deviceId) =>
      _secureStorage.delete(key: _sessionIkKey(userId, deviceId));

  // ── Session Device Tracking (for clearing all sessions for a user)

  String _sessionDevicesKey(String userId) =>
      'crypto_session_devices_$userId';

  Future<void> trackSessionDevice(String userId, String deviceId) async {
    final key = _sessionDevicesKey(userId);
    final existing = await _secureStorage.read(key: key) ?? '';
    final devices =
        existing.isEmpty ? <String>{} : existing.split(',').toSet();
    devices.add(deviceId);
    await _secureStorage.write(key: key, value: devices.join(','));
  }

  Future<void> deleteAllSessionsForUser(String userId) async {
    final key = _sessionDevicesKey(userId);
    final existing = await _secureStorage.read(key: key) ?? '';
    if (existing.isEmpty) return;
    for (final deviceId in existing.split(',')) {
      await deleteSession(userId, deviceId);
      await deleteSessionIdentityKey(userId, deviceId);
      await clearPendingPreKeyInfo(userId, deviceId);
    }
    await _secureStorage.delete(key: key);
  }

  // ── Pending PreKey Info (for first message in new sessions) ──────

  static const _keyPendingPreKeyPrefix = 'crypto_pending_prekey_';

  String _pendingPreKeyKey(String recipientId, String deviceId) =>
      '$_keyPendingPreKeyPrefix${recipientId}_$deviceId';

  Future<void> savePendingPreKeyInfo(
    String recipientId,
    String deviceId,
    String ephemeralPublicKey,
    int? usedOneTimePreKeyId, {
    String? kyberCiphertext,
  }) =>
      _secureStorage.write(
        key: _pendingPreKeyKey(recipientId, deviceId),
        value: jsonEncode({
          'ephemeralPublicKey': ephemeralPublicKey,
          'usedOneTimePreKeyId': usedOneTimePreKeyId,
          if (kyberCiphertext != null) 'kyberCiphertext': kyberCiphertext,
        }),
      );

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

  Future<void> clearPendingPreKeyInfo(
    String recipientId,
    String deviceId,
  ) =>
      _secureStorage.delete(key: _pendingPreKeyKey(recipientId, deviceId));

  // ── Pre-Key Counter ───────────────────────────────────────────────

  Future<int> getNextPreKeyId() async {
    final raw = await _secureStorage.read(key: _keyNextPreKeyId);
    return raw != null ? int.parse(raw) : 0;
  }

  Future<void> setNextPreKeyId(int id) =>
      _secureStorage.write(key: _keyNextPreKeyId, value: id.toString());

  // ── Sender Keys (Group E2EE) ─────────────────────────────────────

  static const _keySenderKeyPrefix = 'crypto_sender_key_';

  String _senderKeyKey(String groupId, String senderId) =>
      '$_keySenderKeyPrefix${groupId}_$senderId';

  Future<void> saveSenderKeyRaw(
    String groupId,
    String senderId,
    Map<String, dynamic> stateJson,
  ) =>
      _secureStorage.write(
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

  static const _keyResetPrefix = 'crypto_session_resets_';

  String _resetKey(String userId, String deviceId) =>
      '$_keyResetPrefix${userId}_$deviceId';

  /// Load the list of reset timestamps (epoch ms) for a session pair.
  Future<List<int>> loadResetTimestamps(
    String userId,
    String deviceId,
  ) async {
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

  // ── Raw Read (for non-crypto keys like user_id) ─────────────────

  Future<String?> readRaw(String key) => _secureStorage.read(key: key);

  // ── Panic Wipe ────────────────────────────────────────────────────

  /// Erase all crypto material from secure storage.
  Future<void> wipeAll() => _secureStorage.clearAll();
}
