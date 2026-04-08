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
  static const _keySignedPreKeyCreatedAt = 'crypto_signed_prekey_created_at';
  static const _keyOneTimePreKeys = 'crypto_one_time_pre_keys';
  static const _keySessionPrefix = 'crypto_session_';
  static const _keyKyberKP = 'crypto_kyber_key_pair';
  static const _keyKyberCreatedAt = 'crypto_kyber_created_at';
  static const _keyNextPreKeyId = 'crypto_next_pre_key_id';
  static const _keyPeerCapPrefix = 'crypto_peer_cap_';

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

  Future<void> removeOneTimePreKey(int keyId) async {
    final keys = await getOneTimePreKeys();
    keys.removeWhere((k) => k.keyId == keyId);
    await saveOneTimePreKeys(keys);
  }

  // ── Kyber Key Pair (ML-KEM-768) ──────────────────────────────────

  Future<void> saveKyberKeyPair(KyberKeyPair keyPair) => _secureStorage.write(
        key: _keyKyberKP,
        value: jsonEncode(keyPair.toJson()),
      );

  Future<KyberKeyPair?> getKyberKeyPair() async {
    final raw = await _secureStorage.read(key: _keyKyberKP);
    if (raw == null) return null;
    return KyberKeyPair.fromJson(jsonDecode(raw) as Map<String, dynamic>);
  }

  // ── Kyber Key Creation Timestamp ─────────────────────────────────

  Future<void> saveKyberCreatedAt(int epochMs) => _secureStorage.write(
        key: _keyKyberCreatedAt,
        value: epochMs.toString(),
      );

  Future<int?> getKyberCreatedAt() async {
    final raw = await _secureStorage.read(key: _keyKyberCreatedAt);
    if (raw == null) return null;
    return int.tryParse(raw);
  }

  // ── Previous Signed Pre-Key (48h overlap) ──────────────────────

  static const _keyPreviousSignedPreKey = 'crypto_previous_signed_pre_key';
  static const _keyPreviousSpkExpiry = 'crypto_previous_spk_expiry';

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

  // ── Previous Kyber Key (48h overlap) ───────────────────────────

  static const _keyPreviousKyberKP = 'crypto_previous_kyber_key_pair';
  static const _keyPreviousKyberExpiry = 'crypto_previous_kyber_expiry';

  Future<void> savePreviousKyberKeyPair(
    KyberKeyPair keyPair,
    int expiryEpochMs,
  ) async {
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

  // ── Peer Identity Key Tracking (reinstall / MITM detection) ───────

  static const _keyPeerIdentityPrefix = 'crypto_peer_identity_';

  String _peerIdentityKey(String userId, String deviceId) =>
      '$_keyPeerIdentityPrefix${userId}_$deviceId';

  /// Save the peer's identity public key for change detection.
  Future<void> savePeerIdentityKey(
    String userId,
    String deviceId,
    String identityPublicKey,
  ) =>
      _secureStorage.write(
        key: _peerIdentityKey(userId, deviceId),
        value: identityPublicKey,
      );

  /// Get the peer's previously stored identity public key.
  /// Returns null if we've never stored a key for this peer.
  Future<String?> getPeerIdentityKey(
    String userId,
    String deviceId,
  ) =>
      _secureStorage.read(key: _peerIdentityKey(userId, deviceId));

  /// Delete the peer's stored identity key (e.g. on session deletion).
  Future<void> deletePeerIdentityKey(String userId, String deviceId) =>
      _secureStorage.delete(key: _peerIdentityKey(userId, deviceId));

  // ── Peer Capability Tracking (anti-downgrade) ─────────────────────

  String _peerCapKey(String userId, String deviceId) =>
      '$_keyPeerCapPrefix${userId}_$deviceId';

  /// Save the peer's known PQXDH capability.
  Future<void> savePeerPqxdhCapability(
    String userId,
    String deviceId,
    bool supportsPqxdh,
  ) =>
      _secureStorage.write(
        key: _peerCapKey(userId, deviceId),
        value: jsonEncode({
          'supportsPqxdh': supportsPqxdh,
          'lastSeen': DateTime.now().millisecondsSinceEpoch,
        }),
      );

  /// Get the peer's last known PQXDH capability.
  /// Returns null if we've never established a session with this peer.
  Future<bool?> getPeerPqxdhCapability(
    String userId,
    String deviceId,
  ) async {
    final raw = await _secureStorage.read(
      key: _peerCapKey(userId, deviceId),
    );
    if (raw == null) return null;
    final json = jsonDecode(raw) as Map<String, dynamic>;
    return json['supportsPqxdh'] as bool?;
  }

  /// Delete peer capability record (e.g. on session deletion).
  Future<void> deletePeerCapability(String userId, String deviceId) =>
      _secureStorage.delete(key: _peerCapKey(userId, deviceId));

  // ── Anti-Replay State Persistence ──────────────────────────────────

  static const _keyReplayPrefix = 'crypto_replay_';

  String _replayKey(String userId, String deviceId) =>
      '$_keyReplayPrefix${userId}_$deviceId';

  /// Save the set of received message numbers for anti-replay.
  /// Stores as JSON list of "dhKey:msgNum" strings.
  Future<void> saveReceivedMessageNumbers(
    String userId,
    String deviceId,
    Set<String> messageIds,
  ) async {
    // Only persist the most recent entries to bound storage size.
    final list = messageIds.toList();
    final trimmed =
        list.length > 2000 ? list.sublist(list.length - 2000) : list;
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

  String _sessionDevicesKey(String userId) => 'crypto_session_devices_$userId';

  Future<void> trackSessionDevice(String userId, String deviceId) async {
    final key = _sessionDevicesKey(userId);
    final existing = await _secureStorage.read(key: key) ?? '';
    final devices = existing.isEmpty ? <String>{} : existing.split(',').toSet();
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
