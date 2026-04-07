/// Abstract interface for secure key-value storage.
///
/// This is the integration point between the crypto layer and the main app's
/// secure storage implementation. The crypto layer stores all key material
/// (identity keys, session state, pre-keys) exclusively through this interface,
/// ensuring platform-appropriate security.
///
/// Implementations should use platform-secure storage backends:
///   - **iOS**: Keychain Services (hardware-backed when available)
///   - **Android**: EncryptedSharedPreferences backed by Android Keystore
///   - **Tests**: In-memory Map (see `test/helpers/fake_secure_storage.dart`)
///
/// All keys are stored as JSON-serialized strings. The storage layer is
/// responsible for encryption at rest (platform-dependent).
///
/// Example implementation:
/// ```dart
/// class FlutterSecureStorageAdapter implements CryptoSecureStorage {
///   final FlutterSecureStorage _storage;
///
///   FlutterSecureStorageAdapter(this._storage);
///
///   @override
///   Future<void> write({required String key, required String value}) =>
///     _storage.write(key: key, value: value);
///
///   @override
///   Future<String?> read({required String key}) =>
///     _storage.read(key: key);
///
///   @override
///   Future<void> delete({required String key}) =>
///     _storage.delete(key: key);
///
///   @override
///   Future<void> clearAll() => _storage.deleteAll();
/// }
/// ```
///
/// See also:
///   - [CryptoStorage] which wraps this interface with crypto-specific logic
///   - [SignalProtocolManager] which calls storage methods during crypto operations
abstract class CryptoSecureStorage {
  /// Write a key-value pair to secure storage.
  ///
  /// Called by the crypto layer to persist identity keys, sessions, pre-keys,
  /// and other cryptographic state. The value is always a JSON-serialized string.
  ///
  /// This operation must be atomic. If the write fails, the future should
  /// complete with an error and the previous value (if any) should remain intact.
  Future<void> write({required String key, required String value});

  /// Read a value from secure storage.
  ///
  /// Returns `null` if the key does not exist. Called frequently during
  /// encrypt/decrypt operations to load session state and identity keys.
  ///
  /// Implementations should cache values in memory when possible to avoid
  /// platform-specific I/O overhead on every crypto operation.
  Future<String?> read({required String key});

  /// Delete a single key-value pair from secure storage.
  ///
  /// Called when a session is removed (e.g., after verifying a safety number
  /// mismatch) or when a one-time pre-key is consumed. Does not fail if the
  /// key does not exist.
  Future<void> delete({required String key});

  /// Delete all stored values.
  ///
  /// Called during panic wipe to destroy all cryptographic key material.
  /// This is a destructive operation with no undo. Implementations should
  /// ensure this completes even if individual deletes fail.
  Future<void> clearAll();
}
