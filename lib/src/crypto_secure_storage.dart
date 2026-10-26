/// Declares the security level of the storage backend.
enum StorageSecurityLevel {
  /// Hardware-backed: key material wrapped by a non-exportable Keystore /
  /// Secure Enclave key. NOTE: not currently wired in production — the app
  /// declares [softwareEncrypted] (see SecureStorageAdapter).
  hardwareBacked,

  /// Software-encrypted: EncryptedSharedPreferences, SQLCipher.
  softwareEncrypted,

  /// Insecure: plain SharedPreferences, in-memory Map (tests only).
  insecure,
}

/// Abstract interface for secure key-value storage.
///
/// This is the integration point between the crypto layer and the main app's
/// secure storage implementation. The crypto layer stores all key material
/// (identity keys, session state, pre-keys) exclusively through this interface,
/// ensuring platform-appropriate security.
///
/// Implementations should use platform-secure storage backends:
///   - **iOS**: Keychain Services (software-encrypted at rest, device-only)
///   - **Android**: EncryptedSharedPreferences (AES, Keystore-wrapped master key)
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
  /// The security level of this storage backend.
  ///
  /// Implementations must declare their security level so the crypto layer
  /// can warn when running on an insecure backend (e.g. in-memory Map).
  StorageSecurityLevel get securityLevel;

  /// Write a key-value pair to secure storage.
  ///
  /// Called by the crypto layer to persist identity keys, sessions, pre-keys,
  /// and other cryptographic state. The value is always a JSON-serialized string.
  ///
  /// This operation must be atomic: readers observe either the complete old
  /// value or the complete new value, never a torn value. A platform/backend
  /// error may be reported after the new value committed, so callers that own a
  /// durable protocol transition must treat thrown completion as ambiguous and
  /// reconcile by rereading the exact value before retrying.
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
  /// key does not exist. As with [write], a thrown completion may be ambiguous:
  /// the key can already be absent, so durable protocol callers must reread.
  Future<void> delete({required String key});

  /// Delete all stored values.
  ///
  /// Called during panic wipe to destroy all cryptographic key material.
  /// This is a destructive operation with no undo. Implementations should
  /// ensure this completes even if individual deletes fail.
  Future<void> clearAll();

  /// Atomically clear every account-scoped value before fresh registration.
  ///
  /// The default clears the entire backend. App adapters may preserve only
  /// explicitly device-scoped values, but must use a delete-all + whitelist
  /// restore strategy rather than best-effort key enumeration.
  Future<void> clearAccountScopedValues() => clearAll();
}
