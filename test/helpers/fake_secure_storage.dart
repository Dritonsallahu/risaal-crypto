import 'package:risaal_crypto/src/crypto_secure_storage.dart';

/// In-memory CryptoSecureStorage replacement for unit tests.
/// Implements all methods using a simple Map instead of platform keychain.
class FakeSecureStorage implements CryptoSecureStorage {
  final Map<String, String> _store = {};

  @override
  StorageSecurityLevel get securityLevel => StorageSecurityLevel.insecure;

  @override
  Future<void> write({required String key, required String value}) async {
    _store[key] = value;
  }

  @override
  Future<String?> read({required String key}) async {
    return _store[key];
  }

  @override
  Future<void> delete({required String key}) async {
    _store.remove(key);
  }

  @override
  Future<void> clearAll() async {
    _store.clear();
  }

  /// Reset all state between tests.
  void reset() {
    _store.clear();
  }

  /// Inspect stored keys (for test assertions).
  Map<String, String> get store => Map.unmodifiable(_store);
}
