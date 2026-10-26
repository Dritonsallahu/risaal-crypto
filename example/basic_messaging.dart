/// Basic two-party encrypted messaging with risaal_crypto.
///
/// This example demonstrates the complete lifecycle:
/// 1. Initialize both parties (generate identity keys)
/// 2. Exchange pre-key bundles via server
/// 3. Establish an encrypted session (X3DH)
/// 4. Send and receive encrypted messages (Double Ratchet)
///
/// In production, the server stores and delivers bundles and messages.
/// Here we simulate everything in-memory.
library;

import 'package:risaal_crypto/risaal_crypto.dart';

import 'example_key_bundle_helper.dart';

// In-memory storage for demonstration
class InMemoryStorage implements CryptoSecureStorage {
  final _store = <String, String>{};

  @override
  StorageSecurityLevel get securityLevel => StorageSecurityLevel.insecure;

  @override
  Future<void> write({required String key, required String value}) async =>
      _store[key] = value;

  @override
  Future<String?> read({required String key}) async => _store[key];

  @override
  Future<void> delete({required String key}) async => _store.remove(key);

  @override
  Future<void> clearAll() async => _store.clear();

  @override
  Future<void> clearAccountScopedValues() => clearAll();
}

Future<void> main() async {
  // ── Step 1: Initialize both parties ─────────────────────────────
  final aliceStorage = InMemoryStorage();
  final bobStorage = InMemoryStorage();

  // Write user IDs (required for sealed sender and safety numbers)
  await aliceStorage.write(key: 'user_id', value: 'alice-001');
  await aliceStorage.write(key: 'device_id', value: 'alice-device-1');
  await bobStorage.write(key: 'user_id', value: 'bob-001');
  await bobStorage.write(key: 'device_id', value: 'bob-device-1');

  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);

  // Generate all key material (identity, signing, pre-keys, Kyber)
  await alice.wipeForFreshRegistration();
  await bob.wipeForFreshRegistration();
  final aliceIsNew = await alice.initialize(); // returns true on first run
  final bobIsNew = await bob.initialize();
  print('Alice new device: $aliceIsNew'); // true
  print('Bob new device: $bobIsNew'); // true

  // ── Step 2: Upload and accept Bob's journal generation ──────────
  // In production, the authenticated server returns the immutable receipt.
  final bobPreKeyBundle = await acceptInitialExampleGeneration(
    bob,
    userId: 'bob-001',
    deviceId: 'bob-device-1',
  );

  // ── Step 3: Alice initiates a session with Bob ──────────────────
  // Alice fetches Bob's bundle from the server
  await alice.createSession(bobPreKeyBundle);
  print('Session established (Alice -> Bob)');

  // ── Step 4: Alice sends a message ───────────────────────────────
  final envelope = await alice.encryptMessage(
    'bob-001',
    'bob-device-1',
    'Hello Bob! This message is end-to-end encrypted.',
  );
  print('Message type: ${envelope['type']}'); // "prekey" for first message

  // ── Step 5: Bob receives and decrypts ───────────────────────────
  final plaintext = await bob.decryptMessage(
    'alice-001',
    'alice-device-1',
    envelope,
  );
  print('Bob received: $plaintext');
  // Output: "Hello Bob! This message is end-to-end encrypted."

  // ── Step 6: Bob replies ─────────────────────────────────────────
  final reply = await bob.encryptMessage(
    'alice-001',
    'alice-device-1',
    'Hi Alice! The ratchet has advanced.',
  );
  print('Reply type: ${reply['type']}'); // "message" (session exists)

  final replyPlaintext = await alice.decryptMessage(
    'bob-001',
    'bob-device-1',
    reply,
  );
  print('Alice received: $replyPlaintext');
}
