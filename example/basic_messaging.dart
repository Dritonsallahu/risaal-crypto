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

// In-memory storage for demonstration
class InMemoryStorage implements CryptoSecureStorage {
  final _store = <String, String>{};

  @override
  Future<void> write({required String key, required String value}) async =>
      _store[key] = value;

  @override
  Future<String?> read({required String key}) async => _store[key];

  @override
  Future<void> delete({required String key}) async => _store.remove(key);

  @override
  Future<void> clearAll() async => _store.clear();
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
  final aliceIsNew = await alice.initialize(); // returns true on first run
  final bobIsNew = await bob.initialize();
  print('Alice new device: $aliceIsNew'); // true
  print('Bob new device: $bobIsNew'); // true

  // ── Step 2: Upload key bundles to "server" ──────────────────────
  // In production, POST these to /api/keys/upload
  // ignore: unused_local_variable
  final aliceBundle = await alice.generateKeyBundle();
  final bobBundle = await bob.generateKeyBundle();

  // ── Step 3: Alice initiates a session with Bob ──────────────────
  // Alice fetches Bob's bundle from the server
  final bobPreKeyBundle = PreKeyBundle(
    userId: 'bob-001',
    deviceId: 'bob-device-1',
    identityKey: bobBundle['identityKey'] as String,
    identitySigningKey: bobBundle['identitySigningKey'] as String?,
    signedPreKey: SignedPreKeyPublic(
      keyId: (bobBundle['signedPreKey'] as Map)['keyId'] as int,
      publicKey: (bobBundle['signedPreKey'] as Map)['publicKey'] as String,
      signature: (bobBundle['signedPreKey'] as Map)['signature'] as String,
    ),
    oneTimePreKey: (bobBundle['oneTimePreKeys'] as List).isNotEmpty
        ? OneTimePreKeyPublic(
            keyId: ((bobBundle['oneTimePreKeys'] as List)[0]
                as Map)['keyId'] as int,
            publicKey: ((bobBundle['oneTimePreKeys'] as List)[0]
                as Map)['publicKey'] as String,
          )
        : null,
  );

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
