/// Sealed Sender: metadata-hiding message envelopes.
///
/// The server routes messages to recipients, but with Sealed Sender,
/// it cannot determine WHO sent a particular message. Only the
/// recipient can unseal the outer encryption layer to discover the
/// sender's identity.
///
/// This prevents the server (even if compromised) from building a
/// social graph of who talks to whom.
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
  // ── Setup Alice and Bob ─────────────────────────────────────────
  final aliceStorage = InMemoryStorage();
  final bobStorage = InMemoryStorage();

  await aliceStorage.write(key: 'user_id', value: 'alice-001');
  await aliceStorage.write(key: 'device_id', value: 'alice-device-1');
  await bobStorage.write(key: 'user_id', value: 'bob-001');
  await bobStorage.write(key: 'device_id', value: 'bob-device-1');

  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);

  await alice.initialize();
  await bob.initialize();

  // Exchange bundles and establish session
  final bobBundle = await bob.generateKeyBundle();
  final bobPreKeyBundle = PreKeyBundle(
    userId: 'bob-001',
    deviceId: 'bob-device-1',
    identityKey: bobBundle['identityKey'] as String,
    identitySigningKey: bobBundle['identitySigningKey'] as String,
    signedPreKey: SignedPreKeyPublic(
      keyId: (bobBundle['signedPreKey'] as Map)['keyId'] as int,
      publicKey: (bobBundle['signedPreKey'] as Map)['publicKey'] as String,
      signature: (bobBundle['signedPreKey'] as Map)['signature'] as String,
    ),
    oneTimePreKey: (bobBundle['oneTimePreKeys'] as List).isNotEmpty
        ? OneTimePreKeyPublic(
            keyId: ((bobBundle['oneTimePreKeys'] as List)[0] as Map)['keyId']
                as int,
            publicKey: ((bobBundle['oneTimePreKeys'] as List)[0]
                as Map)['publicKey'] as String,
          )
        : null,
  );

  await alice.createSession(bobPreKeyBundle);
  print('Session established');

  // ── Sealed Sender Encrypt ───────────────────────────────────────
  // Alice knows Bob's identity public key (from his bundle)
  final bobIdentityKey = await bob.getIdentityPublicKey();

  final sealedEnvelope = await alice.encryptSealedSenderFull(
    senderId: 'alice-001',
    senderDeviceId: 'alice-device-1',
    recipientId: 'bob-001',
    recipientDeviceId: 'bob-device-1',
    recipientIdentityPublicKey: bobIdentityKey,
    plaintext: 'This message hides my identity from the server.',
  );

  // The server sees: {ephemeralPublicKey, ciphertext, nonce}
  // It does NOT know this came from Alice
  print('Sealed envelope keys: ${sealedEnvelope.keys.toList()}');

  // ── Sealed Sender Decrypt ───────────────────────────────────────
  final result = await bob.decryptSealedSender(sealedEnvelope);

  print('Sender: ${result.senderId}'); // "alice-001" (discovered)
  print('Message: ${result.plaintext}'); // "This message hides..."
  print('Device: ${result.senderDeviceId}'); // "alice-device-1"
}
