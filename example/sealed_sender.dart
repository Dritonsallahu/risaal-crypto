/// Sealed Sender: metadata-hiding message envelopes.
///
/// The server routes messages to recipients, but with Sealed Sender,
/// it cannot determine WHO sent a particular message. Only the
/// recipient can unseal the outer encryption layer to discover the
/// sender's identity.
///
/// This prevents the server (even if compromised) from building a
/// social graph of who talks to whom.
///
/// Sender Certificate v1 (R4-C3): the sender also carries a short-lived,
/// server-signed certificate inside the sealed layer, so a recipient that
/// pins the server's certificate key knows the claimed sender is real. A
/// first contact WITHOUT a certificate can be required to carry host
/// evidence (a `FirstContactApproval`), resolved via `peekSealedSender`.
library;

import 'package:risaal_crypto/risaal_crypto.dart';

import 'example_key_bundle_helper.dart';

// In-memory storage for demonstration
class InMemoryStorage implements CryptoSecureStorage {
  @override
  StorageSecurityLevel get securityLevel => StorageSecurityLevel.insecure;

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

  @override
  Future<void> clearAccountScopedValues() => clearAll();
}

Future<void> main() async {
  // ── Setup Alice and Bob ─────────────────────────────────────────
  final aliceStorage = InMemoryStorage();
  final bobStorage = InMemoryStorage();

  // SIMULATION ONLY: in production the server holds this key and the app
  // pins its public half (keyId -> base64 Ed25519 key).
  final server = await SignalKeyHelper.generateSigningKeyPair();
  const keyId = 'sc1';

  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(
    secureStorage: bobStorage,
    sealedSenderTrustPolicy: SealedSenderTrustPolicy(
      serverCertificateSigningKeys: {keyId: server.publicKey},
      requireVerifiedFirstContact: true,
    ),
  );

  await alice.wipeForFreshRegistration();
  await bob.wipeForFreshRegistration();
  await alice.initialize();
  await bob.initialize();
  // Account ids are written after the fresh-registration wipe (which clears
  // them); the sealed layer names the sender with them.
  await aliceStorage.write(key: 'user_id', value: 'alice-001');
  await aliceStorage.write(key: 'device_id', value: 'alice-device-1');
  await bobStorage.write(key: 'user_id', value: 'bob-001');
  await bobStorage.write(key: 'device_id', value: 'bob-device-1');

  // Exchange bundles and establish session
  final bobPreKeyBundle = await acceptInitialExampleGeneration(
    bob,
    userId: 'bob-001',
    deviceId: 'bob-device-1',
  );

  await alice.createSession(bobPreKeyBundle);
  print('Session established');

  // Alice knows Bob's identity public key (from his bundle)
  final bobIdentityKey = await bob.getIdentityPublicKey();

  // ── Uncertified first contact -> peek -> approval -> retry ─────
  final firstEnvelope = await alice.encryptSealedSenderFull(
    senderId: 'alice-001',
    senderDeviceId: 'alice-device-1',
    recipientId: 'bob-001',
    recipientDeviceId: 'bob-device-1',
    recipientIdentityPublicKey: bobIdentityKey,
    plaintext: 'This message hides my identity from the server.',
  );

  // The server sees: {ephemeralPublicKey, ciphertext, nonce, ...routing}
  // It does NOT know this came from Alice
  print('Sealed envelope keys: ${firstEnvelope.keys.toList()}');

  SealedSenderResult first;
  try {
    first = await bob.decryptSealedSender(firstEnvelope);
  } on UnverifiedFirstContactError {
    // Read-only: nothing is stored, the envelope can still be received.
    final peek = await bob.peekSealedSender(firstEnvelope);
    // The host would now compare peek.senderIdentityKey with Alice's
    // published key bundle (or a KT proof) before approving it.
    final approval = FirstContactApproval(
      senderId: peek.senderId,
      senderDeviceId: peek.senderDeviceId,
      senderIdentityKey: peek.senderIdentityKey,
      source: FirstContactApprovalSource.keyBundle,
    );
    first = await bob.decryptSealedSender(
      firstEnvelope,
      firstContactApproval: approval,
    );
  }
  print('Sender: ${first.senderId}'); // "alice-001" (discovered)
  print('Message: ${first.plaintext}'); // "This message hides..."
  print('Device: ${first.senderDeviceId}'); // "alice-device-1"

  // ── Certified send ──────────────────────────────────────────────
  // SIMULATION ONLY: the app gets this from POST /auth/sender-certificate,
  // caches it and renews it when less than 12 h of validity remain.
  final aliceSigning = await CryptoStorage(
    secureStorage: aliceStorage,
  ).getSigningKeyPair();
  final now = DateTime.now().millisecondsSinceEpoch;
  final certificate = await SenderCertificateVerifier.issueForTesting(
    serverSigningPrivateKey: server.privateKey,
    keyId: keyId,
    senderId: 'alice-001',
    senderDeviceId: 'alice-device-1',
    senderIdentityKey: await alice.getIdentityPublicKey(),
    senderSigningKey: aliceSigning!.publicKey,
    issuedAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000,
  );

  final certifiedEnvelope = await alice.encryptSealedSender(
    'bob-001',
    'bob-device-1',
    bobIdentityKey,
    'This one is vouched for by the server.',
    senderCertificate: certificate,
  );
  final certified = await bob.decryptSealedSender(certifiedEnvelope);
  print('Certified: ${certified.senderAuthentication?.certified}'); // true
  print('Message: ${certified.plaintext}');
}
