import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';
import 'fake_secure_storage.dart';

/// Shared test fixtures for crypto tests.
class CryptoTestFixtures {
  /// Generate a complete set of Signal Protocol keys for one user.
  /// Returns: (identityKP, signingKP, signedPreKey, oneTimePreKeys, kyberKP)
  static Future<
      ({
        KeyPair identityKP,
        KeyPair signingKP,
        SignedPreKey signedPreKey,
        List<OneTimePreKey> oneTimePreKeys,
        KyberKeyPair? kyberKP,
      })> generateFullKeySet() async {
    final identityKP = await SignalKeyHelper.generateIdentityKeyPair();
    final signingKP = await SignalKeyHelper.generateSigningKeyPair();
    final signedPreKey =
        await SignalKeyHelper.generateSignedPreKey(0, signingKP);
    final oneTimePreKeys = await SignalKeyHelper.generateOneTimePreKeys(0, 5);

    KyberKeyPair? kyberKP;
    try {
      kyberKP = SignalKeyHelper.generateKyberKeyPair();
    } catch (_) {
      // Kyber FFI not available in test environment
    }

    return (
      identityKP: identityKP,
      signingKP: signingKP,
      signedPreKey: signedPreKey,
      oneTimePreKeys: oneTimePreKeys,
      kyberKP: kyberKP,
    );
  }

  /// Build a PreKeyBundle from a user's key set.
  static PreKeyBundle buildBundle({
    required String userId,
    required String deviceId,
    required KeyPair identityKP,
    required KeyPair signingKP,
    required SignedPreKey signedPreKey,
    required List<OneTimePreKey> oneTimePreKeys,
    KyberKeyPair? kyberKP,
  }) {
    return PreKeyBundle(
      userId: userId,
      deviceId: deviceId,
      identityKey: identityKP.publicKey,
      identitySigningKey: signingKP.publicKey,
      signedPreKey: SignedPreKeyPublic(
        keyId: signedPreKey.keyId,
        publicKey: signedPreKey.keyPair.publicKey,
        signature: signedPreKey.signature,
      ),
      oneTimePreKey: oneTimePreKeys.isNotEmpty
          ? OneTimePreKeyPublic(
              keyId: oneTimePreKeys.first.keyId,
              publicKey: oneTimePreKeys.first.keyPair.publicKey,
            )
          : null,
      kyberPreKey: kyberKP != null
          ? KyberPreKeyPublic(keyId: 0, publicKey: kyberKP.publicKey)
          : null,
    );
  }

  /// Create a fully initialized SignalProtocolManager with in-memory storage.
  /// Calls initialize() to generate all keys.
  static Future<(SignalProtocolManager, FakeSecureStorage)>
      createInitializedManager() async {
    final storage = FakeSecureStorage();
    final manager = SignalProtocolManager(secureStorage: storage);
    await manager.initialize();
    return (manager, storage);
  }

  /// Create two initialized managers (Alice and Bob) with established sessions.
  /// Returns both managers and their storages. Alice has a session to Bob.
  static Future<
      ({
        SignalProtocolManager alice,
        FakeSecureStorage aliceStorage,
        SignalProtocolManager bob,
        FakeSecureStorage bobStorage,
      })> createPairedManagers() async {
    final (alice, aliceStorage) = await createInitializedManager();
    final (bob, bobStorage) = await createInitializedManager();

    // Get Bob's key bundle
    final bobBundle = await bob.generateKeyBundle();
    final bobIdentityKey = bobBundle['identityKey'] as String;
    final bobSigningKey = bobBundle['identitySigningKey'] as String;
    final bobSignedPreKey = bobBundle['signedPreKey'] as Map<String, dynamic>;
    final bobOneTimePreKeys = bobBundle['oneTimePreKeys'] as List<dynamic>;

    // Build PreKeyBundle for Bob
    final bundle = PreKeyBundle(
      userId: 'bob-id',
      deviceId: 'bob-device',
      identityKey: bobIdentityKey,
      identitySigningKey: bobSigningKey,
      signedPreKey: SignedPreKeyPublic(
        keyId: bobSignedPreKey['keyId'] as int,
        publicKey: bobSignedPreKey['publicKey'] as String,
        signature: bobSignedPreKey['signature'] as String,
      ),
      oneTimePreKey: bobOneTimePreKeys.isNotEmpty
          ? OneTimePreKeyPublic(
              keyId: (bobOneTimePreKeys.first as Map<String, dynamic>)['keyId']
                  as int,
              publicKey: (bobOneTimePreKeys.first
                  as Map<String, dynamic>)['publicKey'] as String,
            )
          : null,
      kyberPreKey: bobBundle.containsKey('kyberPreKey')
          ? KyberPreKeyPublic(
              keyId: (bobBundle['kyberPreKey'] as Map<String, dynamic>)['keyId']
                  as int,
              publicKey: (bobBundle['kyberPreKey']
                  as Map<String, dynamic>)['publicKey'] as String,
            )
          : null,
    );

    // Alice creates a session with Bob
    await alice.createSession(bundle);

    // Store Alice's user_id and device_id for sealed sender
    await aliceStorage.write(key: 'user_id', value: 'alice-id');
    await aliceStorage.write(key: 'device_id', value: 'alice-device');
    await bobStorage.write(key: 'user_id', value: 'bob-id');
    await bobStorage.write(key: 'device_id', value: 'bob-device');

    return (
      alice: alice,
      aliceStorage: aliceStorage,
      bob: bob,
      bobStorage: bobStorage,
    );
  }
}
