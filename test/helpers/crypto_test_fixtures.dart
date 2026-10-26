import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/key_bundle_replacement.dart'
    show KeyBundleAcceptedReceipt, KeyBundleReplacementSnapshot;
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';
import 'fake_secure_storage.dart';

const testOpkRoute = OpkGenerationRouting(
  bundleRevision: 1,
  opkGeneration: 1,
  opkSetDigest:
      '0000000000000000000000000000000000000000000000000000000000000000',
);

final class AcceptedTestGeneration {
  final KeyBundleReplacementSnapshot snapshot;
  final KeyBundleAcceptedReceipt receipt;
  final Map<String, dynamic> publicMaterial;

  const AcceptedTestGeneration({
    required this.snapshot,
    required this.receipt,
    required this.publicMaterial,
  });

  OpkGenerationRouting get route => OpkGenerationRouting(
    bundleRevision: receipt.opkAcceptedBundleRevision,
    opkGeneration: receipt.opkGeneration,
    opkSetDigest: receipt.opkSetDigest,
  );

  PreKeyBundle consumerBundle({
    String userId = 'bob-id',
    String deviceId = 'bob-device',
    int? oneTimePreKeyIndex = 0,
  }) {
    final publicOpks = (publicMaterial['oneTimePreKeys'] as List)
        .map((value) => Map<String, dynamic>.from(value as Map))
        .toList(growable: false);
    final selected = oneTimePreKeyIndex == null
        ? null
        : <String, dynamic>{
            ...publicOpks[oneTimePreKeyIndex],
            ...route.toJson(),
          };
    return PreKeyBundle.fromServerJson(<String, dynamic>{
      ...publicMaterial,
      'userId': userId,
      'deviceId': deviceId,
      ...route.toJson(),
      'oneTimePreKey': selected,
    });
  }
}

/// Shared test fixtures for crypto tests.
class CryptoTestFixtures {
  static KeyBundleAcceptedReceipt receiptFor(
    KeyBundleReplacementSnapshot snapshot,
  ) => KeyBundleAcceptedReceipt(
    bundleRevision: snapshot.expectedBundleRevision + 1,
    signedPreKeyId: snapshot.signedPreKeyId,
    kemKeyId: snapshot.kemKeyId,
    cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
    replacementId: snapshot.replacementId,
    opkAcceptedBundleRevision: snapshot.expectedBundleRevision + 1,
    opkGeneration: snapshot.opkGeneration,
    opkSetDigest: snapshot.opkSetDigest,
    opkSetCount: snapshot.opkSetCount,
    opkHighWaterKeyId: snapshot.opkHighWaterKeyId,
    bundlePublicMaterialDigest: snapshot.bundlePublicMaterialDigest,
  );

  static Future<AcceptedTestGeneration> acceptInitialGeneration(
    SignalProtocolManager manager, {
    int oneTimePreKeyCount = 5,
  }) async {
    final snapshot = await manager.prepareInitialKeyBundleRegistration(
      oneTimePreKeyCount: oneTimePreKeyCount,
    );
    await manager.installKeyBundleReplacement(snapshot);
    final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
      snapshot,
    );
    final receipt = receiptFor(snapshot);
    await manager.acknowledgeKeyBundleReplacement(
      snapshot: snapshot,
      acceptance: receipt,
    );
    return AcceptedTestGeneration(
      snapshot: snapshot,
      receipt: receipt,
      publicMaterial: dispatch.toInitialRegistrationKeyBundle(),
    );
  }

  static Future<AcceptedTestGeneration> acceptReplacementGeneration(
    SignalProtocolManager manager, {
    required String deviceId,
    int oneTimePreKeyCount = 100,
  }) async {
    final snapshot = await manager.prepareKeyBundleReplacement(
      oneTimePreKeyCount: oneTimePreKeyCount,
    );
    await manager.installKeyBundleReplacement(snapshot);
    final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
      snapshot,
    );
    final receipt = receiptFor(snapshot);
    await manager.acknowledgeKeyBundleReplacement(
      snapshot: snapshot,
      acceptance: receipt,
    );
    return AcceptedTestGeneration(
      snapshot: snapshot,
      receipt: receipt,
      publicMaterial: dispatch.toReplacementPayload(deviceId: deviceId),
    );
  }

  /// Generate a complete set of Signal Protocol keys for one user.
  /// Returns: (identityKP, signingKP, signedPreKey, oneTimePreKeys, kyberKP)
  static Future<
    ({
      KeyPair identityKP,
      KeyPair signingKP,
      SignedPreKey signedPreKey,
      List<OneTimePreKey> oneTimePreKeys,
      KyberKeyPair? kyberKP,
    })
  >
  generateFullKeySet() async {
    final identityKP = await SignalKeyHelper.generateIdentityKeyPair();
    final signingKP = await SignalKeyHelper.generateSigningKeyPair();
    final signedPreKey = await SignalKeyHelper.generateSignedPreKey(
      1,
      signingKP,
    );
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
  static Future<PreKeyBundle> buildBundle({
    required String userId,
    required String deviceId,
    required KeyPair identityKP,
    required KeyPair signingKP,
    required SignedPreKey signedPreKey,
    required List<OneTimePreKey> oneTimePreKeys,
    KyberKeyPair? kyberKP,
  }) async {
    final kyberSignature = kyberKP == null
        ? null
        : await SignalKeyHelper.sign(
            signingKP.privateKey,
            RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
              keyId: kyberKP.keyId!,
              publicKey: kyberKP.publicKey,
            ),
          );
    return PreKeyBundle(
      opkRoute: testOpkRoute,
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
          ? KyberPreKeyPublic(
              keyId: kyberKP.keyId!,
              publicKey: kyberKP.publicKey,
              signature: kyberSignature!,
              cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
              kemSuite: RisaalCryptoProtocol.kemSuite,
              kemStandard: RisaalCryptoProtocol.kemStandard,
              kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
            )
          : null,
    );
  }

  /// Create a fully initialized SignalProtocolManager with in-memory storage.
  /// Calls initialize() to generate all keys.
  static Future<(SignalProtocolManager, FakeSecureStorage)>
  createInitializedManager({FakeSecureStorage? storage}) async {
    storage ??= FakeSecureStorage();
    final manager = SignalProtocolManager(secureStorage: storage);
    await manager.wipeForFreshRegistration();
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
    })
  >
  createPairedManagers() async {
    final (alice, aliceStorage) = await createInitializedManager();
    final (bob, bobStorage) = await createInitializedManager();

    final acceptedBob = await acceptInitialGeneration(bob);
    final bundle = acceptedBob.consumerBundle();

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
