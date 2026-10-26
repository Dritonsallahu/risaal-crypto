@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';

void main() {
  group('key-bundle journal compare-and-set semantics', () {
    test('dispatch exposes the exact immutable proposed material', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      final prepared = await manager.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 3,
      );
      await manager.installKeyBundleReplacement(prepared);
      final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
        prepared,
      );
      final payload = dispatch.toInitialRegistrationKeyBundle();
      final kyber = payload['kyberPreKey'] as Map<String, dynamic>;
      final oneTimePreKeys = payload['oneTimePreKeys'] as List<dynamic>;

      expect(
        () => kyber['publicKey'] = 'mutated-after-dispatch',
        throwsUnsupportedError,
      );
      expect(
        () => oneTimePreKeys.add(<String, dynamic>{'keyId': 999}),
        throwsUnsupportedError,
      );
      expect(payload['replacementId'], prepared.replacementId);
      expect(payload['opkGeneration'], prepared.opkGeneration);
      expect(payload['opkSetDigest'], prepared.opkSetDigest);
      expect(
        payload['bundlePublicMaterialDigest'],
        prepared.bundlePublicMaterialDigest,
      );
    });

    test('exact acknowledgement clears only its pending proposal', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(
        manager,
        oneTimePreKeyCount: 3,
      );

      expect(await manager.pendingKeyBundleReplacement(), isNull);
      expect(accepted.receipt.bundleRevision, 1);
      expect(accepted.receipt.opkGeneration, accepted.snapshot.opkGeneration);
      expect(accepted.receipt.opkSetDigest, accepted.snapshot.opkSetDigest);
    });

    test('mismatched accepted tuple fails closed and stays pending', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      final prepared = await manager.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 3,
      );
      await manager.installKeyBundleReplacement(prepared);
      await manager.markKeyBundleReplacementDispatchStarted(prepared);
      final wrong = CryptoTestFixtures.receiptFor(
        prepared,
      ).copyWith(kemKeyId: prepared.kemKeyId + 1);

      await expectLater(
        manager.acknowledgeKeyBundleReplacement(
          snapshot: prepared,
          acceptance: wrong,
        ),
        throwsFormatException,
      );
      expect(
        (await manager.pendingKeyBundleReplacement())!.matches(prepared),
        isTrue,
      );
    });

    test('delayed generation N ACK cannot clear pending N+1', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      final first = await CryptoTestFixtures.acceptInitialGeneration(
        manager,
        oneTimePreKeyCount: 3,
      );
      final second = await manager.prepareKeyBundleReplacement(
        oneTimePreKeyCount: 3,
      );
      await manager.installKeyBundleReplacement(second);
      await manager.markKeyBundleReplacementDispatchStarted(second);

      await expectLater(
        manager.acknowledgeKeyBundleReplacement(
          snapshot: first.snapshot,
          acceptance: first.receipt,
        ),
        throwsStateError,
      );
      expect(
        (await manager.pendingKeyBundleReplacement())!.matches(second),
        isTrue,
      );
    });

    test('restart resumes byte-identical dispatched replacement', () async {
      final (manager, storage) =
          await CryptoTestFixtures.createInitializedManager();
      final prepared = await manager.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 3,
      );
      await manager.installKeyBundleReplacement(prepared);
      final dispatched = await manager.markKeyBundleReplacementDispatchStarted(
        prepared,
      );
      final before = jsonEncode(
        dispatched.toReplacementPayload(deviceId: 'device-1'),
      );

      final restarted = SignalProtocolManager(secureStorage: storage);
      final resumed = await restarted.resumeKeyBundleReplacement();

      expect(
        jsonEncode(resumed!.toReplacementPayload(deviceId: 'device-1')),
        before,
      );
      expect(resumed.snapshot.matches(prepared), isTrue);
    });

    test('accepted replacement is monotonic and OPK-disjoint', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      final first = await CryptoTestFixtures.acceptInitialGeneration(
        manager,
        oneTimePreKeyCount: 3,
      );
      final second = await CryptoTestFixtures.acceptReplacementGeneration(
        manager,
        deviceId: 'device-1',
        oneTimePreKeyCount: 3,
      );

      expect(
        second.snapshot.signedPreKeyId,
        greaterThan(first.snapshot.signedPreKeyId),
      );
      expect(second.snapshot.kemKeyId, greaterThan(first.snapshot.kemKeyId));
      expect(second.snapshot.opkGeneration, first.snapshot.opkGeneration + 1);
      expect(
        first.snapshot.oneTimePreKeyIds.toSet().intersection(
          second.snapshot.oneTimePreKeyIds.toSet(),
        ),
        isEmpty,
      );
    });

    test('legacy flat lifecycle entry points remain disabled', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();

      final operations = <Future<Object?> Function()>[
        manager.generateKeyBundle,
        manager.createKeyBundleUploadSnapshot,
        () => manager.rotateSignedPreKeyIfNeeded(maxAge: Duration.zero),
        () => manager.rotateKyberKeyIfNeeded(maxAge: Duration.zero),
        () => manager.rotateKeysIfNeeded(
          signedPreKeyMaxAge: Duration.zero,
          kyberKeyMaxAge: Duration.zero,
        ),
        manager.forceKeyRotationNow,
        () => manager.generateOneTimePreKeys(3),
      ];
      for (final operation in operations) {
        await expectLater(operation(), throwsUnsupportedError);
      }
    });
  });
}
