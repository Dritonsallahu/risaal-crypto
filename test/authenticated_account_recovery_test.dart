@TestOn('vm')
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

void main() {
  test(
    'an empty logged-out install recovers only from authenticated receipt',
    () async {
      final (baselineManager, _) =
          await CryptoTestFixtures.createInitializedManager();
      final baseline = await CryptoTestFixtures.acceptInitialGeneration(
        baselineManager,
        oneTimePreKeyCount: 3,
      );

      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);

      await expectLater(
        manager.initialize(),
        throwsA(isA<MissingKeyBundleJournalRecoveryRequired>()),
      );

      await manager.beginAuthenticatedAccountRecovery(baseline.receipt);

      // The intent is durable: a process restart, not the original manager's
      // memory, must be able to continue the exact recovery.
      final restarted = SignalProtocolManager(secureStorage: storage);
      expect(await restarted.initialize(), isTrue);

      // A second restart after key generation but before replacement prepare
      // must also resume from durable state. This is the exact mobile kill
      // window seen when login succeeded but navigation never completed.
      final afterKeyGenerationRestart = SignalProtocolManager(
        secureStorage: storage,
      );
      expect(await afterKeyGenerationRestart.initialize(), isTrue);
      final snapshot = await afterKeyGenerationRestart
          .prepareKeyBundleReplacement(
            acceptedReceipt: baseline.receipt,
            oneTimePreKeyCount: 3,
          );

      expect(snapshot.expectedBundleRevision, baseline.receipt.bundleRevision);
      expect(snapshot.opkGeneration, baseline.receipt.opkGeneration + 1);
      expect(
        snapshot.signedPreKeyId,
        greaterThan(baseline.receipt.signedPreKeyId),
      );
      expect(snapshot.kemKeyId, greaterThan(baseline.receipt.kemKeyId));
      expect(
        snapshot.oneTimePreKeyIds.first,
        greaterThan(baseline.receipt.opkHighWaterKeyId),
      );
    },
  );

  test('the authenticated recovery intent rejects receipt drift', () async {
    final (baselineManager, _) =
        await CryptoTestFixtures.createInitializedManager();
    final baseline = await CryptoTestFixtures.acceptInitialGeneration(
      baselineManager,
      oneTimePreKeyCount: 3,
    );
    final storage = FakeSecureStorage();
    final manager = SignalProtocolManager(secureStorage: storage);

    await manager.beginAuthenticatedAccountRecovery(baseline.receipt);
    await expectLater(
      manager.beginAuthenticatedAccountRecovery(
        baseline.receipt.copyWith(
          bundleRevision: baseline.receipt.bundleRevision + 1,
        ),
      ),
      throwsFormatException,
    );
  });
}
