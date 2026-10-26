import 'package:flutter_test/flutter_test.dart';

import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// Registration still requires a non-empty OPK set, but upload bytes now come
/// only from a durable journal generation. A missing legacy flat pool must not
/// trigger an implicit compatibility regeneration.
void main() {
  test(
    'initial journal dispatch never ships an empty OPK generation',
    () async {
      final storage = FakeSecureStorage();
      final mgr = SignalProtocolManager(secureStorage: storage);
      await mgr.wipeForFreshRegistration();
      await mgr.initialize();

      final snapshot = await mgr.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 20,
      );
      await mgr.installKeyBundleReplacement(snapshot);
      final dispatch = await mgr.markKeyBundleReplacementDispatchStarted(
        snapshot,
      );
      final bundle = dispatch.toInitialRegistrationKeyBundle();
      final otpks = bundle['oneTimePreKeys'] as List;

      expect(otpks, hasLength(20));
      final first = otpks.first as Map<String, dynamic>;
      expect(first['keyId'], isA<int>());
      expect(first['publicKey'], isA<String>());
      expect((first['publicKey'] as String).isNotEmpty, isTrue);
      expect(snapshot.opkSetCount, otpks.length);
    },
  );

  test('missing flat pool cannot alter or republish accepted OPKs', () async {
    final storage = FakeSecureStorage();
    final mgr = SignalProtocolManager(secureStorage: storage);
    await mgr.wipeForFreshRegistration();
    await mgr.initialize();
    final accepted = await CryptoTestFixtures.acceptInitialGeneration(
      mgr,
      oneTimePreKeyCount: 5,
    );
    await storage.delete(key: 'crypto_one_time_pre_keys');

    final replacement = await mgr.prepareKeyBundleReplacement(
      oneTimePreKeyCount: 5,
    );
    await mgr.installKeyBundleReplacement(replacement);
    final firstDispatch = await mgr.markKeyBundleReplacementDispatchStarted(
      replacement,
    );
    final firstPayload = firstDispatch.toReplacementPayload(
      deviceId: 'device-1',
    );
    final replacementIds = (firstPayload['oneTimePreKeys'] as List)
        .map((entry) => (entry as Map)['keyId'] as int)
        .toSet();
    final acceptedIds = (accepted.publicMaterial['oneTimePreKeys'] as List)
        .map((entry) => (entry as Map)['keyId'] as int)
        .toSet();

    expect(replacementIds.intersection(acceptedIds), isEmpty);
    final resumed = await mgr.resumeKeyBundleReplacement();
    expect(resumed, isNotNull);
    expect(
      resumed!.toReplacementPayload(deviceId: 'device-1'),
      firstPayload,
      reason: 'retries must use the exact persisted dispatch generation',
    );
  });
}
