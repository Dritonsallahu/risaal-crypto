import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

Future<({SignalProtocolManager manager, FakeSecureStorage storage})>
_createInitializedManager({SecurityEventBus? eventBus}) async {
  final storage = FakeSecureStorage();
  final manager = SignalProtocolManager(
    secureStorage: storage,
    securityEventBus: eventBus,
  );
  await manager.wipeForFreshRegistration();
  await manager.initialize();
  return (manager: manager, storage: storage);
}

void main() {
  group('signed pre-key age', () {
    test('freshly initialized key has a near-zero age', () async {
      final fixture = await _createInitializedManager();

      expect(await fixture.manager.signedPreKeyAge(), lessThan(1000));
    });

    test('missing legacy timestamp is reported as zero', () async {
      final fixture = await _createInitializedManager();
      await fixture.storage.delete(key: 'crypto_signed_prekey_created_at');

      expect(await fixture.manager.signedPreKeyAge(), 0);
    });
  });

  group('journaled full replacement', () {
    test('rotates SPK, KEM and OPKs as one monotonic generation', () async {
      final fixture = await _createInitializedManager();
      final first = await CryptoTestFixtures.acceptInitialGeneration(
        fixture.manager,
        oneTimePreKeyCount: 5,
      );
      final second = await CryptoTestFixtures.acceptReplacementGeneration(
        fixture.manager,
        deviceId: 'device-1',
        oneTimePreKeyCount: 5,
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

    test('accepted dispatch payload excludes client-only timestamps', () async {
      final fixture = await _createInitializedManager();
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(
        fixture.manager,
        oneTimePreKeyCount: 5,
      );

      expect(accepted.publicMaterial, isNot(contains('createdAt')));
      expect(
        accepted.publicMaterial.keys,
        containsAll(<String>[
          'replacementId',
          'opkGeneration',
          'opkSetDigest',
          'opkSetCount',
          'opkHighWaterKeyId',
          'bundlePublicMaterialDigest',
          'identityKey',
          'identitySigningKey',
          'signedPreKey',
          'oneTimePreKeys',
          'kyberPreKey',
        ]),
      );
    });

    test('replacement refreshes both installed creation timestamps', () async {
      final fixture = await _createInitializedManager();
      await CryptoTestFixtures.acceptInitialGeneration(fixture.manager);
      final old =
          DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await fixture.storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: old.toString(),
      );
      await fixture.storage.write(
        key: 'crypto_e2_kyber_created_at',
        value: old.toString(),
      );

      // Bound the assertions by the replacement window itself rather than by a
      // fixed wall-clock tolerance. A `< 1000 ms` budget is not a property of
      // the code under test — it is a property of how loaded the machine is, so
      // it fails in parallel CI while proving nothing extra when it passes.
      final beforeReplacement = DateTime.now().millisecondsSinceEpoch;
      await CryptoTestFixtures.acceptReplacementGeneration(
        fixture.manager,
        deviceId: 'device-1',
      );
      final afterReplacement = DateTime.now().millisecondsSinceEpoch;

      Future<int> storedTimestamp(String key) async =>
          int.parse((await fixture.storage.read(key: key))!);

      // Both timestamps must have been rewritten *during* the replacement, so
      // neither can still hold the eight-day-old value seeded above.
      for (final key in const <String>[
        'crypto_signed_prekey_created_at',
        'crypto_e2_kyber_created_at',
      ]) {
        final createdAt = await storedTimestamp(key);
        expect(createdAt, greaterThanOrEqualTo(beforeReplacement), reason: key);
        expect(createdAt, lessThanOrEqualTo(afterReplacement), reason: key);
        expect(createdAt, greaterThan(old), reason: key);
      }

      // The age helper must agree, bounded by real elapsed time.
      expect(
        await fixture.manager.signedPreKeyAge(),
        lessThanOrEqualTo(
          DateTime.now().millisecondsSinceEpoch - beforeReplacement,
        ),
      );
    });

    test('retained generation remains routable after replacement', () async {
      final bobFixture = await _createInitializedManager();
      final first = await CryptoTestFixtures.acceptInitialGeneration(
        bobFixture.manager,
        oneTimePreKeyCount: 3,
      );
      await CryptoTestFixtures.acceptReplacementGeneration(
        bobFixture.manager,
        deviceId: 'bob-device',
        oneTimePreKeyCount: 3,
      );

      final aliceFixture = await _createInitializedManager();
      await aliceFixture.storage.write(key: 'user_id', value: 'alice-id');
      await aliceFixture.storage.write(key: 'device_id', value: 'alice-device');
      await aliceFixture.manager.createSession(
        first.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
      );
      final envelope = await aliceFixture.manager.encryptMessage(
        'bob-id',
        'bob-device',
        'delayed generation message',
      );

      expect(
        await bobFixture.manager.decryptMessage(
          'alice-id',
          'alice-device',
          envelope,
        ),
        'delayed generation message',
      );
      expect(await bobFixture.manager.oneTimePreKeyCount(), 3);
    });
  });

  group('accepted one-time pre-key state', () {
    test(
      'count rejects bootstrap flat material until server acceptance',
      () async {
        final fixture = await _createInitializedManager();

        await expectLater(
          fixture.manager.oneTimePreKeyCount(),
          throwsStateError,
        );

        await CryptoTestFixtures.acceptInitialGeneration(
          fixture.manager,
          oneTimePreKeyCount: 7,
        );
        expect(await fixture.manager.oneTimePreKeyCount(), 7);
      },
    );

    test('replacement count is exact and never additive', () async {
      final fixture = await _createInitializedManager();
      await CryptoTestFixtures.acceptInitialGeneration(
        fixture.manager,
        oneTimePreKeyCount: 7,
      );
      await CryptoTestFixtures.acceptReplacementGeneration(
        fixture.manager,
        deviceId: 'device-1',
        oneTimePreKeyCount: 11,
      );

      expect(await fixture.manager.oneTimePreKeyCount(), 11);
    });

    test('exhaustion threshold uses only latest accepted generation', () async {
      final fixture = await _createInitializedManager();
      await CryptoTestFixtures.acceptInitialGeneration(
        fixture.manager,
        oneTimePreKeyCount: 12,
      );

      expect(
        await fixture.manager.isPreKeyExhaustionNear(threshold: 11),
        isFalse,
      );
      expect(
        await fixture.manager.isPreKeyExhaustionNear(threshold: 12),
        isTrue,
      );
      expect(
        await fixture.manager.isPreKeyExhaustionNear(threshold: 13),
        isTrue,
      );
    });

    test(
      'authenticated consume requests a full replacement, not replenish',
      () async {
        final eventBus = SecurityEventBus();
        final bobFixture = await _createInitializedManager(eventBus: eventBus);
        final accepted = await CryptoTestFixtures.acceptInitialGeneration(
          bobFixture.manager,
          oneTimePreKeyCount: 3,
        );
        int? callbackCount;
        bobFixture.manager.onPreKeyExhaustionWarning = (remaining) {
          callbackCount = remaining;
        };
        final replacementNeeded = eventBus.events.firstWhere(
          (event) => event.type == SecurityEventType.preKeyReplenishmentNeeded,
        );

        final aliceFixture = await _createInitializedManager();
        await aliceFixture.storage.write(key: 'user_id', value: 'alice-id');
        await aliceFixture.storage.write(
          key: 'device_id',
          value: 'alice-device',
        );
        await aliceFixture.manager.createSession(
          accepted.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
        );
        final envelope = await aliceFixture.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'consume accepted OPK',
        );

        expect(
          await bobFixture.manager.decryptMessage(
            'alice-id',
            'alice-device',
            envelope,
          ),
          'consume accepted OPK',
        );
        final event = await replacementNeeded;
        expect(callbackCount, 2);
        expect(event.metadata['generated'], 0);
        expect(event.metadata['previousCount'], 2);
        expect(event.metadata['newTotal'], 2);
        expect(event.metadata['requiresFullReplacement'], isTrue);
        expect(await bobFixture.manager.oneTimePreKeyCount(), 2);
      },
    );
  });

  group('legacy flat lifecycle', () {
    test('all standalone generation and rotation calls fail closed', () async {
      final fixture = await _createInitializedManager();

      final operations = <Future<Object?> Function()>[
        fixture.manager.generateKeyBundle,
        () => fixture.manager.generateOneTimePreKeys(10),
        () => fixture.manager.rotateSignedPreKeyIfNeeded(),
        () => fixture.manager.rotateKyberKeyIfNeeded(),
        fixture.manager.rotateKeysIfNeeded,
        fixture.manager.forceKeyRotationNow,
      ];
      for (final operation in operations) {
        await expectLater(operation(), throwsUnsupportedError);
      }
    });
  });

  group('absolute max key lifetime validation', () {
    test('fresh accepted generation is valid', () async {
      final fixture = await _createInitializedManager();
      await CryptoTestFixtures.acceptInitialGeneration(fixture.manager);

      expect(await fixture.manager.validateKeyFreshness(), isTrue);
    });

    test('expired SPK requires replacement and emits keyExpired', () async {
      final eventBus = SecurityEventBus();
      final fixture = await _createInitializedManager(eventBus: eventBus);
      await CryptoTestFixtures.acceptInitialGeneration(fixture.manager);
      final expired =
          DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await fixture.storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: expired.toString(),
      );
      final eventFuture = eventBus.events.firstWhere(
        (event) =>
            event.type == SecurityEventType.keyExpired &&
            event.metadata['keyType'] == 'signedPreKey',
      );

      expect(await fixture.manager.validateKeyFreshness(), isFalse);
      expect((await eventFuture).metadata['keyType'], 'signedPreKey');
    });

    test('expired KEM requires replacement', () async {
      final fixture = await _createInitializedManager();
      await CryptoTestFixtures.acceptInitialGeneration(fixture.manager);
      final expired =
          DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await fixture.storage.write(
        key: 'crypto_e2_kyber_created_at',
        value: expired.toString(),
      );

      expect(await fixture.manager.validateKeyFreshness(), isFalse);
    });
  });

  group('key lifecycle constants', () {
    test('absolute max key lifetime is 30 days', () {
      expect(
        SignalProtocolManager.absoluteMaxKeyLifetime,
        const Duration(days: 30),
      );
    });

    test('legacy overlap duration constant remains 48 hours', () {
      expect(SignalProtocolManager.keyOverlapWindow, const Duration(hours: 48));
    });

    test('legacy flat replenish batch constant remains 100', () {
      expect(SignalProtocolManager.otpReplenishBatchSize, 100);
    });

    test('latest accepted OPK low-watermark remains 25', () {
      expect(SignalProtocolManager.defaultOtpLowWatermark, 25);
    });
  });
}
