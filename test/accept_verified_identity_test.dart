import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/session_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// Storage whose deletes can be made to fail, to simulate a crash after the
/// new pin is written (step (a)) but before the old state is removed (step b).
class _CrashableStorage extends FakeSecureStorage {
  bool failDeletes = false;

  @override
  Future<void> delete({required String key}) async {
    if (failDeletes) throw StateError('simulated crash during cleanup');
    await super.delete(key: key);
  }
}

class _Fixture {
  _Fixture({
    required this.alice,
    required this.aliceStorage,
    required this.bob1,
    required this.k1,
    required this.k2,
    required this.bob2,
    required this.bob3,
    required this.bob1Gen,
    required this.bob3Gen,
    required this.bob2Bundle,
    required this.bob3Bundle,
  });

  final SignalProtocolManager alice;
  final _CrashableStorage aliceStorage;
  final SignalProtocolManager bob1;
  final String k1;
  final String k2;
  final SignalProtocolManager bob2;
  final SignalProtocolManager bob3;
  final AcceptedTestGeneration bob1Gen;
  final AcceptedTestGeneration bob3Gen;
  final PreKeyBundle bob2Bundle;
  final PreKeyBundle bob3Bundle;
}

Future<(SignalProtocolManager, FakeSecureStorage)> _peer(
  String userId,
  String deviceId,
) async {
  final storage = FakeSecureStorage();
  final manager = SignalProtocolManager(secureStorage: storage);
  await manager.wipeForFreshRegistration();
  await manager.initialize();
  await storage.write(key: 'user_id', value: userId);
  await storage.write(key: 'device_id', value: deviceId);
  return (manager, storage);
}

/// Alice has a live K1 session with bob-id/bob-d1 (both directions) and a K1
/// pin for a second device bob-id/bob-d2. Bob then "changes" identity: bob2
/// holds K2 (the key the user verified), bob3 holds K3 (an interceptor).
Future<_Fixture> _setUp() async {
  final aliceStorage = _CrashableStorage();
  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  await alice.wipeForFreshRegistration();
  await alice.initialize();
  await aliceStorage.write(key: 'user_id', value: 'alice-id');
  await aliceStorage.write(key: 'device_id', value: 'alice-device');

  final (bob1, _) = await _peer('bob-id', 'bob-d1');
  final bob1Gen = await CryptoTestFixtures.acceptInitialGeneration(bob1);
  final bob1Bundle = bob1Gen.consumerBundle(
    userId: 'bob-id',
    deviceId: 'bob-d1',
  );
  await alice.createSession(bob1Bundle);
  final first = await alice.encryptMessage('bob-id', 'bob-d1', 'hello K1');
  expect(
    await bob1.decryptMessage('alice-id', 'alice-device', first),
    'hello K1',
  );
  final reply = await bob1.encryptMessage('alice-id', 'alice-device', 'hi');
  expect(await alice.decryptMessage('bob-id', 'bob-d1', reply), 'hi');
  // Second device of the same contact, same identity K1.
  await alice.createSession(
    bob1Gen.consumerBundle(userId: 'bob-id', deviceId: 'bob-d2'),
  );
  expect(
    await alice.getSessionIdentityKey('bob-id', 'bob-d2'),
    bob1Bundle.identityKey,
  );

  final (bob2, _) = await _peer('bob-id', 'bob-d1');
  final bob2Bundle = (await CryptoTestFixtures.acceptInitialGeneration(
    bob2,
  )).consumerBundle(userId: 'bob-id', deviceId: 'bob-d1');
  final (bob3, _) = await _peer('bob-id', 'bob-d1');
  final bob3Gen = await CryptoTestFixtures.acceptInitialGeneration(bob3);
  final bob3Bundle = bob3Gen.consumerBundle(
    userId: 'bob-id',
    deviceId: 'bob-d1',
  );
  expect(bob2Bundle.identityKey, isNot(bob1Bundle.identityKey));
  expect(bob3Bundle.identityKey, isNot(bob2Bundle.identityKey));

  return _Fixture(
    alice: alice,
    aliceStorage: aliceStorage,
    bob1: bob1,
    k1: bob1Bundle.identityKey,
    k2: bob2Bundle.identityKey,
    bob2: bob2,
    bob3: bob3,
    bob1Gen: bob1Gen,
    bob3Gen: bob3Gen,
    bob2Bundle: bob2Bundle,
    bob3Bundle: bob3Bundle,
  );
}

Future<void> _expectOnlyK2Pinned(_Fixture f) async {
  expect(await f.alice.getSessionIdentityKey('bob-id', 'bob-d1'), f.k2);
  expect(await f.alice.getSessionIdentityKey('bob-id', 'bob-d2'), isNull);
  expect(await f.alice.getSessionDevices('bob-id'), ['bob-d1']);
  expect(await f.alice.hasSession('bob-id', 'bob-d1'), isFalse);
  expect(await f.alice.hasSession('bob-id', 'bob-d2'), isFalse);
}

void main() {
  group('acceptVerifiedPeerIdentity', () {
    test('send side: only the verified key K2 can build a session', () async {
      final f = await _setUp();
      await f.alice.acceptVerifiedPeerIdentity(
        userId: 'bob-id',
        deviceId: 'bob-d1',
        identityKey: f.k2,
      );

      await expectLater(
        f.alice.createSession(f.bob3Bundle),
        throwsA(isA<StateError>()),
      );
      // A relay-invented device id cannot escape the contact's K2 pin either.
      await expectLater(
        f.alice.createSession(
          f.bob3Gen.consumerBundle(userId: 'bob-id', deviceId: 'bob-d9'),
        ),
        throwsA(isA<StateError>()),
      );
      expect(await f.alice.getSessionIdentityKey('bob-id', 'bob-d1'), f.k2);

      await f.alice.createSession(f.bob2Bundle);
      final env = await f.alice.encryptMessage('bob-id', 'bob-d1', 'to K2');
      expect(
        await f.bob2.decryptMessage('alice-id', 'alice-device', env),
        'to K2',
      );
      final back = await f.bob2.encryptMessage(
        'alice-id',
        'alice-device',
        'ok',
      );
      expect(await f.alice.decryptMessage('bob-id', 'bob-d1', back), 'ok');
    });

    test('receive side: PreKey from K2 accepted, from K3 refused', () async {
      final f = await _setUp();
      final aliceBundle = (await CryptoTestFixtures.acceptInitialGeneration(
        f.alice,
      )).consumerBundle(userId: 'alice-id', deviceId: 'alice-device');
      await f.alice.acceptVerifiedPeerIdentity(
        userId: 'bob-id',
        deviceId: 'bob-d1',
        identityKey: f.k2,
      );

      await f.bob3.createSession(aliceBundle);
      final forged = await f.bob3.encryptMessage(
        'alice-id',
        'alice-device',
        'from K3',
      );
      expect(forged['type'], 'prekey');
      await expectLater(
        f.alice.decryptMessage('bob-id', 'bob-d1', forged),
        throwsA(isA<StateError>()),
      );
      await expectLater(
        f.alice.decryptMessage('bob-id', 'bob-d9', forged),
        throwsA(isA<StateError>()),
      );

      await f.bob2.createSession(aliceBundle);
      final genuine = await f.bob2.encryptMessage(
        'alice-id',
        'alice-device',
        'from K2',
      );
      expect(genuine['type'], 'prekey');
      expect(
        await f.alice.decryptMessage('bob-id', 'bob-d1', genuine),
        'from K2',
      );
      expect(await f.alice.getSessionIdentityKey('bob-id', 'bob-d1'), f.k2);
    });

    test(
      'old K1 session, other-device pins and device list are gone',
      () async {
        final f = await _setUp();
        await f.alice.acceptVerifiedPeerIdentity(
          userId: 'bob-id',
          deviceId: 'bob-d1',
          identityKey: f.k2,
        );
        await _expectOnlyK2Pinned(f);

        final stale = await f.bob1.encryptMessage(
          'alice-id',
          'alice-device',
          'x',
        );
        expect(stale['type'], 'message');
        await expectLater(
          f.alice.decryptMessage('bob-id', 'bob-d1', stale),
          throwsA(isA<NoSessionError>()),
        );
        await expectLater(
          f.alice.encryptMessage('bob-id', 'bob-d1', 'y'),
          throwsA(isA<StateError>()),
        );
        await expectLater(
          f.alice.encryptMessage('bob-id', 'bob-d2', 'y'),
          throwsA(isA<StateError>()),
        );
        // The old K1 key itself is now refused for a new session too.
        await expectLater(
          f.alice.createSession(
            f.bob1Gen.consumerBundle(userId: 'bob-id', deviceId: 'bob-d1'),
          ),
          throwsA(isA<StateError>()),
        );
      },
    );

    test(
      'crash after the pin write: old session refused, retry completes',
      () async {
        final f = await _setUp();
        final aliceIk = await f.alice.getIdentityPublicKey();
        // Positive control: the old session works on the sealed lane before.
        final before = await f.bob1.encryptSealedSender(
          'alice-id',
          'alice-device',
          aliceIk,
          'before',
        );
        expect((await f.alice.decryptSealedSender(before)).plaintext, 'before');

        f.aliceStorage.failDeletes = true;
        await expectLater(
          f.alice.acceptVerifiedPeerIdentity(
            userId: 'bob-id',
            deviceId: 'bob-d1',
            identityKey: f.k2,
          ),
          throwsA(isA<StateError>()),
        );
        f.aliceStorage.failDeletes = false;

        // Step (a) landed: the pin is already K2 although the old session
        // survived the interrupted cleanup.
        expect(await f.alice.getSessionIdentityKey('bob-id', 'bob-d1'), f.k2);
        expect(await f.alice.hasSession('bob-id', 'bob-d1'), isTrue);

        // A restarted client reading the interrupted state fails closed.
        final restarted = SignalProtocolManager(secureStorage: f.aliceStorage);
        await restarted.initialize();
        final after = await f.bob1.encryptSealedSender(
          'alice-id',
          'alice-device',
          aliceIk,
          'after',
        );
        await expectLater(
          restarted.decryptSealedSender(after),
          throwsA(isA<StateError>()),
        );
        await expectLater(
          restarted.createSession(f.bob3Bundle),
          throwsA(isA<StateError>()),
        );
        // R4-PKG-SESSION-PIN-CHECK: the old session is refused on EVERY path,
        // also where the envelope carries no identity key (this window used to
        // stay open until the accept was retried).
        final stale = await f.bob1.encryptMessage(
          'alice-id',
          'alice-device',
          'stale',
        );
        expect(stale['type'], 'message');
        for (final m in [f.alice, restarted]) {
          await expectLater(
            m.decryptMessage('bob-id', 'bob-d1', stale),
            throwsA(isA<SessionIdentityMismatchError>()),
          );
          await expectLater(
            m.encryptMessage('bob-id', 'bob-d1', 'y'),
            throwsA(isA<SessionIdentityMismatchError>()),
          );
          await expectLater(
            m.encryptSealedSender('bob-id', 'bob-d1', f.k1, 'y'),
            throwsA(isA<SessionIdentityMismatchError>()),
          );
        }

        await restarted.acceptVerifiedPeerIdentity(
          userId: 'bob-id',
          deviceId: 'bob-d1',
          identityKey: f.k2,
        );
        await _expectOnlyK2Pinned(
          _Fixture(
            alice: restarted,
            aliceStorage: f.aliceStorage,
            bob1: f.bob1,
            k1: f.k1,
            k2: f.k2,
            bob2: f.bob2,
            bob3: f.bob3,
            bob1Gen: f.bob1Gen,
            bob3Gen: f.bob3Gen,
            bob2Bundle: f.bob2Bundle,
            bob3Bundle: f.bob3Bundle,
          ),
        );
        await restarted.createSession(f.bob2Bundle);
      },
    );

    test('invalid input throws ArgumentError and changes nothing', () async {
      final f = await _setUp();
      final snapshot = Map<String, String>.of(f.aliceStorage.store);
      final zero31 = base64Encode(List<int>.filled(31, 0));
      // URL-safe alphabet: decodes to 32 bytes but is not the canonical form.
      final nonCanonical = base64Encode(
        List<int>.filled(32, 0xfb),
      ).replaceAll('+', '-').replaceAll('/', '_');
      expect(base64Decode(nonCanonical), hasLength(32));

      final cases = <(String, String, String)>[
        ('bob-id', 'bob-d1', ''),
        ('bob-id', 'bob-d1', 'not base64 !!'),
        ('bob-id', 'bob-d1', zero31),
        ('bob-id', 'bob-d1', nonCanonical),
        ('bob-id', 'bob-d1', ' ${f.k2}'),
        ('bad id', 'bob-d1', f.k2),
        ('bob-id', 'devices', f.k2),
        ('bob-id', '', f.k2),
      ];
      for (final (userId, deviceId, key) in cases) {
        await expectLater(
          f.alice.acceptVerifiedPeerIdentity(
            userId: userId,
            deviceId: deviceId,
            identityKey: key,
          ),
          throwsA(isA<ArgumentError>()),
          reason: '($userId, $deviceId, "$key")',
        );
        expect(f.aliceStorage.store, snapshot);
      }

      // The live K1 session is untouched, in memory and on disk.
      final env = await f.alice.encryptMessage('bob-id', 'bob-d1', 'still');
      expect(
        await f.bob1.decryptMessage('alice-id', 'alice-device', env),
        'still',
      );
      expect(await f.alice.getSessionIdentityKey('bob-id', 'bob-d1'), f.k1);
    });
  });
}
