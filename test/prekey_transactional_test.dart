@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _journalKey = 'crypto_e2_bundle_replacement_journal_v1';

Future<
  ({
    SignalProtocolManager alice,
    FakeSecureStorage aliceStorage,
    SignalProtocolManager bob,
    FakeSecureStorage bobStorage,
  })
>
_managers() async {
  final aliceStorage = FakeSecureStorage();
  final bobStorage = FakeSecureStorage();
  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);
  await alice.wipeForFreshRegistration();
  await bob.wipeForFreshRegistration();
  await alice.initialize();
  await bob.initialize();
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

void main() {
  test(
    'unknown one-time pre-key fails before any recipient mutation',
    () async {
      final setup = await _managers();
      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
        setup.bob,
      );
      final bobBundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );
      await setup.alice.createSession(bobBundle);
      final envelope = await setup.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first message',
      );
      final unknownOtp = Map<String, dynamic>.from(envelope)
        ..['usedOneTimePreKeyId'] = 999999;
      final journalBefore = await setup.bobStorage.read(key: _journalKey);

      await expectLater(
        setup.bob.decryptMessage('alice-id', 'alice-device', unknownOtp),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Invalid routed PreKey private material'),
          ),
        ),
      );

      expect(await setup.bobStorage.read(key: _journalKey), journalBefore);
      expect(await setup.bob.hasSession('alice-id', 'alice-device'), isFalse);
    },
  );

  test(
    'bad first-message MAC preserves OTP, prior session and pending handshake',
    () async {
      final setup = await _managers();
      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
        setup.bob,
      );
      final bobBundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );
      final acceptedAlice = await CryptoTestFixtures.acceptInitialGeneration(
        setup.alice,
      );
      final aliceBundle = acceptedAlice.consumerBundle(
        userId: 'alice-id',
        deviceId: 'alice-device',
      );

      // Simultaneous first contact: Bob already has a valid outbound session and
      // pending handshake when Alice's inbound PreKey arrives.
      await setup.alice.createSession(bobBundle);
      await setup.bob.createSession(aliceBundle);
      final authentic = await setup.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'authentic first message',
      );
      final tampered = Map<String, dynamic>.from(authentic);
      final tamperedMessage = Map<String, dynamic>.from(
        authentic['message'] as Map,
      );
      final ciphertext = base64Decode(tamperedMessage['ciphertext'] as String);
      ciphertext[0] ^= 0x01;
      tamperedMessage['ciphertext'] = base64Encode(ciphertext);
      tampered['message'] = tamperedMessage;

      const sessionKey = 'crypto_e2_session_alice-id_alice-device';
      const pendingKey = 'crypto_e2_pending_prekey_alice-id_alice-device';
      final sessionBefore = await setup.bobStorage.read(key: sessionKey);
      final pendingBefore = await setup.bobStorage.read(key: pendingKey);
      final journalBefore = await setup.bobStorage.read(key: _journalKey);
      expect(sessionBefore, isNotNull);
      expect(pendingBefore, isNotNull);

      await expectLater(
        setup.bob.decryptMessage('alice-id', 'alice-device', tampered),
        throwsA(anything),
      );

      expect(await setup.bobStorage.read(key: sessionKey), sessionBefore);
      expect(await setup.bobStorage.read(key: pendingKey), pendingBefore);
      expect(await setup.bobStorage.read(key: _journalKey), journalBefore);

      final plaintext = await setup.bob.decryptMessage(
        'alice-id',
        'alice-device',
        authentic,
      );
      expect(plaintext, 'authentic first message');
    },
  );
}
