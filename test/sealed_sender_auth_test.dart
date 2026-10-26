import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

Future<
  ({
    SignalProtocolManager alice,
    SignalProtocolManager bob,
    FakeSecureStorage bobStorage,
    Map<String, dynamic> envelope,
    String aliceIdentityKey,
  })
>
_freshFirstContact() async {
  final (alice, aliceStorage) =
      await CryptoTestFixtures.createInitializedManager();
  final (bob, bobStorage) = await CryptoTestFixtures.createInitializedManager();
  await aliceStorage.write(key: 'user_id', value: 'alice-id');
  await aliceStorage.write(key: 'device_id', value: 'alice-device');
  await bobStorage.write(key: 'user_id', value: 'bob-id');
  await bobStorage.write(key: 'device_id', value: 'bob-device');

  final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
  final bobBundle = acceptedBob.consumerBundle(
    userId: 'bob-id',
    deviceId: 'bob-device',
  );
  await alice.createSession(bobBundle);
  final envelope = await alice.encryptSealedSender(
    'bob-id',
    'bob-device',
    await bob.getIdentityPublicKey(),
    'first sealed message',
  );
  return (
    alice: alice,
    bob: bob,
    bobStorage: bobStorage,
    envelope: envelope,
    aliceIdentityKey: await alice.getIdentityPublicKey(),
  );
}

/// H1 — a sealed-sender certificate is self-asserted (attacker-controlled). Under
/// the "server is hostile" model the recipient must authenticate the claimed
/// sender against the identity key PINNED in the established session, otherwise a
/// forger can spoof any sender. First contact is trust-on-first-use.
void main() {
  group('H1 — sealed sender authenticates the claimed sender', () {
    test('rejects a sealed message whose claimed identity key != the pinned '
        'session key (sender spoofing / MITM)', () async {
      final (bob, bobStorage) =
          await CryptoTestFixtures.createInitializedManager();
      final bobIdentityKey = await bob.getIdentityPublicKey();

      // Bob already has a session with alice, pinning her REAL identity key.
      final realAlice = await SignalKeyHelper.generateX25519KeyPair();
      await bobStorage.write(
        key: 'crypto_e2_session_ik_alice-id_alice-device',
        value: realAlice.publicKey,
      );

      // A forger seals a message claiming to be alice — but with THEIR key.
      final forger = await SignalKeyHelper.generateX25519KeyPair();
      final forged = await SealedSenderEnvelope.seal(
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        senderIdentityKey: forger.publicKey,
        encryptedMessage: {
          'type': 'message',
          'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
          'senderIdentityKey': forger.publicKey,
          'message': const <String, dynamic>{},
        },
        recipientIdentityPublicKey: bobIdentityKey,
      );
      forged['cryptoProtocolEpoch'] = RisaalCryptoProtocol.cryptoProtocolEpoch;

      await expectLater(
        bob.decryptSealedSender(forged),
        throwsA(
          predicate((Object e) => e.toString().contains('identity mismatch')),
        ),
      );
    });

    test('first contact (no pinned key) is NOT rejected on identity grounds '
        '(trust-on-first-use)', () async {
      final (bob, _) = await CryptoTestFixtures.createInitializedManager();
      final bobIdentityKey = await bob.getIdentityPublicKey();

      final stranger = await SignalKeyHelper.generateX25519KeyPair();
      // Keep outer and protected-inner identity equal so this exercises TOFU,
      // not the independent outer/inner binding gate.
      final matching = await SealedSenderEnvelope.seal(
        senderId: 'stranger-id',
        senderDeviceId: 'stranger-device',
        senderIdentityKey: stranger.publicKey,
        encryptedMessage: {
          'type': 'message',
          'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
          'senderIdentityKey': stranger.publicKey,
          'message': <String, dynamic>{},
        },
        recipientIdentityPublicKey: bobIdentityKey,
      );
      matching['cryptoProtocolEpoch'] =
          RisaalCryptoProtocol.cryptoProtocolEpoch;

      // It will fail later (the inner message is synthetic), but NOT with an
      // identity mismatch — first contact must be allowed to proceed past the
      // sender-authentication gate.
      await expectLater(
        bob.decryptSealedSender(matching),
        throwsA(
          predicate((Object e) => !e.toString().contains('identity mismatch')),
        ),
      );
    });

    test(
      'tampered outer KEM routing does not poison nonce for authentic retry',
      () async {
        final setup = await _freshFirstContact();
        final tampered = Map<String, dynamic>.from(setup.envelope);
        tampered['recipientKeyId'] = (tampered['recipientKeyId'] as int) + 1;

        await expectLater(
          setup.bob.decryptSealedSender(tampered),
          throwsA(isA<FormatException>()),
        );
        final recovered = await setup.bob.decryptSealedSender(setup.envelope);
        expect(recovered.plaintext, 'first sealed message');
      },
    );

    test(
      'pinned identity rejection does not poison nonce for corrected retry',
      () async {
        final setup = await _freshFirstContact();
        final wrongIdentity = await SignalKeyHelper.generateX25519KeyPair();
        await setup.bobStorage.write(
          key: 'crypto_e2_session_ik_alice-id_alice-device',
          value: wrongIdentity.publicKey,
        );

        await expectLater(
          setup.bob.decryptSealedSender(setup.envelope),
          throwsA(
            predicate(
              (Object error) => error.toString().contains('identity mismatch'),
            ),
          ),
        );
        await setup.bobStorage.write(
          key: 'crypto_e2_session_ik_alice-id_alice-device',
          value: setup.aliceIdentityKey,
        );
        final recovered = await setup.bob.decryptSealedSender(setup.envelope);
        expect(recovered.plaintext, 'first sealed message');
      },
    );

    test(
      'outer certificate identity must equal protected inner identity',
      () async {
        final (attacker, attackerStorage) =
            await CryptoTestFixtures.createInitializedManager();
        final (bob, bobStorage) =
            await CryptoTestFixtures.createInitializedManager();
        await attackerStorage.write(key: 'user_id', value: 'attacker-id');
        await attackerStorage.write(key: 'device_id', value: 'attacker-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bobBundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        await attacker.createSession(bobBundle);
        final attackerInner = await attacker.encryptMessage(
          'bob-id',
          'bob-device',
          'forged first contact',
        );
        final claimedAlice = await SignalKeyHelper.generateX25519KeyPair();
        await bobStorage.write(
          key: 'crypto_e2_session_ik_alice-id_alice-device',
          value: claimedAlice.publicKey,
        );
        final forged = await SealedSenderEnvelope.seal(
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          senderIdentityKey: claimedAlice.publicKey,
          encryptedMessage: attackerInner,
          recipientIdentityPublicKey: await bob.getIdentityPublicKey(),
        );
        const projectedFields = <String>{
          'cryptoProtocolEpoch',
          'kyberCiphertext',
          'recipientKeyId',
          'recipientSignedPreKeyId',
          'kemSuite',
          'kemStandard',
          'kemWireVersion',
          'bundleRevision',
          'opkGeneration',
          'opkSetDigest',
        };
        for (final field in projectedFields) {
          forged[field] = attackerInner[field];
        }
        final otpBefore = await bobStorage.read(
          key: 'crypto_one_time_pre_keys',
        );

        await expectLater(
          bob.decryptSealedSender(forged),
          throwsA(
            predicate(
              (Object error) =>
                  error.toString().contains('outer/inner identity mismatch'),
            ),
          ),
        );
        expect(
          await bobStorage.read(key: 'crypto_one_time_pre_keys'),
          otpBefore,
          reason: 'identity rejection must happen before one-time key mutation',
        );
        expect(await bob.hasSession('alice-id', 'alice-device'), isFalse);
      },
    );
  });
}
