@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';
import 'package:risaal_crypto/src/sender_key.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    jsonDecode(jsonEncode(value)) as Map<String, dynamic>;

void _setRatchetVersion(Map<String, dynamic> envelope, int? version) {
  final message = envelope['message'] as Map<String, dynamic>;
  if (version == null) {
    message.remove('version');
  } else {
    message['version'] = version;
  }
}

Future<(SenderKeyManager, FakeSecureStorage)> _senderKeyManager(
  String userId,
) async {
  final storage = FakeSecureStorage();
  await storage.write(key: 'user_id', value: userId);
  return (
    SenderKeyManager(cryptoStorage: CryptoStorage(secureStorage: storage)),
    storage,
  );
}

void main() {
  group('epoch-2 Double Ratchet boundary', () {
    for (final legacyVersion in <int?>[null, 1, 4]) {
      test(
        'PreKey rejects inner version $legacyVersion before mutation',
        () async {
          final pair = await CryptoTestFixtures.createPairedManagers();
          final otpCountBefore = await pair.bob.oneTimePreKeyCount();
          final envelope = _deepCopy(
            await pair.alice.encryptMessage('bob-id', 'bob-device', 'first'),
          );
          _setRatchetVersion(envelope, legacyVersion);

          await expectLater(
            pair.bob.decryptMessage('alice-id', 'alice-device', envelope),
            throwsA(isA<FormatException>()),
          );
          expect(
            await pair.bob.hasSession('alice-id', 'alice-device'),
            isFalse,
          );
          expect(await pair.bob.oneTimePreKeyCount(), otpCountBefore);
        },
      );

      test(
        'normal message rejects inner version $legacyVersion without reset',
        () async {
          final pair = await CryptoTestFixtures.createPairedManagers();
          final first = await pair.alice.encryptMessage(
            'bob-id',
            'bob-device',
            'first',
          );
          await pair.bob.decryptMessage('alice-id', 'alice-device', first);
          final original = await pair.alice.encryptMessage(
            'bob-id',
            'bob-device',
            'second',
          );
          final mutated = _deepCopy(original);
          _setRatchetVersion(mutated, legacyVersion);
          const sessionKey = 'crypto_e2_session_alice-id_alice-device';
          final sessionBefore = pair.bobStorage.store[sessionKey];

          await expectLater(
            pair.bob.decryptMessage('alice-id', 'alice-device', mutated),
            throwsA(isA<FormatException>()),
          );
          expect(pair.bobStorage.store[sessionKey], sessionBefore);
          expect(
            await pair.bob.decryptMessage('alice-id', 'alice-device', original),
            'second',
          );
        },
      );
    }

    test('batch rejects a legacy inner version before loading state', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final first = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first',
      );
      await pair.bob.decryptMessage('alice-id', 'alice-device', first);
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'batch',
      );
      final inner = _deepCopy(envelope['message'] as Map<String, dynamic>)
        ..remove('version');
      final malformedEnvelope = _deepCopy(envelope)..['message'] = inner;
      const sessionKey = 'crypto_e2_session_alice-id_alice-device';
      final sessionBefore = pair.bobStorage.store[sessionKey];

      await expectLater(
        pair.bob.decryptNormalBatch(
          'alice-id',
          'alice-device',
          <Map<String, dynamic>>[malformedEnvelope],
          useIsolate: false,
        ),
        throwsA(isA<FormatException>()),
      );
      expect(pair.bobStorage.store[sessionKey], sessionBefore);
    });

    test(
      'sealed sender rejects legacy inner version before mutation',
      () async {
        final pair = await CryptoTestFixtures.createPairedManagers();
        final otpCountBefore = await pair.bob.oneTimePreKeyCount();
        final original = await pair.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          await pair.bob.getIdentityPublicKey(),
          'sealed first message',
        );
        final bobIdentity = KeyPair.fromJson(
          jsonDecode(pair.bobStorage.store['crypto_identity_key_pair']!)
              as Map<String, dynamic>,
        );
        final content = await SealedSenderEnvelope.unseal(
          sealedEnvelope: original,
          recipientIdentityKeyPair: bobIdentity,
          seenNonces: <String>{},
        );
        final legacyInner = _deepCopy(content.encryptedMessage);
        _setRatchetVersion(legacyInner, 1);
        final resealed = await SealedSenderEnvelope.seal(
          senderId: content.senderId,
          senderDeviceId: content.senderDeviceId,
          senderIdentityKey: content.senderIdentityKey,
          encryptedMessage: legacyInner,
          recipientIdentityPublicKey: bobIdentity.publicKey,
        );
        final legacyOuter = <String, dynamic>{...original, ...resealed};

        await expectLater(
          pair.bob.decryptSealedSender(legacyOuter),
          throwsA(isA<FormatException>()),
        );
        expect(await pair.bob.hasSession('alice-id', 'alice-device'), isFalse);
        expect(await pair.bob.oneTimePreKeyCount(), otpCountBefore);
      },
    );
  });

  group('epoch-2 Sender Key boundary', () {
    test('distribution JSON requires an explicit epoch', () async {
      final (alice, _) = await _senderKeyManager('alice');
      final json = (await alice.generateSenderKey('group')).toJson()
        ..remove('epoch');
      expect(
        () => SenderKeyDistribution.fromJson(json),
        throwsA(isA<FormatException>()),
      );
    });

    test(
      'distribution JSON requires the current crypto protocol epoch',
      () async {
        final (alice, _) = await _senderKeyManager('alice');
        final json = (await alice.generateSenderKey('group')).toJson()
          ..remove('cryptoProtocolEpoch');
        expect(
          () => SenderKeyDistribution.fromJson(json),
          throwsA(isA<FormatException>()),
        );
      },
    );

    test('stored Sender Key state requires the current schema', () {
      final state = SenderKeyState(
        cryptoProtocolEpoch: 2,
        groupId: 'group',
        senderId: 'alice',
        iteration: 0,
        epoch: 0,
        chainKey: List<int>.filled(32, 1),
        signingPublicKey: base64Encode(List<int>.filled(32, 2)),
      ).toJson()..remove('storageVersion');
      expect(
        () => SenderKeyState.fromJson(state),
        throwsA(isA<FormatException>()),
      );
    });

    for (final legacyVersion in <int>[1, 2, 4]) {
      test(
        'blob version $legacyVersion rejects before Sender Key mutation',
        () async {
          final (alice, _) = await _senderKeyManager('alice');
          final (bob, bobStorage) = await _senderKeyManager('bob');
          final distribution = await alice.generateSenderKey('group');
          await bob.processSenderKeyDistribution(
            'group',
            'alice',
            distribution,
          );
          final current = await alice.encrypt(
            'group',
            utf8.encode('current group message'),
          );
          final blob = base64Decode(current.ciphertext)..[0] = legacyVersion;
          final typedBypass = SenderKeyMessage(
            iteration: current.iteration,
            ciphertext: base64Encode(blob),
            iv: current.iv,
            signature: current.signature,
          );
          final stateBefore = Map<String, String>.from(bobStorage.store);

          await expectLater(
            bob.decrypt('group', 'alice', typedBypass),
            throwsA(isA<FormatException>()),
          );
          expect(bobStorage.store, stateBefore);
        },
      );
    }

    test(
      'short v3 blob and invalid signature reject before state load',
      () async {
        final (alice, _) = await _senderKeyManager('alice');
        final (bob, bobStorage) = await _senderKeyManager('bob');
        final distribution = await alice.generateSenderKey('group');
        await bob.processSenderKeyDistribution('group', 'alice', distribution);
        final current = await alice.encrypt(
          'group',
          utf8.encode('current group message'),
        );
        final stateBefore = Map<String, String>.from(bobStorage.store);
        final invalidMessages = <SenderKeyMessage>[
          SenderKeyMessage(
            iteration: current.iteration,
            ciphertext: base64Encode(const <int>[3]),
            iv: '',
            signature: current.signature,
          ),
          SenderKeyMessage(
            iteration: current.iteration,
            ciphertext: current.ciphertext,
            iv: '',
            signature: base64Encode(const <int>[1]),
          ),
        ];

        for (final invalid in invalidMessages) {
          await expectLater(
            bob.decrypt('group', 'alice', invalid),
            throwsA(isA<FormatException>()),
          );
          expect(bobStorage.store, stateBefore);
        }
      },
    );

    test('current v3 Sender Key message still round-trips', () async {
      final (alice, _) = await _senderKeyManager('alice');
      final (bob, _) = await _senderKeyManager('bob');
      final distribution = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', distribution);
      final message = await alice.encrypt(
        'group',
        utf8.encode('current group message'),
      );
      expect(
        utf8.decode(await bob.decrypt('group', 'alice', message)),
        'current group message',
      );
    });
  });
}
