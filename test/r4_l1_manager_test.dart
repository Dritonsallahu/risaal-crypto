@Retry(0)
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/message_padding.dart';
import 'package:risaal_crypto/src/models/session_state.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// R4-L1 through [SignalProtocolManager] (contract §5 A and B): the receive
/// WAL lanes accept v3 and transcript 2, refuse a downgrade without touching
/// storage, and the send lanes follow `kSendRatchetV3`.
typedef _Pair = ({
  SignalProtocolManager alice,
  FakeSecureStorage aliceStorage,
  SignalProtocolManager bob,
  FakeSecureStorage bobStorage,
});

const _bobSessionAtAlice = 'crypto_e2_session_bob-id_bob-device';
const _aliceSessionAtBob = 'crypto_e2_session_alice-id_alice-device';
const _bobPinAtAlice = 'crypto_e2_session_ik_bob-id_bob-device';

var _delivery = 0;

Map<String, dynamic> _stored(FakeSecureStorage storage, String key) =>
    jsonDecode(storage.store[key]!) as Map<String, dynamic>;

Map<String, dynamic> _ratchetMessage(Map<String, dynamic> envelope) =>
    Map<String, dynamic>.from(envelope['message'] as Map);

/// Deliver a direct envelope from Alice to Bob through the receive WAL.
Future<String?> _toBob(_Pair pair, Map<String, dynamic> envelope) async {
  final prepared = await pair.bob.prepareReceive(
    deliveryId: 'r4-l1-delivery-${_delivery++}',
    senderId: 'alice-id',
    senderDeviceId: 'alice-device',
    envelope: envelope,
  );
  await pair.bob.acknowledgeReceive(prepared.receipt);
  return prepared.plaintext;
}

Future<String?> _sealedToBob(_Pair pair, Map<String, dynamic> sealed) async {
  final prepared = await pair.bob.prepareSealedReceive(
    deliveryId: 'r4-l1-delivery-${_delivery++}',
    sealedEnvelope: sealed,
  );
  await pair.bob.acknowledgeReceive(prepared.receipt);
  return prepared.plaintext;
}

/// A transcript-1 pair whose first (v2) message Bob has already accepted.
Future<_Pair> _establishedV1Pair() async {
  debugSendRatchetV3Override = false;
  final pair = await CryptoTestFixtures.createPairedManagers();
  final first = await pair.alice.encryptMessage(
    'bob-id',
    'bob-device',
    'first contact',
  );
  expect(first['type'], 'prekey');
  expect(await _toBob(pair, first), 'first contact');
  return pair;
}

void main() {
  tearDown(() => debugSendRatchetV3Override = null);

  group('R4-L1 Part A through the manager', () {
    test('a v3 message marks the peer; a later v2 message is refused and '
        'Bob\'s storage, WAL included, is unchanged', () async {
      final pair = await _establishedV1Pair();
      expect(
        _stored(
          pair.bobStorage,
          _aliceSessionAtBob,
        ).containsKey('peerSpeaksV3'),
        isFalse,
      );

      debugSendRatchetV3Override = true;
      final v3 = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'bound normal',
      );
      expect(v3['type'], 'message');
      expect(_ratchetMessage(v3)['version'], 3);
      expect(await _toBob(pair, v3), 'bound normal');
      expect(
        _stored(pair.bobStorage, _aliceSessionAtBob)['peerSpeaksV3'],
        true,
      );

      // Alice's next chain step, forced back to v2 from a cloned state.
      final aliceState = RatchetState.fromJson(
        _stored(pair.aliceStorage, _bobSessionAtAlice),
      )..sendV3 = false;
      final forged = await DoubleRatchet.fromJson(
        aliceState.toJson(),
      ).encrypt(MessagePadding.padString('late v2'));
      expect(forged.version, 2);
      final downgrade = <String, dynamic>{
        'type': 'message',
        'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
        'senderIdentityKey': await pair.alice.getIdentityPublicKey(),
        'message': forged.toJson(),
      };

      final before = Map<String, String>.of(pair.bobStorage.store);
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'r4-l1-downgrade-wal',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: downgrade,
        ),
        throwsA(isA<FormatException>()),
      );
      expect(pair.bobStorage.store, before);

      // The legacy non-WAL lane refuses it the same way.
      await expectLater(
        pair.bob.decryptMessage('alice-id', 'alice-device', downgrade),
        throwsA(isA<FormatException>()),
      );
      expect(pair.bobStorage.store, before);

      // The genuine v3 stream continues.
      final next = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'still bound',
      );
      expect(await _toBob(pair, next), 'still bound');
    });

    test('a transcript-2 PreKey is accepted on the direct WAL lane, and the '
        'session answers in v3 even with the flag off', () async {
      debugSendRatchetV3Override = true;
      final pair = await CryptoTestFixtures.createPairedManagers();
      final aliceSession = _stored(pair.aliceStorage, _bobSessionAtAlice);
      expect(aliceSession['sendV3'], true);
      expect(aliceSession['peerSpeaksV3'], true);

      final hello = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        't2 hello',
      );
      expect(hello['type'], 'prekey');
      expect(hello['transcriptVersion'], 2);
      expect(_ratchetMessage(hello)['version'], 3);
      expect(await _toBob(pair, hello), 't2 hello');
      final bobSession = _stored(pair.bobStorage, _aliceSessionAtBob);
      expect(bobSession['sendV3'], true);
      expect(bobSession['peerSpeaksV3'], true);

      debugSendRatchetV3Override = false;
      final reply = await pair.bob.encryptMessage(
        'alice-id',
        'alice-device',
        't2 reply',
      );
      expect(reply['type'], 'message');
      expect(_ratchetMessage(reply)['version'], 3);
      final prepared = await pair.alice.prepareReceive(
        deliveryId: 'r4-l1-reply',
        senderId: 'bob-id',
        senderDeviceId: 'bob-device',
        envelope: reply,
      );
      expect(prepared.plaintext, 't2 reply');
      await pair.alice.acknowledgeReceive(prepared.receipt);
    });

    test('a transcript-2 PreKey is accepted on the sealed lane', () async {
      debugSendRatchetV3Override = true;
      final pair = await CryptoTestFixtures.createPairedManagers();
      final sealed = await pair.alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        await pair.bob.getIdentityPublicKey(),
        'sealed t2 hello',
      );
      expect(sealed.containsKey('transcriptVersion'), isFalse);
      expect(await _sealedToBob(pair, sealed), 'sealed t2 hello');
      final bobSession = _stored(pair.bobStorage, _aliceSessionAtBob);
      expect(bobSession['sendV3'], true);
      expect(bobSession['peerSpeaksV3'], true);
    });

    test('a transcript-2 PreKey is accepted on the legacy lane', () async {
      debugSendRatchetV3Override = true;
      final pair = await CryptoTestFixtures.createPairedManagers();
      final hello = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'legacy t2 hello',
      );
      expect(
        await pair.bob.decryptMessage('alice-id', 'alice-device', hello),
        'legacy t2 hello',
      );
      final bobSession = _stored(pair.bobStorage, _aliceSessionAtBob);
      expect(bobSession['sendV3'], true);
      expect(bobSession['peerSpeaksV3'], true);
    });

    test('a transcriptVersion downgrade from 2 to 1 inside the PreKey '
        'message fails without touching storage', () async {
      debugSendRatchetV3Override = true;
      final pair = await CryptoTestFixtures.createPairedManagers();
      final hello = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'do not downgrade me',
      );
      expect(hello['transcriptVersion'], 2);
      final downgraded = Map<String, dynamic>.of(hello)
        ..remove('transcriptVersion');
      final before = Map<String, String>.of(pair.bobStorage.store);

      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'r4-l1-t2-downgrade',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: downgraded,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(pair.bobStorage.store, before);
      await expectLater(
        pair.bob.decryptMessage('alice-id', 'alice-device', downgraded),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(pair.bobStorage.store, before);
      for (final bad in <Object?>[1, 3, '2']) {
        await expectLater(
          pair.bob.prepareReceive(
            deliveryId: 'r4-l1-t2-bad-$bad',
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            envelope: <String, dynamic>{...hello, 'transcriptVersion': bad},
          ),
          throwsA(isA<FormatException>()),
          reason: 'transcriptVersion=$bad',
        );
        expect(pair.bobStorage.store, before);
      }
      expect(await pair.bob.hasSession('alice-id', 'alice-device'), isFalse);

      expect(await _toBob(pair, hello), 'do not downgrade me');
    });

    test('a normal message carrying transcriptVersion is refused', () async {
      final pair = await _establishedV1Pair();
      final normal = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'normal',
      );
      final before = Map<String, String>.of(pair.bobStorage.store);
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'r4-l1-normal-with-transcript',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: <String, dynamic>{...normal, 'transcriptVersion': 2},
        ),
        throwsA(isA<FormatException>()),
      );
      expect(pair.bobStorage.store, before);
      expect(await _toBob(pair, normal), 'normal');
    });
  });

  group('R4-L1 Part B send flag', () {
    test('kSendRatchetV3 ships off', () {
      expect(kSendRatchetV3, isFalse);
      expect(debugSendRatchetV3Override, isNull);
      expect(sendRatchetV3Enabled, isFalse);
    });

    test('flag off: every send keeps today\'s shape (v2, transcript 1, no '
        'new state fields)', () async {
      debugSendRatchetV3Override = false;
      final pair = await CryptoTestFixtures.createPairedManagers();
      final session = _stored(pair.aliceStorage, _bobSessionAtAlice);
      expect(session.containsKey('sendV3'), isFalse);
      expect(session.containsKey('peerSpeaksV3'), isFalse);

      const messageKeys = <String>{
        'dhPublicKey',
        'messageNumber',
        'previousChainLength',
        'ciphertext',
        'nonce',
        'version',
      };
      final first = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'flag off first',
      );
      expect(first.keys.toSet(), <String>{
        'type',
        'senderIdentityKey',
        'senderEphemeralKey',
        'kyberCiphertext',
        'bundleRevision',
        'opkGeneration',
        'opkSetDigest',
        'recipientSignedPreKeyId',
        'usedOneTimePreKeyId',
        'cryptoProtocolEpoch',
        'kemSuite',
        'kemStandard',
        'kemWireVersion',
        'recipientKeyId',
        'message',
      });
      expect(_ratchetMessage(first).keys.toSet(), messageKeys);
      expect(_ratchetMessage(first)['version'], 2);
      final routing = PreKeyHandshakeRouting.fromEnvelopeJson(first);
      expect(routing.transcriptVersion, 1);
      expect(
        utf8.decode(routing.canonicalTranscript().sublist(4, 29)),
        'RISAAL_PQXDH_OPK_ROUTE_v1',
      );
      expect(await _toBob(pair, first), 'flag off first');

      final normal = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'flag off normal',
      );
      expect(normal.keys.toSet(), <String>{
        'type',
        'cryptoProtocolEpoch',
        'senderIdentityKey',
        'message',
      });
      expect(_ratchetMessage(normal).keys.toSet(), messageKeys);
      expect(_ratchetMessage(normal)['version'], 2);
      expect(await _toBob(pair, normal), 'flag off normal');

      final sealed = await pair.alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        await pair.bob.getIdentityPublicKey(),
        'flag off sealed',
      );
      expect(await _sealedToBob(pair, sealed), 'flag off sealed');
      final prepared = await pair.alice.prepareSealedSend(
        deliveryId: 'r4-l1-flag-off-prepared',
        recipientId: 'bob-id',
        recipientDeviceId: 'bob-device',
        recipientIdentityPublicKey: await pair.bob.getIdentityPublicKey(),
        plaintext: 'flag off prepared',
      );
      await pair.alice.acknowledgeSend(prepared.receipt);
      expect(await _sealedToBob(pair, prepared.envelope), 'flag off prepared');

      for (final (storage, key) in <(FakeSecureStorage, String)>[
        (pair.aliceStorage, _bobSessionAtAlice),
        (pair.bobStorage, _aliceSessionAtBob),
      ]) {
        final state = _stored(storage, key);
        expect(state.containsKey('sendV3'), isFalse, reason: key);
        expect(state.containsKey('peerSpeaksV3'), isFalse, reason: key);
      }
    });

    test('flag on: createSession initiates transcript 2', () async {
      debugSendRatchetV3Override = true;
      final pair = await CryptoTestFixtures.createPairedManagers();
      final hello = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'flag on hello',
      );
      final routing = PreKeyHandshakeRouting.fromEnvelopeJson(hello);
      expect(routing.transcriptVersion, 2);
      expect(_ratchetMessage(hello)['version'], 3);
    });

    for (final lane in const ['direct', 'sealed', 'prepared sealed']) {
      test('flag on: the $lane lane sends v3 on an existing session', () async {
        final pair = await _establishedV1Pair();
        debugSendRatchetV3Override = true;
        final bobIdentity = await pair.bob.getIdentityPublicKey();
        switch (lane) {
          case 'direct':
            final envelope = await pair.alice.encryptMessage(
              'bob-id',
              'bob-device',
              lane,
            );
            expect(_ratchetMessage(envelope)['version'], 3);
            expect(await _toBob(pair, envelope), lane);
          case 'sealed':
            final sealed = await pair.alice.encryptSealedSender(
              'bob-id',
              'bob-device',
              bobIdentity,
              lane,
            );
            expect(await _sealedToBob(pair, sealed), lane);
          default:
            final prepared = await pair.alice.prepareSealedSend(
              deliveryId: 'r4-l1-flag-on-prepared',
              recipientId: 'bob-id',
              recipientDeviceId: 'bob-device',
              recipientIdentityPublicKey: bobIdentity,
              plaintext: lane,
            );
            await pair.alice.acknowledgeSend(prepared.receipt);
            expect(await _sealedToBob(pair, prepared.envelope), lane);
        }
        expect(_stored(pair.aliceStorage, _bobSessionAtAlice)['sendV3'], true);
        // Bob saw a v3 message: only v3 sets this.
        expect(
          _stored(pair.bobStorage, _aliceSessionAtBob)['peerSpeaksV3'],
          true,
        );
      });
    }

    test('flag on: a session without a recorded remote identity is never '
        'sent v3 and is marked for re-establishment exactly once', () async {
      final pair = await _establishedV1Pair();
      // A record from before sessions carried their identity, and no pin to
      // stamp it from.
      final legacy = _stored(pair.aliceStorage, _bobSessionAtAlice)
        ..remove('remoteIdentityKey');
      await pair.aliceStorage.write(
        key: _bobSessionAtAlice,
        value: jsonEncode(legacy),
      );
      await pair.aliceStorage.delete(key: _bobPinAtAlice);
      pair.alice.wipeAllSessions();

      final marked = <(String, String)>[];
      pair.alice.onSessionReestablishmentNeeded = (peer, device) =>
          marked.add((peer, device));
      debugSendRatchetV3Override = true;

      for (var i = 0; i < 2; i++) {
        final envelope = await pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'unbound $i',
        );
        expect(_ratchetMessage(envelope)['version'], 2);
        expect(await _toBob(pair, envelope), 'unbound $i');
      }
      final sealed = await pair.alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        await pair.bob.getIdentityPublicKey(),
        'unbound sealed',
      );
      expect(await _sealedToBob(pair, sealed), 'unbound sealed');

      expect(marked, [('bob-id', 'bob-device')]);
      final state = _stored(pair.aliceStorage, _bobSessionAtAlice);
      expect(state.containsKey('sendV3'), isFalse);
      expect(state.containsKey('remoteIdentityKey'), isFalse);
      expect(
        _stored(
          pair.bobStorage,
          _aliceSessionAtBob,
        ).containsKey('peerSpeaksV3'),
        isFalse,
      );
    });
  });
}
