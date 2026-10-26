@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _aliceSessionKey = 'crypto_e2_session_bob-id_bob-device';
const _alicePendingKey = 'crypto_e2_pending_prekey_bob-id_bob-device';
const _sendJournalKey = 'crypto_e2_send_commit_journal_v1';

Map<String, String> _withoutSendWal(Map<String, String> source) =>
    Map<String, String>.from(source)..remove(_sendJournalKey);

final class _InjectedWriteFailure implements Exception {
  const _InjectedWriteFailure();
}

final class _FaultStorage extends FakeSecureStorage {
  String? _faultKey;
  bool _afterCommit = false;
  int _remaining = 0;

  void failWrite(String key, {required bool afterCommit, int occurrence = 1}) {
    _faultKey = key;
    _afterCommit = afterCommit;
    _remaining = occurrence;
  }

  @override
  Future<void> write({required String key, required String value}) async {
    if (_faultKey == key) {
      _remaining -= 1;
      if (_remaining == 0) {
        _faultKey = null;
        if (_afterCommit) await super.write(key: key, value: value);
        throw const _InjectedWriteFailure();
      }
    }
    await super.write(key: key, value: value);
  }
}

Future<
  ({
    SignalProtocolManager alice,
    _FaultStorage aliceStorage,
    SignalProtocolManager bob,
  })
>
_faultPair() async {
  final aliceStorage = _FaultStorage();
  final aliceResult = await CryptoTestFixtures.createInitializedManager(
    storage: aliceStorage,
  );
  final bobResult = await CryptoTestFixtures.createInitializedManager();
  final alice = aliceResult.$1;
  final bob = bobResult.$1;
  final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
  await alice.createSession(acceptedBob.consumerBundle());
  await aliceStorage.write(key: 'user_id', value: 'alice-id');
  await aliceStorage.write(key: 'device_id', value: 'alice-device');
  await bobResult.$2.write(key: 'user_id', value: 'bob-id');
  await bobResult.$2.write(key: 'device_id', value: 'bob-device');
  return (alice: alice, aliceStorage: aliceStorage, bob: bob);
}

void main() {
  test('sealed send commits ratchet only after durable host ACK', () async {
    final pair = await CryptoTestFixtures.createPairedManagers();
    final bobIdentity = await pair.bob.getIdentityPublicKey();
    final before = _withoutSendWal(pair.aliceStorage.store);

    final prepared = await pair.alice.prepareSealedSend(
      deliveryId: 'client-message-1',
      recipientId: 'bob-id',
      recipientDeviceId: 'bob-device',
      recipientIdentityPublicKey: bobIdentity,
      plaintext: 'durable outbound plaintext',
    );

    expect(_withoutSendWal(pair.aliceStorage.store), before);
    expect(pair.aliceStorage.store[_sendJournalKey], isNotNull);
    expect(
      pair.aliceStorage.store[_sendJournalKey],
      isNot(contains('durable outbound plaintext')),
    );
    expect(prepared.envelope['ciphertext'], isA<String>());
    expect(
      prepared.envelope['cryptoProtocolEpoch'],
      RisaalCryptoProtocol.cryptoProtocolEpoch,
    );
    expect(pair.aliceStorage.store[_alicePendingKey], before[_alicePendingKey]);
    expect(pair.aliceStorage.store[_aliceSessionKey], before[_aliceSessionKey]);

    final restarted = SignalProtocolManager(secureStorage: pair.aliceStorage);
    final recovered = await restarted.pendingSend();
    expect(recovered, isNotNull);
    expect(jsonEncode(recovered!.envelope), jsonEncode(prepared.envelope));
    expect(recovered.receipt.matchesExact(prepared.receipt), isTrue);

    await restarted.acknowledgeSend(recovered.receipt);
    expect(pair.aliceStorage.store[_alicePendingKey], isNull);
    expect(
      pair.aliceStorage.store[_aliceSessionKey],
      isNot(before[_aliceSessionKey]),
    );
    await restarted.acknowledgeSend(recovered.receipt);
  });

  test('certified sealed send round-trips through the send WAL', () async {
    final pair = await CryptoTestFixtures.createPairedManagers();
    final bobIdentity = await pair.bob.getIdentityPublicKey();
    final server = await SignalKeyHelper.generateSigningKeyPair();
    final aliceSigning = (await CryptoStorage(
      secureStorage: pair.aliceStorage,
    ).getSigningKeyPair())!;
    final now = DateTime.now().millisecondsSinceEpoch;
    final certificate = await SenderCertificateVerifier.issueForTesting(
      serverSigningPrivateKey: server.privateKey,
      keyId: 'sc-test',
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      senderIdentityKey: await pair.alice.getIdentityPublicKey(),
      senderSigningKey: aliceSigning.publicKey,
      issuedAt: now - 60 * 1000,
      expiresAt: now + 24 * 60 * 60 * 1000,
    );

    final prepared = await pair.alice.prepareSealedSend(
      deliveryId: 'client-message-certified',
      recipientId: 'bob-id',
      recipientDeviceId: 'bob-device',
      recipientIdentityPublicKey: bobIdentity,
      plaintext: 'certified outbound',
      senderCertificate: certificate,
    );
    final acknowledged = await pair.alice.acknowledgeSend(prepared.receipt);
    expect(acknowledged.matchesExact(prepared.receipt), isTrue);
    // The receipt shape is unchanged: the certificate is not journaled.
    expect(acknowledged.toJson().keys.toSet(), {
      'deliveryId',
      'deliveryIdHash',
      'receiptId',
      'envelopeDigest',
      'plaintextDigest',
      'recipientId',
      'recipientDeviceId',
    });
    expect(
      pair.aliceStorage.store[_sendJournalKey],
      isNot(contains(certificate.certificateBase64)),
    );

    final bob = SignalProtocolManager(
      secureStorage: pair.bobStorage,
      sealedSenderTrustPolicy: SealedSenderTrustPolicy(
        serverCertificateSigningKeys: {'sc-test': server.publicKey},
      ),
    );
    await bob.initialize();
    final received = await bob.prepareSealedReceive(
      deliveryId: 'bob-delivery-certified',
      sealedEnvelope: prepared.envelope,
    );
    expect(received.plaintext, 'certified outbound');
    expect(received.senderAuthentication!.certified, isTrue);
    await bob.acknowledgeReceive(received.receipt);
    // R4-C3-V2: the WAL commit set carries no signing-key pin mutation; a
    // certificate's signing key is only server-attested.
    expect(await bob.getPeerSigningKey('alice-id', 'alice-device'), isNull);
    expect(
      pair.bobStorage.store.keys.where(
        (k) => k.startsWith('crypto_e2_peer_signing_'),
      ),
      isEmpty,
    );
  });

  test('aborting an unpersisted send leaves the ratchet reusable', () async {
    final pair = await CryptoTestFixtures.createPairedManagers();
    final bobIdentity = await pair.bob.getIdentityPublicKey();
    final before = _withoutSendWal(pair.aliceStorage.store);

    final prepared = await pair.alice.prepareSealedSend(
      deliveryId: 'client-message-abort',
      recipientId: 'bob-id',
      recipientDeviceId: 'bob-device',
      recipientIdentityPublicKey: bobIdentity,
      plaintext: 'not durable yet',
    );
    await pair.alice.abortPreparedSend(prepared.receipt);

    expect(_withoutSendWal(pair.aliceStorage.store), before);
    expect(await pair.alice.pendingSend(), isNull);

    final retry = await pair.alice.prepareSealedSend(
      deliveryId: 'client-message-retry',
      recipientId: 'bob-id',
      recipientDeviceId: 'bob-device',
      recipientIdentityPublicKey: bobIdentity,
      plaintext: 'retry survives',
    );
    await pair.alice.acknowledgeSend(retry.receipt);
  });

  test(
    'prepared first contact decrypts, then ACK enables the next send',
    () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final bobIdentity = await pair.bob.getIdentityPublicKey();
      final prepared = await pair.alice.prepareSealedSend(
        deliveryId: 'client-message-first-contact',
        recipientId: 'bob-id',
        recipientDeviceId: 'bob-device',
        recipientIdentityPublicKey: bobIdentity,
        plaintext: 'first contact through WAL',
      );

      expect(
        (await pair.bob.decryptSealedSender(prepared.envelope)).plaintext,
        'first contact through WAL',
      );
      await pair.alice.acknowledgeSend(prepared.receipt);

      final next = await pair.alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        bobIdentity,
        'next message after ACK',
      );
      expect(
        (await pair.bob.decryptSealedSender(next)).plaintext,
        'next message after ACK',
      );
    },
  );

  test('prepare write ambiguity is restart-convergent', () async {
    for (final afterCommit in <bool>[false, true]) {
      final pair = await _faultPair();
      final bobIdentity = await pair.bob.getIdentityPublicKey();
      final before = _withoutSendWal(pair.aliceStorage.store);
      pair.aliceStorage.failWrite(_sendJournalKey, afterCommit: afterCommit);

      await expectLater(
        pair.alice.prepareSealedSend(
          deliveryId: 'prepare-ambiguous-$afterCommit',
          recipientId: 'bob-id',
          recipientDeviceId: 'bob-device',
          recipientIdentityPublicKey: bobIdentity,
          plaintext: 'prepare ambiguity',
        ),
        throwsA(isA<_InjectedWriteFailure>()),
      );
      expect(_withoutSendWal(pair.aliceStorage.store), before);

      final restarted = SignalProtocolManager(secureStorage: pair.aliceStorage);
      final pending = await restarted.pendingSend();
      if (afterCommit) {
        expect(pending, isNotNull);
        await restarted.acknowledgeSend(pending!.receipt);
      } else {
        expect(pending, isNull);
        final retry = await restarted.prepareSealedSend(
          deliveryId: 'prepare-ambiguous-$afterCommit',
          recipientId: 'bob-id',
          recipientDeviceId: 'bob-device',
          recipientIdentityPublicKey: bobIdentity,
          plaintext: 'prepare ambiguity',
        );
        await restarted.acknowledgeSend(retry.receipt);
      }
    }
  });

  test(
    'ACK mutation and final-journal ambiguity converge on restart',
    () async {
      for (final target in <String>['session', 'final-journal']) {
        for (final afterCommit in <bool>[false, true]) {
          final pair = await _faultPair();
          final bobIdentity = await pair.bob.getIdentityPublicKey();
          final prepared = await pair.alice.prepareSealedSend(
            deliveryId: '$target-$afterCommit',
            recipientId: 'bob-id',
            recipientDeviceId: 'bob-device',
            recipientIdentityPublicKey: bobIdentity,
            plaintext: '$target ambiguity',
          );
          pair.aliceStorage.failWrite(
            target == 'session' ? _aliceSessionKey : _sendJournalKey,
            afterCommit: afterCommit,
            occurrence: target == 'session' ? 1 : 2,
          );

          await expectLater(
            pair.alice.acknowledgeSend(prepared.receipt),
            throwsA(isA<_InjectedWriteFailure>()),
          );
          final restarted = SignalProtocolManager(
            secureStorage: pair.aliceStorage,
          );
          await restarted.acknowledgeSend(prepared.receipt);
          expect(await restarted.pendingSend(), isNull);
          expect(pair.aliceStorage.store[_alicePendingKey], isNull);
          expect(
            (await pair.bob.decryptSealedSender(prepared.envelope)).plaintext,
            '$target ambiguity',
          );
        }
      }
    },
  );
}
