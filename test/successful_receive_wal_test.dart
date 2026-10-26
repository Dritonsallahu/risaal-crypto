@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/receive_commit.dart'
    show
        ReceiveCommitJournal,
        ReceiveCommitPhase,
        ReceivePendingCommit,
        ReceiveStorageMutation,
        receiveEnvelopeDigest;

import 'helpers/crypto_test_fixtures.dart';

const _receiveJournalKey = 'crypto_e2_receive_commit_journal_v1';
const _bundleJournalKey = 'crypto_e2_bundle_replacement_journal_v1';
const _aliceSessionKey = 'crypto_e2_session_alice-id_alice-device';
const _sealedNonceKey = 'crypto_e2_seen_nonces';

Map<String, String> _withoutReceiveWal(Map<String, String> source) =>
    Map<String, String>.fromEntries(
      source.entries.where((entry) => entry.key != _receiveJournalKey),
    );

Future<void> _establishDirectSession(
  ({
    SignalProtocolManager alice,
    dynamic aliceStorage,
    SignalProtocolManager bob,
    dynamic bobStorage,
  })
  pair,
) async {
  final envelope = await pair.alice.encryptMessage(
    'bob-id',
    'bob-device',
    'first direct receive',
  );
  final prepared = await pair.bob.prepareReceive(
    deliveryId: 'delivery-establish-direct',
    senderId: 'alice-id',
    senderDeviceId: 'alice-device',
    envelope: envelope,
  );
  await pair.bob.acknowledgeReceive(prepared.receipt);
}

void main() {
  group('successful receive WAL boundary', () {
    test('routed PreKey is provisional, idempotent, bounded to one delivery, '
        'and commits OPK only after host ACK', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      const deliveryId = 'delivery-prekey-stable-private-id';
      const plaintext = 'receive-wal-prekey-plaintext';
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        plaintext,
      );

      final before = pair.bobStorage.store;
      final bundleBefore = await pair.bobStorage.read(key: _bundleJournalKey);
      final prepared = await pair.bob.prepareReceive(
        deliveryId: deliveryId,
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );

      expect(prepared.plaintext, plaintext);
      expect(prepared.requiresHostPersistence, isTrue);
      expect(prepared.receipt.kind, ReceiveEnvelopeKind.directPreKey);
      expect(
        _withoutReceiveWal(pair.bobStorage.store),
        _withoutReceiveWal(before),
      );
      expect(await pair.bobStorage.read(key: _bundleJournalKey), bundleBefore);
      final preparedWal =
          await pair.bobStorage.read(key: _receiveJournalKey) ?? '';
      expect(preparedWal, isNot(contains(plaintext)));
      expect(preparedWal, isNot(contains(deliveryId)));

      final sameDelivery = await pair.bob.prepareReceive(
        deliveryId: deliveryId,
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      expect(sameDelivery.plaintext, plaintext);
      expect(sameDelivery.receipt.matchesExact(prepared.receipt), isTrue);

      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'different-delivery-while-pending',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        ),
        throwsA(isA<StateError>()),
      );
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: deliveryId,
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: <String, dynamic>{...envelope, 'transportBit': true},
        ),
        throwsA(isA<StateError>()),
      );

      final acknowledged = await pair.bob.acknowledgeReceive(prepared.receipt);
      expect(acknowledged.matchesExact(prepared.receipt), isTrue);
      expect(await pair.bob.hasSession('alice-id', 'alice-device'), isTrue);
      expect(
        await pair.bobStorage.read(key: _bundleJournalKey),
        isNot(bundleBefore),
      );

      final duplicateAck = await pair.bob.acknowledgeReceive(prepared.receipt);
      expect(duplicateAck.matchesExact(prepared.receipt), isTrue);
      final redelivery = await pair.bob.prepareReceive(
        deliveryId: deliveryId,
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      expect(redelivery.alreadyAcknowledged, isTrue);
      expect(redelivery.plaintext, isNull);
      final completedWal =
          await pair.bobStorage.read(key: _receiveJournalKey) ?? '';
      expect(completedWal, isNot(contains(plaintext)));
      expect(completedWal, isNot(contains(deliveryId)));
    });

    test(
      'normal ratchet state stays byte-identical before ACK and next decrypt works',
      () async {
        final pair = await CryptoTestFixtures.createPairedManagers();
        await _establishDirectSession(pair);
        final envelope = await pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'normal provisional plaintext',
        );
        expect(envelope['type'], 'message');
        final sessionBefore = await pair.bobStorage.read(key: _aliceSessionKey);

        final prepared = await pair.bob.prepareReceive(
          deliveryId: 'delivery-normal-1',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        );
        expect(prepared.plaintext, 'normal provisional plaintext');
        expect(prepared.receipt.kind, ReceiveEnvelopeKind.directMessage);
        expect(
          await pair.bobStorage.read(key: _aliceSessionKey),
          sessionBefore,
        );

        await pair.bob.acknowledgeReceive(prepared.receipt);
        expect(
          await pair.bobStorage.read(key: _aliceSessionKey),
          isNot(sessionBefore),
        );

        final nextEnvelope = await pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'normal after durable commit',
        );
        final next = await pair.bob.prepareReceive(
          deliveryId: 'delivery-normal-2',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: nextEnvelope,
        );
        expect(next.plaintext, 'normal after durable commit');
        await pair.bob.acknowledgeReceive(next.receipt);
      },
    );

    test(
      'sealed routed PreKey authenticates sender and defers session, OPK, and nonce',
      () async {
        final pair = await CryptoTestFixtures.createPairedManagers();
        final sealed = await pair.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          await pair.bob.getIdentityPublicKey(),
          'sealed prekey provisional plaintext',
        );
        final sessionBefore = await pair.bobStorage.read(key: _aliceSessionKey);
        final bundleBefore = await pair.bobStorage.read(key: _bundleJournalKey);
        final nonceBefore = await pair.bobStorage.read(key: _sealedNonceKey);

        final prepared = await pair.bob.prepareSealedReceive(
          deliveryId: 'delivery-sealed-prekey-1',
          sealedEnvelope: sealed,
        );
        expect(prepared.plaintext, 'sealed prekey provisional plaintext');
        expect(prepared.receipt.senderId, 'alice-id');
        expect(prepared.receipt.senderDeviceId, 'alice-device');
        expect(prepared.receipt.kind, ReceiveEnvelopeKind.sealedPreKey);
        expect(
          await pair.bobStorage.read(key: _aliceSessionKey),
          sessionBefore,
        );
        expect(
          await pair.bobStorage.read(key: _bundleJournalKey),
          bundleBefore,
        );
        expect(await pair.bobStorage.read(key: _sealedNonceKey), nonceBefore);

        await pair.bob.acknowledgeReceive(prepared.receipt);
        expect(
          await pair.bobStorage.read(key: _aliceSessionKey),
          isNot(sessionBefore),
        );
        expect(
          await pair.bobStorage.read(key: _bundleJournalKey),
          isNot(bundleBefore),
        );
        expect(
          await pair.bobStorage.read(key: _sealedNonceKey),
          isNot(nonceBefore),
        );
      },
    );

    test(
      'sealed normal nonce and ratchet commit together only after ACK',
      () async {
        final pair = await CryptoTestFixtures.createPairedManagers();
        await _establishDirectSession(pair);
        final sealed = await pair.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          await pair.bob.getIdentityPublicKey(),
          'sealed normal provisional plaintext',
        );
        final sessionBefore = await pair.bobStorage.read(key: _aliceSessionKey);
        final nonceBefore = await pair.bobStorage.read(key: _sealedNonceKey);

        final prepared = await pair.bob.prepareSealedReceive(
          deliveryId: 'delivery-sealed-normal-1',
          sealedEnvelope: sealed,
        );
        expect(prepared.plaintext, 'sealed normal provisional plaintext');
        expect(prepared.receipt.kind, ReceiveEnvelopeKind.sealedMessage);
        expect(
          await pair.bobStorage.read(key: _aliceSessionKey),
          sessionBefore,
        );
        expect(await pair.bobStorage.read(key: _sealedNonceKey), nonceBefore);

        await pair.bob.acknowledgeReceive(prepared.receipt);
        expect(
          await pair.bobStorage.read(key: _aliceSessionKey),
          isNot(sessionBefore),
        );
        expect(
          await pair.bobStorage.read(key: _sealedNonceKey),
          isNot(nonceBefore),
        );
        await expectLater(
          pair.bob.prepareSealedReceive(
            deliveryId: 'delivery-sealed-normal-replay',
            sealedEnvelope: sealed,
          ),
          throwsA(isA<StateError>()),
        );
      },
    );

    test(
      'sealed receive reloads persisted nonces shared by manager instances',
      () async {
        final pair = await CryptoTestFixtures.createPairedManagers();
        await _establishDirectSession(pair);
        final secondBob = SignalProtocolManager(secureStorage: pair.bobStorage);
        await secondBob.initialize();

        final firstSealed = await pair.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          await pair.bob.getIdentityPublicKey(),
          'first shared-storage sealed plaintext',
        );
        final first = await pair.bob.prepareSealedReceive(
          deliveryId: 'delivery-shared-storage-sealed-1',
          sealedEnvelope: firstSealed,
        );
        await pair.bob.acknowledgeReceive(first.receipt);

        final secondSealed = await pair.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          await secondBob.getIdentityPublicKey(),
          'second shared-storage sealed plaintext',
        );
        final second = await secondBob.prepareSealedReceive(
          deliveryId: 'delivery-shared-storage-sealed-2',
          sealedEnvelope: secondSealed,
        );
        await secondBob.acknowledgeReceive(second.receipt);

        final durableNonces =
            jsonDecode(await pair.bobStorage.read(key: _sealedNonceKey) ?? '[]')
                as List<dynamic>;
        expect(durableNonces, contains(firstSealed['nonce']));
        expect(durableNonces, contains(secondSealed['nonce']));
      },
    );
  });

  group('receive journal bounds and canonical envelope identity', () {
    test('map order is stable and ambiguous/unbounded JSON is rejected', () {
      final first = <String, dynamic>{
        'z': <dynamic>[
          3,
          <String, dynamic>{'b': 2, 'a': 1},
        ],
        'a': true,
      };
      final reordered = <String, dynamic>{
        'a': true,
        'z': <dynamic>[
          3,
          <String, dynamic>{'a': 1, 'b': 2},
        ],
      };
      expect(receiveEnvelopeDigest(first), receiveEnvelopeDigest(reordered));
      expect(
        () => receiveEnvelopeDigest(<String, dynamic>{
          'nested': <Object, Object>{1: 'collision'},
        }),
        throwsFormatException,
      );
      expect(
        () =>
            receiveEnvelopeDigest(<String, dynamic>{'number': double.infinity}),
        throwsFormatException,
      );

      Object? deep = 'leaf';
      for (var index = 0; index < 34; index++) {
        deep = <Object?>[deep];
      }
      expect(
        () => receiveEnvelopeDigest(<String, dynamic>{'deep': deep}),
        throwsFormatException,
      );
      expect(
        () => receiveEnvelopeDigest(<String, dynamic>{
          'oversized': 'x' * (1024 * 1024 + 1),
        }),
        throwsFormatException,
      );
    });

    test('completed receipt history and encoded WAL are strictly bounded', () {
      final receipts = List<ReceiveReceipt>.generate(
        ReceiveCommitJournal.maxCompletedReceipts + 1,
        (index) => ReceiveReceipt.create(
          deliveryId: 'bounded-delivery-$index',
          envelopeDigest: '0' * 64,
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          kind: ReceiveEnvelopeKind.directMessage,
        ),
      );
      expect(
        () => ReceiveCommitJournal(
          revision: 1,
          pending: null,
          completed: receipts,
        ),
        throwsFormatException,
      );

      final receipt = receipts.first;
      final oversizedMutation = ReceiveStorageMutation(
        // Must be a key a planner can really produce: a receive mutation is now
        // pinned to the planner-owned namespaces, so `crypto_`-anything is no
        // longer a valid target (P0-3).
        key: 'crypto_e2_session_oversized-id_oversized-device',
        beforeDigest: ReceiveStorageMutation.digestValue(null),
        afterValue: 'x' * ReceiveCommitJournal.maxEncodedBytes,
      );
      final journal = ReceiveCommitJournal(
        revision: 1,
        pending: ReceivePendingCommit(
          receipt: receipt,
          phase: ReceiveCommitPhase.prepared,
          mutations: <ReceiveStorageMutation>[oversizedMutation],
        ),
        completed: const <ReceiveReceipt>[],
      );
      expect(journal.encode, throwsStateError);
      expect(
        () => ReceiveCommitJournal.decode(
          jsonEncode(<String, dynamic>{
            'version': 1,
            'padding': 'x' * ReceiveCommitJournal.maxEncodedBytes,
          }),
        ),
        throwsFormatException,
      );
    });
  });
  group('P1-14 the bounded completed-receipt window really evicts', () {
    test('past the 64-receipt cap the oldest receipt is forgotten and its '
        'redelivery is refused rather than silently replayed', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();

      // The first delivery is the one that must eventually fall out of the
      // window. Keep its exact envelope so it can be redelivered later.
      final firstEnvelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'oldest delivery',
      );
      final first = await pair.bob.prepareReceive(
        deliveryId: 'evict-first',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: firstEnvelope,
      );
      await pair.bob.acknowledgeReceive(first.receipt);

      // Push it out of the bounded window with real acknowledged receives.
      for (var i = 0; i < ReceiveCommitJournal.maxCompletedReceipts; i++) {
        final envelope = await pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'filler $i',
        );
        final prepared = await pair.bob.prepareReceive(
          deliveryId: 'evict-filler-$i',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        );
        await pair.bob.acknowledgeReceive(prepared.receipt);
      }

      final journal = ReceiveCommitJournal.decode(
        pair.bobStorage.store[_receiveJournalKey]!,
      );
      expect(
        journal.completed.length,
        ReceiveCommitJournal.maxCompletedReceipts,
        reason: 'the window must stay bounded',
      );
      expect(
        journal.completedForHash(first.receipt.deliveryIdHash),
        isNull,
        reason:
            'the OLDEST receipt must be the one evicted; keeping the oldest '
            'and dropping the newest would leave every test green',
      );
      expect(
        journal.completed.last.deliveryIdHash,
        ReceiveReceipt.hashDeliveryId(
          'evict-filler-'
          '${ReceiveCommitJournal.maxCompletedReceipts - 1}',
        ),
        reason: 'the newest receipt must be retained',
      );

      // The evicted delivery is now outside the idempotence window. It must
      // NOT be replayed onto the live session: the handshake tombstone and the
      // ratchet replay state are what stop it, not the receipt list.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'evict-first',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: firstEnvelope,
        ),
        throwsA(isA<Object>()),
      );
    });
  });
}
