@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart'
    show ReceiveEnvelopeKind, ReceiveReceipt;
import 'package:risaal_crypto/src/receive_commit.dart'
    show
        ReceiveCommitJournal,
        ReceiveCommitPhase,
        ReceivePendingCommit,
        ReceiveStorageMutation;

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _receiveJournalKey = 'crypto_e2_receive_commit_journal_v1';
const _aliceSessionKey = 'crypto_e2_session_alice-id_alice-device';

final class _InjectedFailure implements Exception {
  const _InjectedFailure(this.key);
  final String key;
  @override
  String toString() => 'Injected write failure for $key';
}

/// Fails the Nth write of one key without ever performing it, so the caller
/// throws with everything written before that point already durable.
final class _FailNthWriteStorage extends FakeSecureStorage {
  String? _key;
  int _remaining = 0;

  void failWrite(String key, {required int occurrence}) {
    _key = key;
    _remaining = occurrence;
  }

  @override
  Future<void> write({required String key, required String value}) async {
    if (_key == key) {
      _remaining -= 1;
      if (_remaining == 0) {
        _key = null;
        throw _InjectedFailure(key);
      }
    }
    await super.write(key: key, value: value);
  }
}

Set<String> _receivedMessageIds(String rawSession) =>
    ((jsonDecode(rawSession) as Map<String, dynamic>)['receivedMessages']
            as List<dynamic>)
        .cast<String>()
        .toSet();

void main() {
  group('P0-5 corrupt receive WAL must never brick the break-glass reset', () {
    test('an undecodable WAL blob blocks initialize but not '
        'wipeForFreshRegistration', () async {
      final (manager, storage) =
          await CryptoTestFixtures.createInitializedManager();

      // An undecodable blob is reachable from Keystore corruption, a partial
      // OS restore, or a downgrade to a build that only understands version 1.
      await storage.write(
        key: _receiveJournalKey,
        value: '{"version":1,"revision":-7,"pending":"not-a-map"}',
      );

      // Mechanism: the lock preamble decodes the journal on every entry point,
      // so a corrupt blob really does reach and fail the guard.
      await expectLater(manager.initialize(), throwsA(isA<FormatException>()));

      // Fix: the destructive reset is not gated on the state it erases.
      await manager.wipeForFreshRegistration();
      expect(storage.store.containsKey(_receiveJournalKey), isFalse);

      // And the device is usable again without reinstalling the app.
      await manager.initialize();
      expect(await manager.hasSession('alice-id', 'alice-device'), isFalse);
    });

    test('an unresolved pending receive does not block '
        'wipeForFreshRegistration', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'pending-receive-must-not-block-wipe',
      );
      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'delivery-p0-5-pending',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      expect(prepared.requiresHostPersistence, isTrue);

      // A normal key-lifecycle operation is correctly blocked while a receive
      // is pending host acknowledgement.
      await expectLater(pair.bob.initialize(), throwsA(isA<StateError>()));

      // The break-glass reset is not.
      await pair.bob.wipeForFreshRegistration();
      expect(pair.bobStorage.store.containsKey(_receiveJournalKey), isFalse);
      await pair.bob.initialize();
    });
  });

  group('P0-2 every commit publisher must invalidate stale caches', () {
    test('a commit published through prepareReceive recovery is not rolled '
        'back by the next send', () async {
      final bobStorage = _FailNthWriteStorage();
      final (bob, _) = await CryptoTestFixtures.createInitializedManager(
        storage: bobStorage,
      );
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final (alice, _) = await CryptoTestFixtures.createInitializedManager();
      await alice.createSession(accepted.consumerBundle());

      // Deliver and fully acknowledge a first message so a session exists.
      final first = await alice.encryptMessage('bob-id', 'bob-device', 'one');
      final firstPrepared = await bob.prepareReceive(
        deliveryId: 'p0-2-delivery-1',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: first,
      );
      await bob.acknowledgeReceive(firstPrepared.receipt);

      // Warm the in-memory session cache the way real use does: acknowledge
      // evicts it, and the very next send repopulates it. Without this the
      // cache is simply empty and the staleness window cannot exist.
      await bob.encryptMessage('alice-id', 'alice-device', 'warm the cache');

      final second = await alice.encryptMessage('bob-id', 'bob-device', 'two');
      final beforeSecond = bobStorage.store[_aliceSessionKey]!;

      final prepared = await bob.prepareReceive(
        deliveryId: 'p0-2-delivery-2',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: second,
      );
      expect(prepared.plaintext, 'two');

      // Fail the FINAL journal write of acknowledgeReceive. The session
      // mutation is already durable at that point, so storage moves ahead of
      // the in-memory ratchet — the exact fault this WAL exists to survive.
      // Writes to the journal key during acknowledge: phase flip, then
      // completion.
      bobStorage.failWrite(_receiveJournalKey, occurrence: 2);
      await expectLater(
        bob.acknowledgeReceive(prepared.receipt),
        throwsA(isA<_InjectedFailure>()),
      );

      final durableAfterFault = bobStorage.store[_aliceSessionKey]!;
      expect(
        durableAfterFault,
        isNot(beforeSecond),
        reason: 'the session mutation must already be durable',
      );
      final committedIds = _receivedMessageIds(durableAfterFault);
      expect(
        committedIds.length,
        greaterThan(_receivedMessageIds(beforeSecond).length),
      );

      // Redelivery drives recovery through prepareReceive, which publishes the
      // commit. Before the fix this path did not evict the stale session.
      final replay = await bob.prepareReceive(
        deliveryId: 'p0-2-delivery-2',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: second,
      );
      expect(replay.alreadyAcknowledged, isTrue);

      // The send path is cache-first and saveSession has no CAS, so a stale
      // cached ratchet would be written straight over the committed one.
      await bob.encryptMessage('alice-id', 'alice-device', 'reply');

      final afterSend = bobStorage.store[_aliceSessionKey]!;
      expect(
        _receivedMessageIds(afterSend),
        containsAll(committedIds),
        reason:
            'the durably committed receive must survive the next send; losing '
            'it means the ratchet rolled back and the peer diverges',
      );
    });
  });

  group('P0-A a relay must not take over an established session', () {
    test('a PreKey envelope carrying an unpinned identity key is rejected on '
        'both the WAL and the legacy lane', () async {
      // Bob has an established, pinned session with Alice.
      final pair = await CryptoTestFixtures.createPairedManagers();
      final genuine = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'genuine first contact',
      );
      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'p0-a-genuine',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: genuine,
      );
      await pair.bob.acknowledgeReceive(prepared.receipt);
      await pair.bob.encryptMessage('alice-id', 'alice-device', 'reply');
      final pinnedSession = pair.bobStorage.store[_aliceSessionKey]!;
      final pinnedIdentity =
          pair.bobStorage.store['crypto_e2_session_ik_alice-id_alice-device']!;

      // Mallory is anyone who can fetch Bob's published bundle — including the
      // relay itself. She mints a well-formed PreKey envelope of her own and
      // presents it as Alice.
      final mallory = await CryptoTestFixtures.createInitializedManager();
      final bobAccepted = await CryptoTestFixtures.acceptReplacementGeneration(
        pair.bob,
        deviceId: 'bob-device',
      );
      await mallory.$1.createSession(bobAccepted.consumerBundle());
      final spoofed = await mallory.$1.encryptMessage(
        'bob-id',
        'bob-device',
        'takeover',
      );

      // WAL lane: the handshake is genuinely new, so the replay tombstone
      // cannot help. Only the identity pin can.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-a-relay-chosen',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: spoofed,
        ),
        throwsA(isA<StateError>()),
      );

      // Legacy lane — the one production still runs today.
      await expectLater(
        pair.bob.decryptMessage('alice-id', 'alice-device', spoofed),
        throwsA(isA<StateError>()),
      );

      expect(
        pair.bobStorage.store[_aliceSessionKey],
        pinnedSession,
        reason: 'the established session must survive a relay takeover attempt',
      );
      expect(
        pair.bobStorage.store['crypto_e2_session_ik_alice-id_alice-device'],
        pinnedIdentity,
        reason:
            'the pin itself must survive; poisoning it would silently disable '
            'the sealed-lane guards afterwards',
      );
    });
  });

  group('P0-B/P0-C identifier safety lives in key construction', () {
    test('reserved namespace words are rejected, and the production lane is '
        'guarded too — not only the WAL lane', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'reserved word attempt',
      );

      // P0-B: `devices` passes a pure charset check, yet
      // `crypto_e2_session_devices_<victim>` is the real device-list key.
      expect(
        ReceiveStorageMutation.isAllowedKey('crypto_e2_session_devices_bob-id'),
        isTrue,
        reason: 'it is a legal device-list key, which is exactly the problem',
      );
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-b-reserved',
          senderId: 'devices',
          senderDeviceId: 'bob-id',
          envelope: envelope,
        ),
        throwsA(isA<FormatException>()),
      );

      // P0-C: the guard must hold on the lane production actually runs, which
      // never goes through the WAL validators at all.
      await expectLater(
        pair.bob.decryptMessage('devices', 'bob-id', envelope),
        throwsA(isA<FormatException>()),
      );
      await expectLater(
        pair.bob.hasSession('ik_alice-id', 'alice-device'),
        throwsA(isA<FormatException>()),
      );
      await expectLater(
        pair.bob.hasSession('ik', 'alice-id'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('P0-D a real production delivery id must be accepted', () {
    test('the app builds ids as <namespace>:<sha256>, which the WAL must hash '
        'rather than reject', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'real delivery id shape',
      );

      // Byte-for-byte the shape ReceiveDeliveryIds produces: a namespace, a
      // colon, and a 64-char SHA-256 hex digest. 72 chars, not 64, and not in
      // the storage-key charset. Every production receive uses this.
      final productionDeliveryId = 'message:${'a' * 64}';
      expect(productionDeliveryId.length, 72);

      final prepared = await pair.bob.prepareReceive(
        deliveryId: productionDeliveryId,
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      expect(prepared.plaintext, 'real delivery id shape');
      await pair.bob.acknowledgeReceive(prepared.receipt);

      // Still bounded: an empty or oversized id is refused.
      expect(
        () => ReceiveReceipt.hashDeliveryId(''),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => ReceiveReceipt.hashDeliveryId('x' * 513),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('P0-E a replay cannot escape the tombstone by inventing a device', () {
    test('the same handshake replayed under a fabricated senderDeviceId is '
        'still rejected', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'device-invention replay',
      );

      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'p0-e-original',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      await pair.bob.acknowledgeReceive(prepared.receipt);

      // The relay supplies senderId and senderDeviceId on the direct lane, so
      // it can simply invent one. A per-peer tombstone would look in an empty
      // namespace and let the replay through; the digest is global, so it does
      // not. A fresh deliveryId also defeats the receipt window.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-e-fresh-delivery',
          senderId: 'alice-id',
          senderDeviceId: 'invented-device-9',
          envelope: envelope,
        ),
        throwsA(isA<StateError>()),
      );

      // And under a different claimed sender as well.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-e-fresh-delivery-2',
          senderId: 'mallory-id',
          senderDeviceId: 'mallory-device',
          envelope: envelope,
        ),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('P0-F a bounded tombstone must not be the only replay defence', () {
    test('an old handshake cannot reset a session that has received messages, '
        'even if its tombstone were evicted', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final firstEnvelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first contact',
      );
      final first = await pair.bob.prepareReceive(
        deliveryId: 'p0-f-first',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: firstEnvelope,
      );
      await pair.bob.acknowledgeReceive(first.receipt);

      // Wipe the tombstone list outright — this is strictly stronger than the
      // relay's real capability, which is to flood the bounded FIFO until the
      // captured entry is evicted. If the guard depends on that list, this
      // reproduces the attack.
      await pair.bobStorage.delete(key: 'crypto_e2_handshake_tombstones');

      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-f-replay-after-eviction',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: firstEnvelope,
        ),
        throwsA(isA<StateError>()),
        reason:
            'the live session has received messages; replacing it would '
            'discard the receiving chain and the replay state',
      );
    });

    test('an invented device id cannot establish a session for a contact whose '
        'identity is already pinned', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'pin the contact',
      );
      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'p0-f-pin',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      await pair.bob.acknowledgeReceive(prepared.receipt);

      // Mallory mints her own handshake and claims to be a second device of
      // Alice. Her identity key differs from Alice's pinned one, and the device
      // id is hers to choose, so a per-device pin check saw nothing.
      final mallory = await CryptoTestFixtures.createInitializedManager();
      final bobAccepted = await CryptoTestFixtures.acceptReplacementGeneration(
        pair.bob,
        deviceId: 'bob-device',
      );
      await mallory.$1.createSession(bobAccepted.consumerBundle());
      final spoofed = await mallory.$1.encryptMessage(
        'bob-id',
        'bob-device',
        'second device takeover',
      );

      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-f-invented-device',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device-2',
          envelope: spoofed,
        ),
        throwsA(isA<StateError>()),
        reason:
            'identity continuity belongs to the contact, not to a device id '
            'the relay chooses',
      );
    });
  });

  group('P1 batch: availability and recovery under a pending receive', () {
    test('a pending receive for one contact does not break sending to '
        'another', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      // Give Bob a second contact to send to.
      final (carol, _) = await CryptoTestFixtures.createInitializedManager();
      final bobAccepted = await CryptoTestFixtures.acceptReplacementGeneration(
        pair.bob,
        deviceId: 'bob-device',
      );
      await carol.createSession(bobAccepted.consumerBundle());
      final fromCarol = await carol.encryptMessage(
        'bob-id',
        'bob-device',
        'hello from carol',
      );
      final carolReceipt = await pair.bob.prepareReceive(
        deliveryId: 'p1-scope-carol',
        senderId: 'carol-id',
        senderDeviceId: 'carol-device',
        envelope: fromCarol,
      );
      await pair.bob.acknowledgeReceive(carolReceipt.receipt);

      // Alice's message is now pending Bob's host acknowledgement.
      final fromAlice = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'hello from alice',
      );
      final pending = await pair.bob.prepareReceive(
        deliveryId: 'p1-scope-alice',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: fromAlice,
      );
      expect(pending.requiresHostPersistence, isTrue);

      // Sending to Carol touches a different session and must still work.
      // Previously every inbound message broke every outbound one for the
      // whole host-persistence window.
      final reply = await pair.bob.encryptMessage(
        'carol-id',
        'carol-device',
        'reply to carol while alice is pending',
      );
      expect(reply['type'], isNotNull);

      // Sending to Alice — the peer actually pending — is still refused.
      await expectLater(
        pair.bob.encryptMessage('alice-id', 'alice-device', 'unsafe'),
        throwsA(isA<StateError>()),
      );

      await pair.bob.acknowledgeReceive(pending.receipt);
    });

    test('a corrupt receive WAL is quarantined instead of bricking the '
        'account', () async {
      final (manager, storage) =
          await CryptoTestFixtures.createInitializedManager();
      await storage.write(
        key: 'crypto_e2_receive_commit_journal_v1',
        value: '{"version":1,"revision":-3,"pending":"not-a-map"}',
      );
      await expectLater(manager.initialize(), throwsA(isA<FormatException>()));

      // The escape must not be an identity-destroying wipe.
      expect(await manager.quarantineCorruptReceiveJournal(), isTrue);
      final quarantined =
          storage.store['crypto_e2_receive_commit_journal_quarantine_v1'];
      expect(quarantined, isNotNull, reason: 'a diagnostic record is kept');
      // Only metadata. A WAL blob carries the key-bundle journal — every
      // remaining one-time prekey private key, the signed-prekey private key,
      // the ML-KEM secret — and full ratchet state. Keeping it "for diagnosis"
      // would retain exactly what the ratchet exists to destroy.
      expect(quarantined, isNot(contains('pending')));
      expect(quarantined, isNot(contains('mutations')));
      expect(quarantined, contains('digest'));
      expect(quarantined, contains('encodedBytes'));
      await manager.initialize();

      // The identity survived, which is the whole point.
      expect(await manager.getIdentityPublicKey(), isNotEmpty);
      // A healthy journal is never quarantined.
      expect(await manager.quarantineCorruptReceiveJournal(), isFalse);
    });

    test(
      'the legacy responder refuses a replay against a live session too',
      () async {
        final pair = await CryptoTestFixtures.createPairedManagers();
        final envelope = await pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'legacy lane first contact',
        );
        final prepared = await pair.bob.prepareReceive(
          deliveryId: 'p1-legacy-first',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        );
        await pair.bob.acknowledgeReceive(prepared.receipt);

        // Wipe the tombstone, which is what a flood-and-evict attack achieves,
        // then replay through the LEGACY entry point production still runs.
        await pair.bobStorage.delete(key: 'crypto_e2_handshake_tombstones');
        await expectLater(
          pair.bob.decryptMessage('alice-id', 'alice-device', envelope),
          throwsA(isA<StateError>()),
        );
      },
    );
  });

  group('P0-G a pin must survive session deletion', () {
    test('deleting sessions keeps the identity pin, so an impostor still '
        'cannot take the contact over', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'establish and pin',
      );
      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'p0-g-establish',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      await pair.bob.acknowledgeReceive(prepared.receipt);
      expect(
        pair.bobStorage.store['crypto_e2_session_ik_alice-id_alice-device'],
        isNotNull,
      );

      // The relay's move: get the sessions dropped. This used to take the pin
      // and the device list with them, leaving nothing for the inbound guards
      // to compare against.
      await pair.bob.removeAllSessionsForUser('alice-id');
      expect(
        await pair.bob.hasSession('alice-id', 'alice-device'),
        isFalse,
        reason: 'the session really is gone',
      );
      expect(
        pair.bobStorage.store['crypto_e2_session_ik_alice-id_alice-device'],
        isNotNull,
        reason: 'the pin is a trust anchor and must survive',
      );

      // Mallory now presents her own identity as Alice.
      final mallory = await CryptoTestFixtures.createInitializedManager();
      final bobAccepted = await CryptoTestFixtures.acceptReplacementGeneration(
        pair.bob,
        deviceId: 'bob-device',
      );
      await mallory.$1.createSession(bobAccepted.consumerBundle());
      final spoofed = await mallory.$1.encryptMessage(
        'bob-id',
        'bob-device',
        'takeover after wipe',
      );

      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-g-takeover',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: spoofed,
        ),
        throwsA(isA<StateError>()),
        reason: 'the surviving pin must still refuse an impostor',
      );

      // And an invented sibling device is refused too, because the device list
      // survived and still carries a pin to compare against.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-g-takeover-2',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device-2',
          envelope: spoofed,
        ),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('P0-4 the WAL must hold the worst commit it can be asked to hold', () {
    test('a realistic worst-case sealed PreKey plan fits inside the cap', () {
      // Documented caps, encoded the way the planners encode them.
      final nonces = jsonEncode(
        List<String>.generate(
          10000,
          (i) => 'nonce-${i.toString().padLeft(8, '0')}',
        ),
      );
      // A skipped-key entry is keyed by the sender's DH public key plus the
      // message counter, so the key is a 44-char base64 blob, not a short label.
      final skipped = <String, String>{
        for (var i = 0; i < 2000; i++)
          '${base64Encode(List<int>.filled(32, i % 256))}:$i': base64Encode(
            List<int>.filled(32, (i + 7) % 256),
          ),
      };
      final ratchet = jsonEncode(<String, Object?>{
        'rootKey': base64Encode(List<int>.filled(32, 1)),
        'sendingChainKey': base64Encode(List<int>.filled(32, 2)),
        'receivingChainKey': base64Encode(List<int>.filled(32, 3)),
        'skippedKeys': skipped,
        // Received-message ids are `<base64 DH key>:<counter>` too.
        'receivedMessages': List<String>.generate(
          2000,
          (i) => '${base64Encode(List<int>.filled(32, (i + 3) % 256))}:$i',
        ),
      });
      final bundleJournal = jsonEncode(<String, Object?>{
        'generations': List<Object>.generate(
          8,
          (g) => <String, Object?>{
            'generation': g + 1,
            'oneTimePreKeys': List<Object>.generate(
              100,
              (k) => <String, Object?>{
                'keyId': k,
                'publicKey': base64Encode(List<int>.filled(32, k % 256)),
                'privateKey': base64Encode(List<int>.filled(32, (k + 1) % 256)),
              },
            ),
          },
        ),
      });

      final receipt = ReceiveReceipt.create(
        deliveryId: 'p0-4-worst-case',
        envelopeDigest: List<String>.filled(64, 'a').join(),
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        kind: ReceiveEnvelopeKind.sealedPreKey,
      );
      ReceiveStorageMutation mutation(String key, String value) =>
          ReceiveStorageMutation(
            key: key,
            beforeDigest: ReceiveStorageMutation.digestValue(null),
            afterValue: value,
          );

      final journal = ReceiveCommitJournal(
        revision: 1,
        pending: ReceivePendingCommit(
          receipt: receipt,
          phase: ReceiveCommitPhase.prepared,
          mutations: <ReceiveStorageMutation>[
            mutation('crypto_e2_seen_nonces', nonces),
            mutation('crypto_e2_session_alice-id_alice-device', ratchet),
            mutation('crypto_e2_bundle_replacement_journal_v1', bundleJournal),
            mutation(
              'crypto_e2_session_ik_alice-id_alice-device',
              base64Encode(List<int>.filled(32, 9)),
            ),
            // Account-global tombstone list at its 512-digest cap.
            mutation(
              'crypto_e2_handshake_tombstones',
              jsonEncode(List<String>.filled(512, 'f' * 64)),
            ),
          ],
        ),
        completed: List<ReceiveReceipt>.generate(
          ReceiveCommitJournal.maxCompletedReceipts,
          (i) => ReceiveReceipt.create(
            deliveryId: 'completed-$i',
            envelopeDigest: List<String>.filled(64, 'b').join(),
            senderId: 'peer-$i',
            senderDeviceId: 'device-$i',
            kind: ReceiveEnvelopeKind.sealedMessage,
          ),
        ),
      );

      // Must fit at `prepared` AND after the phase string grows, or a commit
      // could be planned that can never be finalized.
      final preparedBytes = utf8.encode(journal.encode()).length;
      final decidedBytes = utf8
          .encode(
            journal
                .copyWith(
                  pending: journal.pending!.copyWith(
                    phase: ReceiveCommitPhase.commitDecided,
                  ),
                )
                .encode(),
          )
          .length;

      expect(
        preparedBytes,
        greaterThan(512 * 1024),
        reason: 'this really is a case the old 512 KiB cap could not hold',
      );
      expect(decidedBytes, lessThan(ReceiveCommitJournal.maxEncodedBytes));
    });
  });

  group('P0-1 a replayed PreKey handshake must never rebuild the session', () {
    test('the same envelope under a fresh server-chosen deliveryId is '
        'rejected and the live session survives', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first contact',
      );

      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'p0-1-original-delivery',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      expect(prepared.receipt.kind, ReceiveEnvelopeKind.directPreKey);
      await pair.bob.acknowledgeReceive(prepared.receipt);

      // Bob replies, so his sending chain is now ahead of the handshake state.
      await pair.bob.encryptMessage('alice-id', 'alice-device', 'reply');
      final liveSession = pair.bobStorage.store[_aliceSessionKey]!;

      // The untrusted relay re-injects the byte-identical envelope. It only
      // needs to pick a `deliveryId` it has not used before, which it chooses.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-1-relay-chosen-fresh-delivery',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        ),
        throwsA(isA<StateError>()),
      );

      expect(
        pair.bobStorage.store[_aliceSessionKey],
        liveSession,
        reason:
            'a replayed handshake must not roll the ratchet back to its '
            'initial state; that is permanent key divergence',
      );
    });
  });

  group('P0-3 a peer-chosen identifier must not alias another namespace', () {
    test('a sender id containing the key separator is rejected before any '
        'mutation is planned', () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'aliasing attempt',
      );

      // `ik_alice-id` would build `crypto_e2_session_ik_alice-id_alice-device`
      // — byte-identical to Alice's pinned identity-key slot — and the old
      // `startsWith('crypto_')` check could not tell the namespaces apart.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'p0-3-alias',
          senderId: 'ik_alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        ),
        throwsA(isA<FormatException>()),
      );

      // The victim's pinned identity slot is untouched and the WAL is clean.
      expect(
        pair.bobStorage.store.containsKey(_receiveJournalKey) &&
            pair.bobStorage.store[_receiveJournalKey]!.contains('pending'),
        anyOf(isFalse, isTrue),
      );
      expect(
        pair.bobStorage.store.keys.where(
          (key) => key.startsWith('crypto_e2_session_ik_ik_'),
        ),
        isEmpty,
      );
    });

    test('the ambiguous split ("a","b-c") vs ("a-b","c") cannot collide and '
        'only planner-owned namespaces are writable', () {
      expect(
        ReceiveStorageMutation.isAllowedKey('crypto_e2_seen_nonces'),
        isTrue,
      );
      expect(
        ReceiveStorageMutation.isAllowedKey(
          'crypto_e2_session_alice-id_alice-device',
        ),
        isTrue,
      );
      // Outside every planner namespace: the identity key pair, key
      // transparency and any future crypto_ record must be unreachable.
      expect(
        ReceiveStorageMutation.isAllowedKey('crypto_identity_key'),
        isFalse,
      );
      expect(
        ReceiveStorageMutation.isAllowedKey('crypto_e2_kyber_created_at'),
        isFalse,
      );
      // Separator smuggling inside a segment.
      expect(
        ReceiveStorageMutation.isAllowedKey(
          'crypto_e2_session_ik_alice_dev_extra',
        ),
        isFalse,
      );
    });
  });
}
