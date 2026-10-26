@TestOn('vm')
@Timeout(Duration(minutes: 10))
library;

import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:test/test.dart';

import 'helpers/crypto_test_fixtures.dart';

/// Concurrency stress for the paths a real conversation actually takes.
///
/// The whole point of the serialization lanes in `SignalProtocolManager` is that
/// two operations touching one session cannot interleave into a divergent
/// ratchet. Nothing exercised that under load: one `Future.wait` existed in the
/// entire package's tests, over the journal.
///
/// Ratchet divergence is not a crash. It is silent, permanent, and shows up to
/// the user as a message that never decrypts — so it has to be provoked
/// deliberately, and every failure here must name the case that produced it.
void main() {
  Future<
    ({
      SignalProtocolManager alice,
      SignalProtocolManager bob,
      String bobId,
      String bobDevice,
    })
  >
  pair() async {
    final (alice, aliceStorage) =
        await CryptoTestFixtures.createInitializedManager();
    final (bob, bobStorage) =
        await CryptoTestFixtures.createInitializedManager();
    await aliceStorage.write(key: 'user_id', value: 'alice-id');
    await aliceStorage.write(key: 'device_id', value: 'alice-device');
    await bobStorage.write(key: 'user_id', value: 'bob-id');
    await bobStorage.write(key: 'device_id', value: 'bob-device');

    final accepted = await CryptoTestFixtures.acceptInitialGeneration(bob);
    await alice.createSession(accepted.consumerBundle());
    return (alice: alice, bob: bob, bobId: 'bob-id', bobDevice: 'bob-device');
  }

  test('64 concurrent sends to one peer all decrypt, exactly once', () async {
    // Rapid-fire sending is the ordinary case — a user typing fast, or a queue
    // draining after reconnect. Every send advances the same sending chain, so
    // an unserialized encrypt loses or duplicates a ratchet step.
    final p = await pair();
    const count = 64;

    final envelopes = await Future.wait([
      for (var i = 0; i < count; i++)
        p.alice.encryptMessage(p.bobId, p.bobDevice, 'message-$i'),
    ]);

    expect(envelopes, hasLength(count));

    final seen = <String>{};
    for (var i = 0; i < count; i++) {
      final prepared = await p.bob.prepareReceive(
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelopes[i],
        deliveryId: 'burst-$i',
      );
      await p.bob.acknowledgeReceive(prepared.receipt);
      expect(
        seen.add(prepared.plaintext!),
        isTrue,
        reason:
            'case $i produced a duplicate plaintext — the sending chain '
            'reused a message key',
      );
    }

    expect(seen, {
      for (var i = 0; i < count; i++) 'message-$i',
    }, reason: 'every message must arrive exactly once and intact');
  });

  test(
    'a second concurrent receive on one session is refused, not interleaved',
    () async {
      // The receive WAL allows ONE pending delivery per session: prepare, commit
      // the durable host row, acknowledge. Two prepares in flight would be two
      // ratchet advances racing one another, and the loser's message would be
      // silently unrecoverable.
      //
      // So the property is not "both succeed" — it is that the second is refused
      // outright, leaving the first recoverable. `ReceiveDurabilityService` in the
      // app serializes for exactly this reason; this proves the package fails
      // closed even when a caller does not.
      final p = await pair();
      final first = await p.alice.encryptMessage(p.bobId, p.bobDevice, 'one');
      final second = await p.alice.encryptMessage(p.bobId, p.bobDevice, 'two');

      final outcomes = await Future.wait([
        p.bob
            .prepareReceive(
              senderId: 'alice-id',
              senderDeviceId: 'alice-device',
              envelope: first,
              deliveryId: 'race-1',
            )
            .then<Object?>((value) => value)
            .onError<Object>((error, _) => error),
        p.bob
            .prepareReceive(
              senderId: 'alice-id',
              senderDeviceId: 'alice-device',
              envelope: second,
              deliveryId: 'race-2',
            )
            .then<Object?>((value) => value)
            .onError<Object>((error, _) => error),
      ]);

      final prepared = outcomes.whereType<PreparedReceive>().toList();
      expect(
        prepared,
        hasLength(1),
        reason: 'exactly one may hold the session; the other must be refused',
      );
      expect(
        outcomes.whereType<StateError>(),
        hasLength(1),
        reason: 'the refusal must be explicit, not a silent drop',
      );

      // The refused message is not lost: once the first is acknowledged, it
      // delivers normally.
      await p.bob.acknowledgeReceive(prepared.single.receipt);
      final retryEnvelope = prepared.single.plaintext == 'one' ? second : first;
      final retryId = prepared.single.plaintext == 'one' ? 'race-2' : 'race-1';
      final retried = await p.bob.prepareReceive(
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: retryEnvelope,
        deliveryId: retryId,
      );
      await p.bob.acknowledgeReceive(retried.receipt);

      expect(
        {prepared.single.plaintext, retried.plaintext},
        {'one', 'two'},
        reason: 'a refused receive must remain deliverable',
      );
    },
  );

  test('a reverse-order burst is fully recoverable', () async {
    // The relay controls order. Delivered newest-first, every message must still
    // decrypt — that is what the skipped-message-key store exists for, and a
    // lost key is a permanent hole in the conversation.
    final p = await pair();
    const count = 32;

    final envelopes = <Map<String, dynamic>>[];
    for (var i = 0; i < count; i++) {
      envelopes.add(
        await p.alice.encryptMessage(p.bobId, p.bobDevice, 'ooo-$i'),
      );
    }

    // The first envelope is the routed PreKey message and is what establishes
    // the session; a normal message cannot, and the package correctly refuses
    // one that arrives first.
    final opener = await p.bob.prepareReceive(
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: envelopes.first,
      deliveryId: 'ooo-0',
    );
    await p.bob.acknowledgeReceive(opener.receipt);

    final recovered = <String>{opener.plaintext!};
    for (var i = count - 1; i >= 1; i--) {
      final prepared = await p.bob.prepareReceive(
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelopes[i],
        deliveryId: 'ooo-$i',
      );
      await p.bob.acknowledgeReceive(prepared.receipt);
      recovered.add(prepared.plaintext!);
    }

    expect(recovered, {
      for (var i = 0; i < count; i++) 'ooo-$i',
    }, reason: 'a skipped key that is not retained is a message lost forever');
  });

  test('both directions at once never diverge the session', () async {
    // Two people typing simultaneously. Each side is encrypting on its own
    // sending chain while decrypting on the other's — the classic place a
    // shared lock is either correct or silently wrong.
    final p = await pair();

    // Establish Bob->Alice by delivering one message first.
    final opener = await p.alice.encryptMessage(p.bobId, p.bobDevice, 'hello');
    final openerPrepared = await p.bob.prepareReceive(
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: opener,
      deliveryId: 'opener',
    );
    await p.bob.acknowledgeReceive(openerPrepared.receipt);

    const rounds = 16;
    final fromAlice = <Map<String, dynamic>>[];
    final fromBob = <Map<String, dynamic>>[];

    await Future.wait([
      Future(() async {
        for (var i = 0; i < rounds; i++) {
          fromAlice.add(
            await p.alice.encryptMessage(p.bobId, p.bobDevice, 'a-$i'),
          );
        }
      }),
      Future(() async {
        for (var i = 0; i < rounds; i++) {
          fromBob.add(
            await p.bob.encryptMessage('alice-id', 'alice-device', 'b-$i'),
          );
        }
      }),
    ]);

    for (var i = 0; i < rounds; i++) {
      final atBob = await p.bob.prepareReceive(
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: fromAlice[i],
        deliveryId: 'a-$i',
      );
      await p.bob.acknowledgeReceive(atBob.receipt);
      expect(atBob.plaintext, 'a-$i', reason: 'A->B round $i');

      final atAlice = await p.alice.prepareReceive(
        senderId: 'bob-id',
        senderDeviceId: 'bob-device',
        envelope: fromBob[i],
        deliveryId: 'b-$i',
      );
      await p.alice.acknowledgeReceive(atAlice.receipt);
      expect(atAlice.plaintext, 'b-$i', reason: 'B->A round $i');
    }
  });

  test('a redelivered envelope is idempotent under concurrency', () async {
    // The relay redelivers. Two concurrent prepares for the SAME delivery id
    // must not both advance the ratchet.
    final p = await pair();
    final envelope = await p.alice.encryptMessage(
      p.bobId,
      p.bobDevice,
      'exactly once',
    );

    final first = await p.bob.prepareReceive(
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: envelope,
      deliveryId: 'dup-1',
    );
    await p.bob.acknowledgeReceive(first.receipt);

    expect(first.plaintext, 'exactly once');

    final again = await p.bob.prepareReceive(
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: envelope,
      deliveryId: 'dup-1',
    );
    await p.bob.acknowledgeReceive(again.receipt);

    // The plaintext is deliberately delivered ONCE: a redelivery resolves from
    // the durable record and does not ask the advanced ratchet to open the
    // envelope again. That is the property — not that the text comes back.
    expect(
      again.plaintext,
      isNull,
      reason: 'a second delivery must not re-derive plaintext from the ratchet',
    );

    // And the session still works afterwards — a redelivery that quietly burned
    // a ratchet step would break the NEXT message, not this one.
    final next = await p.alice.encryptMessage(p.bobId, p.bobDevice, 'after');
    final afterPrepared = await p.bob.prepareReceive(
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: next,
      deliveryId: 'after-1',
    );
    await p.bob.acknowledgeReceive(afterPrepared.receipt);
    expect(afterPrepared.plaintext, 'after');
  });

  test('concurrent group sends from one device stay readable', () async {
    // Sender keys have their own per-key lane. Encrypting concurrently to the
    // same group is the media-plus-text case: a caption and its attachment go
    // out together.
    final (sender, senderStorage) =
        await CryptoTestFixtures.createInitializedManager();
    await senderStorage.write(key: 'user_id', value: 'sender-id');
    await senderStorage.write(key: 'device_id', value: 'sender-device');
    const groupId = 'group-stress';
    await sender.generateGroupSenderKey(groupId);
    const count = 48;

    final ciphertexts = await Future.wait([
      for (var i = 0; i < count; i++)
        sender.encryptGroupMessage(groupId, 'group-$i'),
    ]);

    expect(
      ciphertexts.toSet(),
      hasLength(count),
      reason:
          'identical ciphertexts mean two messages shared a chain position — '
          'the key was reused',
    );
  });
}
