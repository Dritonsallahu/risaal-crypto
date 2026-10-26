import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/sender_key.dart';

import 'helpers/fake_secure_storage.dart';

/// External report F6 (2026-10-22) and hardening note B: re-processing a
/// Sender Key distribution at the SAME epoch rolled the stored chain back to
/// an older iteration, so group messages already consumed (and correctly
/// rejected as replays) decrypted again. Processing one's own distribution
/// overwrote the local private signing key and broke group sending.
Future<SenderKeyManager> _manager(String userId) async {
  final storage = FakeSecureStorage();
  await storage.write(key: 'user_id', value: userId);
  return SenderKeyManager(cryptoStorage: CryptoStorage(secureStorage: storage));
}

SenderKeyDistribution _copy(
  SenderKeyDistribution d, {
  String? chainKey,
  String? signingKey,
  int? iteration,
}) => SenderKeyDistribution(
  cryptoProtocolEpoch: d.cryptoProtocolEpoch,
  groupId: d.groupId,
  senderId: d.senderId,
  iteration: iteration ?? d.iteration,
  epoch: d.epoch,
  chainKey: chainKey ?? d.chainKey,
  signingKey: signingKey ?? d.signingKey,
);

void main() {
  const groupId = 'group-f6';

  test(
    'reprocessing the original distribution does not re-enable replay',
    () async {
      final alice = await _manager('alice');
      final bob = await _manager('bob');
      final distribution = await alice.generateSenderKey(groupId);
      await bob.processSenderKeyDistribution(groupId, 'alice', distribution);

      final message = await alice.encrypt(groupId, utf8.encode('once'));
      expect(utf8.decode(await bob.decrypt(groupId, 'alice', message)), 'once');
      await expectLater(
        bob.decrypt(groupId, 'alice', message),
        throwsA(anything),
      );

      // A genuine redelivery of the same distribution stays idempotent.
      await bob.processSenderKeyDistribution(groupId, 'alice', distribution);

      await expectLater(
        bob.decrypt(groupId, 'alice', message),
        throwsA(anything),
      );
      // The live chain still works.
      final next = await alice.encrypt(groupId, utf8.encode('next'));
      expect(utf8.decode(await bob.decrypt(groupId, 'alice', next)), 'next');
    },
  );

  test(
    'a same-chain distribution at an older iteration keeps skipped keys',
    () async {
      final alice = await _manager('alice');
      final bob = await _manager('bob');
      final distribution = await alice.generateSenderKey(groupId);
      await bob.processSenderKeyDistribution(groupId, 'alice', distribution);

      final late = await alice.encrypt(groupId, utf8.encode('late'));
      final early = await alice.encrypt(groupId, utf8.encode('early'));
      // Out of order: iteration 1 first, so iteration 0's key is skipped.
      expect(utf8.decode(await bob.decrypt(groupId, 'alice', early)), 'early');

      await bob.processSenderKeyDistribution(groupId, 'alice', distribution);

      expect(utf8.decode(await bob.decrypt(groupId, 'alice', late)), 'late');
      await expectLater(
        bob.decrypt(groupId, 'alice', early),
        throwsA(anything),
      );
    },
  );

  test(
    'same epoch, same signer, same iteration but a different chain is refused',
    () async {
      final alice = await _manager('alice');
      final bob = await _manager('bob');
      final distribution = await alice.generateSenderKey(groupId);
      await bob.processSenderKeyDistribution(groupId, 'alice', distribution);

      final conflicting = _copy(
        distribution,
        chainKey: base64Encode(List<int>.filled(32, 7)),
      );
      await expectLater(
        bob.processSenderKeyDistribution(groupId, 'alice', conflicting),
        throwsStateError,
      );

      final message = await alice.encrypt(groupId, utf8.encode('still'));
      expect(
        utf8.decode(await bob.decrypt(groupId, 'alice', message)),
        'still',
      );
    },
  );

  test('a same-epoch distribution from a new signer still replaces the chain '
      '(old messages cannot verify under the new signing key)', () async {
    final oldAlice = await _manager('alice');
    final bob = await _manager('bob');
    final first = await oldAlice.generateSenderKey(groupId);
    await bob.processSenderKeyDistribution(groupId, 'alice', first);
    final old = await oldAlice.encrypt(groupId, utf8.encode('old'));
    await bob.decrypt(groupId, 'alice', old);

    // Alice reinstalled: fresh state, epoch 0 again, new signing key.
    final newAlice = await _manager('alice');
    final fresh = await newAlice.generateSenderKey(groupId);
    expect(fresh.epoch, first.epoch);
    await bob.processSenderKeyDistribution(groupId, 'alice', fresh);

    final hello = await newAlice.encrypt(groupId, utf8.encode('hello'));
    expect(utf8.decode(await bob.decrypt(groupId, 'alice', hello)), 'hello');
    await expectLater(bob.decrypt(groupId, 'alice', old), throwsA(anything));
  });

  test(
    'processing our own distribution is refused and sending keeps working',
    () async {
      final alice = await _manager('alice');
      final bob = await _manager('bob');
      final distribution = await alice.generateSenderKey(groupId);
      await bob.processSenderKeyDistribution(groupId, 'alice', distribution);

      await expectLater(
        alice.processSenderKeyDistribution(groupId, 'alice', distribution),
        throwsStateError,
      );

      final message = await alice.encrypt(groupId, utf8.encode('mine'));
      expect(utf8.decode(await bob.decrypt(groupId, 'alice', message)), 'mine');
    },
  );
}
