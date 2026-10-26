import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/sender_key.dart';

import 'helpers/fake_secure_storage.dart';

class _FailRotationDeleteStorage extends FakeSecureStorage {
  bool failNextRotationDelete = false;

  @override
  Future<void> delete({required String key}) async {
    if (failNextRotationDelete && key.contains('sender_key_rotation_')) {
      failNextRotationDelete = false;
      throw StateError('injected rotation delete failure');
    }
    await super.delete(key: key);
  }
}

void main() {
  test(
    'a prepared rotation is durable but the old epoch stays active until commit',
    () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      await aliceStorage.write(key: 'user_id', value: 'alice');
      await bobStorage.write(key: 'user_id', value: 'bob');
      final alice = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: aliceStorage),
      );
      final bob = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: bobStorage),
      );

      final initial = await alice.generateSenderKey('group-1');
      await bob.processSenderKeyDistribution('group-1', 'alice', initial);

      final prepared = await alice.prepareSenderKeyRotation(
        'group-1',
        rotationId: 'rotation-1',
      );
      expect(prepared.distribution.epoch, initial.epoch + 1);
      expect(
        (await alice.currentSenderKeyDistribution('group-1'))!.epoch,
        initial.epoch,
      );

      await expectLater(
        alice.encrypt('group-1', utf8.encode('must pause during rotation')),
        throwsStateError,
      );

      final restarted = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: aliceStorage),
      );
      final replay = await restarted.prepareSenderKeyRotation(
        'group-1',
        rotationId: 'rotation-1',
      );
      expect(replay.toJson(), prepared.toJson());
      await expectLater(
        restarted.prepareSenderKeyRotation(
          'group-1',
          rotationId: 'rotation-drift',
        ),
        throwsStateError,
      );

      await restarted.commitSenderKeyRotation(
        'group-1',
        rotationId: 'rotation-1',
      );
      expect(
        (await restarted.currentSenderKeyDistribution('group-1'))!.epoch,
        prepared.distribution.epoch,
      );
    },
  );

  test(
    'aborting a prepared rotation preserves the previous usable epoch',
    () async {
      final storage = FakeSecureStorage();
      await storage.write(key: 'user_id', value: 'alice');
      final manager = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: storage),
      );
      final initial = await manager.generateSenderKey('group-1');

      await manager.prepareSenderKeyRotation(
        'group-1',
        rotationId: 'rotation-1',
      );
      await manager.abortSenderKeyRotation('group-1', rotationId: 'rotation-1');

      expect(await manager.pendingSenderKeyRotation('group-1'), isNull);
      expect(
        (await manager.currentSenderKeyDistribution('group-1'))!.epoch,
        initial.epoch,
      );
      final oldEpochMessage = await manager.encrypt(
        'group-1',
        utf8.encode('old epoch is usable after abort'),
      );
      expect(oldEpochMessage.ciphertext, isNotEmpty);
    },
  );

  test(
    'restart completes commit after active-save pending-delete crash',
    () async {
      final storage = _FailRotationDeleteStorage();
      await storage.write(key: 'user_id', value: 'alice');
      final manager = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: storage),
      );
      await manager.generateSenderKey('group-1');
      final proposal = await manager.prepareSenderKeyRotation(
        'group-1',
        rotationId: 'rotation-1',
      );

      storage.failNextRotationDelete = true;
      await expectLater(
        manager.commitSenderKeyRotation('group-1', rotationId: 'rotation-1'),
        throwsStateError,
      );
      expect(
        (await manager.currentSenderKeyDistribution('group-1'))!.epoch,
        proposal.distribution.epoch,
      );
      expect(await manager.pendingSenderKeyRotation('group-1'), isNotNull);

      final restarted = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: storage),
      );
      await restarted.commitSenderKeyRotation(
        'group-1',
        rotationId: 'rotation-1',
      );

      expect(await restarted.pendingSenderKeyRotation('group-1'), isNull);
      expect(
        (await restarted.currentSenderKeyDistribution('group-1'))!.epoch,
        proposal.distribution.epoch,
      );
      final message = await restarted.encrypt(
        'group-1',
        utf8.encode('after recovery'),
      );
      expect(message.ciphertext, isNotEmpty);
      expect(
        (await restarted.currentSenderKeyDistribution('group-1'))!.epoch,
        proposal.distribution.epoch,
      );
    },
  );
}
