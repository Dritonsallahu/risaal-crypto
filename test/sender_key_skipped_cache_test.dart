import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/sender_key.dart';

import 'helpers/fake_secure_storage.dart';

Future<
  ({
    SenderKeyManager manager,
    CryptoStorage cryptoStorage,
    FakeSecureStorage storage,
  })
>
_manager(String userId, [FakeSecureStorage? existing]) async {
  final storage = existing ?? FakeSecureStorage();
  await storage.write(key: 'user_id', value: userId);
  final cryptoStorage = CryptoStorage(secureStorage: storage);
  return (
    manager: SenderKeyManager(cryptoStorage: cryptoStorage),
    cryptoStorage: cryptoStorage,
    storage: storage,
  );
}

void main() {
  group('bounded SenderKey skipped-message cache', () {
    test(
      'N+2 before N+1 survives restart and each delayed key is single-use',
      () async {
        final alice = await _manager('alice');
        final bob = await _manager('bob');
        const groupId = 'group-restart-order';

        final distribution = await alice.manager.generateSenderKey(groupId);
        await bob.manager.processSenderKeyDistribution(
          groupId,
          'alice',
          distribution,
        );
        final n = await alice.manager.encrypt(groupId, utf8.encode('N'));
        final n1 = await alice.manager.encrypt(groupId, utf8.encode('N+1'));
        final n2 = await alice.manager.encrypt(groupId, utf8.encode('N+2'));

        expect(
          utf8.decode(await bob.manager.decrypt(groupId, 'alice', n2)),
          'N+2',
        );

        final restartedBob = await _manager('bob', bob.storage);
        expect(
          utf8.decode(await restartedBob.manager.decrypt(groupId, 'alice', n1)),
          'N+1',
        );
        expect(
          utf8.decode(await restartedBob.manager.decrypt(groupId, 'alice', n)),
          'N',
        );

        final beforeReplay = Map<String, String>.from(bob.storage.store);
        await expectLater(
          restartedBob.manager.decrypt(groupId, 'alice', n1),
          throwsA(isA<StateError>()),
        );
        expect(bob.storage.store, beforeReplay);
      },
    );

    test('expired delayed key is purged durably and cannot decrypt', () async {
      final alice = await _manager('alice');
      final bob = await _manager('bob');
      const groupId = 'group-expired-order';

      final distribution = await alice.manager.generateSenderKey(groupId);
      await bob.manager.processSenderKeyDistribution(
        groupId,
        'alice',
        distribution,
      );
      await alice.manager.encrypt(groupId, utf8.encode('N'));
      final n1 = await alice.manager.encrypt(groupId, utf8.encode('N+1'));
      final n2 = await alice.manager.encrypt(groupId, utf8.encode('N+2'));
      await bob.manager.decrypt(groupId, 'alice', n2);

      final raw = await bob.cryptoStorage.getSenderKeyRaw(groupId, 'alice');
      expect(raw, isNotNull);
      final ages = Map<String, dynamic>.from(
        raw!['skippedMessageKeyAges'] as Map,
      );
      ages['1'] = DateTime.now()
          .subtract(SenderKeyState.skippedMessageKeyLifetime)
          .subtract(const Duration(seconds: 1))
          .millisecondsSinceEpoch;
      raw['skippedMessageKeyAges'] = ages;
      await bob.cryptoStorage.saveSenderKeyRaw(groupId, 'alice', raw);

      final restartedBob = await _manager('bob', bob.storage);
      await expectLater(
        restartedBob.manager.decrypt(groupId, 'alice', n1),
        throwsA(isA<StateError>()),
      );
      final persisted = await bob.cryptoStorage.getSenderKeyRaw(
        groupId,
        'alice',
      );
      expect(
        (persisted!['skippedMessageKeys'] as Map).containsKey('1'),
        isFalse,
      );
      expect(
        (persisted['skippedMessageKeyAges'] as Map).containsKey('1'),
        isFalse,
      );
    });

    test('persisted skipped ages are bounded to exact retained-key IDs', () {
      final now = DateTime.now().millisecondsSinceEpoch;
      final key = base64Encode(List<int>.filled(32, 7));
      final skippedKeys = <String, String>{};
      final skippedAges = <String, int>{};
      for (var i = 0; i < SenderKeyState.maxSkippedMessageKeys + 5; i++) {
        skippedKeys['$i'] = key;
        skippedAges['$i'] = now;
      }

      final state = SenderKeyState.fromJson(<String, dynamic>{
        'storageVersion': SenderKeyState.currentStorageVersion,
        'cryptoProtocolEpoch': 2,
        'groupId': 'group-bounded-state',
        'senderId': 'alice',
        'iteration': SenderKeyState.maxSkippedMessageKeys + 5,
        'epoch': 0,
        'chainKey': key,
        'signingPublicKey': key,
        'skippedMessageKeys': skippedKeys,
        'skippedMessageKeyAges': skippedAges,
      });

      expect(
        state.skippedMessageKeys.length,
        SenderKeyState.maxSkippedMessageKeys,
      );
      expect(
        state.skippedMessageKeyAges.keys.toSet(),
        state.skippedMessageKeys.keys.toSet(),
      );
    });

    test('forged high iteration is rejected before state mutation', () async {
      final alice = await _manager('alice');
      final bob = await _manager('bob');
      const groupId = 'group-forged-skip';

      final distribution = await alice.manager.generateSenderKey(groupId);
      await bob.manager.processSenderKeyDistribution(
        groupId,
        'alice',
        distribution,
      );
      final authentic = await alice.manager.encrypt(
        groupId,
        utf8.encode('authentic'),
      );
      final forged = SenderKeyMessage(
        iteration: 50001,
        ciphertext: authentic.ciphertext,
        iv: authentic.iv,
        signature: authentic.signature,
      );
      final before = Map<String, String>.from(bob.storage.store);

      await expectLater(
        bob.manager.decrypt(groupId, 'alice', forged),
        throwsA(
          isA<SenderKeyDependencyError>().having(
            (error) => error.code,
            'code',
            SenderKeyDependencyCode.keyStateMismatch,
          ),
        ),
      );
      expect(bob.storage.store, before);
    });

    test('missing distribution reports a typed causal dependency', () async {
      final bob = await _manager('bob');
      const groupId = 'group-missing-distribution';
      final message = SenderKeyMessage(
        iteration: 0,
        ciphertext: base64Encode(<int>[0x03, ...List<int>.filled(32, 0)]),
        iv: '',
        signature: base64Encode(List<int>.filled(64, 0)),
      );

      await expectLater(
        bob.manager.decrypt(groupId, 'alice', message),
        throwsA(
          isA<SenderKeyDependencyError>().having(
            (error) => error.code,
            'code',
            SenderKeyDependencyCode.missingKey,
          ),
        ),
      );
    });

    test(
      'concurrent out-of-order decrypts serialize without state loss',
      () async {
        final alice = await _manager('alice');
        final bob = await _manager('bob');
        const groupId = 'group-concurrent-order';

        final distribution = await alice.manager.generateSenderKey(groupId);
        await bob.manager.processSenderKeyDistribution(
          groupId,
          'alice',
          distribution,
        );
        final n = await alice.manager.encrypt(groupId, utf8.encode('N'));
        final n1 = await alice.manager.encrypt(groupId, utf8.encode('N+1'));
        final n2 = await alice.manager.encrypt(groupId, utf8.encode('N+2'));

        final decrypted = await Future.wait([
          bob.manager.decrypt(groupId, 'alice', n2),
          bob.manager.decrypt(groupId, 'alice', n1),
        ]);
        expect(decrypted.map(utf8.decode), ['N+2', 'N+1']);

        final restartedBob = await _manager('bob', bob.storage);
        expect(
          utf8.decode(await restartedBob.manager.decrypt(groupId, 'alice', n)),
          'N',
        );
        await expectLater(
          restartedBob.manager.decrypt(groupId, 'alice', n2),
          throwsA(isA<StateError>()),
        );
      },
    );
  });
}
