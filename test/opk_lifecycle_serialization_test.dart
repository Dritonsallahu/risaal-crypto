@Retry(0)
library;

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

class _BlockingJournalReadStorage extends FakeSecureStorage {
  Completer<void>? _readEntered;
  Completer<void>? _releaseRead;
  var journalReadsAfterArm = 0;

  Future<void> get readEntered => _readEntered!.future;

  void armNextJournalRead() {
    _readEntered = Completer<void>();
    _releaseRead = Completer<void>();
    journalReadsAfterArm = 0;
  }

  void release() {
    _releaseRead!.complete();
  }

  @override
  Future<String?> read({required String key}) async {
    if (_readEntered != null &&
        key == 'crypto_e2_bundle_replacement_journal_v1') {
      journalReadsAfterArm++;
      if (journalReadsAfterArm == 1) {
        _readEntered!.complete();
        await _releaseRead!.future;
      }
    }
    return super.read(key: key);
  }
}

void main() {
  test(
    'authenticated OPK consume serializes against concurrent full replacement',
    () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = _BlockingJournalReadStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();

      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final bobBundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );
      await alice.createSession(bobBundle);
      final envelope = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'serialized consume',
      );
      final consumedId = envelope['usedOneTimePreKeyId'] as int;

      bobStorage.armNextJournalRead();
      final decryptFuture = bob.decryptMessage(
        'alice-id',
        'alice-device',
        envelope,
      );
      await bobStorage.readEntered.timeout(const Duration(seconds: 2));

      final concurrentReplacement = bob.prepareKeyBundleReplacement(
        oneTimePreKeyCount: 1,
      );
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(
        bobStorage.journalReadsAfterArm,
        1,
        reason: 'replacement must wait outside the shared lifecycle lane',
      );

      bobStorage.release();
      expect(await decryptFuture, 'serialized consume');
      final replacement = await concurrentReplacement;
      expect(replacement.opkGeneration, acceptedBob.route.opkGeneration + 1);
      expect(replacement.oneTimePreKeyIds, isNot(contains(consumedId)));
      expect(replacement.opkHighWaterKeyId, greaterThan(consumedId));
    },
  );
}
