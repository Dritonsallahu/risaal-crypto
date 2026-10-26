@TestOn('vm')
library;

import 'dart:convert';

import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:test/test.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// What happens to a phone that already has Risaal on it.
///
/// Every other proof in this task starts from `wipeForFreshRegistration()` — a
/// device with nothing on it, which is the one situation no real user is in.
/// The acceptance gate "version/migration with no real user data stranded"
/// stood at `FAIL` with nothing exercising it.
///
/// The property that matters is not "the code does not throw". It is that the
/// person holding that phone keeps their identity — a changed identity key is
/// what every contact sees as a possible impersonation — and can still be
/// reached afterwards.
/// Initialize a device that was just adopted from a pre-journal install.
///
/// Adoption leaves it needing an authenticated generation, which the package
/// reports as a typed recovery rather than a wipe.
Future<void> _initializeAdopted(SignalProtocolManager manager) async {
  try {
    await manager.initialize();
  } on KeyBundleReplacementRecoveryRequired {
    // Expected for a freshly adopted install.
  }
}

void main() {
  const journalKey = 'crypto_e2_bundle_replacement_journal_v1';

  /// A fully-registered install stripped back to the pre-flag-day shape: real
  /// identity, signing, signed pre-key, KEM key and one-time pool, but no
  /// replacement journal, because journals did not exist then.
  Future<({SignalProtocolManager manager, FakeSecureStorage storage})>
  legacyInstall() async {
    final storage = FakeSecureStorage();
    final seeded = SignalProtocolManager(secureStorage: storage);
    await seeded.wipeForFreshRegistration();
    await seeded.initialize();
    await CryptoTestFixtures.acceptInitialGeneration(seeded);
    await storage.delete(key: journalKey);

    // A real pre-journal install still has its flat one-time pre-key pool on
    // disk — registration is what drains it into a generation, and that had not
    // happened yet on those builds. Seeding it is what makes this a migration
    // test rather than a "device with nothing on it" test.
    final flat = await SignalKeyHelper.generateOneTimePreKeys(9000, 4);
    await CryptoStorage(secureStorage: storage).saveOneTimePreKeys(flat);

    return (
      manager: SignalProtocolManager(secureStorage: storage),
      storage: storage,
    );
  }

  test('the harness really produces a pre-upgrade install', () async {
    // Pins the premise, in BOTH directions. The first version of this test
    // asserted only that the journal key reads null after deletion — which is
    // trivially true when the key NAME is wrong, and the name was wrong. Every
    // test below then exercised a normal, already-migrated install and passed
    // for the wrong reason. So the key is proven to exist first, and only then
    // proven gone.
    final storage = FakeSecureStorage();
    final seeded = SignalProtocolManager(secureStorage: storage);
    await seeded.wipeForFreshRegistration();
    await seeded.initialize();
    await CryptoTestFixtures.acceptInitialGeneration(seeded);

    expect(
      await storage.read(key: journalKey),
      isNotNull,
      reason: 'if this is null the key name is wrong and nothing below is real',
    );

    await storage.delete(key: journalKey);
    expect(await storage.read(key: journalKey), isNull);
  });

  test(
    'the legacy pool is quarantined, not deleted and not routable',
    () async {
      // Deleting it would destroy the only record that those key ids were ever
      // handed out; making it routable would put unreceipted material back into
      // the authenticated route this whole task exists to establish.
      final legacy = await legacyInstall();
      await _initializeAdopted(legacy.manager);
      await CryptoTestFixtures.acceptInitialGeneration(legacy.manager);

      final raw = await legacy.storage.read(key: journalKey);
      expect(raw, isNotNull, reason: 'the upgrade must produce a journal');
      final journal = jsonDecode(raw!) as Map<String, dynamic>;
      final generations = (journal['generations'] as List)
          .cast<Map<String, dynamic>>();

      final quarantined = generations.where((g) => g['opkGeneration'] == 0);
      expect(
        quarantined,
        hasLength(1),
        reason: 'the legacy pool is preserved exactly once as provenance',
      );
      expect(quarantined.single['role'], 'legacyQuarantined');
      expect(
        (quarantined.single['oneTimePreKeys'] as List),
        isNotEmpty,
        reason: 'the keys the device already published are kept, not discarded',
      );
      expect(
        generations.where((g) => g['role'] == 'acceptedLookupOnly'),
        hasLength(1),
        reason: 'and a real current generation exists alongside it',
      );
    },
  );

  test('a pre-journal install is adopted rather than refused', () async {
    // Before adoption this threw `No immutable key-bundle journal exists; an
    // explicit fresh-account wipe or external authenticated migration is
    // required` — the app could not start, and the only remedy on offer
    // destroyed the identity key.
    //
    // It now signals the TYPED recovery instead, which means "register a
    // generation", not "wipe". That distinction is the whole point.
    final legacy = await legacyInstall();
    await expectLater(
      legacy.manager.initialize(),
      throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
    );
  });

  test('the identity key survives the upgrade', () async {
    final legacy = await legacyInstall();
    final before = await legacy.manager.getIdentityPublicKey();

    final upgraded = SignalProtocolManager(secureStorage: legacy.storage);
    try {
      await upgraded.initialize();
    } on KeyBundleReplacementRecoveryRequired {
      // Expected: the device needs a generation, not a new identity.
    }
    await CryptoTestFixtures.acceptInitialGeneration(upgraded);

    expect(
      await upgraded.getIdentityPublicKey(),
      before,
      reason:
          'a changed identity key is what every contact sees as a possible '
          'impersonation — an upgrade must never look like one',
    );
  });

  test('a legacy install can still be reached after upgrading', () async {
    // The end-to-end property: an existing user upgrades, registers a current
    // generation, and a peer starts a session and sends them a message.
    final legacy = await legacyInstall();
    final bob = legacy.manager;
    await _initializeAdopted(bob);
    await legacy.storage.write(key: 'user_id', value: 'bob-id');
    await legacy.storage.write(key: 'device_id', value: 'bob-device');

    final accepted = await CryptoTestFixtures.acceptInitialGeneration(bob);

    final (alice, aliceStorage) =
        await CryptoTestFixtures.createInitializedManager();
    await aliceStorage.write(key: 'user_id', value: 'alice-id');
    await aliceStorage.write(key: 'device_id', value: 'alice-device');

    await alice.createSession(accepted.consumerBundle());
    final envelope = await alice.encryptMessage(
      'bob-id',
      'bob-device',
      'the upgrade did not strand this device',
    );

    final prepared = await bob.prepareReceive(
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: envelope,
      deliveryId: 'delivery-legacy-1',
    );
    await bob.acknowledgeReceive(prepared.receipt);

    expect(prepared.plaintext, 'the upgrade did not strand this device');
  });

  test(
    'the upgrade routes a current generation, never generation zero',
    () async {
      // Generation zero is the legacy quarantine. Routing it would put
      // unreceipted material back into the authenticated route this whole task
      // exists to establish.
      final legacy = await legacyInstall();
      await _initializeAdopted(legacy.manager);

      final accepted = await CryptoTestFixtures.acceptInitialGeneration(
        legacy.manager,
      );

      expect(accepted.receipt.opkGeneration, greaterThan(0));
      expect(accepted.consumerBundle().oneTimePreKey, isNotNull);
    },
  );

  test(
    'upgrading twice is idempotent and still leaves a reachable device',
    () async {
      // A crash between the two halves of an upgrade, or a user who force-quits
      // on first launch, re-runs it. That must not produce a second quarantine
      // record or strand the device.
      final legacy = await legacyInstall();
      await _initializeAdopted(legacy.manager);

      final again = SignalProtocolManager(secureStorage: legacy.storage);
      await _initializeAdopted(again);

      final accepted = await CryptoTestFixtures.acceptInitialGeneration(again);
      expect(accepted.receipt.opkGeneration, greaterThan(0));
    },
  );

  test('an adopted device re-attaches to its existing account', () async {
    // The whole point of adoption: an existing user logs back in. The server
    // holds the account's authenticated receipt, handing it in IS the "external
    // authenticated migration" the refusal names, and the device publishes the
    // NEXT generation for that account rather than creating a new one.
    final legacy = await legacyInstall();
    await _initializeAdopted(legacy.manager);

    final serverSide = FakeSecureStorage();
    final serverView = SignalProtocolManager(secureStorage: serverSide);
    await serverView.wipeForFreshRegistration();
    await serverView.initialize();
    final published = await CryptoTestFixtures.acceptInitialGeneration(
      serverView,
    );

    final snapshot = await legacy.manager.prepareKeyBundleReplacement(
      acceptedReceipt: published.receipt,
      oneTimePreKeyCount: 5,
    );

    expect(
      snapshot.opkGeneration,
      published.receipt.opkGeneration + 1,
      reason: 'the NEXT generation for the account, not a restart at one',
    );
    expect(
      snapshot.opkHighWaterKeyId,
      greaterThan(published.receipt.opkHighWaterKeyId),
      reason:
          'it must not reuse a key id the ACCOUNT already published, even '
          'though this device has no local history of it',
    );
    expect(
      snapshot.signedPreKeyId,
      greaterThan(published.receipt.signedPreKeyId),
    );
    expect(snapshot.kemKeyId, greaterThan(published.receipt.kemKeyId));
  });

  test('an adopted baseline is not re-negotiable', () async {
    // Once adopted against one account's receipt, a second, DIFFERENT receipt
    // must not rebase the device onto another account's history. The pending
    // reservation is returned unchanged rather than rebuilt — which is the
    // property that matters; whether it throws is an implementation detail.
    final legacy = await legacyInstall();
    await _initializeAdopted(legacy.manager);

    final firstSide = FakeSecureStorage();
    final first = SignalProtocolManager(secureStorage: firstSide);
    await first.wipeForFreshRegistration();
    await first.initialize();
    final mine = await CryptoTestFixtures.acceptInitialGeneration(first);

    final original = await legacy.manager.prepareKeyBundleReplacement(
      acceptedReceipt: mine.receipt,
      oneTimePreKeyCount: 5,
    );

    final secondSide = FakeSecureStorage();
    final second = SignalProtocolManager(secureStorage: secondSide);
    await second.wipeForFreshRegistration();
    await second.initialize();
    final foreign = await CryptoTestFixtures.acceptInitialGeneration(second);

    final after = await legacy.manager.prepareKeyBundleReplacement(
      acceptedReceipt: foreign.receipt,
      oneTimePreKeyCount: 5,
    );

    expect(
      after.expectedBundleRevision,
      original.expectedBundleRevision,
      reason: 'the baseline is recorded once, against one account',
    );
    expect(after.replacementId, original.replacementId);
    expect(after.opkGeneration, original.opkGeneration);
  });

  test('a device with real local history refuses a foreign receipt', () async {
    final (manager, _) = await CryptoTestFixtures.createInitializedManager();
    await CryptoTestFixtures.acceptInitialGeneration(manager);

    final otherSide = FakeSecureStorage();
    final other = SignalProtocolManager(secureStorage: otherSide);
    await other.wipeForFreshRegistration();
    await other.initialize();
    final foreign = await CryptoTestFixtures.acceptInitialGeneration(other);

    await expectLater(
      manager.prepareKeyBundleReplacement(
        acceptedReceipt: foreign.receipt,
        oneTimePreKeyCount: 5,
      ),
      throwsA(isA<FormatException>()),
    );
  });
}
