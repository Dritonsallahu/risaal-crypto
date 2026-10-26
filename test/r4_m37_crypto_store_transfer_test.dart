import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/transfer/transfer_crypto_store.dart'
    show debugIsTransferableCryptoKey;

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// R4-M37 §3 `crypto_store`: export every package-owned key through
/// [CryptoSecureStorage], import only into a staging scope.
final class _ListingStorage extends FakeSecureStorage
    implements TransferKeyListing {
  @override
  Future<Iterable<String>> listKeys() async => store.keys.toList();
}

const _identityKey = 'crypto_identity_key_pair';
const _signingKey = 'crypto_signing_key_pair';
const _journalKey = 'crypto_e2_bundle_replacement_journal_v1';
const _intentKey = 'crypto_e2_initial_registration_intent_v1';
const _quarantineKey = 'crypto_e2_receive_commit_journal_quarantine_v1';

/// Keys the package writes that must never move.
const _notTransferred = <String>{_intentKey, _quarantineKey};

/// App-owned or secret keys that share the store and must never be exported.
const _appKeys = <String, String>{
  'user_id': 'alice-id',
  'device_id': 'alice-device',
  'access_token': 'secret-access',
  'refresh_token': 'secret-refresh',
  'pin_hash': 'secret-pin',
  'crypto_owner_account_id': 'acct',
  'crypto_sender_certificate_v1': '{"cert":1}',
  'crypto_kt_head_v1': '{"h":1}',
  'crypto_group_roster_v1_group-1': '{"r":1}',
  'crypto_group_intents_index_v1': '[]',
  // A legacy (pre-epoch-2) key nothing reads any more.
  'crypto_session_bob-id_bob-device': '{"legacy":true}',
};

Future<
  ({
    SignalProtocolManager alice,
    _ListingStorage aliceStorage,
    SignalProtocolManager bob,
    FakeSecureStorage bobStorage,
  })
>
_establishedPair() async {
  final aliceStorage = _ListingStorage();
  final (alice, _) = await CryptoTestFixtures.createInitializedManager(
    storage: aliceStorage,
  );
  final (bob, bobStorage) = await CryptoTestFixtures.createInitializedManager();
  await CryptoTestFixtures.acceptInitialGeneration(alice);
  final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
  await alice.createSession(acceptedBob.consumerBundle());
  for (final entry in _appKeys.entries) {
    await aliceStorage.write(key: entry.key, value: entry.value);
  }
  await bobStorage.write(key: 'user_id', value: 'bob-id');
  await bobStorage.write(key: 'device_id', value: 'bob-device');

  // A DM both ways, so both ratchets have stepped.
  final first = await alice.encryptMessage('bob-id', 'bob-device', 'hi bob');
  expect(await bob.decryptMessage('alice-id', 'alice-device', first), 'hi bob');
  final reply = await bob.encryptMessage(
    'alice-id',
    'alice-device',
    'hi alice',
  );
  expect(await alice.decryptMessage('bob-id', 'bob-device', reply), 'hi alice');

  // Sealed sender both ways (seen nonces, WAL receipts).
  final aliceIdentity = await alice.getIdentityPublicKey();
  final bobIdentity = await bob.getIdentityPublicKey();
  final sealedToBob = await alice.encryptSealedSender(
    'bob-id',
    'bob-device',
    bobIdentity,
    'sealed to bob',
  );
  expect(
    (await bob.decryptSealedSender(sealedToBob)).plaintext,
    'sealed to bob',
  );
  final sealedToAlice = await bob.encryptSealedSender(
    'alice-id',
    'alice-device',
    aliceIdentity,
    'sealed to alice',
  );
  expect(
    (await alice.decryptSealedSender(sealedToAlice)).plaintext,
    'sealed to alice',
  );

  // The durable (WAL) lanes both ways, so both commit journals exist.
  final walToAlice = await bob.prepareSealedSend(
    deliveryId: 'wal-to-alice',
    recipientId: 'alice-id',
    recipientDeviceId: 'alice-device',
    recipientIdentityPublicKey: aliceIdentity,
    plaintext: 'durable to alice',
  );
  await bob.acknowledgeSend(walToAlice.receipt);
  final walReceived = await alice.prepareSealedReceive(
    deliveryId: 'wal-to-alice',
    sealedEnvelope: walToAlice.envelope,
  );
  expect(walReceived.plaintext, 'durable to alice');
  await alice.acknowledgeReceive(walReceived.receipt);
  final walToBob = await alice.prepareSealedSend(
    deliveryId: 'wal-to-bob',
    recipientId: 'bob-id',
    recipientDeviceId: 'bob-device',
    recipientIdentityPublicKey: bobIdentity,
    plaintext: 'durable to bob',
  );
  await alice.acknowledgeSend(walToBob.receipt);
  final walAtBob = await bob.prepareSealedReceive(
    deliveryId: 'wal-to-bob',
    sealedEnvelope: walToBob.envelope,
  );
  expect(walAtBob.plaintext, 'durable to bob');
  await bob.acknowledgeReceive(walAtBob.receipt);
  _walToAliceEnvelope = walToAlice.envelope;

  // A group with sender keys both ways.
  final aliceDist = await alice.generateGroupSenderKey('group-1');
  final bobDist = await bob.generateGroupSenderKey('group-1');
  await bob.processGroupSenderKey('group-1', 'alice-id', aliceDist);
  await alice.processGroupSenderKey('group-1', 'bob-id', bobDist);
  final g1 = await alice.encryptGroupMessage('group-1', 'group from alice');
  expect(
    await bob.decryptGroupMessage('group-1', 'alice-id', g1),
    'group from alice',
  );
  final g2 = await bob.encryptGroupMessage('group-1', 'group from bob');
  expect(
    await alice.decryptGroupMessage('group-1', 'bob-id', g2),
    'group from bob',
  );

  return (
    alice: alice,
    aliceStorage: aliceStorage,
    bob: bob,
    bobStorage: bobStorage,
  );
}

/// The last durable delivery to Alice, for the redelivery check.
late Map<String, dynamic> _walToAliceEnvelope;

Map<String, String> _asMap(Iterable<TransferArchiveEntry> entries) => {
  for (final entry in entries) entry.key: entry.valueText,
};

void main() {
  group('export -> archive -> staging import -> export', () {
    test('moves every package key, nothing else, byte-identically, and the '
        'moved account keeps talking without a new session', () async {
      final pair = await _establishedPair();
      final exported = await CryptoStorage(
        secureStorage: pair.aliceStorage,
      ).exportForTransfer();

      expect(
        exported.every((e) => e.kind == TransferArchiveKind.cryptoStore),
        isTrue,
      );
      final exportedMap = _asMap(exported);

      // Completeness: every package-owned key in the store is exported, and
      // exactly with its stored value.
      final packageKeys = pair.aliceStorage.store.keys
          .where((k) => k.startsWith('crypto_') && !_appKeys.containsKey(k))
          .where((k) => !_notTransferred.contains(k))
          .toSet();
      expect(exportedMap.keys.toSet(), packageKeys);
      for (final key in packageKeys) {
        expect(exportedMap[key], pair.aliceStorage.store[key], reason: key);
      }
      // Minimality: no app key, token, PIN or legacy key.
      for (final key in _appKeys.keys) {
        expect(exportedMap.containsKey(key), isFalse, reason: key);
      }
      // The material the contract names is really there.
      for (final key in [
        _identityKey,
        _signingKey,
        _journalKey,
        'crypto_e2_protocol',
        'crypto_e2_session_bob-id_bob-device',
        'crypto_e2_session_ik_bob-id_bob-device',
        'crypto_e2_session_devices_bob-id',
        'crypto_e2_sender_key_group-1_alice-id',
        'crypto_e2_sender_key_group-1_bob-id',
        'crypto_e2_seen_nonces',
        'crypto_e2_receive_commit_journal_v1',
        'crypto_e2_send_commit_journal_v1',
      ]) {
        expect(exportedMap.containsKey(key), isTrue, reason: key);
      }

      final archiveBytes = TransferArchive([
        ...exported,
        TransferArchiveEntry.text(TransferArchiveKind.prefs, 'theme', 'dark'),
      ]).encode();

      // N: decode, import into staging. The live store stays untouched.
      final live = _ListingStorage();
      await live.write(key: 'device_scoped_flag', value: '1');
      final liveBefore = Map<String, String>.of(live.store);
      final staging = _ListingStorage();
      await CryptoStorage(secureStorage: live).importForTransfer(
        TransferArchive.decode(archiveBytes),
        staging: staging,
      );
      expect(live.store, liveBefore, reason: 'import must never write live');
      expect(staging.store, exportedMap);

      // export -> import -> export is byte-identical.
      final reExported = await CryptoStorage(
        secureStorage: staging,
      ).exportForTransfer();
      expect(
        TransferArchive(reExported).encode(),
        TransferArchive(exported).encode(),
      );

      // The app commits the staged scope; same user and device id.
      final moved = FakeSecureStorage();
      for (final entry in staging.store.entries) {
        await moved.write(key: entry.key, value: entry.value);
      }
      await moved.write(key: 'user_id', value: 'alice-id');
      await moved.write(key: 'device_id', value: 'alice-device');
      final alice2 = SignalProtocolManager(secureStorage: moved);
      await alice2.initialize();
      expect(
        await alice2.getIdentityPublicKey(),
        await pair.alice.getIdentityPublicKey(),
      );

      // Bob -> moved Alice, on the existing session (no PreKey, no reset).
      final bobPinBefore = await CryptoStorage(
        secureStorage: pair.bobStorage,
      ).getSessionIdentityKey('alice-id', 'alice-device');
      final toAlice = await pair.bob.encryptMessage(
        'alice-id',
        'alice-device',
        'after the move',
      );
      expect(
        await alice2.decryptMessage('bob-id', 'bob-device', toAlice),
        'after the move',
      );
      final back = await alice2.encryptMessage(
        'bob-id',
        'bob-device',
        'from the new phone',
      );
      expect(
        await pair.bob.decryptMessage('alice-id', 'alice-device', back),
        'from the new phone',
      );
      expect(
        await CryptoStorage(
          secureStorage: pair.bobStorage,
        ).getSessionIdentityKey('alice-id', 'alice-device'),
        bobPinBefore,
        reason: 'contacts see no identity change',
      );

      // Groups keep working both ways with the moved sender keys.
      final g = await pair.bob.encryptGroupMessage('group-1', 'group after');
      expect(
        await alice2.decryptGroupMessage('group-1', 'bob-id', g),
        'group after',
      );
      final g2 = await alice2.encryptGroupMessage('group-1', 'group from new');
      expect(
        await pair.bob.decryptGroupMessage('group-1', 'alice-id', g2),
        'group from new',
      );

      // The moved receive journal recognises a delivery the old phone
      // already acknowledged: no second plaintext, no ratchet step.
      final redelivered = await alice2.prepareSealedReceive(
        deliveryId: 'wal-to-alice',
        sealedEnvelope: _walToAliceEnvelope,
      );
      expect(redelivered.plaintext, isNull);

      // Sealed sender keeps working on the moved account.
      final sealed = await pair.bob.encryptSealedSender(
        'alice-id',
        'alice-device',
        await alice2.getIdentityPublicKey(),
        'sealed after the move',
      );
      expect(
        (await alice2.decryptSealedSender(sealed)).plaintext,
        'sealed after the move',
      );
    });

    test('the moved replay state refuses a message the old phone already '
        'consumed', () async {
      final pair = await _establishedPair();
      final consumed = await pair.bob.encryptMessage(
        'alice-id',
        'alice-device',
        'read on the old phone',
      );
      expect(
        await pair.alice.decryptMessage('bob-id', 'bob-device', consumed),
        'read on the old phone',
      );
      final exported = await CryptoStorage(
        secureStorage: pair.aliceStorage,
      ).exportForTransfer();
      final staging = _ListingStorage();
      await CryptoStorage(
        secureStorage: _ListingStorage(),
      ).importForTransfer(TransferArchive(exported), staging: staging);
      final moved = FakeSecureStorage();
      for (final entry in staging.store.entries) {
        await moved.write(key: entry.key, value: entry.value);
      }
      await moved.write(key: 'user_id', value: 'alice-id');
      await moved.write(key: 'device_id', value: 'alice-device');
      final alice2 = SignalProtocolManager(secureStorage: moved);
      await alice2.initialize();
      await expectLater(
        alice2.decryptMessage('bob-id', 'bob-device', consumed),
        throwsA(anything),
      );
    });
  });

  group('export refuses (fail closed)', () {
    test('a store that cannot list its keys', () async {
      final (_, storage) = await CryptoTestFixtures.createInitializedManager();
      await expectLater(
        CryptoStorage(secureStorage: storage).exportForTransfer(),
        throwsA(
          isA<TransferExportBlocked>().having(
            (e) => e.reason,
            'reason',
            TransferExportBlockedReason.storageNotListable,
          ),
        ),
      );
    });

    test('an account whose registration was never accepted', () async {
      final storage = _ListingStorage();
      await CryptoTestFixtures.createInitializedManager(storage: storage);
      expect(storage.store.containsKey(_intentKey), isTrue);
      await expectLater(
        CryptoStorage(secureStorage: storage).exportForTransfer(),
        throwsA(
          isA<TransferExportBlocked>().having(
            (e) => e.reason,
            'reason',
            TransferExportBlockedReason.unregisteredAccount,
          ),
        ),
      );
    });

    test('a store without an identity', () async {
      await expectLater(
        CryptoStorage(secureStorage: _ListingStorage()).exportForTransfer(),
        throwsA(
          isA<TransferExportBlocked>().having(
            (e) => e.reason,
            'reason',
            TransferExportBlockedReason.incompleteAccount,
          ),
        ),
      );
    });

    test('a pending send commit, until it is acknowledged', () async {
      final pair = await _establishedPair();
      final prepared = await pair.alice.prepareSealedSend(
        deliveryId: 'transfer-pending-send',
        recipientId: 'bob-id',
        recipientDeviceId: 'bob-device',
        recipientIdentityPublicKey: await pair.bob.getIdentityPublicKey(),
        plaintext: 'in flight',
      );
      final storage = CryptoStorage(secureStorage: pair.aliceStorage);
      await expectLater(
        storage.exportForTransfer(),
        throwsA(
          isA<TransferExportBlocked>().having(
            (e) => e.reason,
            'reason',
            TransferExportBlockedReason.pendingSend,
          ),
        ),
      );
      await pair.alice.acknowledgeSend(prepared.receipt);
      expect(await storage.exportForTransfer(), isNotEmpty);
    });

    test('a pending receive commit', () async {
      final pair = await _establishedPair();
      final sealed = await pair.bob.prepareSealedSend(
        deliveryId: 'transfer-pending-receive',
        recipientId: 'alice-id',
        recipientDeviceId: 'alice-device',
        recipientIdentityPublicKey: await pair.alice.getIdentityPublicKey(),
        plaintext: 'arriving',
      );
      await pair.bob.acknowledgeSend(sealed.receipt);
      await pair.alice.prepareSealedReceive(
        deliveryId: 'transfer-pending-receive',
        sealedEnvelope: sealed.envelope,
      );
      await expectLater(
        CryptoStorage(secureStorage: pair.aliceStorage).exportForTransfer(),
        throwsA(
          isA<TransferExportBlocked>().having(
            (e) => e.reason,
            'reason',
            TransferExportBlockedReason.pendingReceive,
          ),
        ),
      );
    });

    test('a key that disappears between listing and reading', () async {
      final pair = await _establishedPair();
      final racing = _VanishingStorage(pair.aliceStorage);
      await expectLater(
        CryptoStorage(secureStorage: racing).exportForTransfer(),
        throwsA(
          isA<TransferExportBlocked>().having(
            (e) => e.reason,
            'reason',
            TransferExportBlockedReason.storeChanged,
          ),
        ),
      );
    });
  });

  group('import refuses (staging only, fail closed)', () {
    late List<TransferArchiveEntry> exported;
    late String pendingSendJournal;

    setUpAll(() async {
      final pair = await _establishedPair();
      exported = await CryptoStorage(
        secureStorage: pair.aliceStorage,
      ).exportForTransfer();
      // A real send WAL with a pending commit, as the old phone would hold it
      // mid-send.
      await pair.alice.prepareSealedSend(
        deliveryId: 'transfer-import-pending',
        recipientId: 'bob-id',
        recipientDeviceId: 'bob-device',
        recipientIdentityPublicKey: await pair.bob.getIdentityPublicKey(),
        plaintext: 'in flight',
      );
      pendingSendJournal =
          pair.aliceStorage.store['crypto_e2_send_commit_journal_v1']!;
    });

    Future<void> refused(
      List<TransferArchiveEntry> entries, {
      Matcher matcher = const TypeMatcher<FormatException>(),
    }) async {
      final live = _ListingStorage();
      final staging = _ListingStorage();
      await expectLater(
        CryptoStorage(
          secureStorage: live,
        ).importForTransfer(TransferArchive(entries), staging: staging),
        throwsA(matcher),
      );
      expect(staging.store, isEmpty, reason: 'nothing staged on refusal');
      expect(live.store, isEmpty, reason: 'nothing live, ever');
    }

    List<TransferArchiveEntry> replaced(String key, String value) => [
      for (final e in exported)
        if (e.key != key) e,
      TransferArchiveEntry.text(TransferArchiveKind.cryptoStore, key, value),
    ];

    test('the live store as the staging target', () async {
      final live = _ListingStorage();
      await expectLater(
        CryptoStorage(
          secureStorage: live,
        ).importForTransfer(TransferArchive(exported), staging: live),
        throwsArgumentError,
      );
      expect(live.store, isEmpty);
    });

    test('a staging scope that already holds crypto state', () async {
      // An identity, whether or not the staging scope can list its keys.
      for (final staging in <FakeSecureStorage>[
        _ListingStorage(),
        FakeSecureStorage(),
      ]) {
        await staging.write(key: _identityKey, value: 'other');
        await expectLater(
          CryptoStorage(
            secureStorage: _ListingStorage(),
          ).importForTransfer(TransferArchive(exported), staging: staging),
          throwsStateError,
        );
        expect(staging.store, {_identityKey: 'other'});
      }
      // A stray session the archive does not carry (listing scope only).
      final stray = _ListingStorage();
      await stray.write(key: 'crypto_e2_session_carol-id_carol-d', value: 's');
      await expectLater(
        CryptoStorage(
          secureStorage: _ListingStorage(),
        ).importForTransfer(TransferArchive(exported), staging: stray),
        throwsStateError,
      );
      expect(stray.store, {'crypto_e2_session_carol-id_carol-d': 's'});
    });

    test('a key outside the package allowlist', () async {
      for (final key in [
        'access_token',
        'user_id',
        'crypto_kt_head_v1',
        'crypto_owner_account_id',
        'crypto_sender_certificate_v1',
        _intentKey,
        _quarantineKey,
        'crypto_e2_session_bob_id_bob-device_x',
        'crypto_e2_session_devices',
      ]) {
        await refused([
          ...exported,
          TransferArchiveEntry.text(TransferArchiveKind.cryptoStore, key, 'x'),
        ]);
      }
    });

    test('a missing identity, signing key or key-bundle journal', () async {
      for (final key in [_identityKey, _signingKey, _journalKey]) {
        await refused([
          for (final e in exported)
            if (e.key != key) e,
        ]);
      }
    });

    test('a mismatched identity or signing key pair', () async {
      final identity =
          jsonDecode(
                exported.singleWhere((e) => e.key == _identityKey).valueText,
              )
              as Map<String, dynamic>;
      final other = await SignalKeyHelper.generateIdentityKeyPair();
      await refused(
        replaced(
          _identityKey,
          jsonEncode({...identity, 'publicKey': other.publicKey}),
        ),
      );
      final signing =
          jsonDecode(
                exported.singleWhere((e) => e.key == _signingKey).valueText,
              )
              as Map<String, dynamic>;
      final otherSigning = await SignalKeyHelper.generateSigningKeyPair();
      await refused(
        replaced(
          _signingKey,
          jsonEncode({...signing, 'publicKey': otherSigning.publicKey}),
        ),
      );
      await refused(replaced(_identityKey, 'not json'));
    });

    test('a corrupt or pending commit journal', () async {
      await refused(replaced('crypto_e2_receive_commit_journal_v1', '{'));
      await refused(replaced('crypto_e2_send_commit_journal_v1', '[]'));
      await refused(
        replaced('crypto_e2_send_commit_journal_v1', pendingSendJournal),
      );
      await refused(replaced(_journalKey, '[]'));
    });

    test('a value that is not UTF-8', () async {
      await refused([
        for (final e in exported)
          if (e.key == 'crypto_e2_seen_nonces')
            TransferArchiveEntry(e.kind, e.key, const [0xff, 0xfe])
          else
            e,
      ]);
    });

    test('an archive with no crypto_store entries', () async {
      await refused([
        TransferArchiveEntry.text(TransferArchiveKind.prefs, 'theme', 'dark'),
      ]);
    });
  });

  test('every storage key the package writes is classified for transfer', () {
    // Static guard: a new package key must be added to the transfer allowlist
    // or to the explicit not-transferred set, never silently left behind.
    final sources = Directory('lib/src')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))
        .where((f) => !f.path.contains('${Platform.pathSeparator}transfer'))
        .map((f) => f.readAsStringSync())
        .join('\n');
    const notKeys = <String>{
      'crypto_', // receive_commit: a comment about prefix checks
      'crypto_e2_', // the prefix constant itself
      'crypto_debug_event', // logger event names
      'crypto_operation_failed',
    };
    final names = <String>{};
    for (final m in RegExp(
      r"'(crypto_[A-Za-z0-9_]*)(\.dart)?",
    ).allMatches(sources)) {
      if (m.group(2) == null) names.add(m.group(1)!); // not an import
    }
    for (final m in RegExp(
      r"'\$\{_epoch2Prefix\}([A-Za-z0-9_]*)",
    ).allMatches(sources)) {
      names.add('crypto_e2_${m.group(1)!}');
    }
    expect(names, contains('crypto_e2_session_'));
    expect(names, contains(_identityKey));
    final unclassified = <String>[];
    for (final name in names.difference(notKeys)) {
      if (_notTransferred.contains(name)) continue;
      final ok =
          debugIsTransferableCryptoKey(name) ||
          debugIsTransferableCryptoKey('${name}u-1_d-1') ||
          debugIsTransferableCryptoKey('${name}u-1') ||
          debugIsTransferableCryptoKey('${name}_u-1_d-1') ||
          debugIsTransferableCryptoKey('${name}_u-1');
      if (!ok) unclassified.add(name);
    }
    expect(unclassified, isEmpty);
    for (final key in _notTransferred) {
      expect(debugIsTransferableCryptoKey(key), isFalse, reason: key);
    }
  });
}

/// Lists a key that is gone by the time it is read.
final class _VanishingStorage extends FakeSecureStorage
    implements TransferKeyListing {
  _VanishingStorage(this._inner);

  final _ListingStorage _inner;

  @override
  Future<Iterable<String>> listKeys() async => [
    ...await _inner.listKeys(),
    'crypto_e2_session_ghost_ghost-device',
  ];

  @override
  Future<String?> read({required String key}) => _inner.read(key: key);
}
