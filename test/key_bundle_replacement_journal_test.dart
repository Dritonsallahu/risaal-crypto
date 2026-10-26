import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/key_bundle_replacement.dart'
    show
        KeyBundleKeyringGeneration,
        KeyBundleReplacementJournal,
        KeyBundleReplacementReservation,
        OpkGenerationRole;
import 'package:test/test.dart';

import 'helpers/fake_secure_storage.dart';

const _journalStorageKey = 'crypto_e2_bundle_replacement_journal_v1';

/// Tests intentionally inspect the private persisted model through their fake
/// backend. Production callers receive only the opaque manager snapshot and a
/// post-intent dispatch capability; CryptoStorage exposes no raw getter.
Future<KeyBundleReplacementJournal?> _readJournalForTest(
  CryptoSecureStorage storage, {
  bool validatePrivateMaterial = true,
}) async {
  final raw = await storage.read(key: _journalStorageKey);
  if (raw == null) return null;
  if (utf8.encode(raw).length > KeyBundleReplacementJournal.maxEncodedBytes) {
    throw const FormatException('Oversized key-bundle journal');
  }
  try {
    final decoded = jsonDecode(raw);
    if (decoded is! Map) {
      throw const FormatException('Corrupt key-bundle journal');
    }
    final journal = KeyBundleReplacementJournal.fromJson(
      Map<String, dynamic>.from(decoded),
    );
    if (validatePrivateMaterial) {
      await CryptoStorage(
        secureStorage: storage,
      ).validateKeyBundleReplacementJournal(journal);
    }
    return journal;
  } on FormatException {
    rethrow;
  } on Object {
    throw const FormatException('Corrupt key-bundle journal');
  }
}

Future<KeyBundleKeyringGeneration?> _routableGenerationForTest(
  CryptoSecureStorage storage,
  int opkGeneration,
) async {
  final journal = await _readJournalForTest(
    storage,
    validatePrivateMaterial: false,
  );
  if (journal == null) return null;
  final matches = journal.generations.where(
    (entry) => entry.opkGeneration == opkGeneration,
  );
  if (matches.length != 1) return null;
  final generation = matches.single;
  if (generation.role == OpkGenerationRole.legacyQuarantined) return null;
  if (generation.role == OpkGenerationRole.stagedUploadOnly &&
      journal.phase != KeyBundleReplacementPhase.dispatchStarted &&
      journal.phase != KeyBundleReplacementPhase.localAckPending) {
    return null;
  }
  return generation;
}

Future<bool> _hasRoutableOneTimePreKeyForTest(
  CryptoSecureStorage storage, {
  required int opkGeneration,
  required int keyId,
}) async =>
    (await _routableGenerationForTest(
      storage,
      opkGeneration,
    ))?.findOneTimePreKey(keyId) !=
    null;

Future<bool> _hasRoutableSignedPreKeyForTest(
  CryptoSecureStorage storage, {
  required int opkGeneration,
  required int keyId,
}) async =>
    (await _routableGenerationForTest(
      storage,
      opkGeneration,
    ))?.signedPreKey?.keyId ==
    keyId;

Future<bool> _hasRoutableKyberKeyForTest(
  CryptoSecureStorage storage, {
  required int opkGeneration,
  required int keyId,
}) async =>
    (await _routableGenerationForTest(
      storage,
      opkGeneration,
    ))?.kyberKeyPair?.keyId ==
    keyId;

KeyBundleAcceptedReceipt _receiptFor(KeyBundleReplacementSnapshot snapshot) =>
    KeyBundleAcceptedReceipt(
      bundleRevision: snapshot.expectedBundleRevision + 1,
      signedPreKeyId: snapshot.signedPreKeyId,
      kemKeyId: snapshot.kemKeyId,
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
      replacementId: snapshot.replacementId,
      opkAcceptedBundleRevision: snapshot.expectedBundleRevision + 1,
      opkGeneration: snapshot.opkGeneration,
      opkSetDigest: snapshot.opkSetDigest,
      opkSetCount: snapshot.opkSetCount,
      opkHighWaterKeyId: snapshot.opkHighWaterKeyId,
      bundlePublicMaterialDigest: snapshot.bundlePublicMaterialDigest,
    );

Map<String, dynamic> _ownerResponseFor(KeyBundleReplacementDispatch dispatch) {
  final snapshot = dispatch.snapshot;
  final payload = dispatch.toReplacementPayload(deviceId: 'device-a');
  return <String, dynamic>{
    'bundleRevision': snapshot.expectedBundleRevision + 1,
    'opkGeneration': snapshot.opkGeneration,
    'opkSetDigest': snapshot.opkSetDigest,
    'identityKey': payload['identityKey'],
    'identitySigningKey': payload['identitySigningKey'],
    'signedPreKey': payload['signedPreKey'],
    'kyberPreKey': payload['kyberPreKey'],
    'oneTimePreKey': null,
    'remainingOpkCount': snapshot.opkSetCount,
    'accepted': _receiptFor(snapshot).toJson(),
  };
}

Future<void> _consumeThroughAuthenticatedPreKey({
  required SignalProtocolManager responder,
  required KeyBundleReplacementSnapshot snapshot,
  required Map<String, dynamic> publicMaterial,
  required int keyId,
}) async {
  final selected = (publicMaterial['oneTimePreKeys'] as List)
      .map((value) => Map<String, dynamic>.from(value as Map))
      .singleWhere((value) => value['keyId'] == keyId);
  final route = <String, dynamic>{
    'bundleRevision': snapshot.expectedBundleRevision + 1,
    'opkGeneration': snapshot.opkGeneration,
    'opkSetDigest': snapshot.opkSetDigest,
  };
  final bundle = PreKeyBundle.fromServerJson(<String, dynamic>{
    ...publicMaterial,
    'userId': 'responder-id',
    'deviceId': 'responder-device',
    ...route,
    'oneTimePreKey': <String, dynamic>{...selected, ...route},
  });
  final senderStorage = FakeSecureStorage();
  final sender = SignalProtocolManager(secureStorage: senderStorage);
  await sender.wipeForFreshRegistration();
  await sender.initialize();
  await sender.createSession(bundle);
  final envelope = await sender.encryptMessage(
    'responder-id',
    'responder-device',
    'authenticated consume ${snapshot.opkGeneration}:$keyId',
  );
  expect(
    await responder.decryptMessage(
      'sender-${snapshot.opkGeneration}-$keyId',
      'sender-device',
      envelope,
    ),
    'authenticated consume ${snapshot.opkGeneration}:$keyId',
  );
}

Map<String, dynamic> _frozenReceiptJson() => <String, dynamic>{
  'bundleRevision': 9,
  'signedPreKeyId': 11,
  'kemKeyId': 21,
  'cryptoProtocolEpoch': 2,
  'replacementId': 'replacement-9',
  'opkAcceptedBundleRevision': 9,
  'opkGeneration': 9,
  'opkSetDigest':
      '80727ddacee11bf47be96b327c18b14fea09864efb5f8cccac81b495f55e9973',
  'opkSetCount': 2,
  'opkHighWaterKeyId': 7,
  'bundlePublicMaterialDigest':
      '5252245ad783eb86301f16c3e5bba805e6bfc292ab48c354e353f838ae6a2c34',
};

class _FaultInjectingStorage extends FakeSecureStorage {
  String? _targetKey;
  String? _journalPhase;
  bool _failAfterWrite = false;
  String? _targetDeleteKey;
  bool _failAfterDelete = false;
  String? attemptedValue;

  void failNextWrite({
    required String key,
    String? journalPhase,
    bool afterWrite = false,
  }) {
    _targetKey = key;
    _journalPhase = journalPhase;
    _failAfterWrite = afterWrite;
    attemptedValue = null;
  }

  void failNextDelete({required String key, bool afterDelete = false}) {
    _targetDeleteKey = key;
    _failAfterDelete = afterDelete;
  }

  @override
  Future<void> write({required String key, required String value}) async {
    var matches = key == _targetKey;
    if (matches && _journalPhase != null) {
      final decoded = jsonDecode(value);
      matches =
          decoded is Map &&
          (_journalPhase == '<idle>'
              ? decoded['phase'] == null
              : decoded['phase'] == _journalPhase);
    }
    if (!matches) {
      return super.write(key: key, value: value);
    }

    attemptedValue = value;
    _targetKey = null;
    _journalPhase = null;
    if (_failAfterWrite) {
      await super.write(key: key, value: value);
    }
    throw StateError('injected storage write failure');
  }

  @override
  Future<void> delete({required String key}) async {
    if (key != _targetDeleteKey) return super.delete(key: key);
    _targetDeleteKey = null;
    if (_failAfterDelete) await super.delete(key: key);
    throw StateError('injected storage delete failure');
  }
}

class _SharedBackendStorage implements CryptoSecureStorage {
  final Map<String, String> backend;

  _SharedBackendStorage(this.backend);

  @override
  StorageSecurityLevel get securityLevel => StorageSecurityLevel.insecure;

  @override
  Future<void> write({required String key, required String value}) async {
    backend[key] = value;
  }

  @override
  Future<String?> read({required String key}) async => backend[key];

  @override
  Future<void> delete({required String key}) async {
    backend.remove(key);
  }

  @override
  Future<void> clearAll() async => backend.clear();

  @override
  Future<void> clearAccountScopedValues() async {
    backend.removeWhere((key, _) => key.startsWith('crypto_'));
  }
}

class _BlockingClearStorage extends FakeSecureStorage {
  final Completer<void> clearStarted = Completer<void>();
  final Completer<void> allowClear = Completer<void>();
  bool blockNextClear = false;

  @override
  Future<void> clearAccountScopedValues() async {
    if (blockNextClear) {
      blockNextClear = false;
      clearStarted.complete();
      await allowClear.future;
    }
    await super.clearAccountScopedValues();
  }
}

void main() {
  test('normal package API exposes no raw journal authority', () {
    final storageSource = File(
      'lib/src/crypto_storage.dart',
    ).readAsStringSync();
    final barrelSource = File('lib/risaal_crypto.dart').readAsStringSync();

    for (final forbidden in <String>[
      'Future<KeyBundleReplacementJournal?> getKeyBundleReplacementJournal',
      'Future<void> saveKeyBundleReplacementJournal',
      'Future<bool> consumeOneTimePreKeyForGeneration',
      'Future<void> markInitialRegistrationIntent',
      'Future<String?> readRaw',
    ]) {
      expect(storageSource, isNot(contains(forbidden)), reason: forbidden);
    }
    final publicJournalMethods = RegExp(
      r'^  Future(?:<[^\n]+>)? ([A-Za-z]\w*(?:Journal|InitialRegistrationIntent)\w*)\s*\(',
      multiLine: true,
    ).allMatches(storageSource).map((match) => match.group(1)).toList();
    expect(publicJournalMethods, <String>[
      'hasInitialRegistrationIntent',
      'clearInitialRegistrationIntent',
      'validateKeyBundleReplacementJournal',
    ]);
    expect(barrelSource, isNot(contains('KeyBundleReplacementJournal')));
    expect(
      barrelSource,
      contains(
        "export 'src/key_bundle_replacement.dart'\n"
        '    show\n'
        '        GenerationRetirementPolicy,\n'
        '        GenerationRetirementView,\n'
        '        KeyBundleAcceptedReceipt,\n'
        '        KeyBundleReplacementCommitment,\n'
        '        KeyBundleReplacementPhase,\n'
        '        KeyBundleReplacementSnapshot,\n'
        '        OpkGenerationRole,\n'
        '        UnacceptedFreshRegistrationRecoveryRequired,\n'
        '        retirableGenerationIds;',
      ),
    );
  });

  group('server-compatible OPK commitments', () {
    test('matches the frozen TypeScript cross-language goldens', () {
      const opks = <OneTimePreKeyPublic>[
        OneTimePreKeyPublic(
          keyId: 7,
          publicKey: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
        ),
        OneTimePreKeyPublic(
          keyId: 3,
          publicKey: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
        ),
      ];

      final opkDigest = KeyBundleReplacementCommitment.opkSetDigest(
        opkGeneration: 9,
        oneTimePreKeys: opks,
      );
      expect(
        opkDigest,
        '80727ddacee11bf47be96b327c18b14fea09864efb5f8cccac81b495f55e9973',
      );
      expect(
        KeyBundleReplacementCommitment.bundlePublicMaterialDigest(
          identityKey: 'identity',
          identitySigningKey: 'identity-signing',
          signedPreKeyId: 11,
          signedPreKeyPublicKey: 'spk',
          signedPreKeySignature: 'spk-sig',
          kemKeyId: 21,
          kemPublicKey: 'kem',
          kemSignature: 'kem-sig',
          cryptoProtocolEpoch: 2,
          kemSuite: 'ML-KEM-768',
          kemStandard: 'FIPS203',
          kemWireVersion: 1,
          opkGeneration: 9,
          opkSetDigest: opkDigest,
          opkSetCount: 2,
          opkHighWaterKeyId: 7,
        ),
        '5252245ad783eb86301f16c3e5bba805e6bfc292ab48c354e353f838ae6a2c34',
      );
      expect(
        KeyBundleReplacementCommitment.opkSetDigest(
          opkGeneration: 9,
          oneTimePreKeys: const <OneTimePreKeyPublic>[
            OneTimePreKeyPublic(
              keyId: 10,
              publicKey: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
            ),
            OneTimePreKeyPublic(
              keyId: 2,
              publicKey: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
            ),
          ],
        ),
        'd1b5db3c01d2a05fa8fc662f8205856b445b3b1344e57a4c61ea91bda79df21b',
      );
    });

    test('rejects duplicate and noncanonical OPK public material', () {
      const first = OneTimePreKeyPublic(
        keyId: 1,
        publicKey: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
      );
      const second = OneTimePreKeyPublic(
        keyId: 2,
        publicKey: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
      );
      expect(
        () => KeyBundleReplacementCommitment.opkSetDigest(
          opkGeneration: 1,
          oneTimePreKeys: <OneTimePreKeyPublic>[
            first,
            OneTimePreKeyPublic(keyId: 1, publicKey: second.publicKey),
          ],
        ),
        throwsFormatException,
      );
      expect(
        () => KeyBundleReplacementCommitment.opkSetDigest(
          opkGeneration: 1,
          oneTimePreKeys: <OneTimePreKeyPublic>[
            first,
            OneTimePreKeyPublic(keyId: 2, publicKey: first.publicKey),
          ],
        ),
        throwsFormatException,
      );
      expect(
        () => KeyBundleReplacementCommitment.opkSetDigest(
          opkGeneration: 1,
          oneTimePreKeys: const <OneTimePreKeyPublic>[
            OneTimePreKeyPublic(
              keyId: 1,
              publicKey: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ',
            ),
          ],
        ),
        throwsFormatException,
      );
      expect(
        KeyBundleReplacementCommitment.canonicalOneTimePreKeys(
          const <OneTimePreKeyPublic>[second, first],
        ).map((key) => key.keyId),
        <int>[1, 2],
      );
    });
  });

  group('accepted receipt contract', () {
    test('normalizes every malformed field type to FormatException', () {
      final valid = _frozenReceiptJson();
      expect(KeyBundleAcceptedReceipt.fromJson(valid).toJson(), valid);

      for (final field in valid.keys) {
        final wrongType = Map<String, dynamic>.from(valid)..[field] = true;
        expect(
          () => KeyBundleAcceptedReceipt.fromJson(wrongType),
          throwsFormatException,
          reason: field,
        );
        final missing = Map<String, dynamic>.from(valid)..remove(field);
        expect(
          () => KeyBundleAcceptedReceipt.fromJson(missing),
          throwsFormatException,
          reason: 'missing $field',
        );
      }
      expect(
        () => KeyBundleAcceptedReceipt.fromJson(
          Map<String, dynamic>.from(valid)..['opkAcceptedBundleRevision'] = 8,
        ),
        throwsFormatException,
      );
      expect(
        () => KeyBundleAcceptedReceipt.fromMutationResponseData(
          <String, dynamic>{'accepted': <Object>[]},
        ),
        throwsFormatException,
      );
    });

    test('parses direct, nested, and fully bound owner response shapes', () {
      final valid = _frozenReceiptJson();
      final receipt = KeyBundleAcceptedReceipt.fromJson(valid);
      expect(KeyBundleAcceptedReceipt.fromMutationResponseData(valid), receipt);
      expect(
        KeyBundleAcceptedReceipt.fromMutationResponseData(<String, dynamic>{
          'accepted': valid,
          'remainingOpkCount': 0,
        }),
        receipt,
      );
      final owner = <String, dynamic>{
        'bundleRevision': 9,
        'opkGeneration': 9,
        'opkSetDigest': valid['opkSetDigest'],
        'identityKey': 'identity',
        'identitySigningKey': 'identity-signing',
        'signedPreKey': <String, dynamic>{
          'keyId': 11,
          'publicKey': 'spk',
          'signature': 'spk-sig',
        },
        'kyberPreKey': <String, dynamic>{
          'keyId': 21,
          'publicKey': 'kem',
          'signature': 'kem-sig',
          'cryptoProtocolEpoch': 2,
          'kemSuite': 'ML-KEM-768',
          'kemStandard': 'FIPS203',
          'kemWireVersion': 1,
        },
        'oneTimePreKey': null,
        'remainingOpkCount': 0,
        'accepted': valid,
      };
      expect(KeyBundleAcceptedReceipt.fromOwnerKeyBundleData(owner), receipt);
      expect(
        () => KeyBundleAcceptedReceipt.fromMutationResponseData(owner),
        throwsFormatException,
      );
      for (final missingAccepted in <Object?>[null, const <Object>[]]) {
        final invalidOwner = Map<String, dynamic>.from(owner)
          ..['accepted'] = missingAccepted;
        expect(
          () => KeyBundleAcceptedReceipt.fromOwnerKeyBundleData(invalidOwner),
          throwsFormatException,
        );
      }
      final absentAccepted = Map<String, dynamic>.from(owner)
        ..remove('accepted');
      expect(
        () => KeyBundleAcceptedReceipt.fromOwnerKeyBundleData(absentAccepted),
        throwsFormatException,
      );

      final mutations = <void Function(Map<String, dynamic>)>[
        (value) => value['bundleRevision'] = 10,
        (value) => value['opkGeneration'] = 10,
        (value) => value['opkSetDigest'] = '${valid['opkSetDigest']}0',
        (value) => value['identityKey'] = 'different',
        (value) => value['identitySigningKey'] = 'different',
        (value) => (value['signedPreKey'] as Map)['keyId'] = 12,
        (value) => (value['signedPreKey'] as Map)['publicKey'] = 'different',
        (value) => (value['signedPreKey'] as Map)['signature'] = 'different',
        (value) => (value['kyberPreKey'] as Map)['keyId'] = 22,
        (value) => (value['kyberPreKey'] as Map)['publicKey'] = 'different',
        (value) => (value['kyberPreKey'] as Map)['signature'] = 'different',
        (value) => (value['kyberPreKey'] as Map)['cryptoProtocolEpoch'] = 3,
        (value) => (value['kyberPreKey'] as Map)['kemSuite'] = 'different',
        (value) => (value['kyberPreKey'] as Map)['kemStandard'] = 'different',
        (value) => (value['kyberPreKey'] as Map)['kemWireVersion'] = 2,
      ];
      for (final mutate in mutations) {
        final drift = Map<String, dynamic>.from(
          jsonDecode(jsonEncode(owner)) as Map,
        );
        mutate(drift);
        expect(
          () => KeyBundleAcceptedReceipt.fromOwnerKeyBundleData(drift),
          throwsFormatException,
        );
      }
    });
  });

  group('KeyBundleReplacementJournal lifecycle', () {
    late FakeSecureStorage storage;
    late SignalProtocolManager manager;

    setUp(() async {
      storage = FakeSecureStorage();
      manager = SignalProtocolManager(secureStorage: storage);
      await manager.wipeForFreshRegistration();
      await manager.initialize();
    });

    test(
      'flat material is quarantined and dispatch payload is journal-only',
      () async {
        final legacy =
            (jsonDecode(storage.store['crypto_one_time_pre_keys']!) as List)
                .cast<Map<String, dynamic>>();
        final legacyIds = legacy.map((value) => value['keyId'] as int).toSet();

        final prepared = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 4,
        );
        expect(prepared.opkGeneration, 1);
        expect(prepared.opkSetCount, 4);
        expect(
          prepared.oneTimePreKeyIds.toSet().intersection(legacyIds),
          isEmpty,
        );

        final journal = await _readJournalForTest(storage);
        expect(journal!.phase, KeyBundleReplacementPhase.prepared);
        expect(
          journal.generations
              .singleWhere(
                (entry) => entry.role == OpkGenerationRole.legacyQuarantined,
              )
              .oneTimePreKeys
              .map((key) => key.keyId)
              .toSet(),
          legacyIds,
        );

        await manager.installKeyBundleReplacement(prepared);
        expect(storage.store['crypto_one_time_pre_keys'], '[]');

        final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
          prepared,
        );
        final payload = dispatch.toReplacementPayload(deviceId: 'device-a');
        final uploadedIds = (payload['oneTimePreKeys'] as List)
            .cast<Map<String, dynamic>>()
            .map((value) => value['keyId'] as int)
            .toSet();
        expect(uploadedIds, prepared.oneTimePreKeyIds.toSet());
        expect(uploadedIds.intersection(legacyIds), isEmpty);
        expect(payload['replacementId'], prepared.replacementId);
        expect(payload['opkGeneration'], 1);
        expect(payload['opkSetDigest'], prepared.opkSetDigest);
        expect(payload['opkSetCount'], 4);
        expect(payload['opkHighWaterKeyId'], prepared.opkHighWaterKeyId);
        expect(
          payload['bundlePublicMaterialDigest'],
          prepared.bundlePublicMaterialDigest,
        );
      },
    );

    test(
      'prepared snapshot is opaque and registration bytes require dispatch',
      () async {
        final prepared = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        final serializedHandle = prepared.toJournalJson();
        expect(serializedHandle.keys.toSet(), <String>{
          'expectedBundleRevision',
          'replacementId',
          'opkGeneration',
          'opkSetDigest',
          'opkSetCount',
          'opkHighWaterKeyId',
          'bundlePublicMaterialDigest',
          'signedPreKeyId',
          'kemKeyId',
          'oneTimePreKeyIds',
        });
        expect(jsonEncode(serializedHandle), isNot(contains('publicKey')));
        expect(jsonEncode(serializedHandle), isNot(contains('identityKey')));
        expect(jsonEncode(serializedHandle), isNot(contains('oneTimePreKeys')));

        await manager.installKeyBundleReplacement(prepared);
        final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
          prepared,
        );
        final registration = dispatch.toInitialRegistrationKeyBundle();
        expect(registration.keys.toSet(), <String>{
          'replacementId',
          'opkGeneration',
          'opkSetDigest',
          'opkSetCount',
          'opkHighWaterKeyId',
          'bundlePublicMaterialDigest',
          'identityKey',
          'identitySigningKey',
          'signedPreKey',
          'oneTimePreKeys',
          'kyberPreKey',
        });
        expect(registration, isNot(contains('expectedBundleRevision')));
        expect(registration, isNot(contains('deviceId')));
      },
    );

    test(
      'lost ACK converges after restart without changing dispatch bytes',
      () async {
        final prepared = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 3,
        );
        await manager.installKeyBundleReplacement(prepared);
        final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
          prepared,
        );
        final payloadBefore = jsonEncode(
          dispatch.toReplacementPayload(deviceId: 'device-a'),
        );

        final usedId = prepared.oneTimePreKeyIds.first;
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: prepared.opkGeneration,
            keyId: usedId,
          ),
          isTrue,
        );
        await _consumeThroughAuthenticatedPreKey(
          responder: manager,
          snapshot: prepared,
          publicMaterial: dispatch.toReplacementPayload(deviceId: 'device-a'),
          keyId: usedId,
        );

        final restarted = SignalProtocolManager(secureStorage: storage);
        final resumed = await restarted.resumeKeyBundleReplacement();
        expect(
          jsonEncode(resumed!.toReplacementPayload(deviceId: 'device-a')),
          payloadBefore,
          reason: 'private-key consumption must not mutate the public proposal',
        );
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: prepared.opkGeneration,
            keyId: usedId,
          ),
          isFalse,
        );

        expect(
          await restarted.reconcileKeyBundleReplacement(
            _ownerResponseFor(resumed),
          ),
          isTrue,
        );
        expect(await restarted.pendingKeyBundleReplacement(), isNull);
        expect(
          (await _readJournalForTest(storage))!.acceptedReceipt,
          _receiptFor(prepared),
        );
      },
    );

    test(
      'authenticated recovery preserves an exact old server baseline for dispatch',
      () async {
        final oldStorage = FakeSecureStorage();
        final oldManager = SignalProtocolManager(secureStorage: oldStorage);
        await oldManager.wipeForFreshRegistration();
        await oldManager.initialize();
        final oldSnapshot = await oldManager
            .prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 2);
        await oldManager.installKeyBundleReplacement(oldSnapshot);
        final oldDispatch = await oldManager
            .markKeyBundleReplacementDispatchStarted(oldSnapshot);
        final oldOwnerState = _ownerResponseFor(oldDispatch);
        final oldReceipt = _receiptFor(oldSnapshot);

        final recoveredStorage = FakeSecureStorage();
        final recovered = SignalProtocolManager(
          secureStorage: recoveredStorage,
        );
        expect(
          await recovered.beginAuthenticatedAccountRecovery(oldReceipt),
          isTrue,
        );
        await recovered.initialize();
        final replacement = await recovered.prepareKeyBundleReplacement(
          acceptedReceipt: oldReceipt,
          oneTimePreKeyCount: 2,
        );
        await recovered.installKeyBundleReplacement(replacement);
        await recovered.markKeyBundleReplacementDispatchStarted(replacement);

        expect(
          await recovered.reconcileKeyBundleReplacement(oldOwnerState),
          isFalse,
          reason: 'the exact old receipt means N+1 still needs dispatch',
        );
        final stillPending = await recovered.pendingKeyBundleReplacement();
        expect(
          stillPending != null && stillPending.matches(replacement),
          isTrue,
          reason: 'reconcile must preserve the byte-identical pending upload',
        );
      },
    );

    test(
      'authenticated account replaces a different unaccepted fresh proposal',
      () async {
        final serverStorage = FakeSecureStorage();
        final serverManager = SignalProtocolManager(
          secureStorage: serverStorage,
        );
        await serverManager.wipeForFreshRegistration();
        await serverManager.initialize();
        final serverSnapshot = await serverManager
            .prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 2);
        await serverManager.installKeyBundleReplacement(serverSnapshot);
        final serverDispatch = await serverManager
            .markKeyBundleReplacementDispatchStarted(serverSnapshot);
        final ownerState = _ownerResponseFor(serverDispatch);
        final ownerReceipt = _receiptFor(serverSnapshot);

        final abandonedStorage = FakeSecureStorage();
        final abandoned = SignalProtocolManager(
          secureStorage: abandonedStorage,
        );
        await abandoned.wipeForFreshRegistration();
        await abandoned.initialize();
        final abandonedSnapshot = await abandoned
            .prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 2);
        await abandoned.installKeyBundleReplacement(abandonedSnapshot);
        await abandoned.markKeyBundleReplacementDispatchStarted(
          abandonedSnapshot,
        );

        await expectLater(
          abandoned.reconcileKeyBundleReplacement(ownerState),
          throwsA(isA<UnacceptedFreshRegistrationRecoveryRequired>()),
        );
        await abandoned
            .replaceUnacceptedFreshRegistrationWithAuthenticatedRecovery(
              ownerReceipt,
            );
        final recoveryJournal = (await _readJournalForTest(abandonedStorage))!;
        expect(recoveryJournal.phase, isNull);
        expect(recoveryJournal.acceptedReceipt, isNull);
        expect(recoveryJournal.adoptedBaselineReceipt, ownerReceipt);
        expect(recoveryJournal.generations, isEmpty);

        await abandoned.initialize();
        final replacement = await abandoned.prepareKeyBundleReplacement(
          acceptedReceipt: ownerReceipt,
          oneTimePreKeyCount: 2,
        );
        expect(replacement.expectedBundleRevision, ownerReceipt.bundleRevision);
        expect(replacement.opkGeneration, ownerReceipt.opkGeneration + 1);
        await abandoned.installKeyBundleReplacement(replacement);
        await abandoned.markKeyBundleReplacementDispatchStarted(replacement);
        final acceptedReplacement = _receiptFor(replacement);
        expect(
          await abandoned.acknowledgeKeyBundleReplacement(
            snapshot: replacement,
            acceptance: acceptedReplacement,
          ),
          isTrue,
        );
        final acceptedJournal = (await _readJournalForTest(abandonedStorage))!;
        expect(acceptedJournal.acceptedReceipt, acceptedReplacement);
        expect(acceptedJournal.adoptedBaselineReceipt, ownerReceipt);
      },
    );

    test(
      'owner reconcile rejects outer routing drift without journal mutation',
      () async {
        final prepared = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(prepared);
        final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
          prepared,
        );
        final owner = _ownerResponseFor(dispatch);
        final baseline = storage.store[_journalStorageKey];
        final mutations = <void Function(Map<String, dynamic>)>[
          (value) =>
              value['bundleRevision'] = (value['bundleRevision'] as int) + 1,
          (value) =>
              value['opkGeneration'] = (value['opkGeneration'] as int) + 1,
          (value) => value['opkSetDigest'] = '0' * 64,
          (value) => value['identityKey'] = 'different',
          (value) => (value['signedPreKey'] as Map)['publicKey'] = 'different',
          (value) => (value['kyberPreKey'] as Map)['publicKey'] = 'different',
        ];

        for (final mutate in mutations) {
          final drift = Map<String, dynamic>.from(
            jsonDecode(jsonEncode(owner)) as Map,
          );
          mutate(drift);
          await expectLater(
            manager.reconcileKeyBundleReplacement(drift),
            throwsFormatException,
          );
          expect(storage.store[_journalStorageKey], baseline);
        }

        expect(await manager.reconcileKeyBundleReplacement(owner), isTrue);
      },
    );

    test('every receipt-field drift leaves the same proposal pending', () async {
      final prepared = await manager.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 2,
      );
      await manager.installKeyBundleReplacement(prepared);
      await manager.markKeyBundleReplacementDispatchStarted(prepared);
      final exact = _receiptFor(prepared);
      final drifts = <KeyBundleAcceptedReceipt>[
        exact.copyWith(bundleRevision: exact.bundleRevision + 1),
        exact.copyWith(signedPreKeyId: exact.signedPreKeyId + 1),
        exact.copyWith(kemKeyId: exact.kemKeyId + 1),
        exact.copyWith(cryptoProtocolEpoch: exact.cryptoProtocolEpoch + 1),
        exact.copyWith(replacementId: '${exact.replacementId}x'),
        exact.copyWith(
          opkAcceptedBundleRevision: exact.opkAcceptedBundleRevision + 1,
        ),
        exact.copyWith(opkGeneration: exact.opkGeneration + 1),
        exact.copyWith(
          opkSetDigest:
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ),
        exact.copyWith(opkSetCount: exact.opkSetCount + 1),
        exact.copyWith(opkHighWaterKeyId: exact.opkHighWaterKeyId + 1),
        exact.copyWith(
          bundlePublicMaterialDigest:
              'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ),
      ];
      for (final drift in drifts) {
        await expectLater(
          manager.acknowledgeKeyBundleReplacement(
            snapshot: prepared,
            acceptance: drift,
          ),
          throwsFormatException,
        );
      }
      expect(
        (await manager.pendingKeyBundleReplacement())!.replacementId,
        prepared.replacementId,
      );
    });

    test(
      'finalized ACK replay is exact, idempotent, and never rewrites state',
      () async {
        final prepared = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(prepared);
        await manager.markKeyBundleReplacementDispatchStarted(prepared);
        final accepted = _receiptFor(prepared);
        expect(
          await manager.acknowledgeKeyBundleReplacement(
            snapshot: prepared,
            acceptance: accepted,
          ),
          isTrue,
        );
        final restarted = SignalProtocolManager(secureStorage: storage);
        final baseline = Map<String, String>.from(storage.store);
        expect(
          await restarted.acknowledgeKeyBundleReplacement(
            snapshot: prepared,
            acceptance: accepted,
          ),
          isFalse,
        );
        expect(storage.store, baseline);

        final receiptDrifts = <KeyBundleAcceptedReceipt>[
          accepted.copyWith(bundleRevision: accepted.bundleRevision + 1),
          accepted.copyWith(signedPreKeyId: accepted.signedPreKeyId + 1),
          accepted.copyWith(kemKeyId: accepted.kemKeyId + 1),
          accepted.copyWith(
            cryptoProtocolEpoch: accepted.cryptoProtocolEpoch + 1,
          ),
          accepted.copyWith(replacementId: '${accepted.replacementId}x'),
          accepted.copyWith(
            opkAcceptedBundleRevision: accepted.opkAcceptedBundleRevision + 1,
          ),
          accepted.copyWith(opkGeneration: accepted.opkGeneration + 1),
          accepted.copyWith(opkSetDigest: 'a' * 64),
          accepted.copyWith(opkSetCount: accepted.opkSetCount + 1),
          accepted.copyWith(opkHighWaterKeyId: accepted.opkHighWaterKeyId + 1),
          accepted.copyWith(bundlePublicMaterialDigest: 'b' * 64),
        ];
        for (final drift in receiptDrifts) {
          await expectLater(
            restarted.acknowledgeKeyBundleReplacement(
              snapshot: prepared,
              acceptance: drift,
            ),
            throwsA(anything),
          );
          expect(storage.store, baseline);
        }

        final snapshotJson = Map<String, dynamic>.from(
          prepared.toJournalJson(),
        );
        snapshotJson['replacementId'] = '${prepared.replacementId}x';
        final driftedSnapshot = KeyBundleReplacementSnapshot.fromJournalJson(
          snapshotJson,
        );
        await expectLater(
          restarted.acknowledgeKeyBundleReplacement(
            snapshot: driftedSnapshot,
            acceptance: accepted,
          ),
          throwsFormatException,
        );
        expect(storage.store, baseline);
      },
    );

    test(
      'pending prepare retry still cross-checks the supplied receipt',
      () async {
        final first = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(first);
        await manager.markKeyBundleReplacementDispatchStarted(first);
        final accepted = _receiptFor(first);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: first,
          acceptance: accepted,
        );
        final pending = await manager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: 2,
        );

        await expectLater(
          manager.prepareKeyBundleReplacement(
            acceptedReceipt: accepted.copyWith(
              replacementId: '${accepted.replacementId}x',
            ),
            oneTimePreKeyCount: 2,
          ),
          throwsFormatException,
        );
        expect(
          (await manager.pendingKeyBundleReplacement())!.matches(pending),
          isTrue,
        );
      },
    );

    test('N remains lookup-only after accepted N+1 and N+2', () async {
      final first = await manager.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 3,
      );
      Future<void> expectFirstGenerationVisibility(bool visible) async {
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: first.opkGeneration,
            keyId: first.oneTimePreKeyIds.last,
          ),
          visible,
        );
        expect(
          await _hasRoutableSignedPreKeyForTest(
            storage,
            opkGeneration: first.opkGeneration,
            keyId: first.signedPreKeyId,
          ),
          visible,
        );
        expect(
          await _hasRoutableKyberKeyForTest(
            storage,
            opkGeneration: first.opkGeneration,
            keyId: first.kemKeyId,
          ),
          visible,
        );
      }

      await expectFirstGenerationVisibility(false);
      await manager.installKeyBundleReplacement(first);
      await expectFirstGenerationVisibility(false);
      await manager.markKeyBundleReplacementDispatchStarted(first);
      await expectFirstGenerationVisibility(true);
      await manager.acknowledgeKeyBundleReplacement(
        snapshot: first,
        acceptance: _receiptFor(first),
      );
      final retainedKeyId = first.oneTimePreKeyIds.last;

      final second = await manager.prepareKeyBundleReplacement(
        oneTimePreKeyCount: 3,
      );
      await manager.installKeyBundleReplacement(second);
      await manager.markKeyBundleReplacementDispatchStarted(second);
      await manager.acknowledgeKeyBundleReplacement(
        snapshot: second,
        acceptance: _receiptFor(second),
      );

      await storage.write(key: 'crypto_e2_next_signed_pre_key_id', value: '1');
      await storage.write(key: 'crypto_e2_next_kyber_key_id', value: '1');
      await storage.write(key: 'crypto_next_pre_key_id', value: '1');

      final third = await manager.prepareKeyBundleReplacement(
        oneTimePreKeyCount: 3,
      );
      expect(third.signedPreKeyId, greaterThan(second.signedPreKeyId));
      expect(third.kemKeyId, greaterThan(second.kemKeyId));
      expect(
        third.oneTimePreKeyIds.first,
        greaterThan(second.opkHighWaterKeyId),
      );
      await manager.installKeyBundleReplacement(third);
      await manager.markKeyBundleReplacementDispatchStarted(third);
      await manager.acknowledgeKeyBundleReplacement(
        snapshot: third,
        acceptance: _receiptFor(third),
      );

      expect(first.opkGeneration, 1);
      expect(second.opkGeneration, 2);
      expect(third.opkGeneration, 3);
      expect(
        await _hasRoutableOneTimePreKeyForTest(
          storage,
          opkGeneration: 1,
          keyId: retainedKeyId,
        ),
        isTrue,
      );
      expect(
        await _hasRoutableSignedPreKeyForTest(
          storage,
          opkGeneration: 1,
          keyId: first.signedPreKeyId,
        ),
        isTrue,
      );
      expect(
        await _hasRoutableKyberKeyForTest(
          storage,
          opkGeneration: 1,
          keyId: first.kemKeyId,
        ),
        isTrue,
      );
      expect(
        await _hasRoutableOneTimePreKeyForTest(
          storage,
          opkGeneration: 2,
          keyId: retainedKeyId,
        ),
        isFalse,
        reason: 'a key id must never route without its exact generation',
      );
      expect(
        await _hasRoutableSignedPreKeyForTest(
          storage,
          opkGeneration: third.opkGeneration,
          keyId: first.signedPreKeyId,
        ),
        isFalse,
      );
      expect(
        await _hasRoutableKyberKeyForTest(
          storage,
          opkGeneration: third.opkGeneration,
          keyId: first.kemKeyId,
        ),
        isFalse,
      );
      final versioned = (await _readJournalForTest(storage))!.generations
          .where((entry) => entry.opkGeneration > 0)
          .toList(growable: false);
      expect(
        versioned.map((entry) => entry.signedPreKey!.keyPair.publicKey).toSet(),
        hasLength(3),
      );
      expect(
        versioned.map((entry) => entry.kyberKeyPair!.publicKey).toSet(),
        hasLength(3),
      );
      expect(
        versioned
            .expand((entry) => entry.publicOneTimePreKeys)
            .map((key) => key.publicKey)
            .toSet(),
        hasLength(9),
      );
    });

    test(
      'consumed generation keeps immutable public uniqueness history',
      () async {
        final first = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 3,
        );
        await manager.installKeyBundleReplacement(first);
        final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
          first,
        );
        for (final keyId in first.oneTimePreKeyIds) {
          await _consumeThroughAuthenticatedPreKey(
            responder: manager,
            snapshot: first,
            publicMaterial: dispatch.toReplacementPayload(deviceId: 'device-a'),
            keyId: keyId,
          );
        }
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: first,
          acceptance: _receiptFor(first),
        );
        final second = await manager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: 3,
        );
        final restartedJournal = await _readJournalForTest(storage);
        final firstGeneration = restartedJournal!.generations.singleWhere(
          (entry) => entry.opkGeneration == first.opkGeneration,
        );
        final secondGeneration = restartedJournal.generations.singleWhere(
          (entry) => entry.opkGeneration == second.opkGeneration,
        );

        expect(firstGeneration.oneTimePreKeys, isEmpty);
        expect(
          firstGeneration.consumedOneTimePreKeyIds,
          first.oneTimePreKeyIds.toSet(),
        );
        expect(
          firstGeneration.publicOneTimePreKeys,
          hasLength(first.opkSetCount),
        );
        expect(
          firstGeneration.publicOneTimePreKeys
              .map((key) => key.keyId)
              .toSet()
              .intersection(
                secondGeneration.publicOneTimePreKeys
                    .map((key) => key.keyId)
                    .toSet(),
              ),
          isEmpty,
        );
        expect(
          firstGeneration.publicOneTimePreKeys
              .map((key) => key.publicKey)
              .toSet()
              .intersection(
                secondGeneration.publicOneTimePreKeys
                    .map((key) => key.publicKey)
                    .toSet(),
              ),
          isEmpty,
        );
      },
    );

    test('legacy upload and mutation entry points fail closed', () async {
      const oldGeneration = KeyBundleGeneration(
        signedPreKeyId: 1,
        kemKeyId: 1,
        cryptoProtocolEpoch: 2,
        publicMaterialDigest:
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      );
      final oldSnapshot = KeyBundleUploadSnapshot(
        keyBundle: const <String, dynamic>{},
        generation: oldGeneration,
        expectedBundleRevision: 0,
      );
      const oldAcceptance = KeyBundleUploadAcceptance(
        bundleRevision: 1,
        generation: oldGeneration,
      );

      final operations = <Future<Object?> Function()>[
        manager.generateKeyBundle,
        manager.createKeyBundleUploadSnapshot,
        () => manager.acknowledgeKeyBundleUpload(
          snapshot: oldSnapshot,
          acceptance: oldAcceptance,
        ),
        () => manager.reconcileObservedServerBundle(oldAcceptance),
        () => manager.rotateSignedPreKeyIfNeeded(maxAge: Duration.zero),
        () => manager.rotateKyberKeyIfNeeded(maxAge: Duration.zero),
        () => manager.rotateKeysIfNeeded(
          signedPreKeyMaxAge: Duration.zero,
          kyberKeyMaxAge: Duration.zero,
        ),
        manager.forceKeyRotationNow,
        () => manager.generateOneTimePreKeys(3),
      ];
      for (final operation in operations) {
        await expectLater(operation(), throwsUnsupportedError);
      }
    });

    test(
      'two managers sharing storage converge on one immutable proposal',
      () async {
        final secondManager = SignalProtocolManager(secureStorage: storage);

        final proposals = await Future.wait(
          <Future<KeyBundleReplacementSnapshot>>[
            manager.prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 3),
            secondManager.prepareInitialKeyBundleRegistration(
              oneTimePreKeyCount: 3,
            ),
          ],
        );

        expect(proposals[0].matches(proposals[1]), isTrue);
        final journal = await _readJournalForTest(storage);
        expect(journal!.proposal!.snapshot.matches(proposals[0]), isTrue);
        expect(journal.proposal!.snapshot.matches(proposals[1]), isTrue);
      },
    );

    test(
      'two managers with different counts preserve the winning proposal',
      () async {
        final secondManager = SignalProtocolManager(secureStorage: storage);
        final winningFuture = manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 3,
        );
        final conflictingFuture = secondManager
            .prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 4);

        final winning = await winningFuture;
        await expectLater(conflictingFuture, throwsStateError);

        final journal = await _readJournalForTest(storage);
        expect(journal!.proposal!.snapshot.matches(winning), isTrue);
        expect(journal.proposal!.snapshot.opkSetCount, 3);
      },
    );

    test(
      'distinct adapters over one backend share the proposal transition',
      () async {
        final backend = <String, String>{};
        final firstStorage = _SharedBackendStorage(backend);
        final secondStorage = _SharedBackendStorage(backend);
        final firstManager = SignalProtocolManager(secureStorage: firstStorage);
        final secondManager = SignalProtocolManager(
          secureStorage: secondStorage,
        );
        await firstManager.wipeForFreshRegistration();
        await firstManager.initialize();

        final proposals =
            await Future.wait(<Future<KeyBundleReplacementSnapshot>>[
              firstManager.prepareInitialKeyBundleRegistration(
                oneTimePreKeyCount: 3,
              ),
              secondManager.prepareInitialKeyBundleRegistration(
                oneTimePreKeyCount: 3,
              ),
            ]);

        expect(proposals[0].matches(proposals[1]), isTrue);
        final journal = await _readJournalForTest(firstStorage);
        expect(journal!.proposal!.snapshot.matches(proposals[0]), isTrue);
        expect(journal.proposal!.snapshot.matches(proposals[1]), isTrue);
      },
    );

    test(
      'fresh-account wipe serializes against another manager prepare',
      () async {
        final blockingStorage = _BlockingClearStorage();
        final firstManager = SignalProtocolManager(
          secureStorage: blockingStorage,
        );
        final secondManager = SignalProtocolManager(
          secureStorage: blockingStorage,
        );
        await firstManager.wipeForFreshRegistration();
        await firstManager.initialize();
        final initial = await firstManager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await firstManager.installKeyBundleReplacement(initial);
        await firstManager.markKeyBundleReplacementDispatchStarted(initial);
        await firstManager.acknowledgeKeyBundleReplacement(
          snapshot: initial,
          acceptance: _receiptFor(initial),
        );

        blockingStorage.blockNextClear = true;
        final wipe = firstManager.wipeForFreshRegistration();
        await blockingStorage.clearStarted.future;
        final racingPrepare = secondManager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: 2,
        );
        await Future<void>.delayed(Duration.zero);
        blockingStorage.allowClear.complete();

        await wipe;
        await expectLater(racingPrepare, throwsStateError);
        final cryptoStorage = CryptoStorage(secureStorage: blockingStorage);
        expect(await cryptoStorage.hasInitialRegistrationIntent(), isTrue);
        expect(await _readJournalForTest(blockingStorage), isNull);
      },
    );

    test('a current account without journal provenance is adopted into '
        'quarantine and still cannot message', () async {
      // This used to assert `initialize()` threw AND mutated nothing at all.
      // That was correct while nothing could distinguish a pre-journal
      // install from corruption — but the cost landed entirely on the user:
      // the app refused to start, and the only remedy on offer was a
      // fresh-account wipe, which destroys the identity key and makes every
      // contact see what looks like an impersonation.
      //
      // The property that actually protects them is narrower: such a store
      // may be adopted, but ONLY into quarantine. It gains no routable and no
      // uploadable authority, and it still cannot message until an
      // authenticated generation is registered. That is what is asserted now.
      await CryptoStorage(
        secureStorage: storage,
      ).clearInitialRegistrationIntent();

      await expectLater(
        SignalProtocolManager(secureStorage: storage).initialize(),
        throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
        reason: 'messaging still requires an authenticated generation',
      );

      final raw = storage.store['crypto_e2_bundle_replacement_journal_v1'];
      expect(raw, isNotNull, reason: 'adoption records provenance');
      final journal = jsonDecode(raw!) as Map<String, dynamic>;
      expect(
        journal['acceptedReceipt'],
        isNull,
        reason: 'adoption never invents a server receipt',
      );
      final generations = (journal['generations'] as List)
          .cast<Map<String, dynamic>>();
      expect(
        generations.map((g) => g['role']).toSet(),
        {'legacyQuarantined'},
        reason:
            'unreceipted material has no authenticated revision/generation/'
            'digest tuple, so it is neither uploadable nor routable',
      );
    });

    test('blank storage cannot self-authorize initial registration', () async {
      final blank = FakeSecureStorage();
      final blankManager = SignalProtocolManager(secureStorage: blank);
      final before = Map<String, String>.from(blank.store);

      await expectLater(blankManager.initialize(), throwsStateError);
      await expectLater(
        blankManager.prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 2),
        throwsStateError,
      );
      expect(blank.store, before);
    });

    test(
      'corrupt journal material and invariants fail closed without writes',
      () async {
        await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        const journalKey = 'crypto_e2_bundle_replacement_journal_v1';
        final baseline = storage.store[journalKey]!;

        Map<String, dynamic> stagedGeneration(Map<String, dynamic> journal) =>
            (journal['generations'] as List)
                .cast<Map<String, dynamic>>()
                .singleWhere(
                  (entry) =>
                      entry['role'] == OpkGenerationRole.stagedUploadOnly.name,
                );
        Map<String, dynamic> quarantinedGeneration(
          Map<String, dynamic> journal,
        ) => (journal['generations'] as List)
            .cast<Map<String, dynamic>>()
            .singleWhere(
              (entry) =>
                  entry['role'] == OpkGenerationRole.legacyQuarantined.name,
            );
        void refreshBundleDigest(Map<String, dynamic> journal) {
          final staged = stagedGeneration(journal);
          final signed = Map<String, dynamic>.from(
            staged['signedPreKey'] as Map,
          );
          final kem = Map<String, dynamic>.from(staged['kyberKeyPair'] as Map);
          final proposal = Map<String, dynamic>.from(
            journal['proposal'] as Map,
          );
          final snapshot = Map<String, dynamic>.from(
            proposal['snapshot'] as Map,
          );
          snapshot['bundlePublicMaterialDigest'] =
              KeyBundleReplacementCommitment.bundlePublicMaterialDigest(
                identityKey: staged['identityKey'] as String,
                identitySigningKey: staged['identitySigningKey'] as String,
                signedPreKeyId: signed['keyId'] as int,
                signedPreKeyPublicKey:
                    (signed['keyPair'] as Map)['publicKey'] as String,
                signedPreKeySignature: signed['signature'] as String,
                kemKeyId: kem['keyId'] as int,
                kemPublicKey: kem['publicKey'] as String,
                kemSignature: staged['kemSignature'] as String,
                cryptoProtocolEpoch: kem['cryptoProtocolEpoch'] as int,
                kemSuite: kem['kemSuite'] as String,
                kemStandard: kem['kemStandard'] as String,
                kemWireVersion: kem['kemWireVersion'] as int,
                opkGeneration: snapshot['opkGeneration'] as int,
                opkSetDigest: snapshot['opkSetDigest'] as String,
                opkSetCount: snapshot['opkSetCount'] as int,
                opkHighWaterKeyId: snapshot['opkHighWaterKeyId'] as int,
              );
          proposal['snapshot'] = snapshot;
          journal['proposal'] = proposal;
        }

        final mutations = <void Function(Map<String, dynamic>)>[
          (journal) => journal['schemaVersion'] = 99,
          (journal) {
            journal['phase'] = KeyBundleReplacementPhase.installed.name;
            journal['installationApplied'] = false;
          },
          (journal) =>
              (journal['proposal'] as Map)['snapshot']['replacementId'] =
                  'different',
          (
            journal,
          ) => (journal['proposal'] as Map)['snapshot']['opkSetDigest'] =
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          (journal) =>
              (journal['proposal'] as Map)['snapshot']['opkSetCount'] = 3,
          (journal) =>
              (journal['proposal'] as Map)['snapshot']['opkHighWaterKeyId'] =
                  ((journal['proposal'] as Map)['snapshot']['opkHighWaterKeyId']
                      as int) +
                  1,
          (journal) =>
              (journal['proposal']
                      as Map)['snapshot']['bundlePublicMaterialDigest'] =
                  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          (journal) {
            final staged = stagedGeneration(journal);
            final legacy = quarantinedGeneration(journal);
            (staged['publicOneTimePreKeys'] as List).first['publicKey'] =
                (legacy['publicOneTimePreKeys'] as List).first['publicKey'];
          },
          (journal) {
            final staged = stagedGeneration(journal);
            final legacy = quarantinedGeneration(journal);
            final privateKey =
                (legacy['signedPreKey'] as Map)['keyPair']['privateKey'];
            (staged['signedPreKey'] as Map)['keyPair']['privateKey'] =
                privateKey;
            (journal['proposal']
                    as Map)['signedPreKey']['keyPair']['privateKey'] =
                privateKey;
          },
          (journal) {
            final staged = stagedGeneration(journal);
            final legacy = quarantinedGeneration(journal);
            final privateKey = (legacy['kyberKeyPair'] as Map)['privateKey'];
            (staged['kyberKeyPair'] as Map)['privateKey'] = privateKey;
            (journal['proposal'] as Map)['kyberKeyPair']['privateKey'] =
                privateKey;
          },
          (journal) {
            final privateKeys =
                (stagedGeneration(journal)['oneTimePreKeys'] as List)
                    .cast<Map<String, dynamic>>();
            final firstPrivate = privateKeys[0]['keyPair']['privateKey'];
            privateKeys[0]['keyPair']['privateKey'] =
                privateKeys[1]['keyPair']['privateKey'];
            privateKeys[1]['keyPair']['privateKey'] = firstPrivate;
          },
          (journal) {
            final invalidSignature = base64Encode(List<int>.filled(64, 0));
            final staged = stagedGeneration(journal);
            staged['signedPreKey']['signature'] = invalidSignature;
            (journal['proposal'] as Map)['signedPreKey']['signature'] =
                invalidSignature;
            refreshBundleDigest(journal);
          },
          (journal) {
            final invalidSignature = base64Encode(List<int>.filled(64, 0));
            stagedGeneration(journal)['kemSignature'] = invalidSignature;
            refreshBundleDigest(journal);
          },
        ];

        for (final mutate in mutations) {
          final corrupt = Map<String, dynamic>.from(
            jsonDecode(baseline) as Map,
          );
          mutate(corrupt);
          await storage.write(key: journalKey, value: jsonEncode(corrupt));
          final before = Map<String, String>.from(storage.store);
          await expectLater(
            _readJournalForTest(storage),
            throwsFormatException,
          );
          expect(storage.store, before);
        }
        await storage.write(key: journalKey, value: baseline);
      },
    );

    test(
      'accepted role cannot be coherently swapped to an older receipt',
      () async {
        final first = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(first);
        await manager.markKeyBundleReplacementDispatchStarted(first);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: first,
          acceptance: _receiptFor(first),
        );
        final second = await manager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(second);
        await manager.markKeyBundleReplacementDispatchStarted(second);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: second,
          acceptance: _receiptFor(second),
        );

        const journalKey = 'crypto_e2_bundle_replacement_journal_v1';
        final corrupt = Map<String, dynamic>.from(
          jsonDecode(storage.store[journalKey]!) as Map,
        );
        final versioned =
            (corrupt['generations'] as List)
                .cast<Map<String, dynamic>>()
                .where((entry) => (entry['opkGeneration'] as int) > 0)
                .toList()
              ..sort(
                (left, right) => (left['opkGeneration'] as int).compareTo(
                  right['opkGeneration'] as int,
                ),
              );
        versioned.first['role'] = OpkGenerationRole.acceptedLookupOnly.name;
        versioned.last['role'] = OpkGenerationRole.retainedLookupOnly.name;
        corrupt['acceptedReceipt'] = versioned.first['acceptedReceipt'];
        await storage.write(key: journalKey, value: jsonEncode(corrupt));
        final before = Map<String, String>.from(storage.store);

        await expectLater(
          SignalProtocolManager(secureStorage: storage).initialize(),
          throwsFormatException,
        );
        expect(storage.store, before);
      },
    );

    test(
      'full journal audit still rejects corruption outside a selected route',
      () async {
        final first = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(first);
        await manager.markKeyBundleReplacementDispatchStarted(first);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: first,
          acceptance: _receiptFor(first),
        );
        final second = await manager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(second);
        await manager.markKeyBundleReplacementDispatchStarted(second);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: second,
          acceptance: _receiptFor(second),
        );

        const journalKey = 'crypto_e2_bundle_replacement_journal_v1';
        final raw = Map<String, dynamic>.from(
          jsonDecode(storage.store[journalKey]!) as Map,
        );
        final firstGeneration = (raw['generations'] as List)
            .cast<Map<String, dynamic>>()
            .singleWhere((entry) => entry['opkGeneration'] == 1);
        final privateKeys = (firstGeneration['oneTimePreKeys'] as List)
            .cast<Map<String, dynamic>>();
        final firstPrivate = privateKeys[0]['keyPair']['privateKey'];
        privateKeys[0]['keyPair']['privateKey'] =
            privateKeys[1]['keyPair']['privateKey'];
        privateKeys[1]['keyPair']['privateKey'] = firstPrivate;
        await storage.write(key: journalKey, value: jsonEncode(raw));

        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: second.opkGeneration,
            keyId: second.oneTimePreKeyIds.first,
          ),
          isTrue,
        );
        await expectLater(_readJournalForTest(storage), throwsFormatException);
      },
    );

    test('oversized journal record is rejected before parsing', () async {
      const journalKey = 'crypto_e2_bundle_replacement_journal_v1';
      await storage.write(
        key: journalKey,
        value: 'x' * (KeyBundleReplacementJournal.maxEncodedBytes + 1),
      );
      final before = Map<String, String>.from(storage.store);
      await expectLater(_readJournalForTest(storage), throwsFormatException);
      expect(storage.store, before);
    });

    test(
      'pre-prepared failure preserves reservation and exposes no material',
      () async {
        final faultStorage = _FaultInjectingStorage();
        final firstManager = SignalProtocolManager(secureStorage: faultStorage);
        await firstManager.wipeForFreshRegistration();
        await firstManager.initialize();
        faultStorage.failNextWrite(
          key: 'crypto_e2_bundle_replacement_journal_v1',
          journalPhase: KeyBundleReplacementPhase.prepared.name,
        );

        await expectLater(
          firstManager.prepareInitialKeyBundleRegistration(
            oneTimePreKeyCount: 3,
          ),
          throwsStateError,
        );
        final attempted = KeyBundleReplacementJournal.fromJson(
          Map<String, dynamic>.from(
            jsonDecode(faultStorage.attemptedValue!) as Map,
          ),
        ).proposal!.snapshot;
        final reserved = await _readJournalForTest(faultStorage);
        expect(reserved!.phase, KeyBundleReplacementPhase.reserved);
        expect(reserved.reservation!.replacementId, attempted.replacementId);
        expect(reserved.reservation!.opkGeneration, attempted.opkGeneration);
        expect(reserved.reservation!.signedPreKeyId, attempted.signedPreKeyId);
        expect(reserved.reservation!.kemKeyId, attempted.kemKeyId);
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            faultStorage,
            opkGeneration: attempted.opkGeneration,
            keyId: attempted.oneTimePreKeyIds.first,
          ),
          isFalse,
        );
        await expectLater(
          firstManager.markKeyBundleReplacementDispatchStarted(attempted),
          throwsStateError,
        );

        final restarted = SignalProtocolManager(secureStorage: faultStorage);
        await expectLater(
          restarted.initialize(),
          throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
        );
        final retried = await restarted.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 3,
        );

        expect(retried.replacementId, attempted.replacementId);
        expect(retried.opkGeneration, attempted.opkGeneration);
        expect(retried.signedPreKeyId, attempted.signedPreKeyId);
        expect(retried.kemKeyId, attempted.kemKeyId);
        expect(retried.oneTimePreKeyIds, attempted.oneTimePreKeyIds);
        final exactRetry = await SignalProtocolManager(
          secureStorage: faultStorage,
        ).prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 3);
        expect(exactRetry.matches(retried), isTrue);
      },
    );

    test(
      'fail-after prepared persistence resumes byte-identical proposal',
      () async {
        final faultStorage = _FaultInjectingStorage();
        final firstManager = SignalProtocolManager(secureStorage: faultStorage);
        await firstManager.wipeForFreshRegistration();
        await firstManager.initialize();
        faultStorage.failNextWrite(
          key: 'crypto_e2_bundle_replacement_journal_v1',
          journalPhase: KeyBundleReplacementPhase.prepared.name,
          afterWrite: true,
        );

        await expectLater(
          firstManager.prepareInitialKeyBundleRegistration(
            oneTimePreKeyCount: 3,
          ),
          throwsStateError,
        );
        final attempted = KeyBundleReplacementJournal.fromJson(
          Map<String, dynamic>.from(
            jsonDecode(faultStorage.attemptedValue!) as Map,
          ),
        ).proposal!.snapshot;

        final restarted = SignalProtocolManager(secureStorage: faultStorage);
        await expectLater(
          restarted.initialize(),
          throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
        );
        final resumed = await restarted.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 3,
        );

        expect(resumed.matches(attempted), isTrue);
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            faultStorage,
            opkGeneration: resumed.opkGeneration,
            keyId: resumed.oneTimePreKeyIds.first,
          ),
          isFalse,
          reason: 'prepared material is not inbound-visible before dispatch',
        );
      },
    );

    test(
      'accepted startup rejects different current material under the same ids',
      () async {
        final prepared = await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await manager.installKeyBundleReplacement(prepared);
        await manager.markKeyBundleReplacementDispatchStarted(prepared);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: prepared,
          acceptance: _receiptFor(prepared),
        );
        final cryptoStorage = CryptoStorage(secureStorage: storage);
        final accepted = (await _readJournalForTest(storage))!.generations
            .singleWhere(
              (entry) => entry.role == OpkGenerationRole.acceptedLookupOnly,
            );
        final signing = (await cryptoStorage.getSigningKeyPair())!;

        final differentSigned = await SignalKeyHelper.generateSignedPreKey(
          accepted.signedPreKey!.keyId,
          signing,
        );
        await cryptoStorage.saveSignedPreKey(differentSigned);
        final beforeSignedCheck = Map<String, String>.from(storage.store);
        await expectLater(
          SignalProtocolManager(secureStorage: storage).initialize(),
          throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
        );
        expect(storage.store, beforeSignedCheck);

        await cryptoStorage.saveSignedPreKey(accepted.signedPreKey!);
        final differentKem = SignalKeyHelper.generateKyberKeyPair(
          keyId: accepted.kyberKeyPair!.keyId!,
        );
        await cryptoStorage.saveKyberKeyPair(differentKem);
        final beforeKemCheck = Map<String, String>.from(storage.store);
        await expectLater(
          SignalProtocolManager(secureStorage: storage).initialize(),
          throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
        );
        expect(storage.store, beforeKemCheck);
      },
    );

    test('generation cap fails closed without automatic retirement', () async {
      for (
        var generation = 1;
        generation < KeyBundleReplacementJournal.maxGenerations;
        generation++
      ) {
        final prepared = generation == 1
            ? await manager.prepareInitialKeyBundleRegistration(
                oneTimePreKeyCount: 1,
              )
            : await manager.prepareKeyBundleReplacement(oneTimePreKeyCount: 1);
        await manager.installKeyBundleReplacement(prepared);
        await manager.markKeyBundleReplacementDispatchStarted(prepared);
        await manager.acknowledgeKeyBundleReplacement(
          snapshot: prepared,
          acceptance: _receiptFor(prepared),
        );
      }

      final journal = await _readJournalForTest(storage);
      expect(
        journal!.generations.length,
        KeyBundleReplacementJournal.maxGenerations,
      );
      expect(
        journal.generations.where(
          (entry) => entry.role == OpkGenerationRole.retainedLookupOnly,
        ),
        hasLength(KeyBundleReplacementJournal.maxGenerations - 2),
      );
      final before = Map<String, String>.from(storage.store);
      await expectLater(
        manager.prepareKeyBundleReplacement(oneTimePreKeyCount: 1),
        throwsStateError,
      );
      expect(storage.store, before);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test(
      'realistic max history resolves and consumes the oldest retained OPK',
      () async {
        KeyBundleReplacementSnapshot? oldest;
        Map<String, dynamic>? oldestPublicMaterial;
        for (
          var generation = 1;
          generation < KeyBundleReplacementJournal.maxGenerations;
          generation++
        ) {
          final prepared = generation == 1
              ? await manager.prepareInitialKeyBundleRegistration(
                  oneTimePreKeyCount: 100,
                )
              : await manager.prepareKeyBundleReplacement(
                  oneTimePreKeyCount: 100,
                );
          oldest ??= prepared;
          await manager.installKeyBundleReplacement(prepared);
          final dispatch = await manager
              .markKeyBundleReplacementDispatchStarted(prepared);
          oldestPublicMaterial ??= dispatch.toReplacementPayload(
            deviceId: 'device-a',
          );
          await manager.acknowledgeKeyBundleReplacement(
            snapshot: prepared,
            acceptance: _receiptFor(prepared),
          );
        }

        final routed = oldest!;
        final keyId = routed.oneTimePreKeyIds.last;
        expect(
          utf8.encode(storage.store[_journalStorageKey]!).length,
          lessThanOrEqualTo(KeyBundleReplacementJournal.maxEncodedBytes),
        );
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: routed.opkGeneration,
            keyId: keyId,
          ),
          isTrue,
        );
        await _consumeThroughAuthenticatedPreKey(
          responder: manager,
          snapshot: routed,
          publicMaterial: oldestPublicMaterial!,
          keyId: keyId,
        );
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: routed.opkGeneration,
            keyId: keyId,
          ),
          isFalse,
        );
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  });

  group('KeyBundleReplacementJournal install crash recovery', () {
    final cuts = <({String name, String key, String? phase})>[
      (
        name: 'installStarted journal',
        key: 'crypto_e2_bundle_replacement_journal_v1',
        phase: KeyBundleReplacementPhase.installStarted.name,
      ),
      (
        name: 'current signed pre-key',
        key: 'crypto_signed_pre_key',
        phase: null,
      ),
      (
        name: 'signed pre-key timestamp',
        key: 'crypto_signed_prekey_created_at',
        phase: null,
      ),
      (
        name: 'current ML-KEM key',
        key: 'crypto_e2_kyber_key_pair',
        phase: null,
      ),
      (
        name: 'ML-KEM timestamp',
        key: 'crypto_e2_kyber_created_at',
        phase: null,
      ),
      (
        name: 'legacy flat-pool clear',
        key: 'crypto_one_time_pre_keys',
        phase: null,
      ),
      (
        name: 'installed journal',
        key: 'crypto_e2_bundle_replacement_journal_v1',
        phase: KeyBundleReplacementPhase.installed.name,
      ),
    ];

    for (final cut in cuts) {
      for (final afterWrite in const <bool>[false, true]) {
        test('${cut.name} ${afterWrite ? 'fail-after' : 'fail-before'} '
            'converges after normal startup', () async {
          final storage = _FaultInjectingStorage();
          final firstManager = SignalProtocolManager(secureStorage: storage);
          await firstManager.wipeForFreshRegistration();
          await firstManager.initialize();
          final prepared = await firstManager
              .prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 2);
          storage.failNextWrite(
            key: cut.key,
            journalPhase: cut.phase,
            afterWrite: afterWrite,
          );

          await expectLater(
            firstManager.installKeyBundleReplacement(prepared),
            throwsStateError,
          );

          final restarted = SignalProtocolManager(secureStorage: storage);
          await expectLater(
            restarted.initialize(),
            throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
          );
          await restarted.installKeyBundleReplacement(prepared);

          final cryptoStorage = CryptoStorage(secureStorage: storage);
          final installed = (await _readJournalForTest(storage))!;
          expect(installed.phase, KeyBundleReplacementPhase.installed);
          expect(installed.proposal!.snapshot.matches(prepared), isTrue);
          expect(
            jsonEncode((await cryptoStorage.getSignedPreKey())!.toJson()),
            jsonEncode(installed.proposal!.signedPreKey.toJson()),
          );
          expect(
            jsonEncode((await cryptoStorage.getKyberKeyPair())!.toJson()),
            jsonEncode(installed.proposal!.kyberKeyPair.toJson()),
          );
          expect(await cryptoStorage.getOneTimePreKeys(), isEmpty);

          final dispatch = await restarted
              .markKeyBundleReplacementDispatchStarted(prepared);
          expect(dispatch.snapshot.matches(prepared), isTrue);
          expect(
            await _hasRoutableOneTimePreKeyForTest(
              storage,
              opkGeneration: prepared.opkGeneration,
              keyId: prepared.oneTimePreKeyIds.first,
            ),
            isTrue,
          );
        });
      }
    }
  });

  group('KeyBundleReplacementJournal reservation crash recovery', () {
    final cuts = <({String name, String key, String? phase})>[
      (
        name: 'legacy quarantine journal',
        key: 'crypto_e2_bundle_replacement_journal_v1',
        phase: '<idle>',
      ),
      (
        name: 'signed pre-key counter',
        key: 'crypto_e2_next_signed_pre_key_id',
        phase: null,
      ),
      (name: 'ML-KEM counter', key: 'crypto_e2_next_kyber_key_id', phase: null),
      (name: 'OPK range counter', key: 'crypto_next_pre_key_id', phase: null),
      (
        name: 'reserved journal',
        key: 'crypto_e2_bundle_replacement_journal_v1',
        phase: KeyBundleReplacementPhase.reserved.name,
      ),
    ];

    for (final cut in cuts) {
      for (final afterWrite in const <bool>[false, true]) {
        test('${cut.name} ${afterWrite ? 'fail-after' : 'fail-before'} '
            'exposes no proposal before retry', () async {
          final storage = _FaultInjectingStorage();
          final firstManager = SignalProtocolManager(secureStorage: storage);
          await firstManager.wipeForFreshRegistration();
          await firstManager.initialize();
          storage.failNextWrite(
            key: cut.key,
            journalPhase: cut.phase,
            afterWrite: afterWrite,
          );

          await expectLater(
            firstManager.prepareInitialKeyBundleRegistration(
              oneTimePreKeyCount: 2,
            ),
            throwsStateError,
          );
          expect(await firstManager.pendingKeyBundleReplacement(), isNull);

          KeyBundleReplacementReservation? attemptedReservation;
          if (cut.name == 'reserved journal') {
            attemptedReservation = KeyBundleReplacementJournal.fromJson(
              Map<String, dynamic>.from(
                jsonDecode(storage.attemptedValue!) as Map,
              ),
            ).reservation;
          }

          final restarted = SignalProtocolManager(secureStorage: storage);
          try {
            await restarted.initialize();
          } on KeyBundleReplacementRecoveryRequired {
            // Expected for a persisted idle quarantine or reservation.
          }
          expect(await restarted.pendingKeyBundleReplacement(), isNull);
          final retried = await restarted.prepareInitialKeyBundleRegistration(
            oneTimePreKeyCount: 2,
          );
          final persisted = (await _readJournalForTest(storage))!;
          expect(persisted.phase, KeyBundleReplacementPhase.prepared);
          expect(persisted.proposal!.snapshot.matches(retried), isTrue);
          if (attemptedReservation != null && afterWrite) {
            expect(retried.replacementId, attemptedReservation.replacementId);
            expect(retried.opkGeneration, attemptedReservation.opkGeneration);
            expect(retried.signedPreKeyId, attemptedReservation.signedPreKeyId);
            expect(retried.kemKeyId, attemptedReservation.kemKeyId);
            expect(
              retried.oneTimePreKeyIds.first,
              attemptedReservation.opkStartKeyId,
            );
          }
        });
      }
    }
  });

  group('KeyBundleReplacementJournal dispatch crash recovery', () {
    for (final afterWrite in const <bool>[false, true]) {
      test('dispatch intent ${afterWrite ? 'fail-after' : 'fail-before'} '
          'issues capability only from persisted state', () async {
        final storage = _FaultInjectingStorage();
        final firstManager = SignalProtocolManager(secureStorage: storage);
        await firstManager.wipeForFreshRegistration();
        await firstManager.initialize();
        final prepared = await firstManager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: 2,
        );
        await firstManager.installKeyBundleReplacement(prepared);
        storage.failNextWrite(
          key: 'crypto_e2_bundle_replacement_journal_v1',
          journalPhase: KeyBundleReplacementPhase.dispatchStarted.name,
          afterWrite: afterWrite,
        );

        await expectLater(
          firstManager.markKeyBundleReplacementDispatchStarted(prepared),
          throwsStateError,
        );
        final persisted = (await _readJournalForTest(storage))!;
        expect(
          persisted.phase,
          afterWrite
              ? KeyBundleReplacementPhase.dispatchStarted
              : KeyBundleReplacementPhase.installed,
        );
        expect(
          await _hasRoutableOneTimePreKeyForTest(
            storage,
            opkGeneration: prepared.opkGeneration,
            keyId: prepared.oneTimePreKeyIds.first,
          ),
          afterWrite,
        );

        final restarted = SignalProtocolManager(secureStorage: storage);
        await expectLater(
          restarted.initialize(),
          throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
        );
        final dispatch = afterWrite
            ? (await restarted.resumeKeyBundleReplacement())!
            : await restarted.markKeyBundleReplacementDispatchStarted(prepared);
        final firstPayload = jsonEncode(
          dispatch.toReplacementPayload(deviceId: 'device-a'),
        );
        final resumed = await SignalProtocolManager(
          secureStorage: storage,
        ).resumeKeyBundleReplacement();
        expect(
          jsonEncode(resumed!.toReplacementPayload(deviceId: 'device-a')),
          firstPayload,
        );
      });
    }
  });

  group('KeyBundleReplacementJournal acceptance crash recovery', () {
    final cuts = <({String name, String key, String? phase, bool isDelete})>[
      (
        name: 'localAckPending journal',
        key: 'crypto_e2_bundle_replacement_journal_v1',
        phase: KeyBundleReplacementPhase.localAckPending.name,
        isDelete: false,
      ),
      (
        name: 'repeated current signed pre-key',
        key: 'crypto_signed_pre_key',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'repeated signed pre-key timestamp',
        key: 'crypto_signed_prekey_created_at',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'repeated current ML-KEM key',
        key: 'crypto_e2_kyber_key_pair',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'repeated ML-KEM timestamp',
        key: 'crypto_e2_kyber_created_at',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'repeated legacy flat-pool clear',
        key: 'crypto_one_time_pre_keys',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'legacy bundle revision',
        key: 'crypto_e2_server_bundle_revision',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'legacy accepted generation',
        key: 'crypto_e2_last_accepted_bundle_generation',
        phase: null,
        isDelete: false,
      ),
      (
        name: 'legacy pending upload delete',
        key: 'crypto_e2_bundle_upload_pending',
        phase: null,
        isDelete: true,
      ),
      (
        name: 'legacy OPK recovery delete',
        key: 'crypto_e2_one_time_pre_key_recovery',
        phase: null,
        isDelete: true,
      ),
      (
        name: 'accepted idle journal',
        key: 'crypto_e2_bundle_replacement_journal_v1',
        phase: '<idle>',
        isDelete: false,
      ),
      (
        name: 'fresh-registration intent delete',
        key: 'crypto_e2_initial_registration_intent_v1',
        phase: null,
        isDelete: true,
      ),
    ];

    for (final cut in cuts) {
      for (final afterOperation in const <bool>[false, true]) {
        test('${cut.name} ${afterOperation ? 'fail-after' : 'fail-before'} '
            'converges exact accepted receipt', () async {
          final storage = _FaultInjectingStorage();
          final firstManager = SignalProtocolManager(secureStorage: storage);
          await firstManager.wipeForFreshRegistration();
          await firstManager.initialize();
          final prepared = await firstManager
              .prepareInitialKeyBundleRegistration(oneTimePreKeyCount: 3);
          await firstManager.installKeyBundleReplacement(prepared);
          final dispatch = await firstManager
              .markKeyBundleReplacementDispatchStarted(prepared);
          final dispatchBytes = jsonEncode(
            dispatch.toReplacementPayload(deviceId: 'device-a'),
          );
          final consumedId = prepared.oneTimePreKeyIds.first;
          await _consumeThroughAuthenticatedPreKey(
            responder: firstManager,
            snapshot: prepared,
            publicMaterial: dispatch.toReplacementPayload(deviceId: 'device-a'),
            keyId: consumedId,
          );
          final acceptance = _receiptFor(prepared);
          if (cut.isDelete) {
            storage.failNextDelete(key: cut.key, afterDelete: afterOperation);
          } else {
            storage.failNextWrite(
              key: cut.key,
              journalPhase: cut.phase,
              afterWrite: afterOperation,
            );
          }

          await expectLater(
            firstManager.acknowledgeKeyBundleReplacement(
              snapshot: prepared,
              acceptance: acceptance,
            ),
            throwsStateError,
          );

          final restarted = SignalProtocolManager(secureStorage: storage);
          try {
            await restarted.initialize();
          } on KeyBundleReplacementRecoveryRequired {
            expect(
              await restarted.reconcileKeyBundleReplacement(
                _ownerResponseFor(dispatch),
              ),
              isTrue,
            );
          }
          expect(
            await SignalProtocolManager(secureStorage: storage).initialize(),
            isFalse,
          );

          final cryptoStorage = CryptoStorage(secureStorage: storage);
          final acceptedJournal = (await _readJournalForTest(storage))!;
          expect(acceptedJournal.phase, isNull);
          expect(acceptedJournal.acceptedReceipt, acceptance);
          expect(
            await cryptoStorage.getServerBundleRevision(),
            acceptance.bundleRevision,
          );
          expect(await cryptoStorage.hasInitialRegistrationIntent(), isFalse);
          final acceptedGeneration = acceptedJournal.generations.singleWhere(
            (entry) => entry.role == OpkGenerationRole.acceptedLookupOnly,
          );
          expect(
            acceptedGeneration.publicOneTimePreKeys.map((key) => key.keyId),
            contains(consumedId),
          );
          expect(acceptedGeneration.findOneTimePreKey(consumedId), isNull);
          expect(
            acceptedGeneration.consumedOneTimePreKeyIds,
            contains(consumedId),
          );
          expect(
            jsonDecode(dispatchBytes)['opkSetCount'],
            acceptedGeneration.publicOneTimePreKeys.length,
          );
        });
      }
    }
  });
}
