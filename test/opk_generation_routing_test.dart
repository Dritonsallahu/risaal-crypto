import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;
import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/key_bundle_replacement.dart'
    show KeyBundleReplacementJournal;
import 'package:test/test.dart';

import 'helpers/fake_secure_storage.dart';

const _journalKey = 'crypto_e2_bundle_replacement_journal_v1';
const _preKeyOnlyFields = <String>[
  'senderEphemeralKey',
  'kyberCiphertext',
  'recipientKeyId',
  'recipientSignedPreKeyId',
  'usedOneTimePreKeyId',
  'kemSuite',
  'kemStandard',
  'kemWireVersion',
  'bundleRevision',
  'opkGeneration',
  'opkSetDigest',
];

final class _BlockingConsumeStorage extends FakeSecureStorage {
  final Completer<void> consumeWriteStarted = Completer<void>();
  final Completer<void> releaseConsumeWrite = Completer<void>();
  bool blockNextConsumeWrite = false;

  @override
  Future<void> write({required String key, required String value}) async {
    if (blockNextConsumeWrite && key == _journalKey) {
      final decoded = jsonDecode(value);
      final generations = decoded is Map ? decoded['generations'] : null;
      final containsTombstone =
          generations is List &&
          generations.whereType<Map>().any(
            (generation) =>
                (generation['consumedOneTimePreKeyIds'] as List?)?.isNotEmpty ??
                false,
          );
      if (containsTombstone) {
        blockNextConsumeWrite = false;
        consumeWriteStarted.complete();
        await releaseConsumeWrite.future;
      }
    }
    await super.write(key: key, value: value);
  }
}

final class _CountingJournalStorage extends FakeSecureStorage {
  int journalReads = 0;

  void resetJournalReads() => journalReads = 0;

  @override
  Future<String?> read({required String key}) async {
    if (key == _journalKey) journalReads++;
    return super.read(key: key);
  }
}

final class _AcceptedGeneration {
  final KeyBundleReplacementSnapshot snapshot;
  final KeyBundleAcceptedReceipt receipt;
  final Map<String, dynamic> publicMaterial;

  const _AcceptedGeneration({
    required this.snapshot,
    required this.receipt,
    required this.publicMaterial,
  });

  OpkGenerationRouting get route => OpkGenerationRouting(
    bundleRevision: receipt.opkAcceptedBundleRevision,
    opkGeneration: receipt.opkGeneration,
    opkSetDigest: receipt.opkSetDigest,
  );

  PreKeyBundle consumerBundle({int? oneTimePreKeyIndex = 0}) {
    final keys = (publicMaterial['oneTimePreKeys'] as List)
        .map((value) => Map<String, dynamic>.from(value as Map))
        .toList(growable: false);
    final selected = oneTimePreKeyIndex == null
        ? null
        : <String, dynamic>{...keys[oneTimePreKeyIndex], ...route.toJson()};
    return PreKeyBundle.fromServerJson(<String, dynamic>{
      ...publicMaterial,
      'userId': 'bob-id',
      'deviceId': 'bob-device',
      ...route.toJson(),
      'oneTimePreKey': selected,
    });
  }
}

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

Future<_AcceptedGeneration> _acceptGeneration(
  SignalProtocolManager manager, {
  required bool initial,
  int oneTimePreKeyCount = 3,
}) async {
  final snapshot = initial
      ? await manager.prepareInitialKeyBundleRegistration(
          oneTimePreKeyCount: oneTimePreKeyCount,
        )
      : await manager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: oneTimePreKeyCount,
        );
  await manager.installKeyBundleReplacement(snapshot);
  final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
    snapshot,
  );
  final material = Map<String, dynamic>.from(
    initial
        ? dispatch.toInitialRegistrationKeyBundle()
        : dispatch.toReplacementPayload(deviceId: 'bob-device'),
  );
  final receipt = _receiptFor(snapshot);
  await manager.acknowledgeKeyBundleReplacement(
    snapshot: snapshot,
    acceptance: receipt,
  );
  return _AcceptedGeneration(
    snapshot: snapshot,
    receipt: receipt,
    publicMaterial: material,
  );
}

Future<({SignalProtocolManager manager, FakeSecureStorage storage})>
_freshManager({
  String? userId,
  String? deviceId,
  FakeSecureStorage? backingStorage,
  SecurityEventBus? securityEventBus,
}) async {
  final storage = backingStorage ?? FakeSecureStorage();
  final manager = SignalProtocolManager(
    secureStorage: storage,
    securityEventBus: securityEventBus,
  );
  await manager.wipeForFreshRegistration();
  await manager.initialize();
  if (userId != null) {
    await storage.write(key: 'user_id', value: userId);
  }
  if (deviceId != null) {
    await storage.write(key: 'device_id', value: deviceId);
  }
  return (manager: manager, storage: storage);
}

String _storageSnapshot(FakeSecureStorage storage) =>
    jsonEncode(SplayTreeMap<String, String>.from(storage.store));

KeyBundleReplacementJournal _journalForTest(FakeSecureStorage storage) =>
    KeyBundleReplacementJournal.fromJson(
      Map<String, dynamic>.from(jsonDecode(storage.store[_journalKey]!) as Map),
    );

bool _hasOneTimePreKeyForTest(
  FakeSecureStorage storage, {
  required int opkGeneration,
  required int keyId,
}) =>
    _journalForTest(storage).generations
        .singleWhere((entry) => entry.opkGeneration == opkGeneration)
        .findOneTimePreKey(keyId) !=
    null;

Map<String, dynamic> _cloneMap(Map<String, dynamic> value) =>
    Map<String, dynamic>.from(jsonDecode(jsonEncode(value)) as Map);

void _tamperCiphertext(Map<String, dynamic> envelope) {
  final message = Map<String, dynamic>.from(envelope['message'] as Map);
  final bytes = base64Decode(message['ciphertext'] as String);
  bytes[0] ^= 0x01;
  message['ciphertext'] = base64Encode(bytes);
  envelope['message'] = message;
}

Map<String, Object?> _preKeyOnlyFieldValues(
  Map<String, dynamic> preKeyEnvelope,
) => <String, Object?>{
  for (final field in _preKeyOnlyFields) field: preKeyEnvelope[field],
};

String _nonCanonicalBase64(String canonical) {
  const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  final significantIndex = canonical.endsWith('=')
      ? canonical.length - 2
      : canonical.length - 1;
  final alphabetIndex = alphabet.indexOf(canonical[significantIndex]);
  if (alphabetIndex < 0 || alphabetIndex % 4 != 0) {
    throw StateError('Fixture does not end in a two-pad-bit base64 quantum');
  }
  return canonical.replaceRange(
    significantIndex,
    significantIndex + 1,
    alphabet[alphabetIndex + 1],
  );
}

void main() {
  group('typed OPK generation routing', () {
    test(
      'no public raw OPK-journal generation lookup/consume or batch helper in barrel',
      () {
        final managerSource = File(
          'lib/src/signal_protocol_manager.dart',
        ).readAsStringSync();
        final storageSource = File(
          'lib/src/crypto_storage.dart',
        ).readAsStringSync();
        final barrelSource = File('lib/risaal_crypto.dart').readAsStringSync();
        for (final source in <String>[managerSource, storageSource]) {
          for (final forbidden in <String>[
            'consumeOneTimePreKeyForGeneration(',
            'getOneTimePreKeyForGeneration(',
            'getSignedPreKeyForGeneration(',
            'getKyberKeyPairForGeneration(',
            '@visibleForTesting',
            'ForTesting(',
            'testOnly',
            'TestOnly',
          ]) {
            expect(source, isNot(contains(forbidden)), reason: forbidden);
          }
        }
        expect(
          barrelSource,
          contains(
            "export 'src/ratchet_batch_decrypt.dart' show RatchetBatchResult;",
          ),
        );
        expect(
          barrelSource,
          isNot(contains("export 'src/ratchet_batch_decrypt.dart';")),
        );

        final responderStart = managerSource.indexOf(
          'Future<String> _processPreKeyMessageUnlocked(',
        );
        final responderEnd = managerSource.indexOf(
          '// ── Encrypt',
          responderStart,
        );
        expect(responderStart, greaterThanOrEqualTo(0));
        expect(responderEnd, greaterThan(responderStart));
        final responder = managerSource.substring(responderStart, responderEnd);
        for (final forbidden in <String>[
          'getSignedPreKeyById(',
          'getOneTimePreKeys(',
          'getKyberKeyPairById(',
          'removeOneTimePreKey(',
        ]) {
          expect(responder, isNot(contains(forbidden)), reason: forbidden);
        }
        final authIndex = responder.indexOf('ratchet.decrypt(');
        final consumeIndex = responder.indexOf(
          '_consumeOneTimePreKeyForGenerationUnlocked(',
        );
        expect(authIndex, greaterThanOrEqualTo(0));
        expect(consumeIndex, greaterThanOrEqualTo(0));
        expect(authIndex, lessThan(consumeIndex));
      },
    );

    test('strict tuple parser and transcript are deterministic', () {
      const route = OpkGenerationRouting(
        bundleRevision: 4294967303,
        opkGeneration: 4294967301,
        opkSetDigest:
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      );
      const kem = MlKemEnvelopeMetadata.current(recipientKeyId: 19);
      const routing = PreKeyHandshakeRouting(
        opkRoute: route,
        recipientSignedPreKeyId: 17,
        usedOneTimePreKeyId: 23,
        kemMetadata: kem,
      );

      final parsed = PreKeyHandshakeRouting.fromEnvelopeJson(
        routing.toEnvelopeJson(),
      );
      expect(parsed, routing);
      final transcript = routing.canonicalTranscript();
      expect(
        transcript
            .map((value) => value.toRadixString(16).padLeft(2, '0'))
            .join(),
        '0000001952495341414c5f50515844485f4f504b5f524f5554455f7631'
        '0000000200000001000000070000000100000005000000200123456789abcdef'
        '0123456789abcdef0123456789abcdef0123456789abcdef000000110100000017'
        '00000013000000010000000a4d4c2d4b454d2d3736380000000746495053323033',
      );
      expect(
        crypto.sha256.convert(transcript).toString(),
        '371849dbf3895d18a3944cab5188f2a4805b83b40be3ca275399b9543042d182',
      );

      final distinct = <PreKeyHandshakeRouting>[
        PreKeyHandshakeRouting(
          opkRoute: OpkGenerationRouting(
            bundleRevision: route.bundleRevision + 1,
            opkGeneration: route.opkGeneration,
            opkSetDigest: route.opkSetDigest,
          ),
          recipientSignedPreKeyId: 17,
          usedOneTimePreKeyId: 23,
          kemMetadata: kem,
        ),
        PreKeyHandshakeRouting(
          opkRoute: OpkGenerationRouting(
            bundleRevision: route.bundleRevision,
            opkGeneration: route.opkGeneration + 1,
            opkSetDigest: route.opkSetDigest,
          ),
          recipientSignedPreKeyId: 17,
          usedOneTimePreKeyId: 23,
          kemMetadata: kem,
        ),
        PreKeyHandshakeRouting(
          opkRoute: OpkGenerationRouting(
            bundleRevision: route.bundleRevision,
            opkGeneration: route.opkGeneration,
            opkSetDigest:
                '1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          ),
          recipientSignedPreKeyId: 17,
          usedOneTimePreKeyId: 23,
          kemMetadata: kem,
        ),
        const PreKeyHandshakeRouting(
          opkRoute: route,
          recipientSignedPreKeyId: 18,
          usedOneTimePreKeyId: 23,
          kemMetadata: kem,
        ),
        const PreKeyHandshakeRouting(
          opkRoute: route,
          recipientSignedPreKeyId: 17,
          usedOneTimePreKeyId: null,
          kemMetadata: kem,
        ),
        const PreKeyHandshakeRouting(
          opkRoute: route,
          recipientSignedPreKeyId: 17,
          usedOneTimePreKeyId: 24,
          kemMetadata: kem,
        ),
        const PreKeyHandshakeRouting(
          opkRoute: route,
          recipientSignedPreKeyId: 17,
          usedOneTimePreKeyId: 23,
          kemMetadata: MlKemEnvelopeMetadata.current(recipientKeyId: 20),
        ),
      ];
      for (final changed in distinct) {
        expect(changed.canonicalTranscript(), isNot(transcript));
      }

      for (final invalidKem in <MlKemEnvelopeMetadata>[
        const MlKemEnvelopeMetadata(
          cryptoProtocolEpoch: 3,
          kemSuite: RisaalCryptoProtocol.kemSuite,
          kemStandard: RisaalCryptoProtocol.kemStandard,
          kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
          recipientKeyId: 19,
        ),
        const MlKemEnvelopeMetadata(
          cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
          kemSuite: 'ML-KEM-1024',
          kemStandard: RisaalCryptoProtocol.kemStandard,
          kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
          recipientKeyId: 19,
        ),
        const MlKemEnvelopeMetadata(
          cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
          kemSuite: RisaalCryptoProtocol.kemSuite,
          kemStandard: 'draft',
          kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
          recipientKeyId: 19,
        ),
        const MlKemEnvelopeMetadata(
          cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
          kemSuite: RisaalCryptoProtocol.kemSuite,
          kemStandard: RisaalCryptoProtocol.kemStandard,
          kemWireVersion: 2,
          recipientKeyId: 19,
        ),
      ]) {
        expect(
          () => PreKeyHandshakeRouting(
            opkRoute: route,
            recipientSignedPreKeyId: 17,
            usedOneTimePreKeyId: 23,
            kemMetadata: invalidKem,
          ).canonicalTranscript(),
          throwsFormatException,
        );
      }

      for (final mutate in <void Function(Map<String, dynamic>)>[
        (value) => value.remove('bundleRevision'),
        (value) => value.remove('opkGeneration'),
        (value) => value.remove('opkSetDigest'),
        (value) => value['bundleRevision'] = 0,
        (value) => value['opkGeneration'] = 9007199254740992,
        (value) => value['opkSetDigest'] = 'A' * 64,
        (value) => value.remove('usedOneTimePreKeyId'),
      ]) {
        final malformed = Map<String, dynamic>.from(routing.toEnvelopeJson());
        mutate(malformed);
        expect(
          () => PreKeyHandshakeRouting.fromEnvelopeJson(malformed),
          throwsFormatException,
        );
      }
    });

    test('consumer bundle requires exact outer and nested OPK route', () async {
      final bob = await _freshManager();
      final generation = await _acceptGeneration(bob.manager, initial: true);
      final encoded = generation.consumerBundle().toJson();
      expect(OpkGenerationRouting.fromJson(encoded), generation.route);
      expect(
        OpkGenerationRouting.fromJson(
          Map<String, dynamic>.from(encoded['oneTimePreKey'] as Map),
        ),
        generation.route,
      );

      final missingExplicitOpk = _cloneMap(encoded)..remove('oneTimePreKey');
      expect(
        () => PreKeyBundle.fromServerJson(missingExplicitOpk),
        throwsFormatException,
      );

      final nestedDrift = _cloneMap(encoded);
      (nestedDrift['oneTimePreKey'] as Map)['opkGeneration'] =
          generation.route.opkGeneration + 1;
      expect(
        () => PreKeyBundle.fromServerJson(nestedDrift),
        throwsFormatException,
      );

      for (final field in <String>[
        'bundleRevision',
        'opkGeneration',
        'opkSetDigest',
      ]) {
        final missingOuter = _cloneMap(encoded)..remove(field);
        expect(
          () => PreKeyBundle.fromServerJson(missingOuter),
          throwsFormatException,
          reason: 'missing outer $field',
        );
        final missingNested = _cloneMap(encoded);
        (missingNested['oneTimePreKey'] as Map).remove(field);
        expect(
          () => PreKeyBundle.fromServerJson(missingNested),
          throwsFormatException,
          reason: 'missing nested $field',
        );
      }

      final noOpk = generation.consumerBundle(oneTimePreKeyIndex: null);
      expect(noOpk.oneTimePreKey, isNull);
      expect(noOpk.opkRoute, generation.route);

      final valid = generation.consumerBundle();
      final directInvalid = PreKeyBundle(
        opkRoute: OpkGenerationRouting(
          bundleRevision: generation.route.bundleRevision,
          opkGeneration: RisaalCryptoProtocol.maxServerSafeInt + 1,
          opkSetDigest: generation.route.opkSetDigest,
        ),
        userId: valid.userId,
        deviceId: valid.deviceId,
        identityKey: valid.identityKey,
        identitySigningKey: valid.identitySigningKey,
        signedPreKey: valid.signedPreKey,
        oneTimePreKey: valid.oneTimePreKey,
        kyberPreKey: valid.kyberPreKey,
      );
      final alice = await _freshManager();
      final baseline = _storageSnapshot(alice.storage);
      await expectLater(
        alice.manager.createSession(directInvalid),
        throwsFormatException,
      );
      expect(_storageSnapshot(alice.storage), baseline);
    });
  });

  group('authenticated journal generation resolution', () {
    test('accepted N direct round-trip consumes only its exact OPK', () async {
      final alice = await _freshManager();
      final bob = await _freshManager();
      final generation = await _acceptGeneration(bob.manager, initial: true);
      final bundle = generation.consumerBundle();
      final opkId = bundle.oneTimePreKey!.keyId;

      await alice.manager.createSession(bundle);
      final envelope = await alice.manager.encryptMessage(
        'bob-id',
        'bob-device',
        'generation N',
      );
      expect(OpkGenerationRouting.fromJson(envelope), generation.route);
      expect(
        await bob.manager.decryptMessage('alice-id', 'alice-device', envelope),
        'generation N',
      );
      expect(
        _hasOneTimePreKeyForTest(
          bob.storage,
          opkGeneration: generation.route.opkGeneration,
          keyId: opkId,
        ),
        isFalse,
      );
    });

    test(
      'public responder rejects noncanonical or oversized key material before journal read',
      () async {
        final alice = await _freshManager();
        final eventBus = SecurityEventBus();
        final events = <SecurityEvent>[];
        final subscription = eventBus.events.listen(events.add);
        final countingStorage = _CountingJournalStorage();
        final bob = await _freshManager(
          backingStorage: countingStorage,
          securityEventBus: eventBus,
        );
        final generation = await _acceptGeneration(bob.manager, initial: true);
        await alice.manager.createSession(generation.consumerBundle());
        final authentic = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'canonical preflight',
        );
        final routing = PreKeyHandshakeRouting.fromEnvelopeJson(authentic);
        final identity = authentic['senderIdentityKey'] as String;
        final ephemeral = authentic['senderEphemeralKey'] as String;
        final ciphertext = authentic['kyberCiphertext'] as String;
        final encryptedMessage = Map<String, dynamic>.from(
          authentic['message'] as Map,
        );
        var warningCalls = 0;
        bob.manager.onPreKeyExhaustionWarning = (_) => warningCalls++;
        await Future<void>.delayed(Duration.zero);
        final eventBaseline = events.length;
        final storageBaseline = _storageSnapshot(bob.storage);

        final cases =
            <
              ({
                String name,
                String identity,
                String ephemeral,
                String ciphertext,
              })
            >[
              (
                name: 'identity malformed',
                identity: '!' * identity.length,
                ephemeral: ephemeral,
                ciphertext: ciphertext,
              ),
              (
                name: 'identity wrong length',
                identity: base64Encode(List<int>.filled(31, 0)),
                ephemeral: ephemeral,
                ciphertext: ciphertext,
              ),
              (
                name: 'identity noncanonical',
                identity: _nonCanonicalBase64(identity),
                ephemeral: ephemeral,
                ciphertext: ciphertext,
              ),
              (
                name: 'identity oversized',
                identity: 'A' * 8192,
                ephemeral: ephemeral,
                ciphertext: ciphertext,
              ),
              (
                name: 'ephemeral malformed',
                identity: identity,
                ephemeral: '!' * ephemeral.length,
                ciphertext: ciphertext,
              ),
              (
                name: 'ephemeral wrong length',
                identity: identity,
                ephemeral: base64Encode(List<int>.filled(31, 0)),
                ciphertext: ciphertext,
              ),
              (
                name: 'ephemeral noncanonical',
                identity: identity,
                ephemeral: _nonCanonicalBase64(ephemeral),
                ciphertext: ciphertext,
              ),
              (
                name: 'ephemeral oversized',
                identity: identity,
                ephemeral: 'A' * 8192,
                ciphertext: ciphertext,
              ),
              (
                name: 'KEM malformed',
                identity: identity,
                ephemeral: ephemeral,
                ciphertext: '!' * ciphertext.length,
              ),
              (
                name: 'KEM wrong length',
                identity: identity,
                ephemeral: ephemeral,
                ciphertext: base64Encode(List<int>.filled(1087, 0)),
              ),
              (
                name: 'KEM noncanonical',
                identity: identity,
                ephemeral: ephemeral,
                ciphertext: _nonCanonicalBase64(ciphertext),
              ),
              (
                name: 'KEM oversized',
                identity: identity,
                ephemeral: ephemeral,
                ciphertext: 'A' * 16384,
              ),
            ];

        for (final malformed in cases) {
          countingStorage.resetJournalReads();
          await expectLater(
            () => bob.manager.processPreKeyMessage(
              senderId: 'alice-id',
              senderDeviceId: 'alice-device',
              senderIdentityKey: malformed.identity,
              senderEphemeralKey: malformed.ephemeral,
              encryptedMessage: encryptedMessage,
              kyberCiphertext: malformed.ciphertext,
              routing: routing,
            ),
            throwsFormatException,
            reason: malformed.name,
          );
          await Future<void>.delayed(Duration.zero);
          expect(countingStorage.journalReads, 0, reason: malformed.name);
          expect(_storageSnapshot(bob.storage), storageBaseline);
          expect(events, hasLength(eventBaseline), reason: malformed.name);
          expect(warningCalls, 0, reason: malformed.name);
          expect(
            await bob.manager.hasSession('alice-id', 'alice-device'),
            isFalse,
          );
        }

        final missingVersion = _cloneMap(encryptedMessage)..remove('version');
        final legacyVersion = _cloneMap(encryptedMessage)..['version'] = 1;
        final futureVersion = _cloneMap(encryptedMessage)..['version'] = 4;
        final missingDhKey = _cloneMap(encryptedMessage)..remove('dhPublicKey');
        final boundaryCases =
            <
              ({
                String name,
                String senderId,
                String senderDeviceId,
                PreKeyHandshakeRouting routing,
                Map<String, dynamic> message,
              })
            >[
              (
                name: 'empty sender id',
                senderId: '',
                senderDeviceId: 'alice-device',
                routing: routing,
                message: encryptedMessage,
              ),
              (
                name: 'empty sender device id',
                senderId: 'alice-id',
                senderDeviceId: '',
                routing: routing,
                message: encryptedMessage,
              ),
              (
                name: 'zero bundle revision',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: PreKeyHandshakeRouting(
                  opkRoute: OpkGenerationRouting(
                    bundleRevision: 0,
                    opkGeneration: routing.opkRoute.opkGeneration,
                    opkSetDigest: routing.opkRoute.opkSetDigest,
                  ),
                  recipientSignedPreKeyId: routing.recipientSignedPreKeyId,
                  usedOneTimePreKeyId: routing.usedOneTimePreKeyId,
                  kemMetadata: routing.kemMetadata,
                ),
                message: encryptedMessage,
              ),
              (
                name: 'future OPK generation',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: PreKeyHandshakeRouting(
                  opkRoute: OpkGenerationRouting(
                    bundleRevision: routing.opkRoute.bundleRevision,
                    opkGeneration: RisaalCryptoProtocol.maxServerSafeInt + 1,
                    opkSetDigest: routing.opkRoute.opkSetDigest,
                  ),
                  recipientSignedPreKeyId: routing.recipientSignedPreKeyId,
                  usedOneTimePreKeyId: routing.usedOneTimePreKeyId,
                  kemMetadata: routing.kemMetadata,
                ),
                message: encryptedMessage,
              ),
              (
                name: 'noncanonical OPK digest',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: PreKeyHandshakeRouting(
                  opkRoute: OpkGenerationRouting(
                    bundleRevision: routing.opkRoute.bundleRevision,
                    opkGeneration: routing.opkRoute.opkGeneration,
                    opkSetDigest: routing.opkRoute.opkSetDigest.toUpperCase(),
                  ),
                  recipientSignedPreKeyId: routing.recipientSignedPreKeyId,
                  usedOneTimePreKeyId: routing.usedOneTimePreKeyId,
                  kemMetadata: routing.kemMetadata,
                ),
                message: encryptedMessage,
              ),
              (
                name: 'future KEM epoch',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: PreKeyHandshakeRouting(
                  opkRoute: routing.opkRoute,
                  recipientSignedPreKeyId: routing.recipientSignedPreKeyId,
                  usedOneTimePreKeyId: routing.usedOneTimePreKeyId,
                  kemMetadata: MlKemEnvelopeMetadata(
                    cryptoProtocolEpoch:
                        RisaalCryptoProtocol.cryptoProtocolEpoch + 1,
                    kemSuite: routing.kemMetadata.kemSuite,
                    kemStandard: routing.kemMetadata.kemStandard,
                    kemWireVersion: routing.kemMetadata.kemWireVersion,
                    recipientKeyId: routing.kemMetadata.recipientKeyId,
                  ),
                ),
                message: encryptedMessage,
              ),
              (
                name: 'missing inner wire version',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: routing,
                message: missingVersion,
              ),
              (
                name: 'legacy inner wire version',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: routing,
                message: legacyVersion,
              ),
              (
                name: 'future inner wire version',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: routing,
                message: futureVersion,
              ),
              (
                name: 'missing inner ratchet key',
                senderId: 'alice-id',
                senderDeviceId: 'alice-device',
                routing: routing,
                message: missingDhKey,
              ),
            ];
        for (final malformed in boundaryCases) {
          countingStorage.resetJournalReads();
          await expectLater(
            () => bob.manager.processPreKeyMessage(
              senderId: malformed.senderId,
              senderDeviceId: malformed.senderDeviceId,
              senderIdentityKey: identity,
              senderEphemeralKey: ephemeral,
              encryptedMessage: malformed.message,
              kyberCiphertext: ciphertext,
              routing: malformed.routing,
            ),
            throwsFormatException,
            reason: malformed.name,
          );
          await Future<void>.delayed(Duration.zero);
          expect(countingStorage.journalReads, 0, reason: malformed.name);
          expect(_storageSnapshot(bob.storage), storageBaseline);
          expect(events, hasLength(eventBaseline), reason: malformed.name);
          expect(warningCalls, 0, reason: malformed.name);
          expect(
            await bob.manager.hasSession('alice-id', 'alice-device'),
            isFalse,
          );
        }

        countingStorage.resetJournalReads();
        expect(
          await bob.manager.processPreKeyMessage(
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            senderIdentityKey: identity,
            senderEphemeralKey: ephemeral,
            encryptedMessage: encryptedMessage,
            kyberCiphertext: ciphertext,
            routing: routing,
          ),
          'canonical preflight',
        );
        expect(countingStorage.journalReads, 2);
        expect(
          await bob.manager.hasSession('alice-id', 'alice-device'),
          isTrue,
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: routing.opkRoute.opkGeneration,
            keyId: routing.usedOneTimePreKeyId!,
          ),
          isFalse,
        );
        await subscription.cancel();
        eventBus.dispose();
      },
    );

    test(
      'throwing post-commit low-pool callback cannot fail authenticated decrypt',
      () async {
        final alice = await _freshManager();
        final bob = await _freshManager();
        final generation = await _acceptGeneration(
          bob.manager,
          initial: true,
          oneTimePreKeyCount: 1,
        );
        final bundle = generation.consumerBundle();
        await alice.manager.createSession(bundle);
        final first = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'callback cannot roll back auth',
        );
        var callbackCalls = 0;
        bob.manager.onPreKeyExhaustionWarning = (_) {
          callbackCalls++;
          throw StateError('injected app callback failure');
        };

        expect(
          await bob.manager.decryptMessage('alice-id', 'alice-device', first),
          'callback cannot roll back auth',
        );
        expect(callbackCalls, 1);
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: bundle.oneTimePreKey!.keyId,
          ),
          isFalse,
        );
        final journal = _journalForTest(bob.storage);
        await CryptoStorage(
          secureStorage: bob.storage,
        ).validateKeyBundleReplacementJournal(journal);

        final second = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'session remains usable',
        );
        expect(
          await bob.manager.decryptMessage('alice-id', 'alice-device', second),
          'session remains usable',
        );
      },
    );

    test(
      'staged authenticated consume stays silent until exact ACK promotes the depleted generation',
      () async {
        final alice = await _freshManager();
        final bob = await _freshManager();
        await _acceptGeneration(
          bob.manager,
          initial: true,
          oneTimePreKeyCount: 3,
        );
        expect(await bob.manager.oneTimePreKeyCount(), 3);
        final snapshot = await bob.manager.prepareKeyBundleReplacement(
          oneTimePreKeyCount: 1,
        );
        await bob.manager.installKeyBundleReplacement(snapshot);
        final dispatch = await bob.manager
            .markKeyBundleReplacementDispatchStarted(snapshot);
        final material = dispatch.toReplacementPayload(deviceId: 'bob-device');
        final route = OpkGenerationRouting(
          bundleRevision: snapshot.expectedBundleRevision + 1,
          opkGeneration: snapshot.opkGeneration,
          opkSetDigest: snapshot.opkSetDigest,
        );
        final selected = Map<String, dynamic>.from(
          (material['oneTimePreKeys'] as List).single as Map,
        );
        final bundle = PreKeyBundle.fromServerJson(<String, dynamic>{
          ...material,
          'userId': 'bob-id',
          'deviceId': 'bob-device',
          ...route.toJson(),
          'oneTimePreKey': <String, dynamic>{...selected, ...route.toJson()},
        });
        await alice.manager.createSession(bundle);
        final envelope = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'staged generation consume',
        );
        final warnings = <int>[];
        bob.manager.onPreKeyExhaustionWarning = warnings.add;

        expect(
          await bob.manager.decryptMessage(
            'alice-id',
            'alice-device',
            envelope,
          ),
          'staged generation consume',
        );
        expect(warnings, isEmpty);
        expect(
          await bob.manager.oneTimePreKeyCount(),
          3,
          reason: 'staged N+1 depletion must not change accepted N count',
        );
        expect(
          await bob.manager.acknowledgeKeyBundleReplacement(
            snapshot: snapshot,
            acceptance: _receiptFor(snapshot),
          ),
          isTrue,
        );
        expect(warnings, <int>[0]);
        expect(await bob.manager.oneTimePreKeyCount(), 0);
      },
    );

    test('delayed N decrypts after N+1 and N+2 are accepted', () async {
      final alice = await _freshManager();
      final bob = await _freshManager();
      final first = await _acceptGeneration(bob.manager, initial: true);
      final firstBundle = first.consumerBundle(oneTimePreKeyIndex: 1);
      await alice.manager.createSession(firstBundle);
      final delayed = await alice.manager.encryptMessage(
        'bob-id',
        'bob-device',
        'delayed generation N',
      );

      await _acceptGeneration(bob.manager, initial: false);
      await _acceptGeneration(bob.manager, initial: false);
      var lowPoolWarnings = 0;
      bob.manager.onPreKeyExhaustionWarning = (_) => lowPoolWarnings++;

      expect(
        await bob.manager.decryptMessage('alice-id', 'alice-device', delayed),
        'delayed generation N',
      );
      expect(
        _hasOneTimePreKeyForTest(
          bob.storage,
          opkGeneration: first.route.opkGeneration,
          keyId: firstBundle.oneTimePreKey!.keyId,
        ),
        isFalse,
      );
      expect(
        lowPoolWarnings,
        0,
        reason: 'retained N depletion is not current N+2 pool depletion',
      );
      expect(
        await bob.manager.oneTimePreKeyCount(),
        3,
        reason: 'retained N consumption must not change current N+2 count',
      );
    });

    test(
      'delayed explicit no-OPK N resolves exact SPK and KEM after N+2',
      () async {
        final alice = await _freshManager();
        final bob = await _freshManager();
        final generation = await _acceptGeneration(bob.manager, initial: true);
        final bundle = generation.consumerBundle(oneTimePreKeyIndex: null);

        await alice.manager.createSession(bundle);
        final envelope = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'no OPK',
        );
        expect(envelope, containsPair('usedOneTimePreKeyId', null));
        await _acceptGeneration(bob.manager, initial: false);
        await _acceptGeneration(bob.manager, initial: false);
        expect(
          await bob.manager.decryptMessage(
            'alice-id',
            'alice-device',
            envelope,
          ),
          'no OPK',
        );
      },
    );

    test(
      '100-OPK route reads journal once before auth and once to consume without private-validating unrelated OPKs',
      () async {
        final alice = await _freshManager();
        final eventBus = SecurityEventBus();
        final events = <SecurityEvent>[];
        final subscription = eventBus.events.listen(events.add);
        final countingStorage = _CountingJournalStorage();
        final bob = await _freshManager(
          backingStorage: countingStorage,
          securityEventBus: eventBus,
        );
        final generation = await _acceptGeneration(
          bob.manager,
          initial: true,
          oneTimePreKeyCount: 100,
        );
        final bundle = generation.consumerBundle(oneTimePreKeyIndex: 0);
        final selectedId = bundle.oneTimePreKey!.keyId;
        await alice.manager.createSession(bundle);
        final authentic = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'single selected-key validation',
        );

        final raw = Map<String, dynamic>.from(
          jsonDecode(countingStorage.store[_journalKey]!) as Map,
        );
        final routedGeneration = (raw['generations'] as List)
            .cast<Map<String, dynamic>>()
            .singleWhere(
              (entry) =>
                  entry['opkGeneration'] == generation.route.opkGeneration,
            );
        final privateOpks = (routedGeneration['oneTimePreKeys'] as List)
            .cast<Map<String, dynamic>>();
        expect(privateOpks, hasLength(100));
        final unselected = privateOpks.last;
        unselected['keyPair']['privateKey'] =
            privateOpks[privateOpks.length - 2]['keyPair']['privateKey'];
        await countingStorage.write(key: _journalKey, value: jsonEncode(raw));

        var warningCalls = 0;
        bob.manager.onPreKeyExhaustionWarning = (_) => warningCalls++;
        await Future<void>.delayed(Duration.zero);
        final eventBaseline = events.length;
        final rejectionBaseline = _storageSnapshot(countingStorage);
        final badMac = _cloneMap(authentic);
        _tamperCiphertext(badMac);
        countingStorage.resetJournalReads();
        await expectLater(
          bob.manager.decryptMessage('alice-id', 'alice-device', badMac),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
        await Future<void>.delayed(Duration.zero);
        expect(countingStorage.journalReads, 1);
        expect(_storageSnapshot(countingStorage), rejectionBaseline);
        expect(events, hasLength(eventBaseline));
        expect(warningCalls, 0);
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: selectedId,
          ),
          isTrue,
        );
        expect(
          await bob.manager.hasSession('alice-id', 'alice-device'),
          isFalse,
        );

        countingStorage.resetJournalReads();
        expect(
          await bob.manager.decryptMessage(
            'alice-id',
            'alice-device',
            authentic,
          ),
          'single selected-key validation',
        );
        expect(
          countingStorage.journalReads,
          2,
          reason: 'one selected-material read plus one post-auth consume read',
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: selectedId,
          ),
          isFalse,
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: unselected['keyId'] as int,
          ),
          isTrue,
        );
        await subscription.cancel();
        eventBus.dispose();
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test(
      'selected routed private-key corruption rejects after one journal read and authentic retry succeeds',
      () async {
        final alice = await _freshManager();
        final countingStorage = _CountingJournalStorage();
        final bob = await _freshManager(backingStorage: countingStorage);
        final generation = await _acceptGeneration(
          bob.manager,
          initial: true,
          oneTimePreKeyCount: 3,
        );
        final bundle = generation.consumerBundle(oneTimePreKeyIndex: 0);
        await alice.manager.createSession(bundle);
        final authentic = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'selected key must validate',
        );

        final originalJournal = countingStorage.store[_journalKey]!;
        final raw = Map<String, dynamic>.from(
          jsonDecode(originalJournal) as Map,
        );
        final routedGeneration = (raw['generations'] as List)
            .cast<Map<String, dynamic>>()
            .singleWhere(
              (entry) =>
                  entry['opkGeneration'] == generation.route.opkGeneration,
            );
        final privateOpks = (routedGeneration['oneTimePreKeys'] as List)
            .cast<Map<String, dynamic>>();
        privateOpks.first['keyPair']['privateKey'] =
            privateOpks[1]['keyPair']['privateKey'];
        await countingStorage.write(key: _journalKey, value: jsonEncode(raw));
        final corruptBaseline = _storageSnapshot(countingStorage);

        countingStorage.resetJournalReads();
        await expectLater(
          bob.manager.decryptMessage('alice-id', 'alice-device', authentic),
          throwsFormatException,
        );
        expect(countingStorage.journalReads, 1);
        expect(_storageSnapshot(countingStorage), corruptBaseline);
        expect(
          await bob.manager.hasSession('alice-id', 'alice-device'),
          isFalse,
        );

        await countingStorage.write(key: _journalKey, value: originalJournal);
        countingStorage.resetJournalReads();
        expect(
          await bob.manager.decryptMessage(
            'alice-id',
            'alice-device',
            authentic,
          ),
          'selected key must validate',
        );
        expect(countingStorage.journalReads, 2);
      },
    );

    test(
      'route drift and bad MAC preserve responder storage byte-for-byte',
      () async {
        final alice = await _freshManager();
        final eventBus = SecurityEventBus();
        final events = <SecurityEvent>[];
        final subscription = eventBus.events.listen(events.add);
        final bob = await _freshManager(securityEventBus: eventBus);
        final generation = await _acceptGeneration(bob.manager, initial: true);
        final bundle = generation.consumerBundle();
        final opkId = bundle.oneTimePreKey!.keyId;
        await alice.manager.createSession(bundle);
        final authentic = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'authentic retry',
        );
        final differentKemBytes = base64Decode(
          authentic['kyberCiphertext'] as String,
        )..[0] ^= 1;
        var warningCalls = 0;
        bob.manager.onPreKeyExhaustionWarning = (_) => warningCalls++;
        await Future<void>.delayed(Duration.zero);
        final eventBaseline = events.length;
        final baseline = _storageSnapshot(bob.storage);

        for (final mutate in <void Function(Map<String, dynamic>)>[
          (value) => value.remove('bundleRevision'),
          (value) => value.remove('usedOneTimePreKeyId'),
          (value) => value.remove('recipientSignedPreKeyId'),
          (value) => value.remove('recipientKeyId'),
          (value) => value.remove('kyberCiphertext'),
          (value) =>
              value['bundleRevision'] = (value['bundleRevision'] as int) + 1,
          (value) =>
              value['opkGeneration'] = (value['opkGeneration'] as int) + 1,
          (value) => value['opkSetDigest'] = 'f' * 64,
          (value) => value['opkGeneration'] = 9007199254740992,
          (value) => value['recipientSignedPreKeyId'] =
              (value['recipientSignedPreKeyId'] as int) + 1,
          (value) =>
              value['recipientKeyId'] = (value['recipientKeyId'] as int) + 1,
          (value) => value['kemSuite'] = 'ML-KEM-1024',
          (value) => value['kemStandard'] = 'draft',
          (value) => value['kemWireVersion'] = 2,
          (value) => value['kyberCiphertext'] = base64Encode(differentKemBytes),
        ]) {
          final rejected = _cloneMap(authentic);
          mutate(rejected);
          await expectLater(
            bob.manager.decryptMessage('alice-id', 'alice-device', rejected),
            throwsA(anything),
          );
          await Future<void>.delayed(Duration.zero);
          expect(_storageSnapshot(bob.storage), baseline);
          expect(events, hasLength(eventBaseline));
          expect(warningCalls, 0);
          expect(
            await bob.manager.hasSession('alice-id', 'alice-device'),
            isFalse,
          );
        }

        final badMac = _cloneMap(authentic);
        _tamperCiphertext(badMac);
        await expectLater(
          bob.manager.decryptMessage('alice-id', 'alice-device', badMac),
          throwsA(anything),
        );
        await Future<void>.delayed(Duration.zero);
        expect(_storageSnapshot(bob.storage), baseline);
        expect(events, hasLength(eventBaseline));
        expect(warningCalls, 0);
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: opkId,
          ),
          isTrue,
        );

        expect(
          await bob.manager.decryptMessage(
            'alice-id',
            'alice-device',
            authentic,
          ),
          'authentic retry',
        );
        await subscription.cancel();
        eventBus.dispose();
      },
    );

    test(
      'explicit-null and alternate valid OPK routes fail authentication without consuming either key',
      () async {
        final alice = await _freshManager();
        final eventBus = SecurityEventBus();
        final events = <SecurityEvent>[];
        final subscription = eventBus.events.listen(events.add);
        final bob = await _freshManager(securityEventBus: eventBus);
        final generation = await _acceptGeneration(
          bob.manager,
          initial: true,
          oneTimePreKeyCount: 3,
        );
        final bundle = generation.consumerBundle(oneTimePreKeyIndex: 0);
        final alternateBundle = generation.consumerBundle(
          oneTimePreKeyIndex: 1,
        );
        final selectedId = bundle.oneTimePreKey!.keyId;
        final alternateId = alternateBundle.oneTimePreKey!.keyId;
        await alice.manager.createSession(bundle);
        final authentic = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'OPK selection is authenticated',
        );
        var warningCalls = 0;
        bob.manager.onPreKeyExhaustionWarning = (_) => warningCalls++;
        await Future<void>.delayed(Duration.zero);
        final eventBaseline = events.length;
        final storageBaseline = _storageSnapshot(bob.storage);

        for (final alternateSelection in <int?>[null, alternateId]) {
          final tampered = _cloneMap(authentic);
          tampered['usedOneTimePreKeyId'] = alternateSelection;
          await expectLater(
            bob.manager.decryptMessage('alice-id', 'alice-device', tampered),
            throwsA(isA<SecretBoxAuthenticationError>()),
          );
          await Future<void>.delayed(Duration.zero);
          expect(_storageSnapshot(bob.storage), storageBaseline);
          expect(
            _hasOneTimePreKeyForTest(
              bob.storage,
              opkGeneration: generation.route.opkGeneration,
              keyId: selectedId,
            ),
            isTrue,
          );
          expect(
            _hasOneTimePreKeyForTest(
              bob.storage,
              opkGeneration: generation.route.opkGeneration,
              keyId: alternateId,
            ),
            isTrue,
          );
          expect(
            await bob.manager.hasSession('alice-id', 'alice-device'),
            isFalse,
          );
          expect(events, hasLength(eventBaseline));
          expect(warningCalls, 0);
        }

        expect(
          await bob.manager.decryptMessage(
            'alice-id',
            'alice-device',
            authentic,
          ),
          'OPK selection is authenticated',
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: selectedId,
          ),
          isFalse,
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: alternateId,
          ),
          isTrue,
        );
        await subscription.cancel();
        eventBus.dispose();
      },
    );

    test(
      'sealed outer route mismatch rolls back nonce and journal state',
      () async {
        final alice = await _freshManager(
          userId: 'alice-id',
          deviceId: 'alice-device',
        );
        final countingStorage = _CountingJournalStorage();
        final bob = await _freshManager(
          userId: 'bob-id',
          deviceId: 'bob-device',
          backingStorage: countingStorage,
        );
        final generation = await _acceptGeneration(bob.manager, initial: true);
        await alice.manager.createSession(generation.consumerBundle());
        final authentic = await alice.manager.encryptSealedSender(
          'bob-id',
          'bob-device',
          await bob.manager.getIdentityPublicKey(),
          'sealed generation N',
        );
        expect(authentic, isNot(contains('usedOneTimePreKeyId')));
        final differentCiphertextBytes = base64Decode(
          authentic['kyberCiphertext'] as String,
        )..[0] ^= 1;
        final differentCiphertext = base64Encode(differentCiphertextBytes);
        final baseline = _storageSnapshot(bob.storage);
        for (final mutate in <void Function(Map<String, dynamic>)>[
          (value) => value.remove('kyberCiphertext'),
          (value) => value.remove('bundleRevision'),
          (value) => value.remove('opkGeneration'),
          (value) => value.remove('opkSetDigest'),
          (value) => value.remove('recipientSignedPreKeyId'),
          (value) => value.remove('recipientKeyId'),
          (value) =>
              value['bundleRevision'] = (value['bundleRevision'] as int) + 1,
          (value) =>
              value['opkGeneration'] = (value['opkGeneration'] as int) + 1,
          (value) => value['opkSetDigest'] = 'e' * 64,
          (value) => value['recipientSignedPreKeyId'] =
              (value['recipientSignedPreKeyId'] as int) + 1,
          (value) => value['recipientSignedPreKeyId'] =
              RisaalCryptoProtocol.maxKeyId + 1,
          (value) =>
              value['recipientKeyId'] = (value['recipientKeyId'] as int) + 1,
          (value) => value['kemSuite'] = 'ML-KEM-1024',
          (value) => value['kemStandard'] = 'draft',
          (value) => value['kemWireVersion'] = 2,
          (value) => value['usedOneTimePreKeyId'] = 1,
          (value) => value['senderEphemeralKey'] = 'A' * 44,
          (value) => value['kyberCiphertext'] =
              '!' * (value['kyberCiphertext'] as String).length,
          (value) => value['kyberCiphertext'] = base64Encode(
            List<int>.filled(1087, 0),
          ),
          (value) => value['kyberCiphertext'] = _nonCanonicalBase64(
            value['kyberCiphertext'] as String,
          ),
          (value) => value['kyberCiphertext'] = 'A' * 16384,
          (value) => value['kyberCiphertext'] = differentCiphertext,
        ]) {
          final tampered = _cloneMap(authentic);
          mutate(tampered);
          countingStorage.resetJournalReads();
          await expectLater(
            bob.manager.decryptSealedSender(tampered),
            throwsFormatException,
          );
          expect(countingStorage.journalReads, 0);
          expect(_storageSnapshot(bob.storage), baseline);
        }
        expect(
          (await bob.manager.decryptSealedSender(authentic)).plaintext,
          'sealed generation N',
        );
      },
    );

    test(
      'valid sealed layer cannot hide protected-inner route drift',
      () async {
        final alice = await _freshManager(
          userId: 'alice-id',
          deviceId: 'alice-device',
        );
        final eventBus = SecurityEventBus();
        final events = <SecurityEvent>[];
        final subscription = eventBus.events.listen(events.add);
        final bob = await _freshManager(
          userId: 'bob-id',
          deviceId: 'bob-device',
          securityEventBus: eventBus,
        );
        final generation = await _acceptGeneration(bob.manager, initial: true);
        final selectedBundle = generation.consumerBundle(oneTimePreKeyIndex: 0);
        final alternateId = generation
            .consumerBundle(oneTimePreKeyIndex: 1)
            .oneTimePreKey!
            .keyId;
        final selectedId = selectedBundle.oneTimePreKey!.keyId;
        await alice.manager.createSession(selectedBundle);
        final inner = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'protected route',
        );
        final routing = PreKeyHandshakeRouting.fromEnvelopeJson(inner);
        final aliceIdentity = await alice.manager.getIdentityPublicKey();
        final bobIdentity = await bob.manager.getIdentityPublicKey();
        final differentCiphertextBytes = base64Decode(
          inner['kyberCiphertext'] as String,
        )..[0] ^= 1;
        var warningCalls = 0;
        bob.manager.onPreKeyExhaustionWarning = (_) => warningCalls++;
        await Future<void>.delayed(Duration.zero);
        final eventBaseline = events.length;
        final baseline = _storageSnapshot(bob.storage);
        for (final mutate in <void Function(Map<String, dynamic>)>[
          (value) =>
              value['opkGeneration'] = routing.opkRoute.opkGeneration + 1,
          (value) => value['usedOneTimePreKeyId'] = null,
          (value) => value['usedOneTimePreKeyId'] = alternateId,
          (value) => value.remove('kyberCiphertext'),
          (value) => value['kyberCiphertext'] =
              '!' * (value['kyberCiphertext'] as String).length,
          (value) => value['kyberCiphertext'] = base64Encode(
            List<int>.filled(1087, 0),
          ),
          (value) => value['kyberCiphertext'] = _nonCanonicalBase64(
            value['kyberCiphertext'] as String,
          ),
          (value) => value['kyberCiphertext'] = 'A' * 16384,
          (value) =>
              value['kyberCiphertext'] = base64Encode(differentCiphertextBytes),
        ]) {
          final driftedInner = _cloneMap(inner);
          mutate(driftedInner);
          final sealedDrift = await SealedSenderEnvelope.seal(
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            senderIdentityKey: aliceIdentity,
            encryptedMessage: driftedInner,
            recipientIdentityPublicKey: bobIdentity,
          );
          sealedDrift.addAll(<String, dynamic>{
            'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
            'kyberCiphertext': inner['kyberCiphertext'],
            ...routing.toSealedProjectionJson(),
          });
          await expectLater(
            bob.manager.decryptSealedSender(sealedDrift),
            throwsA(anything),
          );
          await Future<void>.delayed(Duration.zero);
          expect(_storageSnapshot(bob.storage), baseline);
          expect(events, hasLength(eventBaseline));
          expect(warningCalls, 0);
          expect(
            _hasOneTimePreKeyForTest(
              bob.storage,
              opkGeneration: generation.route.opkGeneration,
              keyId: selectedId,
            ),
            isTrue,
          );
          expect(
            _hasOneTimePreKeyForTest(
              bob.storage,
              opkGeneration: generation.route.opkGeneration,
              keyId: alternateId,
            ),
            isTrue,
          );
          expect(
            await bob.manager.hasSession('alice-id', 'alice-device'),
            isFalse,
          );
        }

        final authentic = await SealedSenderEnvelope.seal(
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          senderIdentityKey: aliceIdentity,
          encryptedMessage: inner,
          recipientIdentityPublicKey: bobIdentity,
        );
        authentic.addAll(<String, dynamic>{
          'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
          'kyberCiphertext': inner['kyberCiphertext'],
          ...routing.toSealedProjectionJson(),
        });
        expect(
          (await bob.manager.decryptSealedSender(authentic)).plaintext,
          'protected route',
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: selectedId,
          ),
          isFalse,
        );
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: generation.route.opkGeneration,
            keyId: alternateId,
          ),
          isTrue,
        );
        await subscription.cancel();
        eventBus.dispose();
      },
    );

    test(
      'direct, sealed inner, sealed outer, and batch normal paths reject each PreKey-only field',
      () async {
        final alice = await _freshManager(
          userId: 'alice-id',
          deviceId: 'alice-device',
        );
        final bob = await _freshManager(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        final generation = await _acceptGeneration(bob.manager, initial: true);
        await alice.manager.createSession(generation.consumerBundle());
        final first = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'first',
        );
        await bob.manager.decryptMessage('alice-id', 'alice-device', first);
        final fieldValues = _preKeyOnlyFieldValues(first);
        final firstRouting = PreKeyHandshakeRouting.fromEnvelopeJson(first);

        final normal = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'normal direct',
        );
        final directBaseline = _storageSnapshot(bob.storage);
        for (final field in _preKeyOnlyFields) {
          final strayDirect = _cloneMap(normal);
          strayDirect[field] = fieldValues[field];
          await expectLater(
            bob.manager.decryptMessage('alice-id', 'alice-device', strayDirect),
            throwsFormatException,
            reason: 'direct normal field $field',
          );
          expect(_storageSnapshot(bob.storage), directBaseline);
        }
        expect(
          await bob.manager.decryptMessage('alice-id', 'alice-device', normal),
          'normal direct',
        );

        final sealedInner = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'normal sealed inner',
        );
        final aliceIdentity = await alice.manager.getIdentityPublicKey();
        final bobIdentity = await bob.manager.getIdentityPublicKey();
        final sealedBaseline = _storageSnapshot(bob.storage);
        for (final field in _preKeyOnlyFields) {
          final protectedStray = _cloneMap(sealedInner);
          protectedStray[field] = fieldValues[field];
          final sealed = await SealedSenderEnvelope.seal(
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            senderIdentityKey: aliceIdentity,
            encryptedMessage: protectedStray,
            recipientIdentityPublicKey: bobIdentity,
          );
          sealed['cryptoProtocolEpoch'] =
              RisaalCryptoProtocol.cryptoProtocolEpoch;
          await expectLater(
            bob.manager.decryptSealedSender(sealed),
            throwsFormatException,
            reason: 'protected normal field $field',
          );
          expect(_storageSnapshot(bob.storage), sealedBaseline);
        }

        final authenticSealed = await SealedSenderEnvelope.seal(
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          senderIdentityKey: aliceIdentity,
          encryptedMessage: sealedInner,
          recipientIdentityPublicKey: bobIdentity,
        );
        authenticSealed['cryptoProtocolEpoch'] =
            RisaalCryptoProtocol.cryptoProtocolEpoch;
        expect(
          (await bob.manager.decryptSealedSender(authenticSealed)).plaintext,
          'normal sealed inner',
        );

        final outerInner = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'normal sealed outer',
        );
        final cleanOuter = await SealedSenderEnvelope.seal(
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          senderIdentityKey: aliceIdentity,
          encryptedMessage: outerInner,
          recipientIdentityPublicKey: bobIdentity,
        );
        cleanOuter['cryptoProtocolEpoch'] =
            RisaalCryptoProtocol.cryptoProtocolEpoch;
        final outerBaseline = _storageSnapshot(bob.storage);
        for (final field in _preKeyOnlyFields) {
          final strayOuter = _cloneMap(cleanOuter);
          strayOuter[field] = fieldValues[field];
          await expectLater(
            bob.manager.decryptSealedSender(strayOuter),
            throwsFormatException,
            reason: 'visible normal outer field $field',
          );
          expect(_storageSnapshot(bob.storage), outerBaseline);
        }
        final completeStrayOuter = _cloneMap(cleanOuter)
          ..addAll(<String, dynamic>{
            'kyberCiphertext': first['kyberCiphertext'],
            ...firstRouting.toSealedProjectionJson(),
          });
        await expectLater(
          bob.manager.decryptSealedSender(completeStrayOuter),
          throwsFormatException,
        );
        expect(_storageSnapshot(bob.storage), outerBaseline);
        expect(
          (await bob.manager.decryptSealedSender(cleanOuter)).plaintext,
          'normal sealed outer',
          reason: 'outer preflight must not claim the authentic nonce',
        );

        final batchEnvelopeA = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'normal batch A',
        );
        final batchEnvelopeB = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'normal batch B',
        );
        final batchBaseline = _storageSnapshot(bob.storage);
        for (final field in _preKeyOnlyFields) {
          final strayBatch = _cloneMap(batchEnvelopeA);
          strayBatch[field] = fieldValues[field];
          await expectLater(
            bob.manager.decryptNormalBatch(
              'alice-id',
              'alice-device',
              <Map<String, dynamic>>[strayBatch],
              useIsolate: false,
            ),
            throwsFormatException,
            reason: 'batch normal field $field',
          );
          expect(_storageSnapshot(bob.storage), batchBaseline);
        }

        final invalidSecondEnvelope = _cloneMap(batchEnvelopeB)
          ..['bundleRevision'] = generation.route.bundleRevision;
        await expectLater(
          bob.manager.decryptNormalBatch(
            'alice-id',
            'alice-device',
            <Map<String, dynamic>>[batchEnvelopeA, invalidSecondEnvelope],
            useIsolate: false,
          ),
          throwsFormatException,
          reason: 'all envelopes must preflight before the session is loaded',
        );
        expect(_storageSnapshot(bob.storage), batchBaseline);

        final batch = await bob.manager.decryptNormalBatch(
          'alice-id',
          'alice-device',
          <Map<String, dynamic>>[batchEnvelopeA, batchEnvelopeB],
          useIsolate: false,
        );
        expect(
          batch.plaintexts,
          <String>['normal batch A', 'normal batch B'],
          reason:
              'the failed mixed batch must leave persisted and cached ratchets unchanged',
        );
      },
    );

    test(
      'consume and next replacement serialize without losing either update',
      () async {
        final alice = await _freshManager();
        final blockingStorage = _BlockingConsumeStorage();
        final bob = await _freshManager(backingStorage: blockingStorage);
        final first = await _acceptGeneration(bob.manager, initial: true);
        final bundle = first.consumerBundle(oneTimePreKeyIndex: 2);
        await alice.manager.createSession(bundle);
        final envelope = await alice.manager.encryptMessage(
          'bob-id',
          'bob-device',
          'serialized lifecycle',
        );

        blockingStorage.blockNextConsumeWrite = true;
        final decrypt = bob.manager.decryptMessage(
          'alice-id',
          'alice-device',
          envelope,
        );
        await blockingStorage.consumeWriteStarted.future.timeout(
          const Duration(seconds: 5),
        );
        var replacementCompleted = false;
        final replacement = bob.manager
            .prepareKeyBundleReplacement(oneTimePreKeyCount: 3)
            .whenComplete(() => replacementCompleted = true);
        await Future<void>.delayed(Duration.zero);
        expect(
          replacementCompleted,
          isFalse,
          reason: 'replacement must wait behind authenticated consume',
        );
        blockingStorage.releaseConsumeWrite.complete();

        expect(
          await decrypt.timeout(const Duration(seconds: 10)),
          'serialized lifecycle',
        );
        expect(
          await replacement.timeout(const Duration(seconds: 10)),
          isA<KeyBundleReplacementSnapshot>(),
        );
        expect(await bob.manager.pendingKeyBundleReplacement(), isNotNull);
        expect(
          _hasOneTimePreKeyForTest(
            bob.storage,
            opkGeneration: first.route.opkGeneration,
            keyId: bundle.oneTimePreKey!.keyId,
          ),
          isFalse,
        );
        expect(bob.storage.store[_journalKey], isNotNull);
      },
    );
  });
}
