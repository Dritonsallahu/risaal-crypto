@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

class _FailBeforeWriteStorage extends FakeSecureStorage {
  String? _keyToFail;

  void failNextWriteTo(String key) {
    _keyToFail = key;
  }

  @override
  Future<void> write({required String key, required String value}) async {
    if (_keyToFail == key) {
      _keyToFail = null;
      throw StateError('injected write failure');
    }
    await super.write(key: key, value: value);
  }
}

Map<String, dynamic> _ownerResponseFor(KeyBundleReplacementDispatch dispatch) {
  final snapshot = dispatch.snapshot;
  final payload = dispatch.toReplacementPayload(deviceId: 'device-1');
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
    'accepted': CryptoTestFixtures.receiptFor(snapshot).toJson(),
  };
}

Future<({SignalProtocolManager manager, FakeSecureStorage storage})>
_acceptedManager() async {
  final (manager, storage) =
      await CryptoTestFixtures.createInitializedManager();
  await CryptoTestFixtures.acceptInitialGeneration(manager);
  return (manager: manager, storage: storage);
}

void main() {
  test(
    'failure after signing persistence but before identity recovers on restart',
    () async {
      final storage = _FailBeforeWriteStorage();
      final firstManager = SignalProtocolManager(secureStorage: storage);
      await firstManager.wipeForFreshRegistration();
      storage.failNextWriteTo('crypto_identity_key_pair');

      await expectLater(firstManager.initialize(), throwsStateError);
      expect(storage.store['crypto_signing_key_pair'], isNotNull);
      expect(storage.store['crypto_identity_key_pair'], isNull);

      final restarted = SignalProtocolManager(secureStorage: storage);
      expect(await restarted.initialize(), isTrue);
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(
        restarted,
        oneTimePreKeyCount: 5,
      );
      expect(accepted.publicMaterial['identityKey'], isNotEmpty);
      expect(accepted.publicMaterial['identitySigningKey'], isNotEmpty);
      final ids = (accepted.publicMaterial['oneTimePreKeys'] as List<dynamic>)
          .map((item) => (item as Map<String, dynamic>)['keyId'] as int)
          .toList(growable: false);
      expect(ids.toSet(), hasLength(ids.length));
      expect(ids, everyElement(greaterThan(0)));
    },
  );

  test('legacy identity-only state cannot self-authorize migration', () async {
    final storage = FakeSecureStorage();
    final identity = await SignalKeyHelper.generateIdentityKeyPair();
    final cryptoStorage = CryptoStorage(secureStorage: storage);
    await cryptoStorage.saveIdentityKeyPair(identity);
    final before = Map<String, String>.from(storage.store);

    await expectLater(
      SignalProtocolManager(secureStorage: storage).initialize(),
      throwsStateError,
    );
    expect(storage.store, before);
  });

  test('accepted journal restarts as stable existing state', () async {
    final fixture = await _acceptedManager();

    final restarted = SignalProtocolManager(secureStorage: fixture.storage);
    expect(await restarted.initialize(), isFalse);
    expect(await restarted.pendingKeyBundleReplacement(), isNull);
    expect(await restarted.oneTimePreKeyCount(), 5);
  });

  test(
    'lost local ACK resumes exact dispatch and reconciles authenticated owner state',
    () async {
      final (manager, storage) =
          await CryptoTestFixtures.createInitializedManager();
      final prepared = await manager.prepareInitialKeyBundleRegistration(
        oneTimePreKeyCount: 4,
      );
      await manager.installKeyBundleReplacement(prepared);
      final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
        prepared,
      );
      final before = jsonEncode(
        dispatch.toReplacementPayload(deviceId: 'device-1'),
      );

      final restarted = SignalProtocolManager(secureStorage: storage);
      await expectLater(
        restarted.initialize(),
        throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
      );
      final resumed = await restarted.resumeKeyBundleReplacement();
      expect(
        jsonEncode(resumed!.toReplacementPayload(deviceId: 'device-1')),
        before,
      );
      expect(
        await restarted.reconcileKeyBundleReplacement(
          _ownerResponseFor(resumed),
        ),
        isTrue,
      );

      final stableRestart = SignalProtocolManager(secureStorage: storage);
      expect(await stableRestart.initialize(), isFalse);
      expect(await stableRestart.pendingKeyBundleReplacement(), isNull);
      expect(await stableRestart.oneTimePreKeyCount(), 4);
    },
  );

  test('accepted journal never imports a reappearing flat OPK pool', () async {
    final fixture = await _acceptedManager();
    final rogue = await SignalKeyHelper.generateOneTimePreKeys(900, 2);
    await CryptoStorage(
      secureStorage: fixture.storage,
    ).saveOneTimePreKeys(rogue);
    final before = Map<String, String>.from(fixture.storage.store);

    await expectLater(
      SignalProtocolManager(secureStorage: fixture.storage).initialize(),
      throwsA(isA<KeyBundleReplacementRecoveryRequired>()),
    );
    expect(fixture.storage.store, before);
  });

  group('accepted current-key invariants', () {
    test('missing identity fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      await fixture.storage.delete(key: 'crypto_identity_key_pair');
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Invalid journal identity material'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });

    test('missing signing key fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      await fixture.storage.delete(key: 'crypto_signing_key_pair');
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Invalid journal identity material'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });

    test('missing ML-KEM key fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      await fixture.storage.delete(key: 'crypto_e2_kyber_key_pair');
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('ML-KEM key is missing or invalid'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });

    test('mismatched identity pair fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      final cryptoStorage = CryptoStorage(secureStorage: fixture.storage);
      final identity = (await cryptoStorage.getIdentityKeyPair())!;
      final unrelated = await SignalKeyHelper.generateIdentityKeyPair();
      await cryptoStorage.saveIdentityKeyPair(
        KeyPair(
          publicKey: identity.publicKey,
          privateKey: unrelated.privateKey,
        ),
      );
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Invalid journal identity material'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });

    test('mismatched signing pair fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      final cryptoStorage = CryptoStorage(secureStorage: fixture.storage);
      final signing = (await cryptoStorage.getSigningKeyPair())!;
      final unrelated = await SignalKeyHelper.generateSigningKeyPair();
      await cryptoStorage.saveSigningKeyPair(
        KeyPair(publicKey: signing.publicKey, privateKey: unrelated.privateKey),
      );
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Invalid journal identity material'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });

    test('mismatched signed pre-key fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      final cryptoStorage = CryptoStorage(secureStorage: fixture.storage);
      final signedPreKey = (await cryptoStorage.getSignedPreKey())!;
      final unrelated = await SignalKeyHelper.generateX25519KeyPair();
      await cryptoStorage.saveSignedPreKey(
        SignedPreKey(
          keyId: signedPreKey.keyId,
          keyPair: KeyPair(
            publicKey: signedPreKey.keyPair.publicKey,
            privateKey: unrelated.privateKey,
          ),
          signature: signedPreKey.signature,
          createdAt: signedPreKey.createdAt,
        ),
      );
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('signed pre-key is missing or invalid'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });

    test('mismatched ML-KEM pair fails closed without mutation', () async {
      final fixture = await _acceptedManager();
      final cryptoStorage = CryptoStorage(secureStorage: fixture.storage);
      final current = (await cryptoStorage.getKyberKeyPair())!;
      final unrelated = SignalKeyHelper.generateKyberKeyPair(
        keyId: current.keyId!,
      );
      await cryptoStorage.saveKyberKeyPair(
        KyberKeyPair(
          publicKey: current.publicKey,
          privateKey: unrelated.privateKey,
          keyId: current.keyId,
          cryptoProtocolEpoch: current.cryptoProtocolEpoch,
          kemSuite: current.kemSuite,
          kemStandard: current.kemStandard,
          kemWireVersion: current.kemWireVersion,
        ),
      );
      final before = Map<String, String>.from(fixture.storage.store);

      await expectLater(
        SignalProtocolManager(secureStorage: fixture.storage).initialize(),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('ML-KEM key pair is invalid'),
          ),
        ),
      );
      expect(fixture.storage.store, before);
    });
  });

  group('OPK reservation and material invariants', () {
    test('negative counter fails closed while legacy zero advances', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      await storage.write(key: 'crypto_next_pre_key_id', value: '0');
      expect(await cryptoStorage.getNextPreKeyId(), 1);

      await storage.write(key: 'crypto_next_pre_key_id', value: '-1');
      await expectLater(cryptoStorage.getNextPreKeyId(), throwsFormatException);
    });

    test('stale counter advances past every stored legacy id', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final existing = await SignalKeyHelper.generateOneTimePreKeys(7, 2);
      await cryptoStorage.saveOneTimePreKeys(existing);
      await storage.write(key: 'crypto_next_pre_key_id', value: '1');

      expect(await cryptoStorage.reserveOneTimePreKeyRange(2), 9);
      expect(storage.store['crypto_next_pre_key_id'], '11');
    });

    test('distinct OPK ids cannot share one-time key material', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final pair = await SignalKeyHelper.generateX25519KeyPair();
      await cryptoStorage.saveOneTimePreKeys(<OneTimePreKey>[
        OneTimePreKey(keyId: 7, keyPair: pair),
        OneTimePreKey(keyId: 8, keyPair: pair),
      ]);

      await expectLater(
        cryptoStorage.validateOneTimePreKeyPool(),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('material'),
          ),
        ),
      );
    });

    test('duplicate stored OPK ids fail before counter reservation', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final duplicate = (await SignalKeyHelper.generateOneTimePreKeys(
        7,
        1,
      )).single;
      await cryptoStorage.saveOneTimePreKeys(<OneTimePreKey>[
        duplicate,
        OneTimePreKey(keyId: duplicate.keyId, keyPair: duplicate.keyPair),
      ]);

      await expectLater(
        cryptoStorage.reserveOneTimePreKeyRange(1),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Duplicate'),
          ),
        ),
      );
      expect(storage.store['crypto_next_pre_key_id'], isNull);
    });
  });
}
