@Retry(0)
library;

import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';
import 'package:risaal_crypto/src/sealed_sender_errors.dart';
import 'package:risaal_crypto/src/sealed_sender_trust_policy.dart';
import 'package:risaal_crypto/src/sender_certificate.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _keyId = 'sc-test';
const _aliceId = 'alice-id';
const _aliceDevice = 'alice-device';
const _hour = 60 * 60 * 1000;

/// Alice holds a pending first-contact session towards Bob; Bob has an
/// accepted key generation. A test server key signs certificates.
final class _Setup {
  _Setup({
    required this.alice,
    required this.aliceStorage,
    required this.bobStorage,
    required this.bobIdentity,
    required this.aliceIdentityKey,
    required this.aliceSigning,
    required this.server,
  });

  final SignalProtocolManager alice;
  final FakeSecureStorage aliceStorage;
  final FakeSecureStorage bobStorage;
  final KeyPair bobIdentity;
  final String aliceIdentityKey;
  final KeyPair aliceSigning;
  final KeyPair server;

  Map<String, String> get pinnedServerKeys => {_keyId: server.publicKey};

  Future<SignalProtocolManager> bob([SealedSenderTrustPolicy? policy]) async {
    final manager = SignalProtocolManager(
      secureStorage: bobStorage,
      sealedSenderTrustPolicy:
          policy ??
          SealedSenderTrustPolicy(
            serverCertificateSigningKeys: pinnedServerKeys,
          ),
    );
    await manager.initialize();
    return manager;
  }

  Future<IssuedSenderCertificate> issue({
    String senderId = _aliceId,
    String senderDeviceId = _aliceDevice,
    String? senderIdentityKey,
    String? senderSigningKey,
    int? issuedAt,
    int? expiresAt,
  }) {
    final now = DateTime.now().millisecondsSinceEpoch;
    return SenderCertificateVerifier.issueForTesting(
      serverSigningPrivateKey: server.privateKey,
      keyId: _keyId,
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey ?? aliceIdentityKey,
      senderSigningKey: senderSigningKey ?? aliceSigning.publicKey,
      issuedAt: issuedAt ?? now - 60 * 1000,
      expiresAt: expiresAt ?? now + 24 * _hour,
    );
  }

  Future<Map<String, dynamic>> send({IssuedSenderCertificate? certificate}) =>
      alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        bobIdentity.publicKey,
        'first sealed message',
        senderCertificate: certificate,
      );
}

Future<_Setup> _setUp() async {
  final (alice, aliceStorage) =
      await CryptoTestFixtures.createInitializedManager();
  final (bob, bobStorage) = await CryptoTestFixtures.createInitializedManager();
  await aliceStorage.write(key: 'user_id', value: _aliceId);
  await aliceStorage.write(key: 'device_id', value: _aliceDevice);
  await bobStorage.write(key: 'user_id', value: 'bob-id');
  await bobStorage.write(key: 'device_id', value: 'bob-device');
  final accepted = await CryptoTestFixtures.acceptInitialGeneration(bob);
  await alice.createSession(
    accepted.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
  );
  return _Setup(
    alice: alice,
    aliceStorage: aliceStorage,
    bobStorage: bobStorage,
    bobIdentity: (await CryptoStorage(
      secureStorage: bobStorage,
    ).getIdentityKeyPair())!,
    aliceIdentityKey: await alice.getIdentityPublicKey(),
    aliceSigning: (await CryptoStorage(
      secureStorage: aliceStorage,
    ).getSigningKeyPair())!,
    server: await SignalKeyHelper.generateSigningKeyPair(),
  );
}

final Matcher _notThisDevice = throwsA(
  isA<StateError>().having(
    (e) => e.message,
    'message',
    'Sender certificate does not describe this device',
  ),
);

Matcher _certificateFailure(SenderCertificateFailure reason) => throwsA(
  isA<SealedSenderCertificateError>().having((e) => e.reason, 'reason', reason),
);

void main() {
  test('1. certified send is accepted as certified and never pins the '
      'signing key (both sealed lanes)', () async {
    final setup = await _setUp();
    final bob = await setup.bob();
    final envelope = await setup.send(certificate: await setup.issue());

    final prepared = await bob.prepareSealedReceive(
      deliveryId: 'delivery-1',
      sealedEnvelope: envelope,
    );
    expect(prepared.plaintext, 'first sealed message');
    expect(prepared.senderAuthentication!.certified, isTrue);
    expect(prepared.senderAuthentication!.certificateKeyId, _keyId);
    await bob.acknowledgeReceive(prepared.receipt);
    // R4-C3-V2: no signing-key pin is seeded from a certificate.
    expect(await bob.getPeerSigningKey(_aliceId, _aliceDevice), isNull);

    // A follow-up certified message on the legacy decrypt lane.
    final followUp = await setup.alice.encryptSealedSender(
      'bob-id',
      'bob-device',
      setup.bobIdentity.publicKey,
      'second',
      senderCertificate: await setup.issue(),
    );
    final result = await bob.decryptSealedSender(followUp);
    expect(result.plaintext, 'second');
    expect(result.senderAuthentication!.certified, isTrue);
    expect(await bob.getPeerSigningKey(_aliceId, _aliceDevice), isNull);
  });

  test('legacy send (no certificate) carries no certificate fields', () async {
    final setup = await _setUp();
    final envelope = await setup.send();
    final content = await SealedSenderEnvelope.unseal(
      sealedEnvelope: envelope,
      recipientIdentityKeyPair: setup.bobIdentity,
      seenNonces: <String>{},
      trustedServerSigningKeys: setup.pinnedServerKeys,
    );
    expect(content.certified, isFalse);
    expect(content.certificateIgnored, isFalse);
    expect(content.senderSigningKey, isNull);
  });

  group('2. a certificate that does not describe this device is refused '
      'before any mutation', () {
    final cases = <String, Future<IssuedSenderCertificate> Function(_Setup s)>{
      "Carol's keys": (s) async => s.issue(
        senderId: 'carol-id',
        senderDeviceId: 'carol-device',
        senderIdentityKey:
            (await SignalKeyHelper.generateX25519KeyPair()).publicKey,
        senderSigningKey:
            (await SignalKeyHelper.generateSigningKeyPair()).publicKey,
      ),
      'other user id': (s) => s.issue(senderId: 'carol-id'),
      'other device id': (s) => s.issue(senderDeviceId: 'alice-device-2'),
      'other identity key': (s) async => s.issue(
        senderIdentityKey:
            (await SignalKeyHelper.generateX25519KeyPair()).publicKey,
      ),
      'other signing key': (s) async => s.issue(
        senderSigningKey:
            (await SignalKeyHelper.generateSigningKeyPair()).publicKey,
      ),
      'malformed bytes': (s) async => IssuedSenderCertificate(
        certificateBytes: (await s.issue()).certificateBytes.sublist(1),
        serverSignature: (await s.issue()).serverSignature,
      ),
    };
    for (final entry in cases.entries) {
      test('${entry.key}: encryptSealedSender + prepareSealedSend', () async {
        final setup = await _setUp();
        final certificate = await entry.value(setup);
        final before = Map<String, String>.from(setup.aliceStorage.store);

        await expectLater(setup.send(certificate: certificate), _notThisDevice);
        expect(setup.aliceStorage.store, before);

        await expectLater(
          setup.alice.prepareSealedSend(
            deliveryId: 'send-1',
            recipientId: 'bob-id',
            recipientDeviceId: 'bob-device',
            recipientIdentityPublicKey: setup.bobIdentity.publicKey,
            plaintext: 'first sealed message',
            senderCertificate: certificate,
          ),
          _notThisDevice,
        );
        expect(setup.aliceStorage.store, before);
        expect(await setup.alice.pendingSend(), isNull);

        // The untouched first-contact chain still works without it.
        final ok = await setup.send();
        expect(ok['ciphertext'], isA<String>());
      });
    }
  });

  test(
    '3. expired / not-yet-valid certificate is refused before mutation',
    () async {
      final setup = await _setUp();
      final now = DateTime.now().millisecondsSinceEpoch;
      final expired = await setup.issue(
        issuedAt: now - 48 * _hour,
        expiresAt: now - 24 * _hour,
      );
      final future = await setup.issue(
        issuedAt: now + 2 * _hour,
        expiresAt: now + 26 * _hour,
      );
      final before = Map<String, String>.from(setup.aliceStorage.store);
      final sessionBefore = await CryptoStorage(
        secureStorage: setup.aliceStorage,
      ).getSession('bob-id', 'bob-device');

      for (final certificate in [expired, future]) {
        await expectLater(setup.send(certificate: certificate), _notThisDevice);
        await expectLater(
          setup.alice.prepareSealedSend(
            deliveryId: 'send-expired',
            recipientId: 'bob-id',
            recipientDeviceId: 'bob-device',
            recipientIdentityPublicKey: setup.bobIdentity.publicKey,
            plaintext: 'first sealed message',
            senderCertificate: certificate,
          ),
          _notThisDevice,
        );
      }
      expect(setup.aliceStorage.store, before);
      final sessionAfter = await CryptoStorage(
        secureStorage: setup.aliceStorage,
      ).getSession('bob-id', 'bob-device');
      expect(sessionAfter!.toJson(), sessionBefore!.toJson());
    },
  );

  test('4. peekSealedSender reports a certified first contact without any '
      'side effect, and the real receive still succeeds', () async {
    final setup = await _setUp();
    final bob = await setup.bob();
    final envelope = await setup.send(certificate: await setup.issue());
    final bobCrypto = CryptoStorage(secureStorage: setup.bobStorage);
    final before = Map<String, String>.from(setup.bobStorage.store);
    final noncesBefore = await bobCrypto.loadSeenNonces();

    final peek = await bob.peekSealedSender(envelope);
    expect(peek.senderId, _aliceId);
    expect(peek.senderDeviceId, _aliceDevice);
    expect(peek.senderIdentityKey, setup.aliceIdentityKey);
    expect(peek.certified, isTrue);
    expect(peek.certificateIgnored, isFalse);
    expect(peek.certificateKeyId, _keyId);
    expect(peek.isFirstContact, isTrue);
    expect(peek.innerType, 'prekey');

    // Peeking twice is fine: nothing was reserved.
    await bob.peekSealedSender(envelope);
    expect(setup.bobStorage.store, before);
    expect(await bobCrypto.loadSeenNonces(), noncesBefore);
    expect(await bob.getSessionIdentityKey(_aliceId, _aliceDevice), isNull);
    expect(await bob.getPeerSigningKey(_aliceId, _aliceDevice), isNull);

    final prepared = await bob.prepareSealedReceive(
      deliveryId: 'delivery-after-peek',
      sealedEnvelope: envelope,
    );
    expect(prepared.plaintext, 'first sealed message');
    await bob.acknowledgeReceive(prepared.receipt);

    // Once pinned, a later message is no longer a first contact.
    final followUp = await setup.send(certificate: await setup.issue());
    final second = await bob.peekSealedSender(followUp);
    expect(second.isFirstContact, isFalse);
    expect(second.innerType, 'message');
  });

  test('peek of an uncertified envelope under a pinned key, and the '
      'UnverifiedFirstContactError -> approval -> retry flow', () async {
    final setup = await _setUp();
    final bob = await setup.bob(
      SealedSenderTrustPolicy(
        serverCertificateSigningKeys: setup.pinnedServerKeys,
        requireVerifiedFirstContact: true,
      ),
    );
    final envelope = await setup.send();
    final before = Map<String, String>.from(setup.bobStorage.store);

    await expectLater(
      bob.prepareSealedReceive(
        deliveryId: 'delivery-uncertified',
        sealedEnvelope: envelope,
      ),
      throwsA(isA<UnverifiedFirstContactError>()),
    );
    final peek = await bob.peekSealedSender(envelope);
    expect(peek.certified, isFalse);
    expect(peek.certificateIgnored, isFalse);
    expect(peek.certificateKeyId, isNull);
    expect(peek.isFirstContact, isTrue);
    expect(setup.bobStorage.store, before);

    final prepared = await bob.prepareSealedReceive(
      deliveryId: 'delivery-uncertified',
      sealedEnvelope: envelope,
      firstContactApproval: FirstContactApproval(
        senderId: peek.senderId,
        senderDeviceId: peek.senderDeviceId,
        senderIdentityKey: peek.senderIdentityKey,
        source: FirstContactApprovalSource.keyBundle,
      ),
    );
    expect(prepared.plaintext, 'first sealed message');
    expect(
      prepared.senderAuthentication!.approvalSource,
      FirstContactApprovalSource.keyBundle,
    );
  });

  test(
    'peek with no pinned server key reports the certificate as ignored',
    () async {
      final setup = await _setUp();
      final bob = await setup.bob(SealedSenderTrustPolicy.legacy);
      final peek = await bob.peekSealedSender(
        await setup.send(certificate: await setup.issue()),
      );
      expect(peek.certified, isFalse);
      expect(peek.certificateIgnored, isTrue);
    },
  );

  test('5. peek rejects a tampered certificate and a foreign envelope, '
      'persisting nothing', () async {
    final setup = await _setUp();
    final bob = await setup.bob();
    final forger = await SignalKeyHelper.generateSigningKeyPair();
    final forged = await SenderCertificateVerifier.issueForTesting(
      serverSigningPrivateKey: forger.privateKey,
      keyId: _keyId,
      senderId: _aliceId,
      senderDeviceId: _aliceDevice,
      senderIdentityKey: setup.aliceIdentityKey,
      senderSigningKey: setup.aliceSigning.publicKey,
      issuedAt: DateTime.now().millisecondsSinceEpoch - 60 * 1000,
      expiresAt: DateTime.now().millisecondsSinceEpoch + 24 * _hour,
    );
    // Alice's own send does not check the server signature, so a forged
    // certificate reaches the wire; Bob must reject it.
    final tampered = await setup.send(certificate: forged);
    final before = Map<String, String>.from(setup.bobStorage.store);

    await expectLater(
      bob.peekSealedSender(tampered),
      _certificateFailure(SenderCertificateFailure.badServerSignature),
    );
    expect(setup.bobStorage.store, before);

    final (carol, carolStorage) =
        await CryptoTestFixtures.createInitializedManager();
    final carolBefore = Map<String, String>.from(carolStorage.store);
    await expectLater(
      carol.peekSealedSender(tampered),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
    expect(carolStorage.store, carolBefore);
  });
}
