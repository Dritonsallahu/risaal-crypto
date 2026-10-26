@Retry(0)
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';
import 'package:risaal_crypto/src/sealed_sender_errors.dart';
import 'package:risaal_crypto/src/sealed_sender_trust_policy.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/sender_certificate.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _keyId = 'sc-test';
const _aliceId = 'alice-id';
const _aliceDevice = 'alice-device';

enum _Lane { wal, legacy }

/// One recipient (Bob) with an accepted key generation and one sender (Alice)
/// holding a pending first-contact session towards Bob.
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
  final events = <SecurityEvent>[];
  var _delivery = 0;

  CryptoStorage get bobCrypto => CryptoStorage(secureStorage: bobStorage);

  Map<String, String> get pinnedServerKeys => {_keyId: server.publicKey};

  Future<SignalProtocolManager> bob(SealedSenderTrustPolicy policy) async {
    final bus = SecurityEventBus();
    bus.events.listen(events.add);
    final manager = SignalProtocolManager(
      secureStorage: bobStorage,
      securityEventBus: bus,
      sealedSenderTrustPolicy: policy,
    );
    await manager.initialize();
    return manager;
  }

  Future<Map<String, dynamic>> sealedFirstContact({
    bool certified = false,
    String? serverSigningPrivateKey,
    String? certifiedSigningKey,
  }) async {
    final envelope = await alice.encryptSealedSender(
      'bob-id',
      'bob-device',
      bobIdentity.publicKey,
      'first sealed message',
    );
    if (!certified) return envelope;
    return recertify(
      envelope,
      serverSigningPrivateKey: serverSigningPrivateKey,
      certifiedSigningKey: certifiedSigningKey,
    );
  }

  /// Re-wraps [envelope]'s protected inner message with a Sender Certificate
  /// v1, exactly as a PKG-3 sender would, keeping the outer routing fields.
  Future<Map<String, dynamic>> recertify(
    Map<String, dynamic> envelope, {
    String? serverSigningPrivateKey,
    String? certifiedSigningKey,
  }) async {
    final content = await SealedSenderEnvelope.unseal(
      sealedEnvelope: envelope,
      recipientIdentityKeyPair: bobIdentity,
      seenNonces: <String>{},
    );
    final now = DateTime.now().millisecondsSinceEpoch;
    final signing = certifiedSigningKey == null
        ? aliceSigning
        : await SignalKeyHelper.generateSigningKeyPair();
    final issued = await SenderCertificateVerifier.issueForTesting(
      serverSigningPrivateKey: serverSigningPrivateKey ?? server.privateKey,
      keyId: _keyId,
      senderId: _aliceId,
      senderDeviceId: _aliceDevice,
      senderIdentityKey: aliceIdentityKey,
      senderSigningKey: signing.publicKey,
      issuedAt: now - 60 * 1000,
      expiresAt: now + 24 * 60 * 60 * 1000,
    );
    final resealed = await SealedSenderEnvelope.seal(
      senderId: _aliceId,
      senderDeviceId: _aliceDevice,
      senderIdentityKey: aliceIdentityKey,
      encryptedMessage: content.encryptedMessage,
      recipientIdentityPublicKey: bobIdentity.publicKey,
      senderCertificate: issued,
    );
    return <String, dynamic>{...envelope, ...resealed};
  }

  /// Receives [envelope] on [lane] to completion and returns what the host
  /// learns about the sender's authentication.
  Future<SenderAuthentication?> receive(
    SignalProtocolManager manager,
    _Lane lane,
    Map<String, dynamic> envelope, {
    FirstContactApproval? approval,
  }) async {
    switch (lane) {
      case _Lane.wal:
        final prepared = await manager.prepareSealedReceive(
          deliveryId: 'delivery-${_delivery++}',
          sealedEnvelope: envelope,
          firstContactApproval: approval,
        );
        expect(prepared.plaintext, 'first sealed message');
        await manager.acknowledgeReceive(prepared.receipt);
        return prepared.senderAuthentication;
      case _Lane.legacy:
        final result = await manager.decryptSealedSender(
          envelope,
          firstContactApproval: approval,
        );
        expect(result.plaintext, 'first sealed message');
        return result.senderAuthentication;
    }
  }

  Future<void> settle() => Future<void>.delayed(Duration.zero);

  Iterable<SecurityEvent> eventsOf(SecurityEventType type) =>
      events.where((event) => event.type == type);
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
  final aliceCrypto = CryptoStorage(secureStorage: aliceStorage);
  return _Setup(
    alice: alice,
    aliceStorage: aliceStorage,
    bobStorage: bobStorage,
    bobIdentity: (await CryptoStorage(
      secureStorage: bobStorage,
    ).getIdentityKeyPair())!,
    aliceIdentityKey: await alice.getIdentityPublicKey(),
    aliceSigning: (await aliceCrypto.getSigningKeyPair())!,
    server: await SignalKeyHelper.generateSigningKeyPair(),
  );
}

Matcher _certificateFailure(SenderCertificateFailure reason) => throwsA(
  isA<SealedSenderCertificateError>().having((e) => e.reason, 'reason', reason),
);

void main() {
  for (final lane in _Lane.values) {
    group('sealed lane ${lane.name}', () {
      test(
        '1. legacy policy + pinned server key: certified first contact is '
        'accepted, reported certified, pins identity but never the signing key',
        () async {
          final setup = await _setUp();
          final bob = await setup.bob(
            SealedSenderTrustPolicy(
              serverCertificateSigningKeys: setup.pinnedServerKeys,
            ),
          );
          final envelope = await setup.sealedFirstContact(certified: true);

          final auth = await setup.receive(bob, lane, envelope);

          expect(auth, isNotNull);
          expect(auth!.certified, isTrue);
          expect(auth.certificateKeyId, _keyId);
          expect(auth.certificateIgnored, isFalse);
          expect(auth.firstContact, isTrue);
          expect(auth.approvalSource, isNull);
          expect(
            await setup.bobCrypto.getSessionIdentityKey(_aliceId, _aliceDevice),
            setup.aliceIdentityKey,
          );
          // R4-C3-V2: the certificate's signing key is only server-attested,
          // so a certified receive never seeds the signing-key pin.
          expect(
            await setup.bobCrypto.getPeerSigningKey(_aliceId, _aliceDevice),
            isNull,
          );
        },
      );

      test('2. legacy policy without a pinned server key ignores the '
          'certificate and says so', () async {
        final setup = await _setUp();
        final bob = await setup.bob(SealedSenderTrustPolicy.legacy);
        final envelope = await setup.sealedFirstContact(certified: true);

        final auth = await setup.receive(bob, lane, envelope);
        await setup.settle();

        expect(auth!.certified, isFalse);
        expect(auth.certificateIgnored, isTrue);
        expect(auth.certificateKeyId, isNull);
        expect(auth.firstContact, isTrue);
        expect(
          setup.eventsOf(SecurityEventType.senderCertificateIgnoredNoPinnedKey),
          hasLength(1),
        );
        expect(
          await setup.bobCrypto.getPeerSigningKey(_aliceId, _aliceDevice),
          isNull,
        );
      });

      test('3. requireCertified rejects an uncertified envelope without any '
          'state change; the same envelope is accepted under legacy', () async {
        final setup = await _setUp();
        final strict = await setup.bob(
          SealedSenderTrustPolicy(
            serverCertificateSigningKeys: setup.pinnedServerKeys,
            requireCertified: true,
          ),
        );
        final envelope = await setup.sealedFirstContact();
        final before = Map<String, String>.from(setup.bobStorage.store);
        final noncesBefore = await setup.bobCrypto.loadSeenNonces();

        await expectLater(
          setup.receive(strict, lane, envelope),
          throwsA(isA<UncertifiedSealedSenderError>()),
        );
        await setup.settle();

        expect(setup.bobStorage.store, before);
        expect(await setup.bobCrypto.loadSeenNonces(), noncesBefore);
        expect(await strict.pendingReceiveReceipt(), isNull);
        expect(await strict.hasSession(_aliceId, _aliceDevice), isFalse);
        expect(
          await setup.bobCrypto.getSessionIdentityKey(_aliceId, _aliceDevice),
          isNull,
        );
        final rejected = setup.eventsOf(
          SecurityEventType.uncertifiedSealedSenderRejected,
        );
        expect(rejected, hasLength(1));
        expect(rejected.single.sessionId, isEmpty);

        final legacy = await setup.bob(SealedSenderTrustPolicy.legacy);
        final auth = await setup.receive(legacy, lane, envelope);
        expect(auth!.certified, isFalse);
        expect(auth.certificateIgnored, isFalse);
        expect(auth.firstContact, isTrue);
      });

      test('3b. requireCertified accepts a verified certificate', () async {
        final setup = await _setUp();
        final strict = await setup.bob(
          SealedSenderTrustPolicy(
            serverCertificateSigningKeys: setup.pinnedServerKeys,
            requireCertified: true,
            requireVerifiedFirstContact: true,
          ),
        );
        final envelope = await setup.sealedFirstContact(certified: true);
        final auth = await setup.receive(strict, lane, envelope);
        expect(auth!.certified, isTrue);
        expect(auth.firstContact, isTrue);
        expect(auth.approvalSource, isNull);
      });

      test(
        '4a. requireVerifiedFirstContact: uncertified first contact without '
        'approval is rejected with the claimed identity, state unchanged',
        () async {
          final setup = await _setUp();
          final bob = await setup.bob(
            const SealedSenderTrustPolicy(requireVerifiedFirstContact: true),
          );
          final envelope = await setup.sealedFirstContact();
          final before = Map<String, String>.from(setup.bobStorage.store);

          await expectLater(
            setup.receive(bob, lane, envelope),
            throwsA(
              isA<UnverifiedFirstContactError>()
                  .having((e) => e.senderId, 'senderId', _aliceId)
                  .having(
                    (e) => e.senderDeviceId,
                    'senderDeviceId',
                    _aliceDevice,
                  )
                  .having(
                    (e) => e.senderIdentityKey,
                    'senderIdentityKey',
                    setup.aliceIdentityKey,
                  ),
            ),
          );
          await setup.settle();
          expect(setup.bobStorage.store, before);
          expect(await bob.pendingReceiveReceipt(), isNull);
          final rejected = setup.eventsOf(
            SecurityEventType.unverifiedFirstContactRejected,
          );
          expect(rejected, hasLength(1));
          expect(rejected.single.metadata, {'lane': 'sealed'});
          expect(rejected.single.sessionId, isEmpty);

          // A mismatching approval (different identity key) is still rejected.
          final other = await SignalKeyHelper.generateIdentityKeyPair();
          await expectLater(
            setup.receive(
              bob,
              lane,
              envelope,
              approval: FirstContactApproval(
                senderId: _aliceId,
                senderDeviceId: _aliceDevice,
                senderIdentityKey: other.publicKey,
                source: FirstContactApprovalSource.keyBundle,
              ),
            ),
            throwsA(isA<UnverifiedFirstContactError>()),
          );
          expect(setup.bobStorage.store, before);

          // The matching approval admits the same envelope.
          final auth = await setup.receive(
            bob,
            lane,
            envelope,
            approval: FirstContactApproval(
              senderId: _aliceId,
              senderDeviceId: _aliceDevice,
              senderIdentityKey: setup.aliceIdentityKey,
              source: FirstContactApprovalSource.keyBundle,
            ),
          );
          expect(auth!.certified, isFalse);
          expect(auth.firstContact, isTrue);
          expect(auth.approvalSource, FirstContactApprovalSource.keyBundle);
          expect(
            await setup.bobCrypto.getSessionIdentityKey(_aliceId, _aliceDevice),
            setup.aliceIdentityKey,
          );
        },
      );

      test('4b. an already-pinned contact needs no approval', () async {
        final setup = await _setUp();
        // A sibling device of alice is already pinned with her identity key.
        await setup.bobStorage.write(
          key: 'crypto_e2_session_ik_${_aliceId}_alice-old',
          value: setup.aliceIdentityKey,
        );
        await setup.bobStorage.write(
          key: 'crypto_e2_session_devices_$_aliceId',
          value: 'alice-old',
        );
        final bob = await setup.bob(
          const SealedSenderTrustPolicy(requireVerifiedFirstContact: true),
        );
        final auth = await setup.receive(
          bob,
          lane,
          await setup.sealedFirstContact(),
        );
        expect(auth!.firstContact, isFalse);
        expect(auth.approvalSource, isNull);
      });

      test(
        '6. a certified signing key that contradicts the pinned peer '
        'signing key is rejected as identityMismatch, no state change',
        () async {
          final setup = await _setUp();
          final pinned = await SignalKeyHelper.generateSigningKeyPair();
          await setup.bobCrypto.savePeerSigningKey(
            _aliceId,
            _aliceDevice,
            pinned.publicKey,
          );
          final bob = await setup.bob(
            SealedSenderTrustPolicy(
              serverCertificateSigningKeys: setup.pinnedServerKeys,
            ),
          );
          final envelope = await setup.sealedFirstContact(certified: true);
          final before = Map<String, String>.from(setup.bobStorage.store);

          await expectLater(
            setup.receive(bob, lane, envelope),
            _certificateFailure(SenderCertificateFailure.identityMismatch),
          );
          await setup.settle();
          expect(setup.bobStorage.store, before);
          expect(
            setup.eventsOf(SecurityEventType.peerIdentityKeyChanged),
            isNotEmpty,
          );
        },
      );

      test('7. a tampered certificate is rejected with an event and does not '
          'poison the authentic envelope', () async {
        final setup = await _setUp();
        final bob = await setup.bob(
          SealedSenderTrustPolicy(
            serverCertificateSigningKeys: setup.pinnedServerKeys,
          ),
        );
        final authentic = await setup.sealedFirstContact(certified: true);
        final forger = await SignalKeyHelper.generateSigningKeyPair();
        final tampered = await setup.recertify(
          authentic,
          serverSigningPrivateKey: forger.privateKey,
        );
        final before = Map<String, String>.from(setup.bobStorage.store);

        await expectLater(
          setup.receive(bob, lane, tampered),
          _certificateFailure(SenderCertificateFailure.badServerSignature),
        );
        await setup.settle();
        expect(setup.bobStorage.store, before);
        final rejected = setup.eventsOf(
          SecurityEventType.senderCertificateRejected,
        );
        expect(rejected, hasLength(1));
        expect(rejected.single.metadata, {'reason': 'badServerSignature'});
        expect(rejected.single.sessionId, isEmpty);

        final auth = await setup.receive(bob, lane, authentic);
        expect(auth!.certified, isTrue);
      });
    });
  }

  group('5. direct (type-2) lane obeys requireVerifiedFirstContact', () {
    Future<(_Setup, SignalProtocolManager, Map<String, dynamic>)>
    directSetup() async {
      final setup = await _setUp();
      final bob = await setup.bob(
        const SealedSenderTrustPolicy(requireVerifiedFirstContact: true),
      );
      final envelope = await setup.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first direct message',
      );
      expect(envelope['type'], 'prekey');
      return (setup, bob, envelope);
    }

    FirstContactApproval approvalFor(_Setup setup, String identityKey) =>
        FirstContactApproval(
          senderId: _aliceId,
          senderDeviceId: _aliceDevice,
          senderIdentityKey: identityKey,
          source: FirstContactApprovalSource.keyTransparency,
        );

    test('prepareReceive', () async {
      final (setup, bob, envelope) = await directSetup();
      final before = Map<String, String>.from(setup.bobStorage.store);
      await expectLater(
        bob.prepareReceive(
          deliveryId: 'direct-1',
          senderId: _aliceId,
          senderDeviceId: _aliceDevice,
          envelope: envelope,
        ),
        throwsA(isA<UnverifiedFirstContactError>()),
      );
      await setup.settle();
      expect(setup.bobStorage.store, before);
      expect(
        setup
            .eventsOf(SecurityEventType.unverifiedFirstContactRejected)
            .single
            .metadata,
        {'lane': 'direct'},
      );
      final other = await SignalKeyHelper.generateIdentityKeyPair();
      await expectLater(
        bob.prepareReceive(
          deliveryId: 'direct-1',
          senderId: _aliceId,
          senderDeviceId: _aliceDevice,
          envelope: envelope,
          firstContactApproval: approvalFor(setup, other.publicKey),
        ),
        throwsA(isA<UnverifiedFirstContactError>()),
      );

      final prepared = await bob.prepareReceive(
        deliveryId: 'direct-1',
        senderId: _aliceId,
        senderDeviceId: _aliceDevice,
        envelope: envelope,
        firstContactApproval: approvalFor(setup, setup.aliceIdentityKey),
      );
      expect(prepared.plaintext, 'first direct message');
      expect(prepared.senderAuthentication!.certified, isFalse);
      expect(prepared.senderAuthentication!.firstContact, isTrue);
      expect(
        prepared.senderAuthentication!.approvalSource,
        FirstContactApprovalSource.keyTransparency,
      );
      await bob.acknowledgeReceive(prepared.receipt);
      expect(
        await setup.bobCrypto.getSessionIdentityKey(_aliceId, _aliceDevice),
        setup.aliceIdentityKey,
      );
      final again = await bob.prepareReceive(
        deliveryId: 'direct-1',
        senderId: _aliceId,
        senderDeviceId: _aliceDevice,
        envelope: envelope,
      );
      expect(again.alreadyAcknowledged, isTrue);
      expect(again.senderAuthentication, isNull);
    });

    test('requireCertified implies verified first contact on the direct '
        'lane (a type-2 envelope can never be certified)', () async {
      final setup = await _setUp();
      final bob = await setup.bob(
        SealedSenderTrustPolicy(
          serverCertificateSigningKeys: setup.pinnedServerKeys,
          requireCertified: true,
        ),
      );
      final envelope = await setup.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first direct message',
      );
      final before = Map<String, String>.from(setup.bobStorage.store);
      await expectLater(
        bob.prepareReceive(
          deliveryId: 'direct-strict',
          senderId: _aliceId,
          senderDeviceId: _aliceDevice,
          envelope: envelope,
        ),
        throwsA(isA<UnverifiedFirstContactError>()),
      );
      await expectLater(
        bob.decryptMessage(_aliceId, _aliceDevice, envelope),
        throwsA(isA<UnverifiedFirstContactError>()),
      );
      expect(setup.bobStorage.store, before);
    });

    test('decryptMessage', () async {
      final (setup, bob, envelope) = await directSetup();
      final before = Map<String, String>.from(setup.bobStorage.store);
      await expectLater(
        bob.decryptMessage(_aliceId, _aliceDevice, envelope),
        throwsA(isA<UnverifiedFirstContactError>()),
      );
      expect(setup.bobStorage.store, before);
      expect(
        await setup.bobCrypto.getSessionIdentityKey(_aliceId, _aliceDevice),
        isNull,
      );
      final plaintext = await bob.decryptMessage(
        _aliceId,
        _aliceDevice,
        envelope,
        firstContactApproval: approvalFor(setup, setup.aliceIdentityKey),
      );
      expect(plaintext, 'first direct message');
      expect(
        await setup.bobCrypto.getSessionIdentityKey(_aliceId, _aliceDevice),
        setup.aliceIdentityKey,
      );
    });
  });

  test('legacy policy is the default and accepts uncertified first contact '
      'on every lane', () async {
    expect(SealedSenderTrustPolicy.legacy.requireCertified, isFalse);
    expect(SealedSenderTrustPolicy.legacy.requireVerifiedFirstContact, isFalse);
    expect(
      SealedSenderTrustPolicy.legacy.serverCertificateSigningKeys,
      isEmpty,
    );
    final setup = await _setUp();
    final bob = SignalProtocolManager(secureStorage: setup.bobStorage);
    await bob.initialize();
    final result = await bob.decryptSealedSender(
      await setup.sealedFirstContact(),
    );
    expect(result.senderAuthentication!.certified, isFalse);
    expect(result.senderAuthentication!.firstContact, isTrue);
  });
}
