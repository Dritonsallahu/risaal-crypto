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
import 'package:risaal_crypto/src/send_commit.dart';
import 'package:risaal_crypto/src/sender_certificate.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _keyId = 'sc-provider-test';
const _aliceId = 'alice-id';
const _aliceDevice = 'alice-device';
const _hour = 60 * 60 * 1000;

/// Alice is built with a [SignalProtocolManager.senderCertificateProvider]
/// whose behaviour each test swaps via [_Setup.provide]; she holds a pending
/// first-contact session towards Bob.
final class _Setup {
  _Setup._(this.requireCertifiedSend);

  final bool requireCertifiedSend;
  final FakeSecureStorage aliceStorage = FakeSecureStorage();
  final SecurityEventBus bus = SecurityEventBus();
  final List<SecurityEventType> events = <SecurityEventType>[];
  late final SignalProtocolManager alice;
  late final FakeSecureStorage bobStorage;
  late final KeyPair bobIdentity;
  late final String aliceIdentityKey;
  late final KeyPair aliceSigning;
  late final KeyPair server;

  /// What the provider does on its next call.
  Future<IssuedSenderCertificate?> Function() provide = () async => null;
  int providerCalls = 0;

  Map<String, String> get pinnedServerKeys => {_keyId: server.publicKey};

  static Future<_Setup> create({bool requireCertifiedSend = false}) async {
    final s = _Setup._(requireCertifiedSend);
    s.bus.events.listen((event) => s.events.add(event.type));
    s.alice = SignalProtocolManager(
      secureStorage: s.aliceStorage,
      securityEventBus: s.bus,
      sealedSenderTrustPolicy: SealedSenderTrustPolicy(
        requireCertifiedSend: requireCertifiedSend,
      ),
      senderCertificateProvider: () {
        s.providerCalls++;
        return s.provide();
      },
    );
    await s.alice.wipeForFreshRegistration();
    await s.alice.initialize();
    await s.aliceStorage.write(key: 'user_id', value: _aliceId);
    await s.aliceStorage.write(key: 'device_id', value: _aliceDevice);

    final (bob, bobStorage) =
        await CryptoTestFixtures.createInitializedManager();
    s.bobStorage = bobStorage;
    await bobStorage.write(key: 'user_id', value: 'bob-id');
    await bobStorage.write(key: 'device_id', value: 'bob-device');
    final accepted = await CryptoTestFixtures.acceptInitialGeneration(bob);
    await s.alice.createSession(
      accepted.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
    );
    s.bobIdentity = (await CryptoStorage(
      secureStorage: bobStorage,
    ).getIdentityKeyPair())!;
    s.aliceIdentityKey = await s.alice.getIdentityPublicKey();
    s.aliceSigning = (await CryptoStorage(
      secureStorage: s.aliceStorage,
    ).getSigningKeyPair())!;
    s.server = await SignalKeyHelper.generateSigningKeyPair();
    // Drop setup noise (e.g. insecureStorageWarning) so tests see only sends.
    await _drainEvents();
    s.events.clear();
    return s;
  }

  Future<IssuedSenderCertificate> issue({
    String senderDeviceId = _aliceDevice,
  }) {
    final now = DateTime.now().millisecondsSinceEpoch;
    return SenderCertificateVerifier.issueForTesting(
      serverSigningPrivateKey: server.privateKey,
      keyId: _keyId,
      senderId: _aliceId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: aliceIdentityKey,
      senderSigningKey: aliceSigning.publicKey,
      issuedAt: now - 60 * 1000,
      expiresAt: now + 24 * _hour,
    );
  }

  Future<Map<String, dynamic>> send({IssuedSenderCertificate? certificate}) =>
      alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        bobIdentity.publicKey,
        'sealed message',
        senderCertificate: certificate,
      );

  Future<PreparedSend> prepare(String deliveryId) => alice.prepareSealedSend(
    deliveryId: deliveryId,
    recipientId: 'bob-id',
    recipientDeviceId: 'bob-device',
    recipientIdentityPublicKey: bobIdentity.publicKey,
    plaintext: 'sealed message',
  );

  Future<Map<String, dynamic>> sendFull() => alice.encryptSealedSenderFull(
    senderId: _aliceId,
    senderDeviceId: _aliceDevice,
    recipientId: 'bob-id',
    recipientDeviceId: 'bob-device',
    recipientIdentityPublicKey: bobIdentity.publicKey,
    plaintext: 'sealed message',
  );

  /// Outer unseal as Bob with the pinned server key (no Bob state touched).
  Future<SealedSenderContent> unseal(Map<String, dynamic> envelope) =>
      SealedSenderEnvelope.unseal(
        sealedEnvelope: envelope,
        recipientIdentityKeyPair: bobIdentity,
        seenNonces: <String>{},
        trustedServerSigningKeys: pinnedServerKeys,
      );

  /// Every send entry point refuses with [matcher] and leaves Alice's store
  /// byte-identical with no pending send.
  Future<void> expectAllRefusedWithoutMutation(Matcher matcher) async {
    final before = Map<String, String>.from(aliceStorage.store);
    await expectLater(send(), matcher);
    await expectLater(prepare('refused-1'), matcher);
    await expectLater(sendFull(), matcher);
    expect(aliceStorage.store, before);
    expect(await alice.pendingSend(), isNull);
  }
}

Future<void> _drainEvents() => Future<void>.delayed(Duration.zero);

final Matcher _certificateRequired = throwsA(
  isA<SenderCertificateRequiredError>(),
);

void main() {
  test('1. provider certificate makes every sealed entry point certified, '
      'one provider call per send', () async {
    final s = await _Setup.create();
    final certificate = await s.issue();
    s.provide = () async => certificate;
    expect(s.alice.hasSenderCertificateProvider, isTrue);
    expect(s.alice.sealedSenderTrustPolicy.requireCertifiedSend, isFalse);

    final first = await s.send();
    expect(s.providerCalls, 1);
    expect((await s.unseal(first)).certified, isTrue);

    // Bob's real receive path also reports a certified sender.
    final bob = SignalProtocolManager(
      secureStorage: s.bobStorage,
      sealedSenderTrustPolicy: SealedSenderTrustPolicy(
        serverCertificateSigningKeys: s.pinnedServerKeys,
      ),
    );
    await bob.initialize();
    final received = await bob.prepareSealedReceive(
      deliveryId: 'delivery-1',
      sealedEnvelope: first,
    );
    expect(received.senderAuthentication!.certified, isTrue);
    await bob.acknowledgeReceive(received.receipt);

    final prepared = await s.prepare('send-1');
    expect(s.providerCalls, 2);
    expect((await s.unseal(prepared.envelope)).certified, isTrue);
    await s.alice.acknowledgeSend(prepared.receipt);

    final full = await s.sendFull();
    expect(s.providerCalls, 3);
    expect((await s.unseal(full)).certified, isTrue);

    await _drainEvents();
    expect(
      s.events,
      isNot(contains(SecurityEventType.senderCertificateProviderFailed)),
    );
  });

  test('2. provider returning null sends the legacy uncertified envelope, '
      'no error, no event', () async {
    final s = await _Setup.create();
    s.provide = () async => null;

    for (final envelope in [
      await s.send(),
      (await s.prepare('send-null')).envelope,
    ]) {
      final content = await s.unseal(envelope);
      expect(content.certified, isFalse);
      expect(content.certificateIgnored, isFalse);
      expect(content.senderSigningKey, isNull);
      expect(content.certificateKeyId, isNull);
    }
    expect(s.providerCalls, 2);
    await _drainEvents();
    expect(s.events, isEmpty);
  });

  test('3a. provider throwing falls back to an uncertified send and emits '
      'senderCertificateProviderFailed', () async {
    final s = await _Setup.create();
    s.provide = () async => throw StateError('network down: secret-token');

    final envelope = await s.send();
    expect((await s.unseal(envelope)).certified, isFalse);
    expect(s.providerCalls, 1);
    await _drainEvents();
    expect(s.events, [SecurityEventType.senderCertificateProviderFailed]);
  });

  test('3b. provider throwing under requireCertifiedSend refuses every entry '
      'point before any mutation', () async {
    final s = await _Setup.create(requireCertifiedSend: true);
    s.provide = () async => throw StateError('network down: secret-token');

    await s.expectAllRefusedWithoutMutation(_certificateRequired);
    expect(s.providerCalls, 3);
    try {
      await s.send();
    } on SenderCertificateRequiredError catch (error) {
      expect(error.message, isNot(contains('secret-token')));
      expect(error.message, isNot(contains(_aliceId)));
    }
  });

  test('4. provider returning null under requireCertifiedSend refuses every '
      'entry point before any mutation; a certificate then succeeds', () async {
    final s = await _Setup.create(requireCertifiedSend: true);
    s.provide = () async => null;

    await s.expectAllRefusedWithoutMutation(_certificateRequired);
    expect(s.providerCalls, 3);

    final certificate = await s.issue();
    s.provide = () async => certificate;
    expect((await s.unseal(await s.send())).certified, isTrue);
  });

  test('5. an explicit senderCertificate wins and the provider is not '
      'called', () async {
    final s = await _Setup.create(requireCertifiedSend: true);
    s.provide = () async => throw StateError('must not be called');
    final certificate = await s.issue();

    final envelope = await s.send(certificate: certificate);
    expect((await s.unseal(envelope)).certified, isTrue);
    final prepared = await s.alice.prepareSealedSend(
      deliveryId: 'send-explicit',
      recipientId: 'bob-id',
      recipientDeviceId: 'bob-device',
      recipientIdentityPublicKey: s.bobIdentity.publicKey,
      plaintext: 'sealed message',
      senderCertificate: certificate,
    );
    expect((await s.unseal(prepared.envelope)).certified, isTrue);
    expect(s.providerCalls, 0);
  });

  test('6. a provider certificate for another device surfaces the PKG-3 '
      'StateError before any mutation', () async {
    final s = await _Setup.create();
    final stale = await s.issue(senderDeviceId: 'alice-device-2');
    s.provide = () async => stale;
    final before = Map<String, String>.from(s.aliceStorage.store);

    await expectLater(
      s.send(),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          'Sender certificate does not describe this device',
        ),
      ),
    );
    expect(s.providerCalls, 1);
    expect(s.aliceStorage.store, before);
    expect(await s.alice.pendingSend(), isNull);
  });

  test('requireCertifiedSend without a provider fails closed', () async {
    final storage = FakeSecureStorage();
    final manager = SignalProtocolManager(
      secureStorage: storage,
      sealedSenderTrustPolicy: const SealedSenderTrustPolicy(
        requireCertifiedSend: true,
      ),
    );
    expect(manager.hasSenderCertificateProvider, isFalse);
    await expectLater(
      manager.encryptSealedSender(
        'bob-id',
        'bob-device',
        (await SignalKeyHelper.generateX25519KeyPair()).publicKey,
        'sealed message',
      ),
      _certificateRequired,
    );
    expect(storage.store, isEmpty);
  });
}
