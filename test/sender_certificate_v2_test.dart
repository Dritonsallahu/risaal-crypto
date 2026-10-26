@Retry(0)
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;
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

/// Sender Certificate contract v2 (R4-C3-V2-PKG): the per-recipient Ed25519
/// sender binding is gone, because it was a transferable, non-deniable proof
/// of contact. A certified payload carries exactly `senderCertificate` +
/// `serverSignature`, and a certified receive never seeds the peer
/// signing-key pin (the certificate's signing key is only server-attested).

const _keyId = 'sc-v2';
const _aliceId = 'alice-id';
const _aliceDevice = 'alice-device';
const _message = <String, dynamic>{'type': 'message', 'data': 'inner'};
const _hour = 60 * 60 * 1000;

Matcher _failsWith(SenderCertificateFailure reason) => throwsA(
  isA<SealedSenderCertificateError>().having((e) => e.reason, 'reason', reason),
);

Future<SecretKey> _outerKey(
  SimpleKeyPair keyPair,
  SimplePublicKey remote,
) async {
  final raw = await X25519().sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: remote,
  );
  return Hkdf(hmac: Hmac(Sha256()), outputLength: 32).deriveKey(
    secretKey: SecretKey(await raw.extractBytes()),
    info: 'Risaal_SealedSender'.codeUnits,
    nonce: Uint8List(32),
  );
}

/// Encrypts an arbitrary sealed payload exactly like
/// [SealedSenderEnvelope.seal] does.
Future<Map<String, dynamic>> _sealRaw(
  Map<String, dynamic> payload,
  String recipientIdentityPublicKey,
) async {
  final ephemeral = await X25519().newKeyPair();
  final key = await _outerKey(
    ephemeral,
    SimplePublicKey(
      base64Decode(recipientIdentityPublicKey),
      type: KeyPairType.x25519,
    ),
  );
  final box = await AesGcm.with256bits().encrypt(
    utf8.encode(jsonEncode(payload)),
    secretKey: key,
  );
  return {
    'ephemeralPublicKey': base64Encode(
      (await ephemeral.extractPublicKey()).bytes,
    ),
    'ciphertext': base64Encode(box.cipherText + box.mac.bytes),
    'nonce': base64Encode(box.nonce),
  };
}

/// Decrypts the outer layer of [envelope] and returns the raw sealed payload.
Future<Map<String, dynamic>> _openRaw(
  Map<String, dynamic> envelope,
  KeyPair recipient,
) async {
  final key = await _outerKey(
    SimpleKeyPairData(
      base64Decode(recipient.privateKey),
      publicKey: SimplePublicKey(
        base64Decode(recipient.publicKey),
        type: KeyPairType.x25519,
      ),
      type: KeyPairType.x25519,
    ),
    SimplePublicKey(
      base64Decode(envelope['ephemeralPublicKey'] as String),
      type: KeyPairType.x25519,
    ),
  );
  final combined = base64Decode(envelope['ciphertext'] as String);
  final clear = await AesGcm.with256bits().decrypt(
    SecretBox(
      combined.sublist(0, combined.length - 16),
      nonce: base64Decode(envelope['nonce'] as String),
      mac: Mac(combined.sublist(combined.length - 16)),
    ),
    secretKey: key,
  );
  return jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
}

void main() {
  group('envelope level', () {
    late KeyPair server;
    late KeyPair senderSigning;
    late KeyPair senderIdentity;
    late KeyPair recipient;
    late Map<String, String> trusted;

    setUpAll(() async {
      server = await SignalKeyHelper.generateSigningKeyPair();
      senderSigning = await SignalKeyHelper.generateSigningKeyPair();
      senderIdentity = await SignalKeyHelper.generateIdentityKeyPair();
      recipient = await SignalKeyHelper.generateIdentityKeyPair();
      trusted = {_keyId: server.publicKey};
    });

    Future<IssuedSenderCertificate> issue() {
      final now = DateTime.now().millisecondsSinceEpoch;
      return SenderCertificateVerifier.issueForTesting(
        serverSigningPrivateKey: server.privateKey,
        keyId: _keyId,
        senderId: _aliceId,
        senderDeviceId: _aliceDevice,
        senderIdentityKey: senderIdentity.publicKey,
        senderSigningKey: senderSigning.publicKey,
        issuedAt: now - 60 * 1000,
        expiresAt: now + 24 * _hour,
      );
    }

    Future<Map<String, dynamic>> rawPayload(
      IssuedSenderCertificate issued, {
      Map<String, dynamic> extra = const {},
      List<String> drop = const [],
    }) async {
      final payload = <String, dynamic>{
        'senderId': _aliceId,
        'senderDeviceId': _aliceDevice,
        'senderIdentityKey': senderIdentity.publicKey,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
        'message': _message,
        'senderCertificate': issued.certificateBase64,
        'serverSignature': issued.serverSignature,
        ...extra,
      };
      for (final key in drop) {
        payload.remove(key);
      }
      return _sealRaw(payload, recipient.publicKey);
    }

    Future<SealedSenderContent> unseal(
      Map<String, dynamic> envelope, {
      Map<String, String>? keys,
      Set<String>? nonces,
    }) => SealedSenderEnvelope.unseal(
      sealedEnvelope: envelope,
      recipientIdentityKeyPair: recipient,
      seenNonces: nonces ?? <String>{},
      trustedServerSigningKeys: keys,
    );

    test('seal adds exactly senderCertificate + serverSignature and needs no '
        'signing private key', () async {
      final issued = await issue();
      final envelope = await SealedSenderEnvelope.seal(
        senderId: _aliceId,
        senderDeviceId: _aliceDevice,
        senderIdentityKey: senderIdentity.publicKey,
        encryptedMessage: _message,
        recipientIdentityPublicKey: recipient.publicKey,
        senderCertificate: issued,
      );
      final payload = await _openRaw(envelope, recipient);
      expect(payload.keys.toSet(), {
        'senderId',
        'senderDeviceId',
        'senderIdentityKey',
        'timestamp',
        'message',
        'senderCertificate',
        'serverSignature',
      });
      expect(payload['senderCertificate'], issued.certificateBase64);
      expect(payload['serverSignature'], issued.serverSignature);
      expect(payload.containsKey('senderSignature'), isFalse);

      final content = await unseal(envelope, keys: trusted);
      expect(content.certified, isTrue);
      expect(content.certificateKeyId, _keyId);
      expect(content.senderSigningKey, senderSigning.publicKey);
    });

    test('a two-field certified payload verifies under a pinned key', () async {
      final content = await unseal(
        await rawPayload(await issue()),
        keys: trusted,
      );
      expect(content.certified, isTrue);
      expect(content.certificateIgnored, isFalse);
    });

    test('a payload still carrying senderSignature is malformed, pinned or '
        'not, and its nonce is not recorded', () async {
      final envelope = await rawPayload(
        await issue(),
        extra: {'senderSignature': base64Encode(List<int>.filled(64, 9))},
      );
      for (final keys in <Map<String, String>?>[trusted, null, const {}]) {
        final nonces = <String>{};
        await expectLater(
          unseal(envelope, keys: keys, nonces: nonces),
          _failsWith(SenderCertificateFailure.malformed),
        );
        expect(nonces, isEmpty);
      }
    });

    test('senderSignature alone (no certificate) is malformed', () async {
      final envelope = await rawPayload(
        await issue(),
        drop: const ['senderCertificate', 'serverSignature'],
        extra: {'senderSignature': base64Encode(List<int>.filled(64, 9))},
      );
      for (final keys in <Map<String, String>?>[trusted, null]) {
        await expectLater(
          unseal(envelope, keys: keys),
          _failsWith(SenderCertificateFailure.malformed),
        );
      }
    });

    test('one of the two fields alone is malformed, pinned or not', () async {
      final issued = await issue();
      for (final drop in const ['senderCertificate', 'serverSignature']) {
        final envelope = await rawPayload(issued, drop: [drop]);
        for (final keys in <Map<String, String>?>[trusted, null]) {
          await expectLater(
            unseal(envelope, keys: keys),
            _failsWith(SenderCertificateFailure.malformed),
          );
        }
      }
    });

    test('the binding failure reason no longer exists', () {
      expect(
        SenderCertificateFailure.values.map((e) => e.name),
        isNot(contains('badSenderBinding')),
      );
    });
  });

  test('the shared vector carries no binding material', () {
    final text = File(
      'test/fixtures/sender_certificate/v1_vectors.json',
    ).readAsStringSync();
    expect(text, isNot(contains('senderSignature')));
    expect(text, isNot(contains('senderBinding')));
    expect(text, isNot(contains('SenderCertBinding')));
    expect(text, isNot(contains('wrong-recipient')));
    expect(text, isNot(contains('recipientIdentityKey')));
  });

  group('manager: certified receive never seeds the signing-key pin', () {
    late SignalProtocolManager alice;
    late FakeSecureStorage bobStorage;
    late KeyPair bobIdentity;
    late KeyPair aliceSigning;
    late KeyPair server;
    late String aliceIdentityKey;

    setUp(() async {
      final (a, aliceStorage) =
          await CryptoTestFixtures.createInitializedManager();
      final (b, bStorage) = await CryptoTestFixtures.createInitializedManager();
      alice = a;
      bobStorage = bStorage;
      await aliceStorage.write(key: 'user_id', value: _aliceId);
      await aliceStorage.write(key: 'device_id', value: _aliceDevice);
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(b);
      await alice.createSession(
        accepted.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
      );
      bobIdentity = (await CryptoStorage(
        secureStorage: bobStorage,
      ).getIdentityKeyPair())!;
      aliceSigning = (await CryptoStorage(
        secureStorage: aliceStorage,
      ).getSigningKeyPair())!;
      aliceIdentityKey = await alice.getIdentityPublicKey();
      server = await SignalKeyHelper.generateSigningKeyPair();
    });

    Future<SignalProtocolManager> bob() async {
      final manager = SignalProtocolManager(
        secureStorage: bobStorage,
        sealedSenderTrustPolicy: SealedSenderTrustPolicy(
          serverCertificateSigningKeys: {_keyId: server.publicKey},
        ),
      );
      await manager.initialize();
      return manager;
    }

    Future<Map<String, dynamic>> send(String text) async {
      final now = DateTime.now().millisecondsSinceEpoch;
      return alice.encryptSealedSender(
        'bob-id',
        'bob-device',
        bobIdentity.publicKey,
        text,
        senderCertificate: await SenderCertificateVerifier.issueForTesting(
          serverSigningPrivateKey: server.privateKey,
          keyId: _keyId,
          senderId: _aliceId,
          senderDeviceId: _aliceDevice,
          senderIdentityKey: aliceIdentityKey,
          senderSigningKey: aliceSigning.publicKey,
          issuedAt: now - 60 * 1000,
          expiresAt: now + 24 * _hour,
        ),
      );
    }

    test('prepareSealedReceive + decryptSealedSender: certified, no pin, no '
        'pin storage key', () async {
      final receiver = await bob();
      final envelope = await send('first');
      expect(
        (await _openRaw(envelope, bobIdentity)).containsKey('senderSignature'),
        isFalse,
      );
      final prepared = await receiver.prepareSealedReceive(
        deliveryId: 'v2-delivery-1',
        sealedEnvelope: envelope,
      );
      expect(prepared.senderAuthentication!.certified, isTrue);
      await receiver.acknowledgeReceive(prepared.receipt);
      expect(await receiver.getPeerSigningKey(_aliceId, _aliceDevice), isNull);

      final result = await receiver.decryptSealedSender(await send('second'));
      expect(result.plaintext, 'second');
      expect(result.senderAuthentication!.certified, isTrue);
      expect(await receiver.getPeerSigningKey(_aliceId, _aliceDevice), isNull);
      expect(
        bobStorage.store.keys.where(
          (k) => k.startsWith('crypto_e2_peer_signing_'),
        ),
        isEmpty,
      );
    });

    test('an existing (e.g. future KT-backed) pin that differs from the '
        'certificate still rejects as identityMismatch', () async {
      await CryptoStorage(secureStorage: bobStorage).savePeerSigningKey(
        _aliceId,
        _aliceDevice,
        (await SignalKeyHelper.generateSigningKeyPair()).publicKey,
      );
      final receiver = await bob();
      await expectLater(
        receiver.prepareSealedReceive(
          deliveryId: 'v2-delivery-2',
          sealedEnvelope: await send('first'),
        ),
        _failsWith(SenderCertificateFailure.identityMismatch),
      );
    });
  });
}
