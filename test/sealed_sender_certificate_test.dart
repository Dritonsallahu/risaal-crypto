@Retry(0)
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';
import 'package:risaal_crypto/src/sealed_sender_errors.dart';
import 'package:risaal_crypto/src/sender_certificate.dart';

const _keyId = 'test-key-1';
const _senderId = '507f1f77bcf86cd799439011';
const _deviceId = 'device-1';
const _message = <String, dynamic>{'type': 'message', 'data': 'inner'};
const _wideWindowMs = 365 * 24 * 60 * 60 * 1000;

Matcher _failsWith(SenderCertificateFailure reason) => throwsA(
  isA<SealedSenderCertificateError>().having((e) => e.reason, 'reason', reason),
);

/// Encrypts an arbitrary sealed payload exactly like
/// [SealedSenderEnvelope.seal] does, so tests can build envelopes a
/// well-behaved sender would refuse to produce.
Future<Map<String, dynamic>> _sealRaw(
  Map<String, dynamic> payload,
  String recipientIdentityPublicKey,
) async {
  final x25519 = X25519();
  final ephemeral = await x25519.newKeyPair();
  final ephemeralPub = await ephemeral.extractPublicKey();
  final raw = await x25519.sharedSecretKey(
    keyPair: ephemeral,
    remotePublicKey: SimplePublicKey(
      base64Decode(recipientIdentityPublicKey),
      type: KeyPairType.x25519,
    ),
  );
  final key = await Hkdf(hmac: Hmac(Sha256()), outputLength: 32).deriveKey(
    secretKey: SecretKey(await raw.extractBytes()),
    info: 'Risaal_SealedSender'.codeUnits,
    nonce: Uint8List(32),
  );
  final box = await AesGcm.with256bits().encrypt(
    utf8.encode(jsonEncode(payload)),
    secretKey: key,
  );
  return {
    'ephemeralPublicKey': base64Encode(ephemeralPub.bytes),
    'ciphertext': base64Encode(box.cipherText + box.mac.bytes),
    'nonce': base64Encode(box.nonce),
  };
}

String _flipFirstByte(String b64) {
  final bytes = base64Decode(b64);
  bytes[0] ^= 0x01;
  return base64Encode(bytes);
}

void main() {
  late KeyPair server;
  late KeyPair senderSigning;
  late KeyPair senderIdentity;
  late KeyPair recipient;
  late Map<String, String> trusted;
  late int now;

  setUpAll(() async {
    server = await SignalKeyHelper.generateSigningKeyPair();
    senderSigning = await SignalKeyHelper.generateSigningKeyPair();
    senderIdentity = await SignalKeyHelper.generateIdentityKeyPair();
    recipient = await SignalKeyHelper.generateIdentityKeyPair();
    trusted = {_keyId: server.publicKey};
  });

  setUp(() => now = DateTime.now().millisecondsSinceEpoch);

  Future<IssuedSenderCertificate> issue({
    String senderId = _senderId,
    String deviceId = _deviceId,
    String? identityKey,
    int? issuedAt,
    int? expiresAt,
  }) {
    final from = issuedAt ?? now - 60 * 1000;
    return SenderCertificateVerifier.issueForTesting(
      serverSigningPrivateKey: server.privateKey,
      keyId: _keyId,
      senderId: senderId,
      senderDeviceId: deviceId,
      senderIdentityKey: identityKey ?? senderIdentity.publicKey,
      senderSigningKey: senderSigning.publicKey,
      issuedAt: from,
      expiresAt: expiresAt ?? from + 24 * 60 * 60 * 1000,
    );
  }

  Future<Map<String, dynamic>> sealCertified({
    IssuedSenderCertificate? cert,
  }) async => SealedSenderEnvelope.seal(
    senderId: _senderId,
    senderDeviceId: _deviceId,
    senderIdentityKey: senderIdentity.publicKey,
    encryptedMessage: _message,
    recipientIdentityPublicKey: recipient.publicKey,
    senderCertificate: cert ?? await issue(),
  );

  /// Builds a full certified payload; [overrides] replace fields before the
  /// raw seal so each verification step can be targeted.
  Future<Map<String, dynamic>> rawCertified({
    IssuedSenderCertificate? cert,
    int? timestamp,
    Map<String, dynamic> overrides = const {},
    List<String> drop = const [],
  }) async {
    final issued = cert ?? await issue();
    final payload = <String, dynamic>{
      'senderId': _senderId,
      'senderDeviceId': _deviceId,
      'senderIdentityKey': senderIdentity.publicKey,
      'timestamp': timestamp ?? now,
      'message': _message,
      'senderCertificate': base64Encode(issued.certificateBytes),
      'serverSignature': issued.serverSignature,
      ...overrides,
    };
    for (final key in drop) {
      payload.remove(key);
    }
    return _sealRaw(payload, recipient.publicKey);
  }

  Future<void> expectRejected(
    Map<String, dynamic> envelope,
    SenderCertificateFailure reason, {
    Map<String, String>? keys,
    bool useTrusted = true,
  }) async {
    final seen = <String>{};
    await expectLater(
      SealedSenderEnvelope.unseal(
        sealedEnvelope: envelope,
        recipientIdentityKeyPair: recipient,
        seenNonces: seen,
        maxReplayWindowMs: _wideWindowMs,
        trustedServerSigningKeys: useTrusted ? (keys ?? trusted) : null,
      ),
      _failsWith(reason),
    );
    expect(seen, isNot(contains(envelope['nonce'])));
    expect(seen, isEmpty);
  }

  group('unseal with a certificate', () {
    test('trusted key pinned -> certified', () async {
      final envelope = await sealCertified();
      final seen = <String>{};
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: envelope,
        recipientIdentityKeyPair: recipient,
        seenNonces: seen,
        trustedServerSigningKeys: trusted,
      );
      expect(content.certified, isTrue);
      expect(content.certificateIgnored, isFalse);
      expect(content.certificateKeyId, _keyId);
      expect(content.senderSigningKey, senderSigning.publicKey);
      expect(content.senderId, _senderId);
      expect(content.encryptedMessage, _message);
      expect(seen, contains(envelope['nonce']));
    });

    test('no trusted keys -> ignored, payload still returned', () async {
      for (final keys in <Map<String, String>?>[null, const {}]) {
        final envelope = await sealCertified();
        final content = await SealedSenderEnvelope.unseal(
          sealedEnvelope: envelope,
          recipientIdentityKeyPair: recipient,
          seenNonces: <String>{},
          trustedServerSigningKeys: keys,
        );
        expect(content.certified, isFalse);
        expect(content.certificateIgnored, isTrue);
        expect(content.certificateKeyId, isNull);
        expect(content.senderSigningKey, isNull);
        expect(content.encryptedMessage, _message);
      }
    });

    test('legacy envelope -> uncertified, not ignored', () async {
      final envelope = await SealedSenderEnvelope.seal(
        senderId: _senderId,
        senderDeviceId: _deviceId,
        senderIdentityKey: senderIdentity.publicKey,
        encryptedMessage: _message,
        recipientIdentityPublicKey: recipient.publicKey,
      );
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: envelope,
        recipientIdentityKeyPair: recipient,
        seenNonces: <String>{},
        trustedServerSigningKeys: trusted,
      );
      expect(content.certified, isFalse);
      expect(content.certificateIgnored, isFalse);
      expect(content.certificateKeyId, isNull);
    });

    test('tampered serverSignature -> badServerSignature', () async {
      final good = await issue();
      await expectRejected(
        await rawCertified(
          cert: good,
          overrides: {'serverSignature': _flipFirstByte(good.serverSignature)},
        ),
        SenderCertificateFailure.badServerSignature,
      );
    });

    test('flipped certificate byte -> badServerSignature', () async {
      final good = await issue();
      final bytes = Uint8List.fromList(good.certificateBytes);
      final at = utf8.decode(bytes).indexOf('device-1') + 'device-'.length;
      bytes[at] ^= 0x02; // "device-1" -> "device-3", JSON stays valid
      await expectRejected(
        await rawCertified(
          cert: IssuedSenderCertificate(
            certificateBytes: bytes,
            serverSignature: good.serverSignature,
          ),
          overrides: {'senderDeviceId': 'device-3'},
        ),
        SenderCertificateFailure.badServerSignature,
      );
    });

    test(
      'certificate issued for another senderId -> identityMismatch',
      () async {
        await expectRejected(
          await rawCertified(cert: await issue(senderId: 'someone-else')),
          SenderCertificateFailure.identityMismatch,
        );
        await expectRejected(
          await rawCertified(cert: await issue(deviceId: 'device-9')),
          SenderCertificateFailure.identityMismatch,
        );
        final otherIdentity = await SignalKeyHelper.generateIdentityKeyPair();
        await expectRejected(
          await rawCertified(
            cert: await issue(identityKey: otherIdentity.publicKey),
          ),
          SenderCertificateFailure.identityMismatch,
        );
      },
    );

    test('unknown keyId -> unknownKeyId', () async {
      await expectRejected(
        await rawCertified(),
        SenderCertificateFailure.unknownKeyId,
        keys: {'other-key': server.publicKey},
      );
    });

    test(
      'sealed timestamp outside the certificate -> expired/notYetValid',
      () async {
        final cert = await issue(
          issuedAt: now - 3 * 24 * 60 * 60 * 1000,
          expiresAt: now - 2 * 24 * 60 * 60 * 1000,
        );
        await expectRejected(
          await rawCertified(cert: cert),
          SenderCertificateFailure.expired,
        );
        final future = await issue(issuedAt: now + 60 * 60 * 1000);
        await expectRejected(
          await rawCertified(cert: future),
          SenderCertificateFailure.notYetValid,
        );
      },
    );

    test(
      'store-and-forward: old sealed timestamp inside validity accepted',
      () async {
        final cert = await issue(
          issuedAt: now - 3 * 24 * 60 * 60 * 1000,
          expiresAt: now - 2 * 24 * 60 * 60 * 1000,
        );
        final content = await SealedSenderEnvelope.unseal(
          sealedEnvelope: await rawCertified(
            cert: cert,
            timestamp: now - 2 * 24 * 60 * 60 * 1000 - 60 * 1000,
          ),
          recipientIdentityKeyPair: recipient,
          seenNonces: <String>{},
          maxReplayWindowMs: _wideWindowMs,
          trustedServerSigningKeys: trusted,
        );
        expect(content.certified, isTrue);
      },
    );

    test('only one of the two fields -> malformed (pinned or not)', () async {
      for (final missing in ['senderCertificate', 'serverSignature']) {
        await expectRejected(
          await rawCertified(drop: [missing]),
          SenderCertificateFailure.malformed,
        );
        await expectRejected(
          await rawCertified(drop: [missing]),
          SenderCertificateFailure.malformed,
          useTrusted: false,
        );
      }
    });

    test(
      'non-string or non-canonical certificate fields -> malformed',
      () async {
        await expectRejected(
          await rawCertified(overrides: {'senderCertificate': 42}),
          SenderCertificateFailure.malformed,
        );
        await expectRejected(
          await rawCertified(overrides: {'senderCertificate': '!!!'}),
          SenderCertificateFailure.malformed,
        );
        await expectRejected(
          await rawCertified(overrides: {'senderCertificate': 42}),
          SenderCertificateFailure.malformed,
          useTrusted: false,
        );
      },
    );
  });

  group('seal with a certificate', () {
    test(
      'identity that does not match the seal arguments -> ArgumentError',
      () async {
        await expectLater(
          sealCertified(cert: await issue(senderId: 'someone-else')),
          throwsArgumentError,
        );
        await expectLater(
          sealCertified(cert: await issue(deviceId: 'device-9')),
          throwsArgumentError,
        );
      },
    );

    test('expired or not-yet-valid certificate -> StateError', () async {
      await expectLater(
        sealCertified(
          cert: await issue(
            issuedAt: now - 2 * 24 * 60 * 60 * 1000,
            expiresAt: now - 24 * 60 * 60 * 1000,
          ),
        ),
        throwsStateError,
      );
      await expectLater(
        sealCertified(cert: await issue(issuedAt: now + 60 * 60 * 1000)),
        throwsStateError,
      );
    });
  });
}
