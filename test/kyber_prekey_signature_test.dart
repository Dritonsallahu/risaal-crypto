import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/x3dh.dart';

import 'helpers/crypto_test_fixtures.dart';

/// Epoch 2 requires a canonical Ed25519 signature over the full ML-KEM routing
/// transcript. Unsigned or unversioned bundles are legacy and fail closed.
Future<PreKeyBundle> _bobBundle({String? kyberSignature}) async {
  final identityKP = await SignalKeyHelper.generateX25519KeyPair();
  final signingKP = await SignalKeyHelper.generateSigningKeyPair();
  final signedPreKey = await SignalKeyHelper.generateSignedPreKey(1, signingKP);
  final kyberKP = SignalKeyHelper.generateKyberKeyPair(keyId: 1);

  // Real signature over the domain-separated canonical transcript, unless the
  // caller deliberately overrides it for a negative test.
  final sig =
      kyberSignature ??
      await SignalKeyHelper.sign(
        signingKP.privateKey,
        RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
          keyId: kyberKP.keyId!,
          publicKey: kyberKP.publicKey,
        ),
      );

  return PreKeyBundle(
    opkRoute: testOpkRoute,
    userId: 'bob-123',
    deviceId: 'device-1',
    identityKey: identityKP.publicKey,
    identitySigningKey: signingKP.publicKey,
    signedPreKey: SignedPreKeyPublic(
      keyId: signedPreKey.keyId,
      publicKey: signedPreKey.keyPair.publicKey,
      signature: signedPreKey.signature,
    ),
    oneTimePreKey: null,
    kyberPreKey: KyberPreKeyPublic(
      keyId: kyberKP.keyId!,
      publicKey: kyberKP.publicKey,
      signature: sig,
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
      kemSuite: RisaalCryptoProtocol.kemSuite,
      kemStandard: RisaalCryptoProtocol.kemStandard,
      kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
    ),
  );
}

@Retry(0)
void main() {
  test('a validly-signed Kyber prekey is accepted', () async {
    final alice = await SignalKeyHelper.generateX25519KeyPair();
    final bundle = await _bobBundle();
    final result = await X3DH.initiateKeyAgreement(
      identityKeyPair: alice,
      recipientBundle: bundle,
    );
    expect(result.sharedSecret, isNotEmpty);
  });

  test('a tampered Kyber prekey signature is REJECTED', () async {
    final alice = await SignalKeyHelper.generateX25519KeyPair();
    // Start from a valid bundle, then corrupt the signature bytes.
    final good = await _bobBundle();
    final badSigBytes = base64Decode(good.kyberPreKey!.signature);
    badSigBytes[0] ^= 0xFF;
    final tampered = PreKeyBundle(
      opkRoute: good.opkRoute,
      userId: good.userId,
      deviceId: good.deviceId,
      identityKey: good.identityKey,
      identitySigningKey: good.identitySigningKey,
      signedPreKey: good.signedPreKey,
      oneTimePreKey: good.oneTimePreKey,
      kyberPreKey: KyberPreKeyPublic(
        keyId: good.kyberPreKey!.keyId,
        publicKey: good.kyberPreKey!.publicKey,
        signature: base64Encode(badSigBytes),
        cryptoProtocolEpoch: good.kyberPreKey!.cryptoProtocolEpoch,
        kemSuite: good.kyberPreKey!.kemSuite,
        kemStandard: good.kyberPreKey!.kemStandard,
        kemWireVersion: good.kyberPreKey!.kemWireVersion,
      ),
    );

    await expectLater(
      X3DH.initiateKeyAgreement(
        identityKeyPair: alice,
        recipientBundle: tampered,
      ),
      throwsA(
        predicate(
          (e) =>
              e is StateError &&
              e.message.contains('signature verification failed'),
        ),
      ),
      reason: 'a swapped/forged Kyber key must abort session establishment',
    );
  });

  test('an unsigned ML-KEM prekey is rejected as legacy', () async {
    final signed = await _bobBundle();
    final unsignedJson = signed.toJson();
    final kyberJson = Map<String, dynamic>.from(
      unsignedJson['kyberPreKey'] as Map,
    )..remove('signature');
    unsignedJson['kyberPreKey'] = kyberJson;

    expect(
      () => PreKeyBundle.fromJson(unsignedJson),
      throwsA(isA<FormatException>()),
    );
  });

  test(
    'journal dispatch always signs the canonical epoch-2 transcript',
    () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(
        manager,
      );
      final bundle = accepted.publicMaterial;
      final kyber = bundle['kyberPreKey'] as Map<String, dynamic>;
      final sig = kyber['signature'] as String?;
      expect(sig, isNotNull);

      // And the emitted signature verifies against the bundle's identity signing key.
      final ok = await SignalKeyHelper.verify(
        bundle['identitySigningKey'] as String,
        RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
          keyId: kyber['keyId'] as int,
          publicKey: kyber['publicKey'] as String,
        ),
        sig!,
      );
      expect(ok, isTrue);
      expect(kyber['cryptoProtocolEpoch'], 2);
      expect(kyber['kemSuite'], 'ML-KEM-768');
      expect(kyber['kemStandard'], 'FIPS203');
      expect(kyber['kemWireVersion'], 1);
    },
  );
}
