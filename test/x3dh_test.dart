import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/x3dh.dart';

void main() {
  // ── Helper: generate a full PreKeyBundle simulating Bob's server-side keys ──

  Future<
      (
        PreKeyBundle bundle,
        KeyPair identityKP,
        KeyPair signingKP,
        SignedPreKey signedPreKey,
        OneTimePreKey otpk,
        KyberKeyPair kyberKP
      )> generateBobBundle() async {
    final identityKP = await SignalKeyHelper.generateX25519KeyPair();
    final signingKP = await SignalKeyHelper.generateSigningKeyPair();
    final signedPreKey =
        await SignalKeyHelper.generateSignedPreKey(1, signingKP);
    final otpks = await SignalKeyHelper.generateOneTimePreKeys(1, 1);
    final kyberKP = SignalKeyHelper.generateKyberKeyPair();

    final bundle = PreKeyBundle(
      userId: 'bob-123',
      deviceId: 'device-1',
      identityKey: identityKP.publicKey,
      identitySigningKey: signingKP.publicKey,
      signedPreKey: SignedPreKeyPublic(
        keyId: signedPreKey.keyId,
        publicKey: signedPreKey.keyPair.publicKey,
        signature: signedPreKey.signature,
      ),
      oneTimePreKey: OneTimePreKeyPublic(
        keyId: otpks.first.keyId,
        publicKey: otpks.first.keyPair.publicKey,
      ),
      kyberPreKey: KyberPreKeyPublic(
        keyId: 1,
        publicKey: kyberKP.publicKey,
      ),
    );

    return (bundle, identityKP, signingKP, signedPreKey, otpks.first, kyberKP);
  }

  group('X3DH Key Agreement', () {
    test('initiator and responder derive the same shared secret', () async {
      // Alice generates her identity key
      final aliceIdentityKP = await SignalKeyHelper.generateX25519KeyPair();

      // Bob publishes his bundle
      final (bundle, bobIdentityKP, _, bobSignedPreKey, bobOTPK, bobKyberKP) =
          await generateBobBundle();

      // Alice initiates
      final aliceResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceIdentityKP,
        recipientBundle: bundle,
      );

      // Bob responds
      final bobSharedSecret = await X3DH.respondKeyAgreement(
        identityKeyPair: bobIdentityKP,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOTPK,
        senderIdentityKey: aliceIdentityKP.publicKey,
        senderEphemeralKey: aliceResult.ephemeralPublicKey,
        kyberKeyPair: bobKyberKP,
        kyberCiphertext: aliceResult.kyberCiphertext,
      );

      expect(aliceResult.sharedSecret, equals(bobSharedSecret));
      expect(aliceResult.sharedSecret.length, 32);
    });

    test('shared secret differs with different identity keys', () async {
      final aliceKP1 = await SignalKeyHelper.generateX25519KeyPair();
      final aliceKP2 = await SignalKeyHelper.generateX25519KeyPair();
      final (bundle, _, _, _, _, _) = await generateBobBundle();

      final result1 = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP1,
        recipientBundle: bundle,
      );
      final result2 = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP2,
        recipientBundle: bundle,
      );

      expect(result1.sharedSecret, isNot(equals(result2.sharedSecret)));
    });

    test('works without one-time pre-key', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final identityKP = await SignalKeyHelper.generateX25519KeyPair();
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(1, signingKP);

      final bundle = PreKeyBundle(
        userId: 'bob-123',
        deviceId: 'device-1',
        identityKey: identityKP.publicKey,
        identitySigningKey: signingKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.keyPair.publicKey,
          signature: signedPreKey.signature,
        ),
        // No oneTimePreKey, no kyberPreKey
      );

      final aliceResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: bundle,
      );

      final bobSharedSecret = await X3DH.respondKeyAgreement(
        identityKeyPair: identityKP,
        signedPreKey: signedPreKey,
        oneTimePreKey: null,
        senderIdentityKey: aliceKP.publicKey,
        senderEphemeralKey: aliceResult.ephemeralPublicKey,
      );

      expect(aliceResult.sharedSecret, equals(bobSharedSecret));
      expect(aliceResult.usedOneTimePreKeyId, isNull);
      expect(aliceResult.kyberCiphertext, isNull);
    });

    test('ephemeral public key is unique per invocation', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final (bundle, _, _, _, _, _) = await generateBobBundle();

      final result1 = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: bundle,
      );
      final result2 = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: bundle,
      );

      expect(result1.ephemeralPublicKey,
          isNot(equals(result2.ephemeralPublicKey)));
    });

    test('rejects tampered signed pre-key signature', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final identityKP = await SignalKeyHelper.generateX25519KeyPair();
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(1, signingKP);

      // Use wrong signing key in the bundle — signature won't verify
      final wrongSigningKP = await SignalKeyHelper.generateSigningKeyPair();

      final bundle = PreKeyBundle(
        userId: 'bob-123',
        deviceId: 'device-1',
        identityKey: identityKP.publicKey,
        identitySigningKey: wrongSigningKP.publicKey, // WRONG key
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.keyPair.publicKey,
          signature: signedPreKey
              .signature, // Signed by correct key, but bundle claims wrong
        ),
      );

      expect(
        () => X3DH.initiateKeyAgreement(
          identityKeyPair: aliceKP,
          recipientBundle: bundle,
        ),
        throwsStateError,
      );
    });

    test('X3DH result includes consumed OTP key ID', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final (bundle, _, _, _, _, _) = await generateBobBundle();

      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: bundle,
      );

      expect(result.usedOneTimePreKeyId, isNotNull);
    });

    test('Kyber ciphertext is present when bundle has Kyber key', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final (bundle, _, _, _, _, _) = await generateBobBundle();

      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: bundle,
      );

      expect(result.kyberCiphertext, isNotNull);
      expect(result.kyberCiphertext!.isNotEmpty, isTrue);
    });
  });
}
