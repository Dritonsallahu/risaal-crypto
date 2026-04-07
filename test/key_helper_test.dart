import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';

void main() {
  // ── X25519 Key Pair Generation ──────────────────────────────────────

  group('SignalKeyHelper.generateX25519KeyPair', () {
    test('produces a valid key pair with base64-encoded 32-byte keys',
        () async {
      final kp = await SignalKeyHelper.generateX25519KeyPair();

      final pubBytes = base64Decode(kp.publicKey);
      final privBytes = base64Decode(kp.privateKey);

      expect(pubBytes.length, 32);
      expect(privBytes.length, 32);
    });

    test('produces unique key pairs on successive calls', () async {
      final kp1 = await SignalKeyHelper.generateX25519KeyPair();
      final kp2 = await SignalKeyHelper.generateX25519KeyPair();

      expect(kp1.publicKey, isNot(equals(kp2.publicKey)));
      expect(kp1.privateKey, isNot(equals(kp2.privateKey)));
    });

    test('public and private keys are different', () async {
      final kp = await SignalKeyHelper.generateX25519KeyPair();
      expect(kp.publicKey, isNot(equals(kp.privateKey)));
    });
  });

  // ── Identity Key Pair ───────────────────────────────────────────────

  group('SignalKeyHelper.generateIdentityKeyPair', () {
    test('produces a valid 32-byte X25519 key pair', () async {
      final kp = await SignalKeyHelper.generateIdentityKeyPair();

      expect(base64Decode(kp.publicKey).length, 32);
      expect(base64Decode(kp.privateKey).length, 32);
    });
  });

  // ── Ed25519 Signing Key Pair ────────────────────────────────────────

  group('SignalKeyHelper.generateSigningKeyPair', () {
    test('produces a valid Ed25519 key pair', () async {
      final kp = await SignalKeyHelper.generateSigningKeyPair();

      final pubBytes = base64Decode(kp.publicKey);
      final privBytes = base64Decode(kp.privateKey);

      // Ed25519 public keys are 32 bytes, seed (private) is 32 bytes
      expect(pubBytes.length, 32);
      expect(privBytes.length, 32);
    });

    test('produces unique signing key pairs', () async {
      final kp1 = await SignalKeyHelper.generateSigningKeyPair();
      final kp2 = await SignalKeyHelper.generateSigningKeyPair();

      expect(kp1.publicKey, isNot(equals(kp2.publicKey)));
    });
  });

  // ── Ed25519 Sign / Verify ──────────────────────────────────────────

  group('SignalKeyHelper sign and verify', () {
    test('sign then verify succeeds with correct key', () async {
      final signingKp = await SignalKeyHelper.generateSigningKeyPair();
      final data = utf8.encode('Risaal test payload');

      final signature = await SignalKeyHelper.sign(signingKp.privateKey, data);
      final valid = await SignalKeyHelper.verify(
        signingKp.publicKey,
        data,
        signature,
      );

      expect(valid, isTrue);
    });

    test('verify fails with wrong public key', () async {
      final signingKp1 = await SignalKeyHelper.generateSigningKeyPair();
      final signingKp2 = await SignalKeyHelper.generateSigningKeyPair();
      final data = utf8.encode('Risaal test payload');

      final signature = await SignalKeyHelper.sign(signingKp1.privateKey, data);
      final valid = await SignalKeyHelper.verify(
        signingKp2.publicKey,
        data,
        signature,
      );

      expect(valid, isFalse);
    });

    test('verify fails with tampered data', () async {
      final signingKp = await SignalKeyHelper.generateSigningKeyPair();
      final data = utf8.encode('Original message');

      final signature = await SignalKeyHelper.sign(signingKp.privateKey, data);
      final valid = await SignalKeyHelper.verify(
        signingKp.publicKey,
        utf8.encode('Tampered message'),
        signature,
      );

      expect(valid, isFalse);
    });
  });

  // ── Signed Pre-Key ─────────────────────────────────────────────────

  group('SignalKeyHelper.generateSignedPreKey', () {
    test('produces a signed pre-key with valid signature', () async {
      final signingKp = await SignalKeyHelper.generateSigningKeyPair();
      final spk = await SignalKeyHelper.generateSignedPreKey(1, signingKp);

      expect(spk.keyId, 1);
      expect(base64Decode(spk.keyPair.publicKey).length, 32);
      expect(spk.signature.isNotEmpty, isTrue);

      // Verify the signature over the pre-key public key
      final valid = await SignalKeyHelper.verify(
        signingKp.publicKey,
        base64Decode(spk.keyPair.publicKey),
        spk.signature,
      );
      expect(valid, isTrue);
    });
  });

  // ── One-Time Pre-Keys ──────────────────────────────────────────────

  group('SignalKeyHelper.generateOneTimePreKeys', () {
    test('produces the correct count with sequential IDs', () async {
      final keys = await SignalKeyHelper.generateOneTimePreKeys(10, 5);

      expect(keys.length, 5);
      for (var i = 0; i < 5; i++) {
        expect(keys[i].keyId, 10 + i);
        expect(base64Decode(keys[i].keyPair.publicKey).length, 32);
      }
    });

    test('all generated one-time pre-keys are unique', () async {
      final keys = await SignalKeyHelper.generateOneTimePreKeys(0, 10);
      final publicKeys = keys.map((k) => k.keyPair.publicKey).toSet();
      expect(publicKeys.length, 10);
    });
  });

  // ── Kyber (ML-KEM-768) Key Pair ────────────────────────────────────

  group('SignalKeyHelper.generateKyberKeyPair', () {
    test('produces a Kyber key pair with non-empty base64 keys', () {
      final kp = SignalKeyHelper.generateKyberKeyPair();

      final pubBytes = base64Decode(kp.publicKey);
      final privBytes = base64Decode(kp.privateKey);

      // Kyber-768 public key is 1184 bytes, secret key is 2400 bytes
      expect(pubBytes.length, greaterThan(0));
      expect(privBytes.length, greaterThan(0));
      expect(pubBytes.length, greaterThan(100)); // sanity: Kyber keys are large
    });

    test('produces unique key pairs', () {
      final kp1 = SignalKeyHelper.generateKyberKeyPair();
      final kp2 = SignalKeyHelper.generateKyberKeyPair();

      expect(kp1.publicKey, isNot(equals(kp2.publicKey)));
      expect(kp1.privateKey, isNot(equals(kp2.privateKey)));
    });
  });

  // ── Kyber Encapsulate / Decapsulate ────────────────────────────────

  group('SignalKeyHelper kyberEncapsulate / kyberDecapsulate', () {
    test('encapsulate then decapsulate produces the same shared secret', () {
      final kp = SignalKeyHelper.generateKyberKeyPair();

      final (ciphertext, sharedSecretEnc) =
          SignalKeyHelper.kyberEncapsulate(kp.publicKey);
      final sharedSecretDec =
          SignalKeyHelper.kyberDecapsulate(kp.privateKey, ciphertext);

      expect(sharedSecretEnc, equals(sharedSecretDec));
    });

    test('shared secret has correct length (32 bytes)', () {
      final kp = SignalKeyHelper.generateKyberKeyPair();

      final (_, sharedSecret) = SignalKeyHelper.kyberEncapsulate(kp.publicKey);

      expect(sharedSecret.length, 32);
    });

    test('different encapsulations produce different ciphertexts', () {
      final kp = SignalKeyHelper.generateKyberKeyPair();

      final (ct1, ss1) = SignalKeyHelper.kyberEncapsulate(kp.publicKey);
      final (ct2, ss2) = SignalKeyHelper.kyberEncapsulate(kp.publicKey);

      // Ciphertexts should differ (randomized KEM)
      expect(ct1, isNot(equals(ct2)));
      // But both decapsulate to different shared secrets (each encaps is independent)
      // Actually for Kyber, different encapsulations produce different shared secrets
      // unless the randomness is identical, which is astronomically unlikely.
    });

    test('decapsulate with wrong private key produces different shared secret',
        () {
      final kp1 = SignalKeyHelper.generateKyberKeyPair();
      final kp2 = SignalKeyHelper.generateKyberKeyPair();

      final (ciphertext, sharedSecretCorrect) =
          SignalKeyHelper.kyberEncapsulate(kp1.publicKey);

      // Decapsulate with the wrong private key — should NOT match
      final sharedSecretWrong =
          SignalKeyHelper.kyberDecapsulate(kp2.privateKey, ciphertext);

      expect(sharedSecretWrong, isNot(equals(sharedSecretCorrect)));
    });
  });

  // ── KeyPair model serialisation ────────────────────────────────────

  group('KeyPair model', () {
    test('toJson / fromJson round-trip', () async {
      final kp = await SignalKeyHelper.generateX25519KeyPair();
      final json = kp.toJson();
      final restored = KeyPair.fromJson(json);

      expect(restored.publicKey, kp.publicKey);
      expect(restored.privateKey, kp.privateKey);
    });
  });
}
