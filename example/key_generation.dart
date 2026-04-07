/// Low-level key generation and management.
///
/// Most applications should use SignalProtocolManager which handles
/// all key management automatically. This example shows the underlying
/// key generation primitives for advanced use cases.
library;

import 'dart:convert';
import 'package:risaal_crypto/risaal_crypto.dart';

Future<void> main() async {
  // ── X25519 Key Pairs (Diffie-Hellman) ───────────────────────────
  final dhKeyPair = await SignalKeyHelper.generateX25519KeyPair();
  print('X25519 public: ${dhKeyPair.publicKey}'); // base64
  print('X25519 private: ${dhKeyPair.privateKey}'); // base64

  // ── Ed25519 Key Pairs (Digital Signatures) ──────────────────────
  final signingKeyPair = await SignalKeyHelper.generateSigningKeyPair();
  print('Ed25519 public: ${signingKeyPair.publicKey}');

  // Sign data
  final data = utf8.encode('data to sign');
  final signature = await SignalKeyHelper.sign(
    signingKeyPair.privateKey,
    data,
  );
  print('Signature: $signature'); // base64

  // Verify signature
  final isValid = await SignalKeyHelper.verify(
    signingKeyPair.publicKey,
    data,
    signature,
  );
  print('Valid: $isValid'); // true

  // ── Signed Pre-Keys ────────────────────────────────────────────
  final signedPreKey = await SignalKeyHelper.generateSignedPreKey(
    0, // keyId
    signingKeyPair,
  );
  print('Signed pre-key id: ${signedPreKey.keyId}');
  print('Signature valid: verifiable via Ed25519');

  // Verify the signed pre-key signature
  final preKeyPublicBytes = base64Decode(signedPreKey.keyPair.publicKey);
  final signatureValid = await SignalKeyHelper.verify(
    signingKeyPair.publicKey,
    preKeyPublicBytes,
    signedPreKey.signature,
  );
  print('Signed pre-key signature verified: $signatureValid');

  // ── One-Time Pre-Keys ──────────────────────────────────────────
  final oneTimeKeys = await SignalKeyHelper.generateOneTimePreKeys(0, 20);
  print('Generated ${oneTimeKeys.length} one-time pre-keys');
  print('First OTP key ID: ${oneTimeKeys.first.keyId}');
  print('Last OTP key ID: ${oneTimeKeys.last.keyId}');

  // ── ML-KEM-768 / Kyber (Post-Quantum) ──────────────────────────
  try {
    final kyberKP = SignalKeyHelper.generateKyberKeyPair();
    print(
        'Kyber public key length: ${base64Decode(kyberKP.publicKey).length} bytes');

    // Encapsulate (sender side)
    final (ciphertext, sharedSecret) = SignalKeyHelper.kyberEncapsulate(
      kyberKP.publicKey,
    );
    print('Kyber shared secret: ${sharedSecret.length} bytes');
    print('Kyber ciphertext length: ${base64Decode(ciphertext).length} bytes');

    // Decapsulate (recipient side)
    final recovered = SignalKeyHelper.kyberDecapsulate(
      kyberKP.privateKey,
      ciphertext,
    );
    print('Secrets match: ${_listEquals(sharedSecret, recovered)}');
  } catch (e) {
    print('Kyber not available on this platform: $e');
  }

  // ── Identity Key Pair (convenience wrapper) ─────────────────────
  final identityKP = await SignalKeyHelper.generateIdentityKeyPair();
  print('Identity key pair generated');
  print('Identity public key: ${identityKP.publicKey.substring(0, 16)}...');
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
