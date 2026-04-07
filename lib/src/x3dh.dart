import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'secure_memory.dart';
import 'key_helper.dart';
import 'models/signal_keys.dart';

/// Result of the PQXDH initiator side (X3DH + Kyber hybrid).
class X3DHResult {
  /// 32-byte shared secret derived from the key agreement.
  final List<int> sharedSecret;

  /// Base64-encoded ephemeral public key (sent to the responder).
  final String ephemeralPublicKey;

  /// ID of the consumed one-time pre-key, if one was available.
  final int? usedOneTimePreKeyId;

  /// Base64-encoded Kyber ciphertext (sent to the responder so they
  /// can decapsulate and derive the same shared secret). Null if the
  /// recipient's bundle didn't include a Kyber pre-key.
  final String? kyberCiphertext;

  const X3DHResult({
    required this.sharedSecret,
    required this.ephemeralPublicKey,
    this.usedOneTimePreKeyId,
    this.kyberCiphertext,
  });
}

/// Extended Triple Diffie-Hellman key agreement (X3DH).
///
/// Establishes a shared secret between an initiator (Alice) and a
/// responder (Bob) without requiring both to be online simultaneously.
class X3DH {
  static const _info = 'Risaal_X3DH';
  static final _x25519 = X25519();
  static final _hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);

  // ── Initiator (Alice) ─────────────────────────────────────────────

  /// Alice initiates a session with Bob using his [recipientBundle].
  ///
  /// Protocol:
  /// 1. Generate ephemeral key pair EK
  /// 2. DH1 = DH(IK_A, SPK_B)
  /// 3. DH2 = DH(EK_A, IK_B)
  /// 4. DH3 = DH(EK_A, SPK_B)
  /// 5. DH4 = DH(EK_A, OPK_B) — if available
  /// 6. SK  = HKDF(DH1 || DH2 || DH3 [|| DH4])
  static Future<X3DHResult> initiateKeyAgreement({
    required KeyPair identityKeyPair,
    required PreKeyBundle recipientBundle,
  }) async {
    // Verify the signed pre-key signature using the recipient's Ed25519
    // signing key (if available). Falls back to skipping verification when
    // the bundle doesn't include a signing key (pre-upgrade bundles).
    final signingKey = recipientBundle.identitySigningKey;
    if (signingKey != null) {
      final signatureValid = await SignalKeyHelper.verify(
        signingKey,
        base64Decode(recipientBundle.signedPreKey.publicKey),
        recipientBundle.signedPreKey.signature,
      );
      if (!signatureValid) {
        throw StateError('Signed pre-key signature verification failed');
      }
    }

    // Generate ephemeral key pair
    final ephemeralKeyPair = await SignalKeyHelper.generateX25519KeyPair();

    // Build SimpleKeyPair / SimplePublicKey instances for DH
    final ikA = await _buildKeyPair(identityKeyPair);
    final ekA = await _buildKeyPair(ephemeralKeyPair);
    final spkB = _buildPublicKey(recipientBundle.signedPreKey.publicKey);
    final ikB = _buildPublicKey(recipientBundle.identityKey);

    // DH1 = DH(IK_A, SPK_B)
    final dh1 = await _dh(ikA, spkB);

    // DH2 = DH(EK_A, IK_B)
    final dh2 = await _dh(ekA, ikB);

    // DH3 = DH(EK_A, SPK_B)
    final dh3 = await _dh(ekA, spkB);

    // DH4 = DH(EK_A, OPK_B) — optional
    List<int>? dh4;
    int? usedOPKId;
    if (recipientBundle.oneTimePreKey != null) {
      final opkB = _buildPublicKey(recipientBundle.oneTimePreKey!.publicKey);
      dh4 = await _dh(ekA, opkB);
      usedOPKId = recipientBundle.oneTimePreKey!.keyId;
    }

    // Kyber KEM encapsulation (post-quantum layer) — optional
    // If the recipient published a Kyber pre-key, encapsulate against it
    // so the shared secret is protected by BOTH X25519 AND Kyber.
    // Wrapped in try/catch: if Kyber fails (e.g. platform FFI issue),
    // we degrade gracefully to pure X25519 X3DH.
    List<int>? kyberSharedSecret;
    String? kyberCiphertext;
    if (recipientBundle.kyberPreKey != null) {
      try {
        final (ct, ss) = SignalKeyHelper.kyberEncapsulate(
          recipientBundle.kyberPreKey!.publicKey,
        );
        kyberCiphertext = ct;
        kyberSharedSecret = ss;
      } catch (e) {
        // Kyber failed — degrade to pure X25519
        kyberSharedSecret = null;
        kyberCiphertext = null;
      }
    }

    // Concatenate all DH outputs + Kyber shared secret
    final dhConcat = <int>[
      ...dh1,
      ...dh2,
      ...dh3,
      if (dh4 != null) ...dh4,
      if (kyberSharedSecret != null) ...kyberSharedSecret,
    ];

    // Derive the shared secret via HKDF
    final sharedSecret = await _deriveSecret(dhConcat);

    // Securely wipe DH intermediaries — they must not persist in RAM.
    SecureMemory.zeroBytes(dh1);
    SecureMemory.zeroBytes(dh2);
    SecureMemory.zeroBytes(dh3);
    if (dh4 != null) SecureMemory.zeroBytes(dh4);
    if (kyberSharedSecret != null) SecureMemory.zeroBytes(kyberSharedSecret);
    SecureMemory.zeroBytes(dhConcat);

    return X3DHResult(
      sharedSecret: sharedSecret,
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
      usedOneTimePreKeyId: usedOPKId,
      kyberCiphertext: kyberCiphertext,
    );
  }

  // ── Responder (Bob) ───────────────────────────────────────────────

  /// Bob computes the same shared secret upon receiving Alice's first
  /// message.
  static Future<List<int>> respondKeyAgreement({
    required KeyPair identityKeyPair,
    required SignedPreKey signedPreKey,
    required OneTimePreKey? oneTimePreKey,
    required String senderIdentityKey,
    required String senderEphemeralKey,
    KyberKeyPair? kyberKeyPair,
    String? kyberCiphertext,
  }) async {
    final ikB = await _buildKeyPair(identityKeyPair);
    final spkB = await _buildKeyPair(signedPreKey.keyPair);
    final ikA = _buildPublicKey(senderIdentityKey);
    final ekA = _buildPublicKey(senderEphemeralKey);

    // DH1 = DH(SPK_B, IK_A) — mirrors Alice's DH(IK_A, SPK_B)
    final dh1 = await _dh(spkB, ikA);

    // DH2 = DH(IK_B, EK_A)  — mirrors Alice's DH(EK_A, IK_B)
    final dh2 = await _dh(ikB, ekA);

    // DH3 = DH(SPK_B, EK_A) — mirrors Alice's DH(EK_A, SPK_B)
    final dh3 = await _dh(spkB, ekA);

    // DH4 — optional
    List<int>? dh4;
    if (oneTimePreKey != null) {
      final opkB = await _buildKeyPair(oneTimePreKey.keyPair);
      dh4 = await _dh(opkB, ekA);
    }

    // Kyber KEM decapsulation (post-quantum layer) — optional
    // Wrapped in try/catch: must match initiator's behavior exactly.
    // If initiator's Kyber failed (no ciphertext sent), we skip too.
    List<int>? kyberSharedSecret;
    if (kyberKeyPair != null && kyberCiphertext != null) {
      try {
        kyberSharedSecret = SignalKeyHelper.kyberDecapsulate(
          kyberKeyPair.privateKey,
          kyberCiphertext,
        );
      } catch (e) {
        // Kyber failed — degrade to pure X25519 (must match initiator)
        kyberSharedSecret = null;
      }
    }

    final dhConcat = <int>[
      ...dh1,
      ...dh2,
      ...dh3,
      if (dh4 != null) ...dh4,
      if (kyberSharedSecret != null) ...kyberSharedSecret,
    ];

    final sharedSecret = await _deriveSecret(dhConcat);

    // Securely wipe DH intermediaries
    SecureMemory.zeroBytes(dh1);
    SecureMemory.zeroBytes(dh2);
    SecureMemory.zeroBytes(dh3);
    if (dh4 != null) SecureMemory.zeroBytes(dh4);
    if (kyberSharedSecret != null) SecureMemory.zeroBytes(kyberSharedSecret);
    SecureMemory.zeroBytes(dhConcat);

    return sharedSecret;
  }

  // ── Helpers ───────────────────────────────────────────────────────

  /// Perform a single X25519 DH exchange and return the raw bytes.
  static Future<List<int>> _dh(
    SimpleKeyPair localKeyPair,
    SimplePublicKey remotePublicKey,
  ) async {
    final secret = await _x25519.sharedSecretKey(
      keyPair: localKeyPair,
      remotePublicKey: remotePublicKey,
    );
    return secret.extractBytes();
  }

  /// HKDF-SHA256 derivation of a 32-byte shared secret.
  /// [inputKeyMaterial] is NOT wiped here — caller is responsible.
  static Future<List<int>> _deriveSecret(List<int> inputKeyMaterial) async {
    final secretKey = await _hkdf.deriveKey(
      secretKey: SecretKey(inputKeyMaterial),
      info: _info.codeUnits,
      nonce: Uint8List(32), // 32-byte zero salt per Signal spec
    );
    return secretKey.extractBytes();
  }

  /// Reconstruct a [SimpleKeyPair] from a base64-encoded [KeyPair].
  static Future<SimpleKeyPair> _buildKeyPair(KeyPair kp) async {
    final privateBytes = base64Decode(kp.privateKey);
    final publicBytes = base64Decode(kp.publicKey);
    return SimpleKeyPairData(
      privateBytes,
      publicKey: SimplePublicKey(publicBytes, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
  }

  /// Build a [SimplePublicKey] from a base64 string.
  static SimplePublicKey _buildPublicKey(String base64Key) {
    return SimplePublicKey(base64Decode(base64Key), type: KeyPairType.x25519);
  }
}
