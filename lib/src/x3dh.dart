import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'crypto_protocol.dart';
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
  /// recipient's bundle didn't include a Kyber pre-key or if the
  /// [PqxdhPolicy] was [PqxdhPolicy.classicalOnly].
  final String? kyberCiphertext;

  /// Exact recipient KEM key routing metadata. Present iff
  /// [kyberCiphertext] is present.
  final MlKemEnvelopeMetadata? kemMetadata;

  /// Exact server-accepted generation and key-selection transcript.
  final PreKeyHandshakeRouting routing;

  /// Whether the post-quantum Kyber component was successfully used.
  ///
  /// `true` if Kyber encapsulation succeeded and the Kyber shared secret
  /// was mixed into the final key material. `false` if the session was
  /// established with classical X25519-only security.
  ///
  /// Callers should inspect this flag to display a security indicator
  /// (e.g., "Post-quantum protected" vs "Classical security only").
  final bool pqxdhUsed;

  const X3DHResult({
    required this.sharedSecret,
    required this.ephemeralPublicKey,
    this.usedOneTimePreKeyId,
    this.kyberCiphertext,
    this.kemMetadata,
    required this.routing,
    required this.pqxdhUsed,
  });
}

/// Extended Triple Diffie-Hellman key agreement (X3DH).
///
/// Establishes a shared secret between an initiator (Alice) and a
/// responder (Bob) without requiring both to be online simultaneously.
class X3DH {
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
  ///
  /// The [pqxdhPolicy] controls post-quantum Kyber handling:
  ///   - [PqxdhPolicy.requirePq] (default): Abort if Kyber fails or is unavailable
  ///   - [PqxdhPolicy.preferPq]: Use Kyber if available, degrade with warning
  ///   - [PqxdhPolicy.classicalOnly]: Skip Kyber entirely
  ///
  /// The default is [PqxdhPolicy.requirePq] so that every new session is
  /// hybrid by construction. Callers that legitimately need to interoperate
  /// with peers missing a Kyber key must opt into [preferPq] explicitly.
  ///
  /// [transcriptVersion] 2 (R4-L1) binds both identity keys into the HKDF
  /// info; the returned [X3DHResult.routing] carries it for the PreKey
  /// message. The responder derives with whatever version that routing names.
  static Future<X3DHResult> initiateKeyAgreement({
    required KeyPair identityKeyPair,
    required PreKeyBundle recipientBundle,
    PqxdhPolicy pqxdhPolicy = PqxdhPolicy.requirePq,
    int transcriptVersion = 1,
  }) async {
    if (pqxdhPolicy != PqxdhPolicy.requirePq) {
      throw UnsupportedError(
        'Epoch 2 requires PQXDH; downgrade policies are not supported',
      );
    }
    final routing = recipientBundle
        .requireCurrentRouting()
        .withTranscriptVersion(transcriptVersion);
    routing.requireCurrent();

    // Verify the signed pre-key signature using the recipient's Ed25519
    // signing key. Verification is mandatory — bundles without a signing
    // key are rejected at the model layer, and invalid signatures abort
    // session establishment to prevent impersonation attacks.
    final signatureValid = await SignalKeyHelper.verify(
      recipientBundle.identitySigningKey,
      base64Decode(recipientBundle.signedPreKey.publicKey),
      recipientBundle.signedPreKey.signature,
    );
    if (!signatureValid) {
      throw StateError('Signed pre-key signature verification failed');
    }

    // Validate all static ML-KEM material before ephemeral generation or DH.
    final recipientKem = recipientBundle.kyberPreKey;
    if (recipientKem == null || !recipientKem.isCurrentProtocol) {
      throw StateError('PQXDH requires a current ML-KEM pre-key');
    }
    final kyberSigValid = await SignalKeyHelper.verify(
      recipientBundle.identitySigningKey,
      RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
        keyId: recipientKem.keyId,
        publicKey: recipientKem.publicKey,
      ),
      recipientKem.signature,
    );
    if (!kyberSigValid) {
      throw StateError('ML-KEM pre-key signature verification failed');
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

    late final List<int> kyberSharedSecret;
    late final String kyberCiphertext;
    try {
      final (ct, ss) = SignalKeyHelper.kyberEncapsulate(recipientKem.publicKey);
      kyberCiphertext = ct;
      kyberSharedSecret = ss;
    } catch (error) {
      throw StateError(
        'PQXDH required but ML-KEM encapsulation failed: $error',
      );
    }
    final kemMetadata = MlKemEnvelopeMetadata.current(
      recipientKeyId: recipientKem.keyId,
    );

    // Concatenate all DH outputs + Kyber shared secret
    final dhConcat = <int>[
      ...dh1,
      ...dh2,
      ...dh3,
      if (dh4 != null) ...dh4,
      ...kyberSharedSecret,
    ];

    // Derive the shared secret via HKDF. Transcript 2 binds both identity
    // keys into the info (R4-L1); transcript 1 ignores them.
    final sharedSecret = await _deriveSecret(
      dhConcat,
      routing.bindIdentityKeys(
        initiatorIdentityKey: identityKeyPair.publicKey,
        responderIdentityKey: recipientBundle.identityKey,
      ),
    );

    // Wipe the package-owned DH intermediaries (best-effort, Dart heap).
    // Non-short-circuit `&`: every buffer is zeroed, also in release builds.
    final wiped =
        SecureMemory.zeroBytes(dh1) &
        SecureMemory.zeroBytes(dh2) &
        SecureMemory.zeroBytes(dh3) &
        (dh4 == null || SecureMemory.zeroBytes(dh4)) &
        SecureMemory.zeroBytes(kyberSharedSecret) &
        SecureMemory.zeroBytes(dhConcat);
    assert(wiped, 'X3DH intermediaries must be package-owned and zeroable');

    return X3DHResult(
      sharedSecret: sharedSecret,
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
      usedOneTimePreKeyId: usedOPKId,
      kyberCiphertext: kyberCiphertext,
      kemMetadata: kemMetadata,
      routing: routing,
      pqxdhUsed: true,
    );
  }

  // ── Responder (Bob) ───────────────────────────────────────────────

  /// Bob computes the same shared secret upon receiving Alice's first
  /// message.
  ///
  /// The [pqxdhPolicy] controls post-quantum Kyber handling on the
  /// responder side (mirrors the initiator's policy):
  ///   - [PqxdhPolicy.requirePq] (default): Abort if Kyber decapsulation fails
  ///   - [PqxdhPolicy.preferPq]: Degrade with warning if Kyber fails
  ///   - [PqxdhPolicy.classicalOnly]: Ignore Kyber ciphertext
  ///
  /// The default is [PqxdhPolicy.requirePq]: a missing or invalid Kyber
  /// ciphertext aborts the handshake rather than silently producing a
  /// classical-only session.
  static Future<List<int>> respondKeyAgreement({
    required KeyPair identityKeyPair,
    required SignedPreKey signedPreKey,
    required OneTimePreKey? oneTimePreKey,
    required String senderIdentityKey,
    required String senderEphemeralKey,
    required KyberKeyPair kyberKeyPair,
    required String kyberCiphertext,
    required PreKeyHandshakeRouting routing,
    PqxdhPolicy pqxdhPolicy = PqxdhPolicy.requirePq,
  }) async {
    if (pqxdhPolicy != PqxdhPolicy.requirePq) {
      throw UnsupportedError(
        'Epoch 2 requires PQXDH; downgrade policies are not supported',
      );
    }
    routing.requireCurrent();
    if (!kyberKeyPair.isCurrentProtocol) {
      throw StateError('PQXDH requires current, versioned ML-KEM material');
    }
    if (signedPreKey.keyId != routing.recipientSignedPreKeyId ||
        oneTimePreKey?.keyId != routing.usedOneTimePreKeyId ||
        kyberKeyPair.keyId != routing.kemMetadata.recipientKeyId) {
      throw const FormatException(
        'PQXDH private material does not match authenticated routing',
      );
    }

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

    late final List<int> kyberSharedSecret;
    try {
      kyberSharedSecret = SignalKeyHelper.kyberDecapsulate(
        kyberKeyPair.privateKey,
        kyberCiphertext,
      );
    } catch (error) {
      throw StateError(
        'PQXDH required but ML-KEM decapsulation failed: $error',
      );
    }

    final dhConcat = <int>[
      ...dh1,
      ...dh2,
      ...dh3,
      if (dh4 != null) ...dh4,
      ...kyberSharedSecret,
    ];

    final sharedSecret = await _deriveSecret(
      dhConcat,
      routing.bindIdentityKeys(
        initiatorIdentityKey: senderIdentityKey,
        responderIdentityKey: identityKeyPair.publicKey,
      ),
    );

    // Wipe the package-owned DH intermediaries (best-effort, Dart heap).
    // Non-short-circuit `&`: every buffer is zeroed, also in release builds.
    final wiped =
        SecureMemory.zeroBytes(dh1) &
        SecureMemory.zeroBytes(dh2) &
        SecureMemory.zeroBytes(dh3) &
        (dh4 == null || SecureMemory.zeroBytes(dh4)) &
        SecureMemory.zeroBytes(kyberSharedSecret) &
        SecureMemory.zeroBytes(dhConcat);
    assert(wiped, 'X3DH intermediaries must be package-owned and zeroable');

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
    final out = SecureMemory.ownedCopy(await secret.extractBytes());
    secret.destroy();
    SignalKeyHelper.requireContributoryX25519(out);
    return out;
  }

  /// HKDF-SHA256 derivation of a 32-byte shared secret.
  /// [inputKeyMaterial] is NOT wiped here — caller is responsible.
  ///
  /// A2-4 (Signal X3DH / PQXDH spec compliance): the KDF input is prefixed with
  /// F = 32 bytes of 0xFF (one X25519 public-key length). F provides domain
  /// separation / downgrade resistance — without it the KDF is not separated
  /// from a hypothetical classical-only variant. NOTE: this changes the derived
  /// secret, so it is a WIRE-BREAKING change — a peer on an old build derives a
  /// different SK and cannot establish a NEW session (existing ratchets keep
  /// their stored state). Roll out to all clients together.
  static Future<List<int>> _deriveSecret(
    List<int> inputKeyMaterial,
    PreKeyHandshakeRouting routing,
  ) async {
    final km = <int>[...List<int>.filled(32, 0xFF), ...inputKeyMaterial];
    final secretKey = await _hkdf.deriveKey(
      secretKey: SecretKey(km),
      info: routing.canonicalTranscript(),
      nonce: Uint8List(32), // 32-byte zero salt per Signal spec
    );
    final out = SecureMemory.ownedCopy(await secretKey.extractBytes());
    secretKey.destroy();
    // `SecretKey(km)` wrapped km without copying; it holds the DH outputs.
    SecureMemory.zeroBytes(km);
    return out;
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
