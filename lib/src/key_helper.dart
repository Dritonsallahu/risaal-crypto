import 'dart:convert';
import 'dart:isolate';
import 'package:cryptography/cryptography.dart' hide KeyPair;
import 'package:pqcrypto/pqcrypto.dart';

import 'crypto_protocol.dart';
import 'models/signal_keys.dart';

/// Low-level cryptographic primitive layer for Signal Protocol key generation.
///
/// Provides stateless factory methods for generating all types of keys used in
/// the Signal Protocol:
///   - **X25519**: Elliptic curve Diffie-Hellman (ECDH) for key agreement
///   - **Ed25519**: Edwards-curve digital signatures (EdDSA)
///   - **Kyber-768**: Post-quantum key encapsulation mechanism (ML-KEM)
///
/// All keys are returned as base64-encoded strings for JSON serialization and
/// wire transport. The encoding is standard RFC 4648 base64.
///
/// This class is used internally by [SignalProtocolManager] during [initialize]
/// and [generateKeyBundle]. Clients rarely call these methods directly.
///
/// See also:
///   - [SignalProtocolManager.initialize] which generates all keys on first run
///   - [KeyPair], [SignedPreKey], [OneTimePreKey], [KyberKeyPair] for models
class SignalKeyHelper {
  static const bool _isWeb = bool.fromEnvironment('dart.library.js_interop');

  // ── X25519 Key Pair ───────────────────────────────────────────────

  /// Generate an X25519 key pair for Diffie-Hellman key agreement.
  ///
  /// X25519 is used for:
  ///   - Identity keys (long-term)
  ///   - Signed pre-keys (medium-term, rotated weekly)
  ///   - One-time pre-keys (ephemeral, single-use)
  ///   - Double Ratchet DH keys (ephemeral, rotated per reply)
  ///
  /// Returns a [KeyPair] with base64-encoded public and private keys.
  /// Key lengths (after base64 decoding): 32 bytes each.
  static Future<KeyPair> generateX25519KeyPair() async {
    final algorithm = X25519();
    final kp = await algorithm.newKeyPair();
    final publicKey = await kp.extractPublicKey();
    final privateBytes = await kp.extractPrivateKeyBytes();

    return KeyPair(
      publicKey: base64Encode(publicKey.bytes),
      privateKey: base64Encode(privateBytes),
    );
  }

  /// Verify that a stored X25519 public/private pair represents one key.
  ///
  /// Shape checks alone are insufficient: two unrelated 32-byte values decode
  /// successfully but derive different X3DH secrets and surface later as an
  /// undecryptable first message. This reconstructs the public key from the
  /// stored private seed and compares it without early exit.
  static Future<bool> isValidX25519KeyPair(KeyPair keyPair) async {
    return _isValidX25519KeyPairDirect(keyPair);
  }

  static Future<bool> _isValidX25519KeyPairDirect(KeyPair keyPair) async {
    try {
      final publicBytes = base64Decode(keyPair.publicKey);
      final privateBytes = base64Decode(keyPair.privateKey);
      if (publicBytes.length != 32 ||
          privateBytes.length != 32 ||
          base64Encode(publicBytes) != keyPair.publicKey ||
          base64Encode(privateBytes) != keyPair.privateKey) {
        return false;
      }

      final reconstructed = await X25519().newKeyPairFromSeed(privateBytes);
      final derivedPublic = (await reconstructed.extractPublicKey()).bytes;
      return _constantTimeBytesEqual(derivedPublic, publicBytes);
    } on FormatException {
      return false;
    } on ArgumentError {
      return false;
    }
  }

  /// Validate a batch without monopolizing Flutter's UI isolate.
  ///
  /// A current key-bundle journal can contain 100 X25519 OPKs. The pure-Dart
  /// X25519 implementation is intentionally portable, but validating that
  /// whole pool on Android debug builds can block rendering for several
  /// seconds. Native Dart platforms therefore do the exact same validation in
  /// a worker isolate. Web keeps the portable direct path because isolates are
  /// not available there.
  static Future<bool> areValidX25519KeyPairs(Iterable<KeyPair> keyPairs) async {
    final pairs = keyPairs.toList(growable: false);
    if (pairs.isEmpty) return true;
    if (_isWeb || pairs.length == 1) {
      for (final pair in pairs) {
        if (!await _isValidX25519KeyPairDirect(pair)) return false;
      }
      return true;
    }
    return Isolate.run(() async {
      for (final pair in pairs) {
        if (!await _isValidX25519KeyPairDirect(pair)) return false;
      }
      return true;
    });
  }

  /// Verify that a stored Ed25519 signing public key belongs to its private
  /// seed. This prevents a structurally valid but mismatched restore from
  /// silently signing material peers can never authenticate.
  static Future<bool> isValidEd25519KeyPair(KeyPair keyPair) async {
    try {
      final publicBytes = base64Decode(keyPair.publicKey);
      final privateBytes = base64Decode(keyPair.privateKey);
      if (publicBytes.length != 32 ||
          privateBytes.isEmpty ||
          base64Encode(publicBytes) != keyPair.publicKey ||
          base64Encode(privateBytes) != keyPair.privateKey) {
        return false;
      }

      final reconstructed = await Ed25519().newKeyPairFromSeed(privateBytes);
      final derivedPublic = (await reconstructed.extractPublicKey()).bytes;
      return _constantTimeBytesEqual(derivedPublic, publicBytes);
    } on FormatException {
      return false;
    } on ArgumentError {
      return false;
    }
  }

  /// Verify the exact current ML-KEM pair with a real encapsulation roundtrip.
  /// ML-KEM implicit rejection returns a different secret for a mismatched
  /// private key, so equality is the required validity signal.
  static bool isValidKyberKeyPair(KyberKeyPair keyPair) {
    try {
      final publicBytes = base64Decode(keyPair.publicKey);
      final privateBytes = base64Decode(keyPair.privateKey);
      if (!keyPair.isCurrentProtocol ||
          publicBytes.length != 1184 ||
          privateBytes.length != 2400 ||
          base64Encode(publicBytes) != keyPair.publicKey ||
          base64Encode(privateBytes) != keyPair.privateKey) {
        return false;
      }
      final encapsulated = kyberEncapsulate(keyPair.publicKey);
      final decapsulated = kyberDecapsulate(
        keyPair.privateKey,
        encapsulated.$1,
      );
      return _constantTimeBytesEqual(encapsulated.$2, decapsulated);
    } on FormatException {
      return false;
    } on ArgumentError {
      return false;
    }
  }

  static bool _constantTimeBytesEqual(List<int> left, List<int> right) {
    var difference = left.length ^ right.length;
    final comparedLength = left.length < right.length
        ? left.length
        : right.length;
    for (var i = 0; i < comparedLength; i++) {
      difference |= left[i] ^ right[i];
    }
    return difference == 0;
  }

  /// Reject an all-zero X25519 output (RFC 7748 §6.1).
  ///
  /// A low-order remote public key forces the shared secret to zero whatever
  /// our private key is, so the "secret" is a public constant. Every DH call
  /// site runs its output through this before it feeds a KDF. The output is
  /// zero, so there is nothing to wipe on the rejection path.
  static void requireContributoryX25519(List<int> sharedSecret) {
    var accumulator = 0;
    for (final byte in sharedSecret) {
      accumulator |= byte;
    }
    if (accumulator == 0) {
      throw ArgumentError(
        'X25519 produced an all-zero shared secret (low-order public key)',
      );
    }
  }

  // ── X25519 Identity Key Pair (for DH in X3DH & Sealed Sender) ────

  /// Generate the X25519 identity key pair (long-term DH key).
  ///
  /// This is the device's long-term Diffie-Hellman key, used for:
  ///   - X3DH key agreement (session establishment)
  ///   - Sealed Sender unsealing (recipient side)
  ///
  /// The identity key pair is generated once on first run and never rotated
  /// (unless the user reinstalls or panic-wipes). The public key is uploaded
  /// to the server as part of the key bundle.
  ///
  /// Alias for [generateX25519KeyPair].
  static Future<KeyPair> generateIdentityKeyPair() async =>
      generateX25519KeyPair();

  // ── Ed25519 Signing Key Pair ────────────────────────────────────

  /// Generate an Ed25519 key pair for digital signatures.
  ///
  /// Used to sign the X25519 signed pre-key, proving that the identity key
  /// owner endorsed the pre-key. Recipients verify the signature before
  /// performing X3DH to prevent impersonation attacks.
  ///
  /// Returns a [KeyPair] with base64-encoded public and private keys.
  /// Key lengths (after base64 decoding):
  ///   - Public: 32 bytes
  ///   - Private: 64 bytes (32-byte seed + 32-byte derived public key)
  static Future<KeyPair> generateSigningKeyPair() async {
    final algorithm = Ed25519();
    final kp = await algorithm.newKeyPair();
    final publicKey = await kp.extractPublicKey();
    final privateBytes = await kp.extractPrivateKeyBytes();

    return KeyPair(
      publicKey: base64Encode(publicKey.bytes),
      privateKey: base64Encode(privateBytes),
    );
  }

  // ── Signed Pre-Key ────────────────────────────────────────────────

  /// Generate a signed X25519 pre-key.
  ///
  /// Generates a new X25519 key pair and signs the public key with the
  /// [signingKeyPair] (Ed25519 identity signing key). The signature proves
  /// that the identity key owner endorsed this pre-key.
  ///
  /// Parameters:
  ///   - [keyId]: Unique identifier (e.g., incrementing counter or 0 for current)
  ///   - [signingKeyPair]: Ed25519 signing key pair (from [generateSigningKeyPair])
  ///
  /// Returns a [SignedPreKey] with the X25519 key pair, signature, and timestamp.
  ///
  /// Signed pre-keys are rotated periodically (e.g., weekly) for security hygiene.
  static Future<SignedPreKey> generateSignedPreKey(
    int keyId,
    KeyPair signingKeyPair,
  ) async {
    final keyPair = await generateX25519KeyPair();
    final publicKeyBytes = base64Decode(keyPair.publicKey);
    final signature = await sign(signingKeyPair.privateKey, publicKeyBytes);

    return SignedPreKey(
      keyId: keyId,
      keyPair: keyPair,
      signature: signature,
      createdAt: DateTime.now(),
    );
  }

  // ── One-Time Pre-Keys ─────────────────────────────────────────────

  /// Generate a batch of one-time X25519 pre-keys.
  ///
  /// One-time pre-keys are ephemeral keys consumed once during X3DH session
  /// establishment. Generating them in batches (e.g., 100) reduces server
  /// round-trips.
  ///
  /// Parameters:
  ///   - [startId]: First key ID in the batch (e.g., 0, 100, 200, ...)
  ///   - [count]: Number of keys to generate (e.g., 100)
  ///
  /// Returns a list of [OneTimePreKey] with sequential key IDs.
  ///
  /// Upload the public portions to the server via [generateKeyBundle]. The
  /// server returns one to session initiators and marks it as consumed.
  static Future<List<OneTimePreKey>> generateOneTimePreKeys(
    int startId,
    int count,
  ) async {
    if (!_isWeb && count > 1) {
      final encoded = await Isolate.run(
        () => _generateOneTimePreKeysEncoded(startId, count),
      );
      return encoded.map(OneTimePreKey.fromJson).toList(growable: false);
    }
    return _generateOneTimePreKeysDirect(startId, count);
  }

  static Future<List<OneTimePreKey>> _generateOneTimePreKeysDirect(
    int startId,
    int count,
  ) async {
    final keys = <OneTimePreKey>[];
    for (var i = 0; i < count; i++) {
      final keyPair = await generateX25519KeyPair();
      keys.add(OneTimePreKey(keyId: startId + i, keyPair: keyPair));
    }
    return keys;
  }

  static Future<List<Map<String, dynamic>>> _generateOneTimePreKeysEncoded(
    int startId,
    int count,
  ) async {
    final keys = await _generateOneTimePreKeysDirect(startId, count);
    return keys.map((key) => key.toJson()).toList(growable: false);
  }

  // ── Ed25519 Sign ──────────────────────────────────────────────────

  /// Sign data with an Ed25519 private key.
  ///
  /// Used internally by [generateSignedPreKey] to sign the X25519 pre-key
  /// public key. The signature is base64-encoded for wire transport.
  ///
  /// Parameters:
  ///   - [privateKeyBase64]: Base64-encoded Ed25519 private key (64 bytes raw)
  ///   - [data]: Bytes to sign (e.g., X25519 public key)
  ///
  /// Returns base64-encoded Ed25519 signature (64 bytes raw).
  static Future<String> sign(String privateKeyBase64, List<int> data) async {
    final algorithm = Ed25519();
    final privateBytes = base64Decode(privateKeyBase64);
    final keyPair = await algorithm.newKeyPairFromSeed(privateBytes);
    final signature = await algorithm.sign(data, keyPair: keyPair);

    return base64Encode(signature.bytes);
  }

  // ── Ed25519 Verify ────────────────────────────────────────────────

  /// Verify an Ed25519 signature.
  ///
  /// Used internally during X3DH to verify the signed pre-key signature before
  /// performing key agreement. Prevents impersonation attacks.
  ///
  /// Parameters:
  ///   - [publicKeyBase64]: Base64-encoded Ed25519 public key (32 bytes raw)
  ///   - [data]: Bytes that were signed (e.g., X25519 pre-key public)
  ///   - [signatureBase64]: Base64-encoded Ed25519 signature (64 bytes raw)
  ///
  /// Returns `true` if signature is valid, `false` otherwise.
  static Future<bool> verify(
    String publicKeyBase64,
    List<int> data,
    String signatureBase64,
  ) async {
    final algorithm = Ed25519();
    final publicKeyBytes = base64Decode(publicKeyBase64);
    final signatureBytes = base64Decode(signatureBase64);

    final publicKey = SimplePublicKey(
      publicKeyBytes,
      type: KeyPairType.ed25519,
    );
    final signature = Signature(signatureBytes, publicKey: publicKey);

    return algorithm.verify(data, signature: signature);
  }

  // ── ML-KEM-768 (Kyber) ─────────────────────────────────────────────

  /// Generate a Kyber-768 key pair for post-quantum key encapsulation.
  ///
  /// Kyber (ML-KEM-768) is a NIST-standardized lattice-based KEM providing
  /// post-quantum security. Used in PQXDH (hybrid X3DH + Kyber) to protect
  /// sessions against future quantum computers.
  ///
  /// Key sizes (after base64 decoding):
  ///   - Public key: 1184 bytes
  ///   - Private key: 2400 bytes
  ///
  /// The exact `pqcrypto 0.4.0` implementation is pure Dart. [keyId] is supplied
  /// by the storage-backed rotation coordinator and must never be reused on the
  /// same device.
  ///
  /// Returns a [KyberKeyPair] with base64-encoded public and private keys.
  ///
  /// See also:
  ///   - [kyberEncapsulate] to encapsulate a shared secret
  ///   - [kyberDecapsulate] to decapsulate using the private key
  static KyberKeyPair generateKyberKeyPair({int keyId = 1}) {
    if (keyId <= 0) {
      throw ArgumentError.value(keyId, 'keyId', 'must be positive');
    }
    final kem = PqcKem.kyber768;
    final (pk, sk) = kem.generateKeyPair();
    return KyberKeyPair(
      publicKey: base64Encode(pk),
      privateKey: base64Encode(sk),
      keyId: keyId,
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
      kemSuite: RisaalCryptoProtocol.kemSuite,
      kemStandard: RisaalCryptoProtocol.kemStandard,
      kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
    );
  }

  /// Encapsulate a shared secret using Kyber public key (sender side).
  ///
  /// Produces a ciphertext that only the private key holder can decapsulate
  /// to recover the same shared secret. This is the Kyber equivalent of
  /// Diffie-Hellman key agreement, but asymmetric (no DH step required).
  ///
  /// Used by the session initiator (Alice) during PQXDH to add post-quantum
  /// protection to the X3DH shared secret.
  ///
  /// Parameters:
  ///   - [publicKeyBase64]: Recipient's Kyber public key (base64, 1184 bytes raw)
  ///
  /// Returns a tuple:
  ///   - `ciphertext`: Base64-encoded ciphertext (1088 bytes raw)
  ///   - `sharedSecret`: Raw 32-byte shared secret
  ///
  /// The ciphertext is sent to the recipient (embedded in the PreKey message).
  /// The shared secret is mixed with the X3DH shared secret via XOR or HKDF.
  static (String ciphertext, List<int> sharedSecret) kyberEncapsulate(
    String publicKeyBase64,
  ) {
    final kem = PqcKem.kyber768;
    final pk = base64Decode(publicKeyBase64);
    final (ct, ss) = kem.encapsulate(pk);
    return (base64Encode(ct), ss.toList());
  }

  /// Decapsulate a shared secret using Kyber private key (receiver side).
  ///
  /// Recovers the same shared secret that the sender encapsulated. This is
  /// the Kyber equivalent of performing a DH exchange, but asymmetric.
  ///
  /// Used by the session responder (Bob) during PQXDH to recover the post-quantum
  /// shared secret from the ciphertext embedded in Alice's PreKey message.
  ///
  /// Parameters:
  ///   - [privateKeyBase64]: Local Kyber private key (base64, 2400 bytes raw)
  ///   - [ciphertextBase64]: Ciphertext from encapsulation (base64, 1088 bytes raw)
  ///
  /// Returns the 32-byte shared secret (same as the sender's).
  ///
  /// Throws if decapsulation fails (e.g., corrupted ciphertext, wrong private key).
  static List<int> kyberDecapsulate(
    String privateKeyBase64,
    String ciphertextBase64,
  ) {
    final kem = PqcKem.kyber768;
    final sk = base64Decode(privateKeyBase64);
    final ct = base64Decode(ciphertextBase64);
    return kem.decapsulate(sk, ct).toList();
  }
}
