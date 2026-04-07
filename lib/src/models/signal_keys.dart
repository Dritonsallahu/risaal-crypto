/// Base64-encoded asymmetric key pair for storage and transport.
///
/// Used for X25519 (DH) and Ed25519 (signing) key pairs. Both keys are
/// stored as base64-encoded byte arrays for JSON serialization and wire
/// transport. The encoding is standard base64 (RFC 4648).
///
/// Key lengths (after base64 decoding):
///   - X25519: 32 bytes public, 32 bytes private
///   - Ed25519: 32 bytes public, 64 bytes private (seed + derived public)
///
/// The `toString()` implementation truncates the public key to prevent
/// accidental logging of full key material in debug output.
class KeyPair {
  /// Base64-encoded public key bytes.
  final String publicKey;

  /// Base64-encoded private key bytes.
  final String privateKey;

  const KeyPair({required this.publicKey, required this.privateKey});

  Map<String, dynamic> toJson() => {
        'publicKey': publicKey,
        'privateKey': privateKey,
      };

  factory KeyPair.fromJson(Map<String, dynamic> json) => KeyPair(
        publicKey: json['publicKey'] as String,
        privateKey: json['privateKey'] as String,
      );

  /// Returns a truncated representation for safe debug logging.
  ///
  /// Only the first 8 base64 characters of the public key are shown.
  /// The private key is never included in the output.
  @override
  String toString() => 'KeyPair(publicKey: ${publicKey.substring(0, 8)}...)';
}

/// X25519 pre-key signed with the identity Ed25519 key.
///
/// Part of the X3DH (Extended Triple Diffie-Hellman) protocol. The signed
/// pre-key proves that the recipient's identity key endorsed this ephemeral
/// pre-key, preventing impersonation attacks.
///
/// The signature is computed as `Ed25519.sign(x25519_public_key)` using the
/// identity signing key's private portion. Recipients verify the signature
/// using the sender's identity signing public key before performing X3DH.
///
/// Signed pre-keys are rotated periodically (e.g., weekly) but kept around
/// for a grace period to allow delayed messages to arrive.
///
/// See also:
///   - [SignalKeyHelper.generateSignedPreKey] for key generation
///   - [PreKeyBundle.signedPreKey] for server-side public portion
class SignedPreKey {
  /// Unique identifier for this signed pre-key (e.g., incrementing counter).
  final int keyId;

  /// X25519 key pair (public + private).
  final KeyPair keyPair;

  /// Base64-encoded Ed25519 signature over the X25519 public key.
  final String signature;

  /// Timestamp when this key was generated.
  final DateTime createdAt;

  const SignedPreKey({
    required this.keyId,
    required this.keyPair,
    required this.signature,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
        'keyId': keyId,
        'keyPair': keyPair.toJson(),
        'signature': signature,
        'createdAt': createdAt.toIso8601String(),
      };

  factory SignedPreKey.fromJson(Map<String, dynamic> json) => SignedPreKey(
        keyId: json['keyId'] as int,
        keyPair: KeyPair.fromJson(json['keyPair'] as Map<String, dynamic>),
        signature: json['signature'] as String,
        createdAt: DateTime.parse(json['createdAt'] as String),
      );
}

/// Ephemeral one-time pre-key (consumed on first use).
///
/// Part of the X3DH protocol. Each one-time pre-key is used only once to
/// establish a session, then deleted. This provides **forward secrecy** for
/// the initial X3DH handshake: even if the long-term identity key is later
/// compromised, past sessions cannot be decrypted because the one-time pre-key
/// no longer exists.
///
/// Clients generate a batch (e.g., 100 keys) and upload the public portions
/// to the server. When Alice initiates a session with Bob, the server returns
/// one of Bob's one-time pre-keys and marks it as consumed. Bob deletes the
/// private key after processing the first message.
///
/// If all one-time pre-keys are exhausted, X3DH falls back to using only the
/// signed pre-key (slightly weaker forward secrecy).
///
/// See also:
///   - [SignalKeyHelper.generateOneTimePreKeys] for batch generation
///   - [PreKeyBundle.oneTimePreKey] for server-returned key
class OneTimePreKey {
  /// Unique identifier for this one-time pre-key.
  final int keyId;

  /// X25519 key pair (public + private).
  final KeyPair keyPair;

  const OneTimePreKey({required this.keyId, required this.keyPair});

  Map<String, dynamic> toJson() => {
        'keyId': keyId,
        'keyPair': keyPair.toJson(),
      };

  factory OneTimePreKey.fromJson(Map<String, dynamic> json) => OneTimePreKey(
        keyId: json['keyId'] as int,
        keyPair: KeyPair.fromJson(json['keyPair'] as Map<String, dynamic>),
      );
}

/// Kyber (ML-KEM-768) key pair for post-quantum key encapsulation.
///
/// Part of the PQXDH (Post-Quantum X3DH) hybrid protocol. Kyber is a
/// lattice-based KEM (Key Encapsulation Mechanism) standardized as ML-KEM
/// by NIST for post-quantum cryptography.
///
/// The hybrid approach combines X25519 (classical ECDH) with Kyber-768:
///   - If a future quantum computer breaks X25519, Kyber still protects the session
///   - If Kyber is cryptanalyzed, X25519 provides fallback security
///
/// Key sizes (after base64 decoding):
///   - Public key: 1184 bytes
///   - Private key: 2400 bytes
///   - Ciphertext: 1088 bytes (from encapsulation)
///   - Shared secret: 32 bytes
///
/// See also:
///   - [SignalKeyHelper.generateKyberKeyPair] for key generation
///   - [SignalKeyHelper.kyberEncapsulate] and [kyberDecapsulate] for KEM operations
class KyberKeyPair {
  /// Base64-encoded ML-KEM-768 public key (1184 bytes raw).
  final String publicKey;

  /// Base64-encoded ML-KEM-768 private key (2400 bytes raw).
  final String privateKey;

  const KyberKeyPair({required this.publicKey, required this.privateKey});

  Map<String, dynamic> toJson() => {
        'publicKey': publicKey,
        'privateKey': privateKey,
      };

  factory KyberKeyPair.fromJson(Map<String, dynamic> json) => KyberKeyPair(
        publicKey: json['publicKey'] as String,
        privateKey: json['privateKey'] as String,
      );
}

/// Public portion of a Kyber pre-key (no private key material).
///
/// Uploaded to the server and returned to session initiators as part of a
/// [PreKeyBundle]. The initiator uses this public key to encapsulate a shared
/// secret (producing a ciphertext), which the responder decapsulates using
/// their private Kyber key.
///
/// Only one Kyber pre-key is stored per device (rotated periodically), unlike
/// one-time pre-keys which are batched. If the private key is lost, the client
/// regenerates and re-uploads a new Kyber pre-key.
class KyberPreKeyPublic {
  /// Unique identifier for this Kyber pre-key (typically 0 for current key).
  final int keyId;

  /// Base64-encoded ML-KEM-768 public key.
  final String publicKey;

  const KyberPreKeyPublic({required this.keyId, required this.publicKey});

  Map<String, dynamic> toJson() => {
        'keyId': keyId,
        'publicKey': publicKey,
      };

  factory KyberPreKeyPublic.fromJson(Map<String, dynamic> json) =>
      KyberPreKeyPublic(
        keyId: json['keyId'] as int,
        publicKey: json['publicKey'] as String,
      );
}

/// Server-side bundle of a recipient's public keys (used by initiator).
///
/// Fetched from the server when Alice wants to send a message to Bob for the
/// first time. The bundle contains all the public key material needed to perform
/// X3DH (or PQXDH if Kyber is present) and establish a Double Ratchet session.
///
/// Key components:
///   - **identityKey**: Bob's long-term X25519 public key (for DH operations)
///   - **identitySigningKey**: Bob's Ed25519 public key (to verify signed pre-key)
///   - **signedPreKey**: Bob's current signed X25519 pre-key + signature
///   - **oneTimePreKey**: A single-use X25519 pre-key (consumed after X3DH)
///   - **kyberPreKey**: Bob's ML-KEM-768 public key (post-quantum component)
///
/// The server returns this bundle from the `/keys/{userId}/{deviceId}` endpoint.
/// After Alice uses the one-time pre-key, the server deletes it so no other
/// client can reuse it.
///
/// See also:
///   - [SignalProtocolManager.createSession] which consumes this bundle
///   - [SignalProtocolManager.generateKeyBundle] which produces the upload payload
class PreKeyBundle {
  /// The recipient's user ID.
  final String userId;

  /// The recipient's device ID (users can have multiple devices).
  final String deviceId;

  /// Base64-encoded X25519 public key (long-term identity for DH).
  final String identityKey;

  /// Base64-encoded Ed25519 public key (for signature verification).
  ///
  /// May be `null` for legacy clients that only use X25519.
  final String? identitySigningKey;

  /// The recipient's current signed pre-key (always present).
  final SignedPreKeyPublic signedPreKey;

  /// A one-time pre-key (consumed after use).
  ///
  /// `null` if the server has exhausted all one-time pre-keys for this device.
  final OneTimePreKeyPublic? oneTimePreKey;

  /// ML-KEM-768 public key for post-quantum protection.
  ///
  /// `null` if the recipient's device doesn't support Kyber (degrades to X25519-only).
  final KyberPreKeyPublic? kyberPreKey;

  const PreKeyBundle({
    required this.userId,
    required this.deviceId,
    required this.identityKey,
    this.identitySigningKey,
    required this.signedPreKey,
    this.oneTimePreKey,
    this.kyberPreKey,
  });

  Map<String, dynamic> toJson() => {
        'userId': userId,
        'deviceId': deviceId,
        'identityKey': identityKey,
        if (identitySigningKey != null)
          'identitySigningKey': identitySigningKey,
        'signedPreKey': signedPreKey.toJson(),
        if (oneTimePreKey != null) 'oneTimePreKey': oneTimePreKey!.toJson(),
        if (kyberPreKey != null) 'kyberPreKey': kyberPreKey!.toJson(),
      };

  factory PreKeyBundle.fromJson(Map<String, dynamic> json) => PreKeyBundle(
        userId: json['userId'] as String,
        deviceId: json['deviceId'] as String,
        identityKey: json['identityKey'] as String,
        identitySigningKey: json['identitySigningKey'] as String?,
        signedPreKey: SignedPreKeyPublic.fromJson(
          json['signedPreKey'] as Map<String, dynamic>,
        ),
        oneTimePreKey: json['oneTimePreKey'] != null
            ? OneTimePreKeyPublic.fromJson(
                json['oneTimePreKey'] as Map<String, dynamic>,
              )
            : null,
        kyberPreKey: json['kyberPreKey'] != null
            ? KyberPreKeyPublic.fromJson(
                json['kyberPreKey'] as Map<String, dynamic>,
              )
            : null,
      );

  /// Parse from the server's JSON response format.
  factory PreKeyBundle.fromServerJson(Map<String, dynamic> json) =>
      PreKeyBundle.fromJson(json);
}

/// Public portion of a signed pre-key (no private key material).
///
/// Uploaded to the server as part of the key bundle. Recipients download this
/// to verify the signature (proving the identity key owner endorsed this pre-key)
/// before performing X3DH.
///
/// The signature is computed over the X25519 public key using Ed25519:
/// ```
/// signature = Ed25519.sign(identitySigningPrivateKey, x25519PublicKey)
/// ```
///
/// See also:
///   - [SignedPreKey] for the full key pair with private material
class SignedPreKeyPublic {
  /// Unique identifier for this signed pre-key.
  final int keyId;

  /// Base64-encoded X25519 public key.
  final String publicKey;

  /// Base64-encoded Ed25519 signature over the public key.
  final String signature;

  const SignedPreKeyPublic({
    required this.keyId,
    required this.publicKey,
    required this.signature,
  });

  Map<String, dynamic> toJson() => {
        'keyId': keyId,
        'publicKey': publicKey,
        'signature': signature,
      };

  factory SignedPreKeyPublic.fromJson(Map<String, dynamic> json) =>
      SignedPreKeyPublic(
        keyId: json['keyId'] as int,
        publicKey: json['publicKey'] as String,
        signature: json['signature'] as String,
      );
}

/// Public portion of a one-time pre-key (no private key material).
///
/// Uploaded to the server in batches. When a session initiator fetches a
/// [PreKeyBundle], the server includes one of these keys and marks it as consumed
/// so it cannot be reused. After the responder processes the first message, they
/// delete the corresponding private key from local storage.
///
/// This ephemeral key provides forward secrecy for the X3DH handshake: even if
/// the long-term identity key is later compromised, the one-time pre-key is gone.
///
/// See also:
///   - [OneTimePreKey] for the full key pair with private material
class OneTimePreKeyPublic {
  /// Unique identifier for this one-time pre-key.
  final int keyId;

  /// Base64-encoded X25519 public key.
  final String publicKey;

  const OneTimePreKeyPublic({required this.keyId, required this.publicKey});

  Map<String, dynamic> toJson() => {
        'keyId': keyId,
        'publicKey': publicKey,
      };

  factory OneTimePreKeyPublic.fromJson(Map<String, dynamic> json) =>
      OneTimePreKeyPublic(
        keyId: json['keyId'] as int,
        publicKey: json['publicKey'] as String,
      );
}
