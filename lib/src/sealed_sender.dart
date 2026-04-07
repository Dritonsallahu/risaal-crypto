import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'secure_memory.dart';
import 'crypto_debug_logger.dart';
import 'key_helper.dart';
import 'models/signal_keys.dart';

/// Content extracted from an unsealed Sealed Sender envelope.
///
/// Contains the sender's identity (user ID, device ID, identity key) plus the
/// inner encrypted message envelope. The identity is hidden from the server
/// during transmission — only the recipient can discover it by unsealing the
/// outer encryption layer.
///
/// The [encryptedMessage] is still encrypted with the Double Ratchet and must
/// be decrypted via [SignalProtocolManager.decryptMessage].
///
/// See also:
///   - [SealedSenderEnvelope.unseal] which produces this result
class SealedSenderContent {
  /// The sender's user ID (UUID).
  ///
  /// Hidden from the server during transmission. Only discovered after unsealing.
  final String senderId;

  /// The sender's device ID (UUID).
  final String senderDeviceId;

  /// The sender's X25519 identity public key (base64).
  ///
  /// Used to verify the sender's identity against a stored key or display a
  /// safety number.
  final String senderIdentityKey;

  /// The inner encrypted message envelope (type `prekey` or `message`).
  ///
  /// This is still encrypted with the Double Ratchet. Pass it to
  /// [SignalProtocolManager.decryptMessage] to get the plaintext.
  final Map<String, dynamic> encryptedMessage;

  /// Timestamp from the sender certificate (Unix milliseconds).
  ///
  /// Used for replay protection. The unsealing process rejects messages with
  /// timestamps outside a 5-minute window (prevents old messages from being
  /// replayed by a network attacker).
  final int timestamp;

  const SealedSenderContent({
    required this.senderId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
    required this.encryptedMessage,
    required this.timestamp,
  });
}

/// Sealed Sender envelope — hides the sender identity from the server.
///
/// Provides **metadata protection** by encrypting the sender's identity in a
/// second encryption layer. The server can route the message to the recipient
/// but cannot determine who sent it (preventing server-side social graph analysis).
///
/// Two-layer encryption model:
///   1. **Inner layer**: Double Ratchet encryption (normal Signal message)
///   2. **Outer layer**: AES-256-GCM with ephemeral X25519 key exchange
///
/// The outer layer encrypts a "sender certificate" containing:
///   - Sender user ID and device ID
///   - Sender identity key
///   - Timestamp (for replay protection)
///   - The inner encrypted message
///
/// Only the recipient can unseal the outer layer (using their long-term identity
/// private key) to discover who sent the message.
///
/// Wire format (outer envelope):
/// ```json
/// {
///   "ephemeralPublicKey": "<base64 X25519 ephemeral public key>",
///   "ciphertext":         "<base64 AES-256-GCM(senderCert + innerMessage) + MAC>",
///   "nonce":              "<base64 12-byte GCM nonce>"
/// }
/// ```
///
/// Inner plaintext (encrypted in ciphertext):
/// ```json
/// {
///   "senderId":          "alice-uuid",
///   "senderDeviceId":    "device-uuid",
///   "senderIdentityKey": "<base64 X25519 public key>",
///   "timestamp":         1678901234567,
///   "message":           { <Double Ratchet envelope> }
/// }
/// ```
///
/// Replay protection:
///   - Messages with timestamps outside a 5-minute window are rejected
///   - Prevents attackers from replaying old sealed messages
///
/// Privacy trade-offs:
///   - Server cannot build social graph or correlate message patterns
///   - Slightly larger message size (ephemeral key + extra MAC)
///   - Server cannot enforce sender authentication (anyone with recipient's
///     identity key can send sealed messages claiming to be Alice)
///
/// See also:
///   - [SignalProtocolManager.encryptSealedSender] to create sealed messages
///   - [SignalProtocolManager.decryptSealedSender] to unseal and decrypt
class SealedSenderEnvelope {
  static const _info = 'Risaal_SealedSender';
  static final _x25519 = X25519();
  static final _hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
  static final _aesGcm = AesGcm.with256bits();

  // ── Seal (Sender Side) ───────────────────────────────────────────

  /// Seal a message with sender identity encryption (metadata protection).
  ///
  /// Encrypts the sender's identity ([senderId], [senderDeviceId], [senderIdentityKey])
  /// together with the already-encrypted [encryptedMessage] (from Double Ratchet)
  /// in an outer AES-256-GCM layer.
  ///
  /// Encryption process:
  ///   1. Generate ephemeral X25519 key pair for this message
  ///   2. Perform DH: `sharedSecret = DH(ephemeralPriv, recipientIdentityPub)`
  ///   3. Derive AES-GCM key via HKDF-SHA256 from the shared secret
  ///   4. Build sender certificate JSON (senderId, deviceId, identityKey, timestamp, message)
  ///   5. Encrypt certificate with AES-256-GCM
  ///   6. Return envelope with ephemeral public key + ciphertext + nonce
  ///
  /// The recipient can reverse this (using their identity private key and the
  /// ephemeral public key) to recover the sender certificate and inner message.
  ///
  /// A timestamp is included for replay protection. Messages older than 5 minutes
  /// are rejected during unseal.
  ///
  /// Parameters:
  ///   - [senderId]: Sender's user ID (UUID)
  ///   - [senderDeviceId]: Sender's device ID (UUID)
  ///   - [senderIdentityKey]: Sender's X25519 identity public key (base64)
  ///   - [encryptedMessage]: Inner encrypted message from [DoubleRatchet.encrypt]
  ///   - [recipientIdentityPublicKey]: Recipient's X25519 identity public key (base64)
  ///
  /// Returns a JSON map ready for wire transmission.
  static Future<Map<String, dynamic>> seal({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required Map<String, dynamic> encryptedMessage,
    required String recipientIdentityPublicKey,
  }) async {
    CryptoDebugLogger.log('SS_SEAL', 'Sealing: sender=$senderId device=$senderDeviceId');
    CryptoDebugLogger.logKeyInfo('SS_SEAL', 'Recipient identity key', recipientIdentityPublicKey);

    // 1. Generate an ephemeral X25519 key pair for this seal operation
    final ephemeralKP = await SignalKeyHelper.generateX25519KeyPair();
    CryptoDebugLogger.logKeyInfo('SS_SEAL', 'Ephemeral key', ephemeralKP.publicKey);

    // 2. Derive a shared secret: DH(ephemeral, recipientIdentityPub)
    final sharedSecret = await _deriveSharedKey(
      ephemeralKP,
      recipientIdentityPublicKey,
    );
    CryptoDebugLogger.log('SS_SEAL', 'Shared secret derived: ${sharedSecret.length} bytes');

    // 3. Build the sender certificate + message payload
    final sealedContent = jsonEncode({
      'senderId': senderId,
      'senderDeviceId': senderDeviceId,
      'senderIdentityKey': senderIdentityKey,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'message': encryptedMessage,
    });

    // 4. Encrypt the payload with AES-256-GCM
    final secretKey = SecretKey(sharedSecret);
    final secretBox = await _aesGcm.encrypt(
      utf8.encode(sealedContent),
      secretKey: secretKey,
    );

    // 5. Build the wire-format envelope
    return {
      'ephemeralPublicKey': ephemeralKP.publicKey,
      'ciphertext':
          base64Encode(secretBox.cipherText + secretBox.mac.bytes),
      'nonce': base64Encode(secretBox.nonce),
    };
  }

  // ── Unseal (Recipient Side) ──────────────────────────────────────

  /// Unseal a Sealed Sender envelope to discover the sender and inner message.
  ///
  /// Decrypts the outer AES-256-GCM layer to extract the sender certificate
  /// (sender identity) and the inner encrypted message.
  ///
  /// Unsealing process:
  ///   1. Extract ephemeral public key from envelope
  ///   2. Perform DH: `sharedSecret = DH(recipientIdentityPriv, ephemeralPub)`
  ///   3. Derive AES-GCM key via HKDF-SHA256 from the shared secret
  ///   4. Decrypt ciphertext to recover sender certificate JSON
  ///   5. Verify timestamp (reject if outside 5-minute window — replay protection)
  ///   6. Extract sender identity (user ID, device ID, identity key) and inner message
  ///
  /// The inner message is still encrypted with the Double Ratchet and must be
  /// decrypted separately via [SignalProtocolManager.decryptMessage].
  ///
  /// Returns [SealedSenderContent] containing the sender's identity and the
  /// inner encrypted message envelope.
  ///
  /// Throws:
  ///   - [StateError] if timestamp is outside allowed window (replay attack)
  ///   - [SecretBoxAuthenticationError] if MAC verification fails (wrong key / tampered)
  static Future<SealedSenderContent> unseal({
    required Map<String, dynamic> sealedEnvelope,
    required KeyPair recipientIdentityKeyPair,
  }) async {
    CryptoDebugLogger.log('SS_UNSEAL', 'Unsealing envelope...');
    final ephemeralPublicKey = sealedEnvelope['ephemeralPublicKey'] as String;
    final ciphertextB64 = sealedEnvelope['ciphertext'] as String;
    final nonceB64 = sealedEnvelope['nonce'] as String;
    CryptoDebugLogger.logKeyInfo('SS_UNSEAL', 'Ephemeral key from envelope', ephemeralPublicKey);
    CryptoDebugLogger.logKeyInfo('SS_UNSEAL', 'Our identity key', recipientIdentityKeyPair.publicKey);

    // 1. Derive the shared secret: DH(recipientIdentityPriv, ephemeralPub)
    final sharedSecret = await _deriveSharedKey(
      recipientIdentityKeyPair,
      ephemeralPublicKey,
    );
    CryptoDebugLogger.log('SS_UNSEAL', 'Shared secret derived: ${sharedSecret.length} bytes');

    // 2. Decrypt the AES-256-GCM ciphertext
    final combined = base64Decode(ciphertextB64);
    final nonce = base64Decode(nonceB64);
    CryptoDebugLogger.log('SS_UNSEAL', 'Ciphertext: ${combined.length} bytes, nonce: ${nonce.length} bytes');

    // Last 16 bytes are the GCM MAC tag
    final ciphertext = combined.sublist(0, combined.length - 16);
    final mac = Mac(combined.sublist(combined.length - 16));

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
    final secretKey = SecretKey(sharedSecret);

    final plainBytes = await _aesGcm.decrypt(secretBox, secretKey: secretKey);
    final payload = jsonDecode(utf8.decode(plainBytes)) as Map<String, dynamic>;

    CryptoDebugLogger.log('SS_UNSEAL', 'Unsealed payload: senderId=${payload['senderId']} deviceId=${payload['senderDeviceId']} innerType=${(payload['message'] as Map?)?['type']}');

    // 3. Replay protection — reject messages outside a 5-minute window
    final timestamp = payload['timestamp'] as int;
    final now = DateTime.now().millisecondsSinceEpoch;
    const maxDriftMs = 5 * 60 * 1000; // 5 minutes
    if ((now - timestamp).abs() > maxDriftMs) {
      throw StateError(
        'Sealed sender timestamp outside allowed window '
        '(drift=${((now - timestamp) / 1000).round()}s)',
      );
    }

    // 4. Extract the sender certificate and message
    return SealedSenderContent(
      senderId: payload['senderId'] as String,
      senderDeviceId: payload['senderDeviceId'] as String,
      senderIdentityKey: payload['senderIdentityKey'] as String,
      timestamp: payload['timestamp'] as int,
      encryptedMessage: payload['message'] as Map<String, dynamic>,
    );
  }

  // ── Private Helpers ──────────────────────────────────────────────

  /// Perform X25519 DH + HKDF to derive a 32-byte symmetric key.
  static Future<List<int>> _deriveSharedKey(
    KeyPair localKeyPair,
    String remotePublicKeyBase64,
  ) async {
    final privateBytes = base64Decode(localKeyPair.privateKey);
    final publicBytes = base64Decode(localKeyPair.publicKey);
    final remoteBytes = base64Decode(remotePublicKeyBase64);

    final kp = SimpleKeyPairData(
      privateBytes,
      publicKey: SimplePublicKey(publicBytes, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
    final remotePub = SimplePublicKey(remoteBytes, type: KeyPairType.x25519);

    final rawSecret = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: remotePub,
    );
    final rawBytes = await rawSecret.extractBytes();

    // HKDF to derive the final symmetric key
    final derived = await _hkdf.deriveKey(
      secretKey: SecretKey(rawBytes),
      info: _info.codeUnits,
      nonce: Uint8List(32), // 32-byte zero salt
    );
    final result = await derived.extractBytes();

    // Zero raw DH secret — no longer needed after HKDF derivation
    SecureMemory.zeroBytes(rawBytes);

    return result;
  }
}
