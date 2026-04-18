import 'dart:convert';

import 'crypto_secure_storage.dart';
import 'crypto_debug_logger.dart';
import 'crypto_storage.dart';
import 'double_ratchet.dart';
import 'key_helper.dart';
import 'message_padding.dart';
import 'models/signal_keys.dart';
import 'safety_number.dart';
import 'sealed_sender.dart';
import 'sender_key.dart';
import 'security_event_bus.dart';
import 'session_reset_errors.dart';
import 'x3dh.dart';

/// Result of decrypting a Sealed Sender (type 3) message.
class SealedSenderResult {
  /// The sender's user ID (discovered from the sealed envelope).
  final String senderId;

  /// The sender's device ID.
  final String senderDeviceId;

  /// The decrypted plaintext message.
  final String plaintext;

  const SealedSenderResult({
    required this.senderId,
    required this.senderDeviceId,
    required this.plaintext,
  });
}

/// High-level API for the Signal Protocol layer.
///
/// This is the main interface between the app and the crypto layer. All
/// cryptographic operations (session establishment, encryption, decryption,
/// key management) go through this class.
///
/// Responsibilities:
///   - **Key generation**: Identity keys, pre-keys, Kyber keys (post-quantum)
///   - **Session management**: X3DH handshake, session storage, session deletion
///   - **Message encryption**: Double Ratchet for 1-to-1, Sender Keys for groups
///   - **Metadata protection**: Sealed Sender (hides sender from server)
///   - **Safety numbers**: Fingerprint verification for identity keys
///
/// Lifecycle:
///   1. Call [initialize] once on app startup to generate/load identity keys
///   2. Upload the key bundle ([generateKeyBundle]) to the server
///   3. To send a message: fetch recipient's bundle, call [createSession], then [encryptMessage]
///   4. To receive a message: call [decryptMessage] (auto-establishes session if needed)
///
/// Sessions are cached in memory and persisted to [CryptoSecureStorage] after
/// every operation. The cache is cleared on panic wipe.
///
/// Example:
/// ```dart
/// final manager = SignalProtocolManager(secureStorage: storage);
///
/// // First run: generate keys
/// final isNewInstall = await manager.initialize();
/// if (isNewInstall) {
///   final bundle = await manager.generateKeyBundle();
///   await uploadKeysToServer(bundle);
/// }
///
/// // Send first message to Alice
/// final aliceBundle = await fetchBundleFromServer('alice-id', 'device-1');
/// await manager.createSession(aliceBundle);
/// final encrypted = await manager.encryptMessage('alice-id', 'device-1', 'Hello!');
/// await sendToServer(encrypted);
/// ```
///
/// See also:
///   - [DoubleRatchet] for the encryption algorithm
///   - [X3DH] for the key agreement protocol
///   - [SealedSenderEnvelope] for metadata protection
class SignalProtocolManager {
  final CryptoStorage _cryptoStorage;
  final CryptoSecureStorage _secureStorage;

  /// Stream-based security event bus for observability.
  ///
  /// If provided, security-relevant events (session resets, key rotations,
  /// exhaustion warnings, etc.) are emitted here. The host app can subscribe
  /// via `bus.events.listen(...)` to drive UI or telemetry.
  final SecurityEventBus? _eventBus;

  /// In-memory nonce deduplication set for Sealed Sender replay protection.
  Set<String> _seenNonces = {};

  /// In-memory session cache: "recipientId:deviceId" → DoubleRatchet.
  final Map<String, DoubleRatchet> _sessions = {};

  /// Clear all in-memory sessions. Called on panic wipe to prevent
  /// forensic recovery of ratchet state from the Dart heap.
  void wipeAllSessions() {
    _sessions.clear();
  }

  /// Sender Key manager for group E2EE.
  late final SenderKeyManager _senderKeyManager;

  /// Optional callback invoked when pre-key replenishment is needed
  /// (e.g. after a session reset consumes an OTP).
  void Function()? _onPreKeyReplenishmentNeeded;

  /// Set the pre-key replenishment callback.
  set onPreKeyReplenishmentNeeded(void Function()? callback) {
    _onPreKeyReplenishmentNeeded = callback;
  }

  /// Optional callback invoked when the one-time pre-key count drops
  /// below the exhaustion threshold.
  void Function(int remaining)? _onPreKeyExhaustionWarning;

  /// Set the pre-key exhaustion warning callback.
  set onPreKeyExhaustionWarning(void Function(int remaining)? callback) {
    _onPreKeyExhaustionWarning = callback;
  }

  /// Default signed pre-key rotation interval: 7 days.
  static const Duration defaultSignedPreKeyMaxAge = Duration(days: 7);

  /// Default Kyber key rotation interval: 7 days (alongside signed pre-key).
  static const Duration defaultKyberKeyMaxAge = Duration(days: 7);

  /// Absolute maximum key lifetime. Keys older than this are rejected outright
  /// and force-rotated. This is a hard safety net above the rotation interval.
  static const Duration absoluteMaxKeyLifetime = Duration(days: 30);

  /// Duration to keep old keys after rotation so in-flight sessions that
  /// reference the previous key ID can still complete.
  static const Duration keyOverlapWindow = Duration(hours: 48);

  /// Default OTP low-watermark threshold. When the pool drops to or below
  /// this count, [SecurityEventType.otpPoolLow] is emitted.
  static const int defaultOtpLowWatermark = 25;

  /// Number of one-time pre-keys to auto-generate when pool is low.
  static const int otpReplenishBatchSize = 100;

  /// Grace period for key expiry checks to tolerate device clock drift.
  /// If a key appears expired by less than this amount, it's still treated
  /// as valid. This prevents false expirations on devices with slightly
  /// fast clocks.
  static const Duration clockDriftGracePeriod = Duration(hours: 1);

  SignalProtocolManager({
    required CryptoSecureStorage secureStorage,
    SecurityEventBus? securityEventBus,
  })  : _cryptoStorage = CryptoStorage(secureStorage: secureStorage),
        _secureStorage = secureStorage,
        _eventBus = securityEventBus {
    _senderKeyManager = SenderKeyManager(cryptoStorage: _cryptoStorage);
  }

  // ── Initialise ────────────────────────────────────────────────────

  /// Load or generate the local identity key pairs.
  ///
  /// Call this once during app startup before any crypto operations. If keys
  /// already exist (loaded from [CryptoSecureStorage]), they are loaded into
  /// memory. If this is the first run (or after a panic wipe), new keys are
  /// generated:
  ///
  ///   - X25519 identity key pair (DH for X3DH and Sealed Sender)
  ///   - Ed25519 signing key pair (for signed pre-key signatures)
  ///   - Signed pre-key (X25519, signed with Ed25519)
  ///   - 20 one-time pre-keys (X25519, ephemeral)
  ///   - Kyber-768 key pair (post-quantum, optional — skipped if FFI unavailable)
  ///
  /// Returns `true` if keys were freshly generated, meaning the app must upload
  /// the key bundle to the server via [generateKeyBundle]. Returns `false` if
  /// keys were loaded from storage (no server upload needed).
  ///
  /// This method is idempotent — calling it multiple times is safe (subsequent
  /// calls load existing keys).
  ///
  /// Example:
  /// ```dart
  /// final isNewInstall = await manager.initialize();
  /// if (isNewInstall) {
  ///   final bundle = await manager.generateKeyBundle();
  ///   await api.uploadKeys(bundle);
  /// }
  /// ```
  Future<bool> initialize() async {
    // Warn if storage backend is insecure
    if (_secureStorage.securityLevel == StorageSecurityLevel.insecure) {
      _eventBus?.emitType(SecurityEventType.insecureStorageWarning);
      CryptoDebugLogger.log(
        'SECURITY',
        'WARNING: Insecure storage backend detected',
      );
    }

    final existing = await _cryptoStorage.getIdentityKeyPair();
    if (existing != null) {
      CryptoDebugLogger.log('INIT', 'Identity key pair already exists');
      CryptoDebugLogger.logKeyInfo(
        'INIT',
        'Identity public key',
        existing.publicKey,
      );
      _seenNonces = await _cryptoStorage.loadSeenNonces();
      return false;
    }

    CryptoDebugLogger.log('INIT', '═══ First run — generating all keys ═══');

    // First run — generate identity keys (X25519 for DH + Ed25519 for signing)
    final identityKP = await SignalKeyHelper.generateIdentityKeyPair();
    await _cryptoStorage.saveIdentityKeyPair(identityKP);
    CryptoDebugLogger.logKeyInfo(
      'INIT',
      'Generated X25519 identity key',
      identityKP.publicKey,
    );

    final signingKP = await SignalKeyHelper.generateSigningKeyPair();
    await _cryptoStorage.saveSigningKeyPair(signingKP);
    CryptoDebugLogger.logKeyInfo(
      'INIT',
      'Generated Ed25519 signing key',
      signingKP.publicKey,
    );

    final signedPreKey = await SignalKeyHelper.generateSignedPreKey(
      0,
      signingKP, // Sign with Ed25519 signing key
    );
    await _cryptoStorage.saveSignedPreKey(signedPreKey);
    await _cryptoStorage.saveSignedPreKeyCreatedAt(
      DateTime.now().millisecondsSinceEpoch,
    );
    CryptoDebugLogger.logKeyInfo(
      'INIT',
      'Generated signed pre-key',
      signedPreKey.keyPair.publicKey,
    );

    final oneTimePreKeys = await SignalKeyHelper.generateOneTimePreKeys(0, 20);
    await _cryptoStorage.saveOneTimePreKeys(oneTimePreKeys);
    await _cryptoStorage.setNextPreKeyId(20);
    CryptoDebugLogger.log(
      'INIT',
      'Generated ${oneTimePreKeys.length} one-time pre-keys',
    );

    // Kyber (ML-KEM-768) — post-quantum key encapsulation
    // Wrapped in try/catch: if the pqcrypto FFI fails on this platform,
    // we degrade to pure X25519 (no post-quantum protection).
    try {
      final kyberKP = SignalKeyHelper.generateKyberKeyPair();
      await _cryptoStorage.saveKyberKeyPair(kyberKP);
      await _cryptoStorage.saveKyberCreatedAt(
        DateTime.now().millisecondsSinceEpoch,
      );
      CryptoDebugLogger.logKeyInfo(
        'INIT',
        'Generated Kyber-768 public key',
        kyberKP.publicKey,
      );
    } catch (e) {
      CryptoDebugLogger.logError(
        'INIT',
        'Kyber key generation failed — skipping post-quantum',
        e,
      );
    }

    CryptoDebugLogger.log('INIT', '═══ Key generation complete ═══');
    return true;
  }

  // ── Key Bundle for Server Upload ──────────────────────────────────

  /// Build the public key bundle for server upload.
  ///
  /// Generates a JSON map containing all public key material needed for other
  /// users to initiate sessions with this device. The bundle includes:
  ///
  ///   - `identityKey`: X25519 public key (long-term)
  ///   - `identitySigningKey`: Ed25519 public key (for signature verification)
  ///   - `signedPreKey`: Current signed pre-key (public + signature + keyId)
  ///   - `oneTimePreKeys`: Array of one-time pre-key public portions
  ///   - `kyberPreKey`: ML-KEM-768 public key (post-quantum, if available)
  ///
  /// Upload this to the server's `/keys` endpoint after calling [initialize].
  /// The server stores the bundle and returns it to session initiators.
  ///
  /// Call this method again when:
  ///   - One-time pre-keys are exhausted (server notifies or returns empty list)
  ///   - Signed pre-key needs rotation (e.g., weekly)
  ///   - Device reinstall (after panic wipe)
  ///
  /// Returns a JSON-serializable map ready for HTTP POST.
  Future<Map<String, dynamic>> generateKeyBundle() async {
    final identityKP = await _requireIdentityKeyPair();
    final signingKP = await _cryptoStorage.getSigningKeyPair();
    final signedPreKey = await _cryptoStorage.getSignedPreKey();
    final oneTimePreKeys = await _cryptoStorage.getOneTimePreKeys();

    if (signedPreKey == null) {
      throw StateError('Signed pre-key not found. Call initialize() first.');
    }

    final kyberKP = await _cryptoStorage.getKyberKeyPair();

    if (signingKP == null) {
      throw StateError(
        'Signing key pair not found. Call initialize() first. '
        'The Ed25519 signing key is required for all key bundles.',
      );
    }

    final createdAtMs = await _cryptoStorage.getSignedPreKeyCreatedAt();

    return {
      'identityKey': identityKP.publicKey, // X25519 DH public key
      'identitySigningKey': signingKP.publicKey, // Ed25519 signing public key
      'signedPreKey': {
        'keyId': signedPreKey.keyId,
        'publicKey': signedPreKey.keyPair.publicKey,
        'signature': signedPreKey.signature,
      },
      'oneTimePreKeys': oneTimePreKeys
          .map((k) => {'keyId': k.keyId, 'publicKey': k.keyPair.publicKey})
          .toList(),
      if (kyberKP != null)
        'kyberPreKey': {'keyId': 0, 'publicKey': kyberKP.publicKey},
      'createdAt': createdAtMs ?? DateTime.now().millisecondsSinceEpoch,
    };
  }

  // ── Session Creation (Initiator / Alice) ──────────────────────────

  /// Establish a new session with a remote user (X3DH initiator / Alice role).
  ///
  /// Performs the X3DH key agreement using the recipient's [PreKeyBundle]
  /// (fetched from the server) and the local identity key. Derives a shared
  /// secret via multiple Diffie-Hellman operations:
  ///
  ///   1. `DH(localIdentity, recipientSignedPreKey)`
  ///   2. `DH(localEphemeral, recipientIdentity)`
  ///   3. `DH(localEphemeral, recipientSignedPreKey)`
  ///   4. `DH(localEphemeral, recipientOneTimePreKey)` — if available
  ///   5. `Kyber.Encapsulate(recipientKyberKey)` — if available (PQXDH)
  ///
  /// The shared secret initializes a Double Ratchet in **sender mode**. The
  /// session is persisted to storage and cached in memory. Pending pre-key
  /// info is saved so the first outgoing message includes X3DH handshake data.
  ///
  /// After calling this, use [encryptMessage] to send messages. The first
  /// encrypted message will be type `prekey` and include X3DH metadata
  /// (ephemeral key, used OTP ID, Kyber ciphertext).
  ///
  /// This method does NOT contact the server — the caller must fetch the
  /// [PreKeyBundle] separately and pass it in.
  ///
  /// Throws [StateError] if [initialize] hasn't been called yet.
  ///
  /// Example:
  /// ```dart
  /// final bundle = await api.fetchBundle('bob-id', 'device-1');
  /// await manager.createSession(PreKeyBundle.fromJson(bundle));
  /// final encrypted = await manager.encryptMessage('bob-id', 'device-1', 'Hi Bob!');
  /// ```
  Future<void> createSession(
    PreKeyBundle recipientBundle, {
    PqxdhPolicy pqxdhPolicy = PqxdhPolicy.preferPq,
  }) async {
    CryptoDebugLogger.log('X3DH', '═══ Creating session (initiator/Alice) ═══');
    CryptoDebugLogger.log(
      'X3DH',
      'Recipient: ${recipientBundle.userId}:${recipientBundle.deviceId}',
    );
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Our identity key',
      (await _requireIdentityKeyPair()).publicKey,
    );
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Recipient identity key',
      recipientBundle.identityKey,
    );
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Recipient signed pre-key',
      recipientBundle.signedPreKey.publicKey,
    );
    if (recipientBundle.oneTimePreKey != null) {
      CryptoDebugLogger.logKeyInfo(
        'X3DH',
        'Recipient OTP key (id=${recipientBundle.oneTimePreKey!.keyId})',
        recipientBundle.oneTimePreKey!.publicKey,
      );
    }

    final identityKP = await _requireIdentityKeyPair();

    // ── Anti-downgrade check ──────────────────────────────────────
    // If we previously established a PQXDH session with this peer but
    // their new bundle lacks a Kyber key, that's a potential downgrade
    // attack (MITM stripping the post-quantum layer).
    final bundleHasPqxdh = recipientBundle.kyberPreKey != null;
    final previousCap = await _cryptoStorage.getPeerPqxdhCapability(
      recipientBundle.userId,
      recipientBundle.deviceId,
    );
    if (previousCap == true &&
        !bundleHasPqxdh &&
        pqxdhPolicy != PqxdhPolicy.classicalOnly) {
      CryptoDebugLogger.log(
        'X3DH',
        'BLOCKED: Anti-downgrade — peer previously supported PQXDH '
            'but new bundle has no Kyber key. Session refused.',
      );
      _eventBus?.emitType(
        SecurityEventType.antiDowngradeTriggered,
        sessionId: _sessionKey(
          recipientBundle.userId,
          recipientBundle.deviceId,
        ),
        metadata: {
          'previousPqxdh': true,
          'currentPqxdh': false,
          'reason': 'Peer Kyber key missing from new bundle',
          'action': 'session_refused',
        },
      );
      throw PqxdhDowngradeError(
        userId: recipientBundle.userId,
        deviceId: recipientBundle.deviceId,
      );
    }

    // ── First-session Kyber awareness ────────────────────────────────
    if (previousCap == null && !bundleHasPqxdh) {
      if (pqxdhPolicy == PqxdhPolicy.requirePq) {
        CryptoDebugLogger.log(
          'X3DH',
          'BLOCKED: requirePq policy — first-contact bundle has no Kyber key.',
        );
        _eventBus?.emitType(
          SecurityEventType.firstSessionNoPqxdh,
          sessionId:
              _sessionKey(recipientBundle.userId, recipientBundle.deviceId),
          metadata: {'policy': 'requirePq', 'action': 'session_refused'},
        );
        throw PqxdhDowngradeError(
          userId: recipientBundle.userId,
          deviceId: recipientBundle.deviceId,
        );
      } else if (pqxdhPolicy == PqxdhPolicy.preferPq) {
        CryptoDebugLogger.log(
          'X3DH',
          'WARNING: First-contact bundle has no Kyber key. Proceeding without post-quantum protection.',
        );
        _eventBus?.emitType(
          SecurityEventType.firstSessionNoPqxdh,
          sessionId:
              _sessionKey(recipientBundle.userId, recipientBundle.deviceId),
          metadata: {'policy': 'preferPq', 'action': 'proceeding_without_pq'},
        );
      }
    }

    // ── Peer identity key change detection ───────────────────────
    // If we previously stored a peer's identity key and it changed,
    // this means the peer reinstalled, switched devices, or a MITM
    // is presenting a different key. Emit event so the app can warn.
    final previousPeerKey = await _cryptoStorage.getPeerIdentityKey(
      recipientBundle.userId,
      recipientBundle.deviceId,
    );
    if (previousPeerKey != null &&
        previousPeerKey != recipientBundle.identityKey) {
      _eventBus?.emitType(
        SecurityEventType.peerIdentityKeyChanged,
        sessionId: _sessionKey(
          recipientBundle.userId,
          recipientBundle.deviceId,
        ),
        metadata: {
          'reason': 'Identity key differs from stored key. '
              'Peer may have reinstalled or this may be a MITM attack.',
        },
      );
    }

    final X3DHResult x3dhResult;
    try {
      x3dhResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: identityKP,
        recipientBundle: recipientBundle,
        pqxdhPolicy: pqxdhPolicy,
      );
    } catch (e) {
      if (e.toString().contains('signature verification failed')) {
        _eventBus?.emitType(
          SecurityEventType.signatureVerificationFailed,
          sessionId: _sessionKey(
            recipientBundle.userId,
            recipientBundle.deviceId,
          ),
          metadata: {'source': 'x3dh', 'reason': 'signed_pre_key'},
        );
      }
      rethrow;
    }

    // Record peer's current PQXDH capability for future downgrade checks
    await _cryptoStorage.savePeerPqxdhCapability(
      recipientBundle.userId,
      recipientBundle.deviceId,
      x3dhResult.pqxdhUsed,
    );

    // Store the peer's identity key for future change detection
    await _cryptoStorage.savePeerIdentityKey(
      recipientBundle.userId,
      recipientBundle.deviceId,
      recipientBundle.identityKey,
    );

    CryptoDebugLogger.log(
      'X3DH',
      'Shared secret derived: ${x3dhResult.sharedSecret.length} bytes '
          '(pqxdhUsed=${x3dhResult.pqxdhUsed})',
    );
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Ephemeral public key',
      x3dhResult.ephemeralPublicKey,
    );
    CryptoDebugLogger.log(
      'X3DH',
      'Used OTP key ID: ${x3dhResult.usedOneTimePreKeyId}',
    );

    final ratchet = await DoubleRatchet.initSender(
      sharedSecret: x3dhResult.sharedSecret,
      recipientPublicKey: recipientBundle.signedPreKey.publicKey,
    );

    CryptoDebugLogger.logRatchetState(
      'X3DH',
      'Initial sender ratchet',
      ratchet.state.toJson(),
    );

    final sessionKey = _sessionKey(
      recipientBundle.userId,
      recipientBundle.deviceId,
    );
    _sessions[sessionKey] = ratchet;

    await _cryptoStorage.saveSession(
      recipientBundle.userId,
      recipientBundle.deviceId,
      ratchet.state,
    );
    await _cryptoStorage.saveSessionIdentityKey(
      recipientBundle.userId,
      recipientBundle.deviceId,
      recipientBundle.identityKey,
    );
    await _cryptoStorage.trackSessionDevice(
      recipientBundle.userId,
      recipientBundle.deviceId,
    );

    // Save prekey info so the first message includes X3DH handshake data
    await _cryptoStorage.savePendingPreKeyInfo(
      recipientBundle.userId,
      recipientBundle.deviceId,
      x3dhResult.ephemeralPublicKey,
      x3dhResult.usedOneTimePreKeyId,
      kyberCiphertext: x3dhResult.kyberCiphertext,
    );
    if (x3dhResult.kyberCiphertext != null) {
      CryptoDebugLogger.log(
        'X3DH',
        'PQXDH: Kyber ciphertext included in pending prekey info',
      );
    }
    CryptoDebugLogger.log('X3DH', '═══ Session created (initiator) ═══');
  }

  // ── Process Incoming PreKeyMessage (Responder / Bob) ──────────────

  /// Process the first message from a new sender (X3DH responder / Bob role).
  ///
  /// Called when receiving a message with `type: 'prekey'`. Performs the X3DH
  /// key agreement from the responder side using:
  ///   - Local identity key pair
  ///   - Local signed pre-key (referenced by the sender)
  ///   - Local one-time pre-key (if sender used one — then deleted after use)
  ///   - Sender's identity key (from the message)
  ///   - Sender's ephemeral key (from the message)
  ///   - Kyber ciphertext (if present — decapsulated with local Kyber private key)
  ///
  /// Derives the same shared secret as the initiator (Alice) and initializes
  /// a Double Ratchet in **receiver mode**. The session is persisted to storage.
  ///
  /// After establishing the session, this method decrypts the first message
  /// (embedded in the PreKey envelope) and returns the plaintext.
  ///
  /// The consumed one-time pre-key is deleted from storage to prevent reuse
  /// (forward secrecy). If the one-time pre-key is missing, X3DH falls back
  /// to using only the signed pre-key.
  ///
  /// Throws [StateError] if the signed pre-key is missing or if decryption fails.
  ///
  /// Returns the decrypted plaintext string.
  Future<String> processPreKeyMessage({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required String senderEphemeralKey,
    required int? usedOneTimePreKeyId,
    required Map<String, dynamic> encryptedMessage,
    String? kyberCiphertext,
  }) async {
    CryptoDebugLogger.log(
      'X3DH',
      '═══ Processing PreKey message (responder/Bob) ═══',
    );
    CryptoDebugLogger.log('X3DH', 'From: $senderId:$senderDeviceId');
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Sender identity key',
      senderIdentityKey,
    );
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Sender ephemeral key',
      senderEphemeralKey,
    );
    CryptoDebugLogger.log('X3DH', 'Used OTP key ID: $usedOneTimePreKeyId');

    final identityKP = await _requireIdentityKeyPair();
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Our identity key',
      identityKP.publicKey,
    );

    final signedPreKey = await _cryptoStorage.getSignedPreKey();

    if (signedPreKey == null) {
      throw StateError('Signed pre-key not found. Call initialize() first.');
    }
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Our signed pre-key',
      signedPreKey.keyPair.publicKey,
    );

    // Look up the one-time pre-key if one was consumed
    OneTimePreKey? oneTimePreKey;
    if (usedOneTimePreKeyId != null) {
      final allOTPKs = await _cryptoStorage.getOneTimePreKeys();
      CryptoDebugLogger.log(
        'X3DH',
        'Available OTP keys: ${allOTPKs.map((k) => k.keyId).toList()}',
      );
      oneTimePreKey =
          allOTPKs.where((k) => k.keyId == usedOneTimePreKeyId).firstOrNull;
      CryptoDebugLogger.log(
        'X3DH',
        'OTP key $usedOneTimePreKeyId: ${oneTimePreKey != null ? "FOUND" : "NOT FOUND"}',
      );
    }

    // Load Kyber key pair for PQXDH (if we have one and sender included ciphertext)
    KyberKeyPair? kyberKP;
    if (kyberCiphertext != null) {
      kyberKP = await _cryptoStorage.getKyberKeyPair();
      if (kyberKP != null) {
        CryptoDebugLogger.log(
          'X3DH',
          'PQXDH: Kyber ciphertext present — will decapsulate',
        );
      }
    }

    // PQXDH responder (X3DH + Kyber hybrid)
    final sharedSecret = await X3DH.respondKeyAgreement(
      identityKeyPair: identityKP,
      signedPreKey: signedPreKey,
      oneTimePreKey: oneTimePreKey,
      senderIdentityKey: senderIdentityKey,
      senderEphemeralKey: senderEphemeralKey,
      kyberKeyPair: kyberKP,
      kyberCiphertext: kyberCiphertext,
    );

    CryptoDebugLogger.log(
      'X3DH',
      'Shared secret derived (responder${kyberKP != null ? ", PQXDH" : ""}): ${sharedSecret.length} bytes',
    );

    // Record peer's PQXDH capability (whether they sent Kyber ciphertext)
    await _cryptoStorage.savePeerPqxdhCapability(
      senderId,
      senderDeviceId,
      kyberCiphertext != null && kyberKP != null,
    );

    // Remove the consumed one-time pre-key
    if (usedOneTimePreKeyId != null) {
      await _cryptoStorage.removeOneTimePreKey(usedOneTimePreKeyId);
      CryptoDebugLogger.log(
        'X3DH',
        'Removed consumed OTP key $usedOneTimePreKeyId',
      );
      // Check if OTPs are running low and fire exhaustion callback
      await _checkPreKeyExhaustion();
    }

    // Initialise ratchet as receiver
    final ratchet = await DoubleRatchet.initReceiver(
      sharedSecret: sharedSecret,
      dhKeyPair: signedPreKey.keyPair,
    );

    CryptoDebugLogger.logRatchetState(
      'X3DH',
      'Initial receiver ratchet',
      ratchet.state.toJson(),
    );

    final sessionKey = _sessionKey(senderId, senderDeviceId);
    _sessions[sessionKey] = ratchet;

    // Clear any stale pendingPreKeyInfo from a prior initiator session
    // with this user/device. If we had created an initiator session first
    // (both sides opened the chat) and then received their PreKey message,
    // the old pending info would incorrectly tag our next outgoing message
    // as a PreKey message with wrong X3DH handshake data.
    await _cryptoStorage.clearPendingPreKeyInfo(senderId, senderDeviceId);

    // Decrypt the first message
    final message = EncryptedMessage.fromJson(encryptedMessage);
    CryptoDebugLogger.log(
      'RATCHET',
      'Decrypting first PreKey message: msgNum=${message.messageNumber} prevChain=${message.previousChainLength}',
    );
    CryptoDebugLogger.logKeyInfo(
      'RATCHET',
      'Message DH public key',
      message.dhPublicKey,
    );
    final plainBytes = await ratchet.decrypt(message);

    CryptoDebugLogger.logRatchetState(
      'X3DH',
      'Ratchet after first decrypt',
      ratchet.state.toJson(),
    );

    // Persist the session after decryption advances the ratchet
    await _cryptoStorage.saveSession(senderId, senderDeviceId, ratchet.state);
    await _cryptoStorage.saveSessionIdentityKey(
      senderId,
      senderDeviceId,
      senderIdentityKey,
    );
    await _cryptoStorage.trackSessionDevice(senderId, senderDeviceId);

    CryptoDebugLogger.log(
      'X3DH',
      '═══ PreKey message processed successfully ═══',
    );
    return MessagePadding.unpadString(plainBytes);
  }

  // ── Encrypt ───────────────────────────────────────────────────────

  /// Encrypt a message for a recipient with an existing session.
  ///
  /// Uses the Double Ratchet to encrypt [plaintext] for the session identified
  /// by `recipientId:recipientDeviceId`. The plaintext is padded to a fixed
  /// bucket size (256B, 1KB, 4KB, etc.) to hide message length.
  ///
  /// Returns a wire-format envelope ready for transmission:
  ///   - **Type 1 (prekey)**: First message after [createSession]. Includes
  ///     X3DH handshake data (ephemeral key, used OTP ID, Kyber ciphertext).
  ///   - **Type 2 (message)**: Subsequent messages. Only contains the ratchet
  ///     ciphertext and sender's identity key.
  ///
  /// Envelope structure (type 1):
  /// ```json
  /// {
  ///   "type": "prekey",
  ///   "senderIdentityKey": "<base64>",
  ///   "senderEphemeralKey": "<base64>",
  ///   "usedOneTimePreKeyId": 42,
  ///   "kyberCiphertext": "<base64>",  // optional (PQXDH)
  ///   "message": { <EncryptedMessage> }
  /// }
  /// ```
  ///
  /// Envelope structure (type 2):
  /// ```json
  /// {
  ///   "type": "message",
  ///   "senderIdentityKey": "<base64>",
  ///   "message": { <EncryptedMessage> }
  /// }
  /// ```
  ///
  /// The session state is advanced (chain key ratchets forward) and persisted
  /// to storage after encryption.
  ///
  /// Throws [StateError] if no session exists for this recipient. Call
  /// [createSession] first or wait for the recipient to send a PreKey message.
  Future<Map<String, dynamic>> encryptMessage(
    String recipientId,
    String recipientDeviceId,
    String plaintext,
  ) async {
    CryptoDebugLogger.log(
      'ENCRYPT',
      'encryptMessage for $recipientId:$recipientDeviceId',
    );
    final ratchet = await _loadSession(recipientId, recipientDeviceId);
    CryptoDebugLogger.logRatchetState(
      'ENCRYPT',
      'Ratchet BEFORE encrypt',
      ratchet.state.toJson(),
    );
    final encrypted = await ratchet.encrypt(
      MessagePadding.padString(plaintext),
    );
    CryptoDebugLogger.log(
      'ENCRYPT',
      'Encrypted: msgNum=${encrypted.messageNumber} prevChain=${encrypted.previousChainLength}',
    );
    CryptoDebugLogger.logKeyInfo(
      'ENCRYPT',
      'DH public key in msg',
      encrypted.dhPublicKey,
    );
    CryptoDebugLogger.logRatchetState(
      'ENCRYPT',
      'Ratchet AFTER encrypt',
      ratchet.state.toJson(),
    );

    // Persist the updated ratchet state
    await _cryptoStorage.saveSession(
      recipientId,
      recipientDeviceId,
      ratchet.state,
    );

    final identityKP = await _requireIdentityKeyPair();

    // Check if this is the first message in a new session
    final pendingPreKey = await _cryptoStorage.getPendingPreKeyInfo(
      recipientId,
      recipientDeviceId,
    );

    if (pendingPreKey != null) {
      CryptoDebugLogger.log(
        'ENCRYPT',
        'First message — including PreKey handshake data',
      );
      // First message — include X3DH handshake info so recipient can
      // establish their side of the session
      await _cryptoStorage.clearPendingPreKeyInfo(
        recipientId,
        recipientDeviceId,
      );
      return {
        'type': 'prekey',
        'senderIdentityKey': identityKP.publicKey,
        'senderEphemeralKey': pendingPreKey['ephemeralPublicKey'] as String,
        'usedOneTimePreKeyId': pendingPreKey['usedOneTimePreKeyId'] as int?,
        if (pendingPreKey['kyberCiphertext'] != null)
          'kyberCiphertext': pendingPreKey['kyberCiphertext'] as String,
        'message': encrypted.toJson(),
      };
    }

    CryptoDebugLogger.log('ENCRYPT', 'Normal message (session exists)');
    return {
      'type': 'message',
      'senderIdentityKey': identityKP.publicKey,
      'message': encrypted.toJson(),
    };
  }

  // ── Decrypt ───────────────────────────────────────────────────────

  /// Decrypt an incoming message envelope.
  ///
  /// Handles both PreKey messages (type 1, first message from sender) and
  /// normal messages (type 2, subsequent messages). The envelope type is
  /// determined by the `type` field.
  ///
  /// For PreKey messages:
  ///   - Establishes a new session via [processPreKeyMessage]
  ///   - Decrypts the embedded first message
  ///   - Deletes the consumed one-time pre-key
  ///
  /// For normal messages:
  ///   - Loads the existing session from storage/cache
  ///   - Decrypts using the Double Ratchet
  ///   - Advances the ratchet state and persists it
  ///
  /// **Auto-reset behavior**: If decryption fails with an authentication error
  /// (MAC mismatch), the session is automatically deleted and a [SessionResetError]
  /// is thrown. The app should display a "session reset" warning to the user.
  /// If the failed message was a PreKey message, auto-reset attempts immediate
  /// re-establishment.
  ///
  /// Rate-limiting: If more than 3 auto-resets occur within 1 hour for the same
  /// session pair, a [SessionUnstableError] is thrown and auto-reset is disabled
  /// for 24 hours (prevents attack where a malicious peer forces repeated resets).
  ///
  /// Returns the decrypted plaintext string (after unpadding).
  ///
  /// Throws:
  ///   - [StateError] if session doesn't exist and this isn't a PreKey message
  ///   - [SessionResetError] if decryption failed and session was deleted
  ///   - [SessionUnstableError] if reset rate limit exceeded
  Future<String> decryptMessage(
    String senderId,
    String senderDeviceId,
    Map<String, dynamic> envelope,
  ) async {
    final type = envelope['type'] as String;
    CryptoDebugLogger.log(
      'DECRYPT_MSG',
      'decryptMessage type=$type from $senderId:$senderDeviceId',
    );

    try {
      return await _decryptMessageInner(senderId, senderDeviceId, envelope);
    } catch (e) {
      final msg = e.toString();

      // Replay rejection — emit event and rethrow without triggering reset
      if (msg.contains('Replay attack detected') ||
          msg.contains('already received')) {
        _eventBus?.emitType(
          SecurityEventType.replayRejected,
          sessionId: _sessionKey(senderId, senderDeviceId),
          metadata: {'source': 'double_ratchet'},
        );
        rethrow;
      }

      // Skipped-key cap exceeded — emit event and rethrow
      if (msg.contains('Too many skipped message keys')) {
        _eventBus?.emitType(
          SecurityEventType.skippedKeyCapReached,
          sessionId: _sessionKey(senderId, senderDeviceId),
          metadata: {'source': 'double_ratchet'},
        );
        rethrow;
      }

      if (!_shouldTriggerReset(e)) rethrow;

      CryptoDebugLogger.log(
        'DECRYPT_MSG',
        'Auth error detected — checking rate limit for $senderId:$senderDeviceId',
      );

      // Rate-limit check: too many resets → flag as unstable
      if (await _isResetRateLimited(senderId, senderDeviceId)) {
        final count = await _getRecentResetCount(senderId, senderDeviceId);
        CryptoDebugLogger.log(
          'DECRYPT_MSG',
          'Session UNSTABLE — $count resets in window, blocking auto-reset',
        );
        final sid = _sessionKey(senderId, senderDeviceId);
        _eventBus?.emitType(
          SecurityEventType.resetRateLimitHit,
          sessionId: sid,
          metadata: {'resetCount': count},
        );
        _eventBus?.emitType(
          SecurityEventType.sessionUnstable,
          sessionId: sid,
          metadata: {'resetCount': count},
        );
        throw SessionUnstableError(
          senderId: senderId,
          senderDeviceId: senderDeviceId,
          resetCount: count,
        );
      }

      // Delete the broken session
      await removeSession(senderId, senderDeviceId);
      await _recordSessionReset(senderId, senderDeviceId);
      CryptoDebugLogger.log(
        'DECRYPT_MSG',
        'Broken session deleted — recorded reset event',
      );

      _eventBus?.emitType(
        SecurityEventType.sessionReset,
        sessionId: _sessionKey(senderId, senderDeviceId),
        metadata: {'originalError': e.toString()},
      );

      // Trigger pre-key replenishment check — session reset consumes an OTP
      _onPreKeyReplenishmentNeeded?.call();
      _eventBus?.emitType(SecurityEventType.preKeyReplenishmentNeeded);

      // If this IS a PreKey message, try re-establishing immediately
      if (type == 'prekey') {
        CryptoDebugLogger.log(
          'DECRYPT_MSG',
          'PreKey message — attempting immediate re-establishment',
        );
        try {
          return await processPreKeyMessage(
            senderId: senderId,
            senderDeviceId: senderDeviceId,
            senderIdentityKey: envelope['senderIdentityKey'] as String,
            senderEphemeralKey: envelope['senderEphemeralKey'] as String,
            usedOneTimePreKeyId: envelope['usedOneTimePreKeyId'] as int?,
            encryptedMessage: envelope['message'] as Map<String, dynamic>,
            kyberCiphertext: envelope['kyberCiphertext'] as String?,
          );
        } catch (retryError) {
          CryptoDebugLogger.logError(
            'DECRYPT_MSG',
            'PreKey re-establishment also failed',
            retryError,
          );
          // Fall through to throw SessionResetError
        }
      }

      // Normal message or PreKey retry failed: session is deleted,
      // next outgoing message will re-establish via PreKey
      throw SessionResetError(
        senderId: senderId,
        senderDeviceId: senderDeviceId,
        originalError: e.toString(),
      );
    }
  }

  /// The original decrypt logic, extracted so decryptMessage() can wrap
  /// it with auto-reset error handling.
  Future<String> _decryptMessageInner(
    String senderId,
    String senderDeviceId,
    Map<String, dynamic> envelope,
  ) async {
    final type = envelope['type'] as String;

    if (type == 'prekey') {
      CryptoDebugLogger.log(
        'DECRYPT_MSG',
        'PreKey message — establishing session and decrypting',
      );
      return processPreKeyMessage(
        senderId: senderId,
        senderDeviceId: senderDeviceId,
        senderIdentityKey: envelope['senderIdentityKey'] as String,
        senderEphemeralKey: envelope['senderEphemeralKey'] as String,
        usedOneTimePreKeyId: envelope['usedOneTimePreKeyId'] as int?,
        encryptedMessage: envelope['message'] as Map<String, dynamic>,
        kyberCiphertext: envelope['kyberCiphertext'] as String?,
      );
    }

    CryptoDebugLogger.log(
      'DECRYPT_MSG',
      'Normal message — loading existing session',
    );
    final ratchet = await _loadSession(senderId, senderDeviceId);
    final message = EncryptedMessage.fromJson(
      envelope['message'] as Map<String, dynamic>,
    );
    CryptoDebugLogger.log(
      'DECRYPT_MSG',
      'Message: msgNum=${message.messageNumber} prevChain=${message.previousChainLength}',
    );
    CryptoDebugLogger.logKeyInfo(
      'DECRYPT_MSG',
      'Message DH key',
      message.dhPublicKey,
    );
    CryptoDebugLogger.logRatchetState(
      'DECRYPT_MSG',
      'Ratchet BEFORE decrypt',
      ratchet.state.toJson(),
    );

    final plainBytes = await ratchet.decrypt(message);

    CryptoDebugLogger.logRatchetState(
      'DECRYPT_MSG',
      'Ratchet AFTER decrypt',
      ratchet.state.toJson(),
    );

    await _cryptoStorage.saveSession(senderId, senderDeviceId, ratchet.state);

    final result = MessagePadding.unpadString(plainBytes);
    CryptoDebugLogger.log('DECRYPT_MSG', 'Decrypted: "$result"');
    return result;
  }

  // ── Session Queries ───────────────────────────────────────────────

  /// Whether a session exists with the given user and device.
  Future<bool> hasSession(String userId, String deviceId) async {
    final key = _sessionKey(userId, deviceId);
    if (_sessions.containsKey(key)) return true;
    final stored = await _cryptoStorage.getSession(userId, deviceId);
    return stored != null;
  }

  /// Remove a session for a specific user and device (in-memory + storage).
  Future<void> removeSession(String userId, String deviceId) async {
    final key = _sessionKey(userId, deviceId);
    _sessions.remove(key);
    await _cryptoStorage.deleteSession(userId, deviceId);
    await _cryptoStorage.deleteSessionIdentityKey(userId, deviceId);
    await _cryptoStorage.clearPendingPreKeyInfo(userId, deviceId);
    await _cryptoStorage.clearReceivedMessageNumbers(userId, deviceId);
    CryptoDebugLogger.log('SESSION', 'Removed session $userId:$deviceId');
  }

  /// Remove all sessions for a user (any device). Used when the peer
  /// changes their identity key (logout + re-login).
  Future<void> removeAllSessionsForUser(String userId) async {
    _sessions.removeWhere((key, _) => key.startsWith('$userId:'));
    await _cryptoStorage.deleteAllSessionsForUser(userId);
    CryptoDebugLogger.log('SESSION', 'Removed all sessions for user $userId');
  }

  /// Get the remote identity key stored when the session was created.
  Future<String?> getSessionIdentityKey(String userId, String deviceId) =>
      _cryptoStorage.getSessionIdentityKey(userId, deviceId);

  // ── Sealed Sender Encrypt ─────────────────────────────────────────

  /// Encrypt a message using Sealed Sender (metadata protection).
  ///
  /// Hides the sender's identity from the server by wrapping the encrypted
  /// message in a second layer of encryption. The server sees only:
  ///   - Recipient ID (required for routing)
  ///   - Encrypted blob (no sender info, no message type)
  ///
  /// The sender's identity (user ID, device ID, identity key) is encrypted
  /// inside the sealed envelope using a shared secret derived from:
  ///   - Sender's ephemeral X25519 key pair (generated per message)
  ///   - Recipient's identity X25519 public key
  ///
  /// Only the recipient can unseal the envelope (using their identity private
  /// key) to discover who sent the message. This provides **sender anonymity**
  /// against the server and network observers.
  ///
  /// The sealed envelope includes a timestamp for replay protection (5-minute
  /// window). Messages outside this window are rejected during unseal.
  ///
  /// Wire format (outer envelope):
  /// ```json
  /// {
  ///   "type": "sealed",
  ///   "ephemeralPublicKey": "<base64>",
  ///   "ciphertext": "<base64 AES-GCM ciphertext>",
  ///   "nonce": "<base64 12-byte nonce>"
  /// }
  /// ```
  ///
  /// Inner payload (encrypted):
  /// ```json
  /// {
  ///   "senderId": "...",
  ///   "senderDeviceId": "...",
  ///   "senderIdentityKey": "<base64>",
  ///   "timestamp": <unix_ms>,
  ///   "message": { <normal or prekey envelope> }
  /// }
  /// ```
  ///
  /// Use this for sensitive conversations where you don't want the server to
  /// build a social graph. Trade-off: slightly larger message size and no
  /// server-side sender verification.
  ///
  /// See also:
  ///   - [decryptSealedSender] to unseal and decrypt
  ///   - [encryptSealedSenderFull] for the preferred variant with explicit sender info
  Future<Map<String, dynamic>> encryptSealedSender(
    String recipientId,
    String recipientDeviceId,
    String recipientIdentityPublicKey,
    String plaintext,
  ) async {
    CryptoDebugLogger.log('SEAL', '═══ Encrypting Sealed Sender ═══');
    CryptoDebugLogger.log('SEAL', 'Recipient: $recipientId:$recipientDeviceId');
    CryptoDebugLogger.logKeyInfo(
      'SEAL',
      'Recipient identity key',
      recipientIdentityPublicKey,
    );

    // First, encrypt the message with the Double Ratchet as usual
    final ratchet = await _loadSession(recipientId, recipientDeviceId);
    CryptoDebugLogger.logRatchetState(
      'SEAL',
      'Ratchet BEFORE encrypt',
      ratchet.state.toJson(),
    );
    final encrypted = await ratchet.encrypt(
      MessagePadding.padString(plaintext),
    );
    CryptoDebugLogger.log(
      'SEAL',
      'Ratchet encrypted: msgNum=${encrypted.messageNumber} prevChain=${encrypted.previousChainLength}',
    );
    CryptoDebugLogger.logRatchetState(
      'SEAL',
      'Ratchet AFTER encrypt',
      ratchet.state.toJson(),
    );

    // Persist the updated ratchet state
    await _cryptoStorage.saveSession(
      recipientId,
      recipientDeviceId,
      ratchet.state,
    );

    final identityKP = await _requireIdentityKeyPair();

    // Check if this is the first message in a new session
    final pendingPreKey = await _cryptoStorage.getPendingPreKeyInfo(
      recipientId,
      recipientDeviceId,
    );

    Map<String, dynamic> innerEnvelope;
    if (pendingPreKey != null) {
      CryptoDebugLogger.log(
        'SEAL',
        'First message — inner envelope type=prekey',
      );
      // First message — include X3DH handshake info
      await _cryptoStorage.clearPendingPreKeyInfo(
        recipientId,
        recipientDeviceId,
      );
      innerEnvelope = {
        'type': 'prekey',
        'senderIdentityKey': identityKP.publicKey,
        'senderEphemeralKey': pendingPreKey['ephemeralPublicKey'] as String,
        'usedOneTimePreKeyId': pendingPreKey['usedOneTimePreKeyId'] as int?,
        if (pendingPreKey['kyberCiphertext'] != null)
          'kyberCiphertext': pendingPreKey['kyberCiphertext'] as String,
        'message': encrypted.toJson(),
      };
    } else {
      CryptoDebugLogger.log(
        'SEAL',
        'Subsequent message — inner envelope type=message',
      );
      innerEnvelope = {
        'type': 'message',
        'senderIdentityKey': identityKP.publicKey,
        'message': encrypted.toJson(),
      };
    }

    // Read sender info from storage for the sealed envelope
    final senderId = await _cryptoStorage.readRaw('user_id');
    final senderDeviceId = await _cryptoStorage.readRaw('device_id');
    if (senderId == null ||
        senderId.isEmpty ||
        senderDeviceId == null ||
        senderDeviceId.isEmpty) {
      throw StateError(
          'Missing user_id or device_id for sealed sender envelope');
    }
    CryptoDebugLogger.log(
      'SEAL',
      'Sender info: userId=$senderId deviceId=$senderDeviceId',
    );

    // Wrap in a Sealed Sender envelope
    final sealedEnvelope = await SealedSenderEnvelope.seal(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: identityKP.publicKey,
      encryptedMessage: innerEnvelope,
      recipientIdentityPublicKey: recipientIdentityPublicKey,
    );

    CryptoDebugLogger.log('SEAL', '═══ Sealed Sender envelope created ═══');
    return sealedEnvelope;
  }

  /// Encrypt a message using Sealed Sender with full sender info.
  ///
  /// This is the preferred method — it includes sender identity inside
  /// the sealed envelope so the recipient can identify the sender.
  Future<Map<String, dynamic>> encryptSealedSenderFull({
    required String senderId,
    required String senderDeviceId,
    required String recipientId,
    required String recipientDeviceId,
    required String recipientIdentityPublicKey,
    required String plaintext,
  }) async {
    final ratchet = await _loadSession(recipientId, recipientDeviceId);
    final encrypted = await ratchet.encrypt(
      MessagePadding.padString(plaintext),
    );

    await _cryptoStorage.saveSession(
      recipientId,
      recipientDeviceId,
      ratchet.state,
    );

    final identityKP = await _requireIdentityKeyPair();

    final innerEnvelope = {
      'type': 'message',
      'senderIdentityKey': identityKP.publicKey,
      'message': encrypted.toJson(),
    };

    return SealedSenderEnvelope.seal(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: identityKP.publicKey,
      encryptedMessage: innerEnvelope,
      recipientIdentityPublicKey: recipientIdentityPublicKey,
    );
  }

  // ── Sealed Sender Decrypt ─────────────────────────────────────────

  /// Decrypt a Sealed Sender message (metadata protection).
  ///
  /// Unseals the outer encryption layer to discover the sender's identity,
  /// then decrypts the inner message using the normal Double Ratchet path.
  ///
  /// Process:
  ///   1. Derive shared secret: `DH(localIdentityPrivate, ephemeralPublic)`
  ///   2. Decrypt outer AES-GCM layer to extract sender certificate
  ///   3. Verify timestamp (reject if outside 5-minute window — replay protection)
  ///   4. Extract inner envelope (type `prekey` or `message`)
  ///   5. Call [decryptMessage] to handle the inner envelope
  ///
  /// Returns a [SealedSenderResult] containing:
  ///   - `senderId`: Discovered sender user ID
  ///   - `senderDeviceId`: Discovered sender device ID
  ///   - `plaintext`: Decrypted message text
  ///
  /// The caller can now display the sender identity (e.g., "Alice sent you
  /// a message") even though the server never saw Alice's name.
  ///
  /// Throws:
  ///   - [StateError] if timestamp is outside allowed window (replay attack)
  ///   - [SecretBoxAuthenticationError] if MAC verification fails (wrong key or tampered)
  ///   - [SessionResetError] if inner message decryption fails
  ///
  /// Example:
  /// ```dart
  /// final result = await manager.decryptSealedSender(envelope);
  /// print('Message from ${result.senderId}: ${result.plaintext}');
  /// ```
  Future<SealedSenderResult> decryptSealedSender(
    Map<String, dynamic> sealedEnvelope,
  ) async {
    CryptoDebugLogger.log('UNSEAL', '═══ Decrypting Sealed Sender ═══');
    CryptoDebugLogger.log(
      'UNSEAL',
      'Envelope keys: ${sealedEnvelope.keys.toList()}',
    );

    final identityKP = await _requireIdentityKeyPair();
    CryptoDebugLogger.logKeyInfo(
      'UNSEAL',
      'Our identity key',
      identityKP.publicKey,
    );

    // Unseal the outer envelope to discover the sender
    final SealedSenderContent content;
    try {
      content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealedEnvelope,
        recipientIdentityKeyPair: identityKP,
        seenNonces: _seenNonces,
      );
      await _cryptoStorage.saveSeenNonces(_seenNonces);
    } catch (e) {
      final msg = e.toString();
      if (msg.contains('nonce already seen') || msg.contains('replay window')) {
        _eventBus?.emitType(
          SecurityEventType.replayRejected,
          metadata: {'source': 'sealed_sender', 'reason': msg},
        );
      }
      rethrow;
    }

    CryptoDebugLogger.log(
      'UNSEAL',
      'Unsealed: senderId=${content.senderId} deviceId=${content.senderDeviceId} timestamp=${content.timestamp}',
    );
    CryptoDebugLogger.log(
      'UNSEAL',
      'Inner envelope type: ${content.encryptedMessage['type']}',
    );

    // Now decrypt the inner message using the normal decryption path
    final innerEnvelope = content.encryptedMessage;
    final plaintext = await decryptMessage(
      content.senderId,
      content.senderDeviceId,
      innerEnvelope,
    );

    CryptoDebugLogger.log(
      'UNSEAL',
      '═══ Sealed Sender decrypted successfully ═══',
    );

    return SealedSenderResult(
      senderId: content.senderId,
      senderDeviceId: content.senderDeviceId,
      plaintext: plaintext,
    );
  }

  // ── Identity ──────────────────────────────────────────────────────

  /// Return the local identity public key as a base64 string.
  Future<String> getIdentityPublicKey() async {
    final kp = await _requireIdentityKeyPair();
    return kp.publicKey;
  }

  // ── Safety Number ───────────────────────────────────────────────

  /// Generate the formatted safety number for identity verification.
  ///
  /// Produces a 60-digit numeric fingerprint by hashing both parties' identity
  /// keys and user IDs. Both Alice and Bob will see the same safety number
  /// because the algorithm sorts the keys before hashing.
  ///
  /// Format: `12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890`
  /// (12 groups of 5 digits, space-separated).
  ///
  /// Users verify their safety number out-of-band (in person, phone call, video)
  /// to confirm they're talking to the right person and not a man-in-the-middle.
  /// If the safety number changes later, it means one party reinstalled the app
  /// (new identity key) or there's an active MITM attack.
  ///
  /// The safety number is stable as long as both parties keep their identity keys.
  ///
  /// Example:
  /// ```dart
  /// final safetyNumber = await manager.getSafetyNumber(
  ///   myUserId: 'alice-id',
  ///   theirUserId: 'bob-id',
  ///   theirIdentityKey: bobSession.identityKey,
  /// );
  ///
  /// showDialog(
  ///   title: 'Verify Safety Number',
  ///   content: Text('Compare this with Bob:\n$safetyNumber'),
  /// );
  /// ```
  ///
  /// See also:
  ///   - [getSafetyNumberQrPayload] for QR code scanning
  ///   - [SafetyNumber.generateFormatted] for the underlying algorithm
  Future<String> getSafetyNumber({
    required String myUserId,
    required String theirUserId,
    required String theirIdentityKey,
  }) async {
    final myKey = await getIdentityPublicKey();
    return SafetyNumber.generateFormatted(
      myUserId: myUserId,
      myIdentityKey: myKey,
      theirUserId: theirUserId,
      theirIdentityKey: theirIdentityKey,
    );
  }

  /// Generate the QR code payload for safety number verification.
  ///
  /// Produces a compact binary payload for QR code encoding. Both parties scan
  /// each other's QR code and compare the decoded fingerprint to verify identity.
  ///
  /// The payload is a base64-encoded concatenation of:
  ///   - Version byte (0x00)
  ///   - Alice's key + ID
  ///   - Bob's key + ID
  ///   - SHA-256 hash of the above
  ///
  /// This is faster than reading 60 digits aloud but requires both parties to
  /// be physically present (in-person verification).
  ///
  /// Example:
  /// ```dart
  /// final qrPayload = await manager.getSafetyNumberQrPayload(
  ///   myUserId: 'alice-id',
  ///   theirUserId: 'bob-id',
  ///   theirIdentityKey: bobSession.identityKey,
  /// );
  ///
  /// showQrCodeDialog(qrPayload);  // Display QR for Bob to scan
  /// ```
  Future<String> getSafetyNumberQrPayload({
    required String myUserId,
    required String theirUserId,
    required String theirIdentityKey,
  }) async {
    final myKey = await getIdentityPublicKey();
    return SafetyNumber.generateQrPayload(
      myUserId: myUserId,
      myIdentityKey: myKey,
      theirUserId: theirUserId,
      theirIdentityKey: theirIdentityKey,
    );
  }

  // ── Key Lifecycle ─────────────────────────────────────────────────

  /// Return the age of the current signed pre-key in milliseconds.
  ///
  /// Returns 0 if no creation timestamp is stored (e.g. first-run keys
  /// generated before lifecycle tracking was added).
  Future<int> signedPreKeyAge() async {
    final createdAt = await _cryptoStorage.getSignedPreKeyCreatedAt();
    if (createdAt == null) return 0;
    return DateTime.now().millisecondsSinceEpoch - createdAt;
  }

  /// Rotate the signed pre-key if it is older than [maxAge].
  ///
  /// Checks the stored creation timestamp against the current time. If the
  /// signed pre-key exceeds [maxAge] (default 7 days), a new signed pre-key
  /// is generated, signed with the Ed25519 signing key, and persisted.
  ///
  /// Returns the updated key bundle (for re-upload to the server) if rotation
  /// occurred, or `null` if the key is still fresh.
  ///
  /// Call this periodically (e.g. on app foreground) to ensure key hygiene.
  Future<Map<String, dynamic>?> rotateSignedPreKeyIfNeeded({
    Duration maxAge = const Duration(days: 7),
  }) async {
    // First, clean up any expired previous key from the overlap window
    await _cleanupExpiredPreviousSignedPreKey();

    final createdAt = await _cryptoStorage.getSignedPreKeyCreatedAt();
    final now = DateTime.now().millisecondsSinceEpoch;

    if (createdAt != null && (now - createdAt) < maxAge.inMilliseconds) {
      // Check absolute max lifetime — never use a key past this age.
      // Grace period tolerates small clock drifts (e.g. device clock 30min ahead).
      final maxWithGrace = absoluteMaxKeyLifetime.inMilliseconds +
          clockDriftGracePeriod.inMilliseconds;
      if ((now - createdAt) > maxWithGrace) {
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'EXPIRED: Signed pre-key exceeded absolute max lifetime — forcing rotation',
        );
        _eventBus?.emitType(
          SecurityEventType.keyExpired,
          metadata: {
            'keyType': 'signedPreKey',
            'ageMs': now - createdAt,
            'maxLifetimeMs': absoluteMaxKeyLifetime.inMilliseconds,
          },
        );
      } else {
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'Signed pre-key is fresh (age=${now - createdAt}ms < ${maxAge.inMilliseconds}ms)',
        );
        return null; // Still fresh — no rotation needed
      }
    }

    CryptoDebugLogger.log(
      'KEY_LIFECYCLE',
      '═══ Rotating signed pre-key ═══',
    );

    final signingKP = await _cryptoStorage.getSigningKeyPair();
    if (signingKP == null) {
      throw StateError(
        'Signing key pair not found. Call initialize() first.',
      );
    }

    // Store current key as previous with 48h overlap expiry
    final currentSignedPreKey = await _cryptoStorage.getSignedPreKey();
    if (currentSignedPreKey != null) {
      final overlapExpiry = now + keyOverlapWindow.inMilliseconds;
      await _cryptoStorage.savePreviousSignedPreKey(
        currentSignedPreKey,
        overlapExpiry,
      );
      CryptoDebugLogger.log(
        'KEY_LIFECYCLE',
        'Old signed pre-key (keyId=${currentSignedPreKey.keyId}) '
            'retained for ${keyOverlapWindow.inHours}h overlap',
      );
    }

    final newKeyId = (currentSignedPreKey?.keyId ?? 0) + 1;

    final newSignedPreKey = await SignalKeyHelper.generateSignedPreKey(
      newKeyId,
      signingKP,
    );
    await _cryptoStorage.saveSignedPreKey(newSignedPreKey);
    await _cryptoStorage.saveSignedPreKeyCreatedAt(now);

    CryptoDebugLogger.logKeyInfo(
      'KEY_LIFECYCLE',
      'Rotated signed pre-key (keyId=$newKeyId)',
      newSignedPreKey.keyPair.publicKey,
    );

    _eventBus?.emitType(
      SecurityEventType.keyRotationCompleted,
      metadata: {'keyType': 'signedPreKey', 'keyId': newKeyId},
    );

    return generateKeyBundle();
  }

  /// Remove the previous signed pre-key if its 48h overlap window has expired.
  /// Wipes key material via SecureMemory before deletion.
  Future<void> _cleanupExpiredPreviousSignedPreKey() async {
    final expiry = await _cryptoStorage.getPreviousSpkExpiry();
    if (expiry == null) return;

    final now = DateTime.now().millisecondsSinceEpoch;
    if (now >= expiry) {
      CryptoDebugLogger.log(
        'KEY_LIFECYCLE',
        'Previous signed pre-key overlap expired — wiping',
      );
      await _cryptoStorage.deletePreviousSignedPreKey();
    }
  }

  /// Rotate the Kyber (ML-KEM-768) key if it is older than [maxAge].
  ///
  /// Similar to [rotateSignedPreKeyIfNeeded], checks the stored creation
  /// timestamp and generates a new Kyber key pair if the current one exceeds
  /// [maxAge] (default 7 days).
  ///
  /// Returns `true` if rotation occurred, `false` if the key is still fresh
  /// or if Kyber is not available on this platform.
  Future<bool> rotateKyberKeyIfNeeded({
    Duration maxAge = const Duration(days: 7),
  }) async {
    // Clean up expired previous Kyber key
    await _cleanupExpiredPreviousKyberKey();

    final createdAt = await _cryptoStorage.getKyberCreatedAt();
    final now = DateTime.now().millisecondsSinceEpoch;

    if (createdAt != null && (now - createdAt) < maxAge.inMilliseconds) {
      // Check absolute max lifetime with clock drift grace period
      final maxWithGrace = absoluteMaxKeyLifetime.inMilliseconds +
          clockDriftGracePeriod.inMilliseconds;
      if ((now - createdAt) > maxWithGrace) {
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'EXPIRED: Kyber key exceeded absolute max lifetime — forcing rotation',
        );
        _eventBus?.emitType(
          SecurityEventType.keyExpired,
          metadata: {
            'keyType': 'kyber',
            'ageMs': now - createdAt,
            'maxLifetimeMs': absoluteMaxKeyLifetime.inMilliseconds,
          },
        );
      } else {
        return false; // Still fresh
      }
    }

    CryptoDebugLogger.log('KEY_LIFECYCLE', '═══ Rotating Kyber key ═══');

    try {
      // Store current key as previous with 48h overlap
      final currentKyber = await _cryptoStorage.getKyberKeyPair();
      if (currentKyber != null) {
        final overlapExpiry = now + keyOverlapWindow.inMilliseconds;
        await _cryptoStorage.savePreviousKyberKeyPair(
          currentKyber,
          overlapExpiry,
        );
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'Old Kyber key retained for ${keyOverlapWindow.inHours}h overlap',
        );
      }

      final kyberKP = SignalKeyHelper.generateKyberKeyPair();
      await _cryptoStorage.saveKyberKeyPair(kyberKP);
      await _cryptoStorage.saveKyberCreatedAt(now);

      CryptoDebugLogger.logKeyInfo(
        'KEY_LIFECYCLE',
        'Rotated Kyber-768 public key',
        kyberKP.publicKey,
      );

      _eventBus?.emitType(
        SecurityEventType.keyRotationCompleted,
        metadata: {'keyType': 'kyber'},
      );

      return true;
    } catch (e) {
      CryptoDebugLogger.logError(
        'KEY_LIFECYCLE',
        'Kyber rotation failed — post-quantum unavailable',
        e,
      );
      return false;
    }
  }

  /// Remove the previous Kyber key if its 48h overlap window has expired.
  Future<void> _cleanupExpiredPreviousKyberKey() async {
    final expiry = await _cryptoStorage.getPreviousKyberExpiry();
    if (expiry == null) return;

    final now = DateTime.now().millisecondsSinceEpoch;
    if (now >= expiry) {
      CryptoDebugLogger.log(
        'KEY_LIFECYCLE',
        'Previous Kyber key overlap expired — wiping',
      );
      await _cryptoStorage.deletePreviousKyberKeyPair();
    }
  }

  /// Rotate all keys that have exceeded their max age.
  ///
  /// Convenience method that checks and rotates both the signed pre-key
  /// and the Kyber key in one call. Returns the updated key bundle if
  /// any rotation occurred, or `null` if all keys are fresh.
  ///
  /// Call this periodically (e.g. on app foreground) to ensure key hygiene.
  Future<Map<String, dynamic>?> rotateKeysIfNeeded({
    Duration signedPreKeyMaxAge = const Duration(days: 7),
    Duration kyberKeyMaxAge = const Duration(days: 7),
  }) async {
    final spkBundle = await rotateSignedPreKeyIfNeeded(
      maxAge: signedPreKeyMaxAge,
    );
    final kyberRotated = await rotateKyberKeyIfNeeded(maxAge: kyberKeyMaxAge);

    // If either rotated, return a fresh bundle for server upload
    if (spkBundle != null) return spkBundle;
    if (kyberRotated) return generateKeyBundle();
    return null;
  }

  /// Force immediate rotation of all rotatable keys.
  ///
  /// Use during incident response when key compromise is suspected.
  /// Bypasses age checks and rotates both signed pre-key and Kyber key
  /// unconditionally.
  ///
  /// Returns the updated key bundle — caller MUST upload to server
  /// immediately after this call.
  Future<Map<String, dynamic>> forceKeyRotationNow() async {
    final bundle = await rotateKeysIfNeeded(
      signedPreKeyMaxAge: Duration.zero,
      kyberKeyMaxAge: Duration.zero,
    );
    // rotateKeysIfNeeded returns null only when both keys are fresh.
    // With Duration.zero every key is "stale", so bundle will always be
    // non-null. Defensive fallback just in case.
    return bundle ?? await generateKeyBundle();
  }

  /// Return the number of one-time pre-keys currently stored locally.
  Future<int> oneTimePreKeyCount() async {
    final keys = await _cryptoStorage.getOneTimePreKeys();
    return keys.length;
  }

  /// Whether the one-time pre-key count is at or below [threshold].
  ///
  /// Returns `true` if exhaustion is near (time to generate and upload more
  /// one-time pre-keys to the server).
  Future<bool> isPreKeyExhaustionNear({int threshold = 10}) async {
    final count = await oneTimePreKeyCount();
    return count <= threshold;
  }

  /// Check OTP exhaustion and fire the warning callback / event if needed.
  ///
  /// Called internally after operations that consume OTPs (e.g.
  /// [processPreKeyMessage]). Uses [defaultOtpLowWatermark] as threshold.
  ///
  /// When the pool is low, automatically generates [otpReplenishBatchSize]
  /// new OTPs and stores them. The app layer is notified via the callback
  /// and event bus so it can upload the new keys to the server.
  Future<void> _checkPreKeyExhaustion() async {
    final count = await oneTimePreKeyCount();
    if (count <= defaultOtpLowWatermark) {
      if (count == 0) {
        _eventBus?.emitType(
          SecurityEventType.otpPoolExhausted,
          metadata: {'remaining': 0},
        );
      } else {
        _eventBus?.emitType(
          SecurityEventType.otpPoolLow,
          metadata: {
            'remaining': count,
            'threshold': defaultOtpLowWatermark,
          },
        );
      }

      // Auto-generate a fresh batch of OTPs
      CryptoDebugLogger.log(
        'KEY_LIFECYCLE',
        'OTP pool low ($count <= $defaultOtpLowWatermark) — '
            'auto-generating $otpReplenishBatchSize new OTPs',
      );
      final newKeys = await generateOneTimePreKeys(otpReplenishBatchSize);

      // Notify app layer so it can upload to server
      _onPreKeyExhaustionWarning?.call(count);

      _eventBus?.emitType(
        SecurityEventType.preKeyReplenishmentNeeded,
        metadata: {
          'generated': newKeys.length,
          'previousCount': count,
          'newTotal': count + newKeys.length,
        },
      );
    }
  }

  // ── One-Time Pre-Key Replenishment ────────────────────────────────

  /// Generate [count] fresh one-time pre-keys and persist them.
  /// Returns the public portions for upload to the server.
  Future<List<Map<String, dynamic>>> generateOneTimePreKeys(int count) async {
    final startId = await _cryptoStorage.getNextPreKeyId();
    final newKeys = await SignalKeyHelper.generateOneTimePreKeys(
      startId,
      count,
    );

    // Merge with existing keys
    final existing = await _cryptoStorage.getOneTimePreKeys();
    existing.addAll(newKeys);
    await _cryptoStorage.saveOneTimePreKeys(existing);
    await _cryptoStorage.setNextPreKeyId(startId + count);

    return newKeys
        .map((k) => {'keyId': k.keyId, 'publicKey': k.keyPair.publicKey})
        .toList();
  }

  // ── Key Expiry Enforcement ──────────────────────────────────────

  /// Validate that all local keys are within their maximum lifetime.
  ///
  /// Call on app startup (after [initialize]) to ensure no key is being
  /// used past its absolute max lifetime. Returns `true` if all keys are
  /// valid, `false` if any key was expired (force-rotation will have been
  /// triggered via [rotateKeysIfNeeded]).
  ///
  /// **This is a hard safety net.** Even if the app fails to call
  /// [rotateKeysIfNeeded] periodically, this check catches expired keys
  /// on the next launch.
  Future<bool> validateKeyFreshness() async {
    final now = DateTime.now().millisecondsSinceEpoch;
    var allFresh = true;

    // Clock drift grace period for all expiry checks
    final maxWithGrace = absoluteMaxKeyLifetime.inMilliseconds +
        clockDriftGracePeriod.inMilliseconds;

    // Check signed pre-key age
    final spkCreatedAt = await _cryptoStorage.getSignedPreKeyCreatedAt();
    if (spkCreatedAt != null) {
      final age = now - spkCreatedAt;
      if (age > maxWithGrace) {
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'EXPIRED: Signed pre-key age ${age}ms exceeds '
              '${absoluteMaxKeyLifetime.inMilliseconds}ms — forcing rotation',
        );
        _eventBus?.emitType(
          SecurityEventType.keyExpired,
          metadata: {'keyType': 'signedPreKey', 'ageMs': age},
        );
        allFresh = false;
      }
    }

    // Check Kyber key age
    final kyberCreatedAt = await _cryptoStorage.getKyberCreatedAt();
    if (kyberCreatedAt != null) {
      final age = now - kyberCreatedAt;
      if (age > maxWithGrace) {
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'EXPIRED: Kyber key age ${age}ms exceeds '
              '${absoluteMaxKeyLifetime.inMilliseconds}ms — forcing rotation',
        );
        _eventBus?.emitType(
          SecurityEventType.keyExpired,
          metadata: {'keyType': 'kyber', 'ageMs': age},
        );
        allFresh = false;
      }
    }

    // Clean up any expired overlap keys
    await _cleanupExpiredPreviousSignedPreKey();
    await _cleanupExpiredPreviousKyberKey();

    return allFresh;
  }

  /// Get the previous signed pre-key (within 48h overlap window) for
  /// decrypting messages that reference the old key ID.
  Future<SignedPreKey?> getPreviousSignedPreKey() async {
    final expiry = await _cryptoStorage.getPreviousSpkExpiry();
    if (expiry == null) return null;
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now >= expiry) {
      await _cryptoStorage.deletePreviousSignedPreKey();
      return null;
    }
    return _cryptoStorage.getPreviousSignedPreKey();
  }

  /// Get the previous Kyber key pair (within 48h overlap window) for
  /// decapsulating ciphertexts that reference the old Kyber key.
  Future<KyberKeyPair?> getPreviousKyberKeyPair() async {
    final expiry = await _cryptoStorage.getPreviousKyberExpiry();
    if (expiry == null) return null;
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now >= expiry) {
      await _cryptoStorage.deletePreviousKyberKeyPair();
      return null;
    }
    return _cryptoStorage.getPreviousKyberKeyPair();
  }

  // ── Group E2EE (Sender Keys) ─────────────────────────────────────

  /// Generate a Sender Key for group encryption (encrypt-once, decrypt-many).
  ///
  /// Creates a new AES-256-CBC + Ed25519 sender key for the specified group.
  /// The sender key allows you to encrypt a message once and send it to all group
  /// members (instead of encrypting N times with N 1-to-1 sessions).
  ///
  /// The returned [SenderKeyDistribution] contains:
  ///   - `groupId`: The group identifier
  ///   - `senderId`: Your user ID
  ///   - `chainKey`: 32-byte AES chain key (base64)
  ///   - `signingKey`: Ed25519 public signing key (base64) — private key stays local
  ///   - `iteration`: 0 (initial state)
  ///
  /// You must encrypt this distribution with each member's 1-to-1 session and
  /// send it to them (e.g., as a special control message). After all members
  /// have your sender key, you can broadcast group messages.
  ///
  /// Each member generates their own sender key and distributes it to the group.
  /// When Bob sends a group message, all members decrypt using Bob's sender key.
  ///
  /// Example:
  /// ```dart
  /// final distribution = await manager.generateGroupSenderKey('group-123');
  ///
  /// for (final member in groupMembers) {
  ///   final encrypted = await manager.encryptMessage(
  ///     member.userId,
  ///     member.deviceId,
  ///     jsonEncode(distribution.toJson()),
  ///   );
  ///   await sendToServer(encrypted);
  /// }
  /// ```
  Future<SenderKeyDistribution> generateGroupSenderKey(String groupId) async {
    CryptoDebugLogger.log('GROUP', '═══ Generating group Sender Key ═══');
    CryptoDebugLogger.log('GROUP', 'groupId=$groupId');
    final distribution = await _senderKeyManager.generateSenderKey(groupId);
    CryptoDebugLogger.log('GROUP', '═══ Group Sender Key generated ═══');
    return distribution;
  }

  /// Process a received Sender Key distribution from a group member.
  ///
  /// Stores the sender's key so you can decrypt their future group messages.
  /// The [distribution] should be extracted from a 1-to-1 encrypted message
  /// sent by the sender.
  ///
  /// After calling this, you can decrypt group messages from [senderId] using
  /// [decryptGroupMessage]. Each group member distributes their sender key to
  /// all other members, so everyone can decrypt everyone's messages.
  ///
  /// Example:
  /// ```dart
  /// // Alice receives Bob's sender key distribution via 1-to-1 message
  /// final plaintext = await manager.decryptMessage(bobId, bobDevice, envelope);
  /// final distribution = SenderKeyDistribution.fromJson(jsonDecode(plaintext));
  ///
  /// await manager.processGroupSenderKey('group-123', bobId, distribution);
  /// // Now Alice can decrypt Bob's group messages
  /// ```
  Future<void> processGroupSenderKey(
    String groupId,
    String senderId,
    SenderKeyDistribution distribution,
  ) async {
    CryptoDebugLogger.log(
      'GROUP',
      'Processing Sender Key from $senderId for group $groupId',
    );
    await _senderKeyManager.processSenderKeyDistribution(
      groupId,
      senderId,
      distribution,
    );
  }

  /// Encrypt a message for a group using your Sender Key.
  ///
  /// Encrypts [plaintext] with AES-256-CBC using a key derived from your sender
  /// key's chain key. The chain key ratchets forward after each message (forward
  /// secrecy within the group). The ciphertext is authenticated with HMAC-SHA256.
  ///
  /// Returns a JSON string of [SenderKeyMessage] ready for broadcast. All group
  /// members who have your sender key (via [processGroupSenderKey]) can decrypt
  /// this message.
  ///
  /// The message includes an iteration number so recipients can fast-forward
  /// their chain key if they missed messages.
  ///
  /// You must call [generateGroupSenderKey] and distribute your sender key to
  /// all members before calling this method.
  ///
  /// Throws [StateError] if you haven't generated a sender key for this group.
  Future<String> encryptGroupMessage(String groupId, String plaintext) async {
    CryptoDebugLogger.log('GROUP', 'Encrypting group message for $groupId');
    final padded = MessagePadding.padString(plaintext);
    final senderKeyMessage = await _senderKeyManager.encrypt(groupId, padded);
    return jsonEncode(senderKeyMessage.toJson());
  }

  /// Decrypt a group message from a specific sender.
  ///
  /// Decrypts a [SenderKeyMessage] (JSON string) from [senderId] using their
  /// sender key (previously received via [processGroupSenderKey]). Verifies
  /// the HMAC signature and advances the sender key's chain to the message
  /// iteration.
  ///
  /// If the message iteration is ahead of the stored chain state, the chain
  /// is fast-forwarded (up to 256 iterations) to catch up. This handles
  /// out-of-order delivery or missed messages.
  ///
  /// Returns the decrypted plaintext string (after unpadding).
  ///
  /// Throws:
  ///   - [StateError] if you don't have the sender's sender key (call [processGroupSenderKey] first)
  ///   - [StateError] if HMAC verification fails (tampered message)
  ///   - [StateError] if iteration is behind stored state (replay attack)
  ///   - [StateError] if too many iterations skipped (DoS protection)
  Future<String> decryptGroupMessage(
    String groupId,
    String senderId,
    String ciphertext,
  ) async {
    CryptoDebugLogger.log(
      'GROUP',
      'Decrypting group message from $senderId in $groupId',
    );
    final messageJson = jsonDecode(ciphertext) as Map<String, dynamic>;
    final senderKeyMessage = SenderKeyMessage.fromJson(messageJson);
    try {
      final paddedPlaintext = await _senderKeyManager.decrypt(
        groupId,
        senderId,
        senderKeyMessage,
      );
      return MessagePadding.unpadString(paddedPlaintext);
    } catch (e) {
      final msg = e.toString();
      if (msg.contains('signature verification failed')) {
        _eventBus?.emitType(
          SecurityEventType.signatureVerificationFailed,
          sessionId: groupId,
          metadata: {'source': 'sender_key', 'senderId': senderId},
        );
      } else if (msg.contains('Possible replay attack')) {
        _eventBus?.emitType(
          SecurityEventType.replayRejected,
          sessionId: groupId,
          metadata: {'source': 'sender_key', 'senderId': senderId},
        );
      } else if (msg.contains('Too many skipped iterations')) {
        _eventBus?.emitType(
          SecurityEventType.skippedKeyCapReached,
          sessionId: groupId,
          metadata: {'source': 'sender_key', 'senderId': senderId},
        );
      }
      rethrow;
    }
  }

  /// Whether we have our own Sender Key for a group (ready to encrypt).
  Future<bool> hasGroupSenderKey(String groupId) =>
      _senderKeyManager.hasOwnSenderKey(groupId);

  /// Whether we have a specific member's Sender Key (ready to decrypt
  /// their messages).
  Future<bool> hasGroupSenderKeyFor(String groupId, String senderId) =>
      _senderKeyManager.hasSenderKeyFor(groupId, senderId);

  /// Access the underlying SenderKeyManager for advanced operations.
  SenderKeyManager get senderKeyManager => _senderKeyManager;

  // ── Private Helpers ───────────────────────────────────────────────

  String _sessionKey(String recipientId, String deviceId) =>
      '$recipientId:$deviceId';

  Future<KeyPair> _requireIdentityKeyPair() async {
    final kp = await _cryptoStorage.getIdentityKeyPair();
    if (kp == null) {
      throw StateError('Identity key pair not found. Call initialize() first.');
    }
    return kp;
  }

  Future<DoubleRatchet> _loadSession(
    String recipientId,
    String deviceId,
  ) async {
    final key = _sessionKey(recipientId, deviceId);

    if (_sessions.containsKey(key)) {
      CryptoDebugLogger.log(
        'SESSION',
        'Loaded session from MEMORY cache: $key',
      );
      return _sessions[key]!;
    }

    CryptoDebugLogger.log(
      'SESSION',
      'Session not in memory, loading from STORAGE: $key',
    );
    final state = await _cryptoStorage.getSession(recipientId, deviceId);
    if (state == null) {
      CryptoDebugLogger.log(
        'SESSION',
        'NO SESSION FOUND for $key — will throw',
      );
      throw StateError(
        'No session found for $recipientId:$deviceId. '
        'Establish a session first via createSession() or '
        'processPreKeyMessage().',
      );
    }

    CryptoDebugLogger.logRatchetState(
      'SESSION',
      'Loaded from storage',
      state.toJson(),
    );
    final ratchet = DoubleRatchet.fromJson(state.toJson());
    _sessions[key] = ratchet;
    return ratchet;
  }

  // ── Session Auto-Reset Helpers ──────────────────────────────────

  /// Rate-limit threshold: max resets per session pair within the window.
  static const int _maxResetsPerWindow = 3;

  /// Rate-limit window: 1 hour.
  static const Duration _resetWindow = Duration(hours: 1);

  /// Cooldown period: 24 hours after flagging before auto-reset resumes.
  static const Duration _resetCooldown = Duration(hours: 24);

  /// Whether the error type should trigger an automatic session reset.
  bool _shouldTriggerReset(Object error) {
    final msg = error.toString();
    return msg.contains('SecretBoxAuthenticationError') ||
        msg.contains('wrong message authentication code');
  }

  /// Check if the session pair has exceeded the reset rate limit.
  ///
  /// Includes backward-clock defense: if the current wall clock is before
  /// the most recent recorded reset, the clock went backwards (NTP drift,
  /// manual change, or deliberate attack). In that case we conservatively
  /// keep the rate limit active to prevent bypass via clock manipulation.
  Future<bool> _isResetRateLimited(String userId, String deviceId) async {
    final timestamps = await _cryptoStorage.loadResetTimestamps(
      userId,
      deviceId,
    );
    if (timestamps.isEmpty) return false;

    final now = DateTime.now().millisecondsSinceEpoch;
    final lastReset = timestamps.last;

    // Backward-clock defense: if now < lastReset, clock went backwards.
    // Conservatively treat as rate-limited to prevent bypass.
    if (now < lastReset) {
      CryptoDebugLogger.log(
        'RATE_LIMIT',
        'Clock went backwards (now=$now < lastReset=$lastReset). '
            'Keeping rate limit active.',
      );
      return true;
    }

    // Check cooldown: if last reset was >24h ago, clear and allow
    if (now - lastReset > _resetCooldown.inMilliseconds) {
      await _cryptoStorage.clearResetTimestamps(userId, deviceId);
      return false;
    }

    final windowStart = now - _resetWindow.inMilliseconds;

    // Count resets within the window
    final recentResets = timestamps.where((t) => t > windowStart).length;
    return recentResets >= _maxResetsPerWindow;
  }

  /// Record a session reset event with the current timestamp.
  Future<void> _recordSessionReset(String userId, String deviceId) async {
    final timestamps = await _cryptoStorage.loadResetTimestamps(
      userId,
      deviceId,
    );
    timestamps.add(DateTime.now().millisecondsSinceEpoch);
    await _cryptoStorage.saveResetTimestamps(userId, deviceId, timestamps);
  }

  /// Get the number of recent resets for a session pair (within the window).
  Future<int> _getRecentResetCount(String userId, String deviceId) async {
    final timestamps = await _cryptoStorage.loadResetTimestamps(
      userId,
      deviceId,
    );
    final windowStart =
        DateTime.now().millisecondsSinceEpoch - _resetWindow.inMilliseconds;
    return timestamps.where((t) => t > windowStart).length;
  }
}
