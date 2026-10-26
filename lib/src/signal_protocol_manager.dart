import 'dart:async';
import 'dart:convert';
import 'dart:isolate';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;

import 'crypto_secure_storage.dart';
import 'crypto_debug_logger.dart';
import 'crypto_protocol.dart';
import 'crypto_storage.dart';
import 'double_ratchet.dart';
import 'group_roster.dart';
import 'key_bundle_replacement.dart';
import 'key_helper.dart';
import 'message_padding.dart';
import 'models/session_state.dart';
import 'models/signal_keys.dart';
import 'ratchet_batch_decrypt.dart';
import 'receive_commit.dart';
import 'safety_number.dart';
import 'sealed_sender.dart';
import 'sealed_sender_errors.dart';
import 'session_errors.dart';
import 'sealed_sender_trust_policy.dart';
import 'send_commit.dart';
import 'sender_certificate.dart';
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

  /// What this receive established about the sender (R4-C3). Nullable only
  /// for source compatibility; the manager always populates it.
  final SenderAuthentication? senderAuthentication;

  const SealedSenderResult({
    required this.senderId,
    required this.senderDeviceId,
    required this.plaintext,
    this.senderAuthentication,
  });
}

/// Network payload capability issued only after SignalProtocolManager has
/// persisted and re-read `dispatchStarted`. Its constructor is package-private
/// to this manager library, so a prepared high-level handle cannot mint one.
/// Raw journal codecs remain storage plumbing for the trusted same-process
/// crypto layer; they are not an isolation boundary against a caller that can
/// already read the secure-storage backend.
class KeyBundleReplacementDispatch {
  final KeyBundleReplacementSnapshot snapshot;
  final Map<String, dynamic> _keyBundle;

  KeyBundleReplacementDispatch._(this.snapshot, Map<String, dynamic> keyBundle)
    : _keyBundle = _freezeDispatchMap(keyBundle);

  factory KeyBundleReplacementDispatch._fromPersistedJournal(
    KeyBundleReplacementJournal journal,
  ) {
    journal.requireValid();
    if (journal.phase != KeyBundleReplacementPhase.dispatchStarted ||
        !journal.installationApplied ||
        journal.proposal == null) {
      throw StateError('Replacement dispatch intent is not durable');
    }
    final staged = journal.generations.where(
      (generation) => generation.role == OpkGenerationRole.stagedUploadOnly,
    );
    if (staged.length != 1) {
      throw StateError('Replacement dispatch keyring is unavailable');
    }
    final generation = staged.single;
    final signedPreKey = generation.signedPreKey!;
    final kyberKeyPair = generation.kyberKeyPair!;
    return KeyBundleReplacementDispatch._(
      journal.proposal!.snapshot,
      <String, dynamic>{
        'identityKey': generation.identityKey,
        'identitySigningKey': generation.identitySigningKey,
        'signedPreKey': <String, dynamic>{
          'keyId': signedPreKey.keyId,
          'publicKey': signedPreKey.keyPair.publicKey,
          'signature': signedPreKey.signature,
        },
        'oneTimePreKeys': generation.publicOneTimePreKeys
            .map((key) => key.toJson())
            .toList(growable: false),
        'kyberPreKey': <String, dynamic>{
          'keyId': kyberKeyPair.keyId,
          'publicKey': kyberKeyPair.publicKey,
          'signature': generation.kemSignature,
          'cryptoProtocolEpoch': kyberKeyPair.cryptoProtocolEpoch,
          'kemSuite': kyberKeyPair.kemSuite,
          'kemStandard': kyberKeyPair.kemStandard,
          'kemWireVersion': kyberKeyPair.kemWireVersion,
        },
      },
    );
  }

  Map<String, dynamic> toReplacementPayload({required String deviceId}) {
    if (deviceId.isEmpty || deviceId.length > 100) {
      throw ArgumentError.value(deviceId, 'deviceId', 'must be 1..100 chars');
    }
    return _freezeDispatchMap(<String, dynamic>{
      'deviceId': deviceId,
      'expectedBundleRevision': snapshot.expectedBundleRevision,
      'replacementId': snapshot.replacementId,
      'opkGeneration': snapshot.opkGeneration,
      'opkSetDigest': snapshot.opkSetDigest,
      'opkSetCount': snapshot.opkSetCount,
      'opkHighWaterKeyId': snapshot.opkHighWaterKeyId,
      'bundlePublicMaterialDigest': snapshot.bundlePublicMaterialDigest,
      ..._keyBundle,
    });
  }

  Map<String, dynamic> toInitialRegistrationKeyBundle() {
    if (snapshot.expectedBundleRevision != 0 || snapshot.opkGeneration != 1) {
      throw StateError('Dispatch is not an initial registration');
    }
    return _freezeDispatchMap(<String, dynamic>{
      'replacementId': snapshot.replacementId,
      'opkGeneration': snapshot.opkGeneration,
      'opkSetDigest': snapshot.opkSetDigest,
      'opkSetCount': snapshot.opkSetCount,
      'opkHighWaterKeyId': snapshot.opkHighWaterKeyId,
      'bundlePublicMaterialDigest': snapshot.bundlePublicMaterialDigest,
      ..._keyBundle,
    });
  }
}

class KeyBundleReplacementRecoveryRequired extends StateError {
  final KeyBundleReplacementPhase? phase;

  KeyBundleReplacementRecoveryRequired(this.phase)
    : super(
        'Key-bundle replacement recovery is required before messaging '
        '(phase=${phase?.name ?? 'journal-baseline'})',
      );
}

/// The authenticated account still exists, but this device has no local
/// immutable key-bundle journal or private material to resume.
///
/// This is intentionally distinct from corruption and from an interrupted
/// replacement. The application may recover only after fetching the exact
/// owner receipt through an authenticated account request and passing it to
/// [SignalProtocolManager.beginAuthenticatedAccountRecovery].
class MissingKeyBundleJournalRecoveryRequired extends StateError {
  MissingKeyBundleJournalRecoveryRequired()
    : super('Authenticated key-bundle recovery is required before messaging');
}

Map<String, dynamic> _freezeDispatchMap(Map<String, dynamic> source) =>
    Map<String, dynamic>.unmodifiable(
      source.map(
        (key, value) => MapEntry<String, dynamic>(key, _freezeDispatch(value)),
      ),
    );

Object? _freezeDispatch(Object? value) {
  if (value is Map) {
    return _freezeDispatchMap(Map<String, dynamic>.from(value));
  }
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_freezeDispatch));
  }
  return value;
}

Future<RatchetBatchResult> _runRatchetBatchDecryptInIsolate(
  RatchetBatchRequest request,
) => Isolate.run(() => ratchetBatchDecrypt(request));

const bool _isWebRuntime = bool.fromEnvironment('dart.library.js_interop');

Future<X3DHResult> _runX3dhInitiator({
  required KeyPair identityKeyPair,
  required PreKeyBundle recipientBundle,
  required PqxdhPolicy pqxdhPolicy,
  required int transcriptVersion,
}) {
  if (_isWebRuntime) {
    return X3DH.initiateKeyAgreement(
      identityKeyPair: identityKeyPair,
      recipientBundle: recipientBundle,
      pqxdhPolicy: pqxdhPolicy,
      transcriptVersion: transcriptVersion,
    );
  }
  return Isolate.run(
    () => X3DH.initiateKeyAgreement(
      identityKeyPair: identityKeyPair,
      recipientBundle: recipientBundle,
      pqxdhPolicy: pqxdhPolicy,
      transcriptVersion: transcriptVersion,
    ),
  );
}

Future<List<int>> _runX3dhResponder({
  required KeyPair identityKeyPair,
  required SignedPreKey signedPreKey,
  required OneTimePreKey? oneTimePreKey,
  required String senderIdentityKey,
  required String senderEphemeralKey,
  required KyberKeyPair kyberKeyPair,
  required String kyberCiphertext,
  required PreKeyHandshakeRouting routing,
}) {
  Future<List<int>> run() => X3DH.respondKeyAgreement(
    identityKeyPair: identityKeyPair,
    signedPreKey: signedPreKey,
    oneTimePreKey: oneTimePreKey,
    senderIdentityKey: senderIdentityKey,
    senderEphemeralKey: senderEphemeralKey,
    kyberKeyPair: kyberKeyPair,
    kyberCiphertext: kyberCiphertext,
    routing: routing,
  );
  if (_isWebRuntime) return run();
  return Isolate.run(run);
}

class _ValidatedPendingPreKey {
  final String senderEphemeralKey;
  final String kyberCiphertext;
  final PreKeyHandshakeRouting routing;

  const _ValidatedPendingPreKey({
    required this.senderEphemeralKey,
    required this.kyberCiphertext,
    required this.routing,
  });
}

/// Private, immutable authority produced by one exact journal read and used by
/// the responder until post-auth tombstoning completes under the same lock.
class _RoutedPreKeyMaterial {
  final int journalRevision;
  final PreKeyHandshakeRouting routing;
  final SignedPreKey signedPreKey;
  final KyberKeyPair kyberKeyPair;
  final OneTimePreKey? oneTimePreKey;
  final OpkGenerationRole role;

  const _RoutedPreKeyMaterial({
    required this.journalRevision,
    required this.routing,
    required this.signedPreKey,
    required this.kyberKeyPair,
    required this.oneTimePreKey,
    required this.role,
  });
}

class _PlannedOpkConsumption {
  final String journalAfter;
  final int remaining;
  final bool isLatestAccepted;

  const _PlannedOpkConsumption({
    required this.journalAfter,
    required this.remaining,
    required this.isLatestAccepted,
  });
}

class _ReceiveCandidate {
  final ReceiveReceipt receipt;
  final String plaintext;
  final List<ReceiveStorageMutation> mutations;

  /// One-time-prekey pool state after this candidate's consumption, or null if
  /// the handshake used no one-time prekey. Reported only after the durable
  /// commit, so a provisional receive never triggers a replenishment upload.
  final _PlannedOpkConsumption? opkConsumption;

  /// What the receive established about the sender (R4-C3).
  final SenderAuthentication senderAuthentication;

  const _ReceiveCandidate({
    required this.receipt,
    required this.plaintext,
    required this.mutations,
    required this.senderAuthentication,
    this.opkConsumption,
  });
}

/// Per-delivery inbound trust context (R4-C3), threaded from the public receive
/// entry points into the PreKey responders. The certificate facts are set on
/// the sealed lane from the verified [SealedSenderContent]; the first-contact
/// outcome is recorded by [SignalProtocolManager._authorizeFirstContactUnlocked].
class _InboundTrust {
  _InboundTrust.direct(this.approval)
    : sealed = false,
      certified = false,
      certificateKeyId = null,
      certificateIgnored = false;

  _InboundTrust.sealed(SealedSenderContent content, this.approval)
    : sealed = true,
      certified = content.certified,
      certificateKeyId = content.certificateKeyId,
      certificateIgnored = content.certificateIgnored;

  final bool sealed;
  final bool certified;
  final String? certificateKeyId;
  final bool certificateIgnored;
  final FirstContactApproval? approval;
  bool firstContact = false;
  FirstContactApprovalSource? approvalSource;

  SenderAuthentication get authentication => SenderAuthentication(
    certified: certified,
    certificateKeyId: certificateKeyId,
    certificateIgnored: certificateIgnored,
    firstContact: firstContact,
    approvalSource: approvalSource,
  );
}

class _SendCandidate {
  final Map<String, dynamic> envelope;
  final List<ReceiveStorageMutation> mutations;

  const _SendCandidate({required this.envelope, required this.mutations});
}

/// The answer of [SignalProtocolManager.peerIdentityPinStatus].
enum PeerIdentityPinStatus {
  /// A pin this device holds for the contact equals the key.
  matchesPin,

  /// The contact has no pinned identity on this device.
  noPin,

  /// The contact has pins and none equals the key: an identity change that
  /// needs the user's explicit re-verification.
  contradictsPin,
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
///   1. Fresh registration: [wipeForFreshRegistration], then [initialize]
///   2. Prepare with [prepareInitialKeyBundleRegistration], install, then call
///      [markKeyBundleReplacementDispatchStarted] before the first HTTP byte
///   3. Persist the exact server receipt with [acknowledgeKeyBundleReplacement]
///   4. Existing accounts resume/reconcile any journal phase before messaging;
///      later rotations use [prepareKeyBundleReplacement]
///
/// Sessions are cached in memory and persisted to [CryptoSecureStorage] after
/// every operation. The cache is cleared on panic wipe.
///
/// Example:
/// ```dart
/// final manager = SignalProtocolManager(secureStorage: storage);
///
/// // Explicit fresh-account registration
/// await manager.wipeForFreshRegistration();
/// await manager.initialize();
/// final prepared = await manager.prepareInitialKeyBundleRegistration();
/// await manager.installKeyBundleReplacement(prepared);
/// final dispatch =
///     await manager.markKeyBundleReplacementDispatchStarted(prepared);
/// final acceptance = await register(
///   dispatch.toInitialRegistrationKeyBundle(),
/// );
/// await manager.acknowledgeKeyBundleReplacement(
///   snapshot: prepared,
///   acceptance: acceptance,
/// );
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

  // Journal transitions are composite read-modify-write operations. Distinct
  // adapter objects can still address the same account/backend, so object
  // identity is not a safe lock key. Serialize every lifecycle transition in
  // this isolate until the storage interface exposes an atomic CAS primitive.
  static Future<void> _sharedKeyLifecycleTail = Future<void>.value();
  static Future<void> _sharedReceiveTail = Future<void>.value();
  static final Object _keyLifecycleLockZoneKey = Object();
  static final Object _receiveLockZoneKey = Object();
  Future<void> _sealedDecryptTail = Future<void>.value();

  /// True when a pending receive genuinely conflicts with this operation.
  ///
  /// The blanket rule — refuse every key-lifecycle and receive operation while
  /// any receive awaits host acknowledgement — is far wider than the invariant
  /// it protects. That invariant is only that nobody mutates the exact storage
  /// slots a prepared commit has captured a pre-state digest for. In practice
  /// the blanket rule meant that receiving a message from one contact made
  /// sending to a *different* contact throw, and every media-key lookup fail,
  /// for the whole host-persistence window — which happens on every single
  /// inbound message.
  ///
  /// Scoping to the affected peer keeps the protection exactly where it is
  /// needed. Unscoped callers keep the conservative behaviour, and a commit is
  /// still verified against its pre-state at apply time, so an interfering
  /// write is detected rather than silently applied.
  Future<bool> _pendingReceiveConflicts(String? scope) async {
    final pending = (await _readReceiveCommitJournalUnlocked()).pending;
    if (pending == null) return false;
    if (scope == null) return true;
    final receipt = pending.receipt;
    return _sessionKey(receipt.senderId, receipt.senderDeviceId) == scope;
  }

  Future<bool> _pendingSendConflicts(String? scope) async {
    final pending = (await _readSendCommitJournalUnlocked()).pending;
    if (pending == null) return false;
    if (scope == null) return true;
    final receipt = pending.receipt;
    return _sessionKey(receipt.recipientId, receipt.recipientDeviceId) == scope;
  }

  Future<T> _withKeyLifecycleLock<T>(
    Future<T> Function() action, {
    bool allowPendingReceive = false,
    bool allowPendingSend = false,
    String? pendingScope,
  }) async {
    if (Zone.current[_keyLifecycleLockZoneKey] == true) {
      if (!allowPendingReceive &&
          await _pendingReceiveConflicts(pendingScope)) {
        throw StateError('A durable receive is pending host acknowledgement');
      }
      if (!allowPendingSend && await _pendingSendConflicts(pendingScope)) {
        throw StateError('A durable send is pending host acknowledgement');
      }
      return action();
    }
    final previous = _sharedKeyLifecycleTail;
    final release = Completer<void>();
    _sharedKeyLifecycleTail = release.future;
    await previous;
    try {
      return await runZoned(() async {
        if (!allowPendingReceive &&
            await _pendingReceiveConflicts(pendingScope)) {
          throw StateError('A durable receive is pending host acknowledgement');
        }
        if (!allowPendingSend && await _pendingSendConflicts(pendingScope)) {
          throw StateError('A durable send is pending host acknowledgement');
        }
        return action();
      }, zoneValues: <Object, Object>{_keyLifecycleLockZoneKey: true});
    } finally {
      release.complete();
    }
  }

  Future<T> _withReceiveLock<T>(
    Future<T> Function() action, {
    bool allowPendingReceive = false,
    bool allowPendingSend = false,
    String? pendingScope,
  }) async {
    if (Zone.current[_receiveLockZoneKey] == true) {
      if (!allowPendingReceive &&
          await _pendingReceiveConflicts(pendingScope)) {
        throw StateError('A durable receive is pending host acknowledgement');
      }
      if (!allowPendingSend && await _pendingSendConflicts(pendingScope)) {
        throw StateError('A durable send is pending host acknowledgement');
      }
      return action();
    }
    final previous = _sharedReceiveTail;
    final release = Completer<void>();
    _sharedReceiveTail = release.future;
    await previous;
    try {
      return await runZoned(() async {
        if (!allowPendingReceive &&
            await _pendingReceiveConflicts(pendingScope)) {
          throw StateError('A durable receive is pending host acknowledgement');
        }
        if (!allowPendingSend && await _pendingSendConflicts(pendingScope)) {
          throw StateError('A durable send is pending host acknowledgement');
        }
        return action();
      }, zoneValues: <Object, Object>{_receiveLockZoneKey: true});
    } finally {
      release.complete();
    }
  }

  Future<T> _withSealedDecryptLock<T>(Future<T> Function() action) async {
    final previous = _sealedDecryptTail;
    final release = Completer<void>();
    _sealedDecryptTail = release.future;
    await previous;
    try {
      return await action();
    } finally {
      release.complete();
    }
  }

  /// Stream-based security event bus for observability.
  ///
  /// If provided, security-relevant events (session resets, key rotations,
  /// exhaustion warnings, etc.) are emitted here. The host app can subscribe
  /// via `bus.events.listen(...)` to drive UI or telemetry.
  final SecurityEventBus? _eventBus;

  /// In-memory nonce deduplication set for Sealed Sender replay protection.
  Set<String> _seenNonces = {};

  /// Nonces currently being authenticated/decrypted. This closes the race in
  /// which two concurrent deliveries could both pass the persisted replay
  /// check before either one records success.
  final Set<String> _inFlightSealedNonces = <String>{};

  /// Replay-window bound passed to [SealedSenderEnvelope.unseal]. The PERSISTENT
  /// [_seenNonces] set (loadSeenNonces/saveSeenNonces) is the actual replay
  /// control; this timestamp bound only rejects absurdly stale or far-future
  /// envelopes. The library default (5 min) silently broke store-and-forward
  /// delivery — any 1:1 message first opened > ~5 min after sealing (i.e. the
  /// recipient was offline) was rejected forever while the sender saw
  /// delivered/read (audit 2026-06 showstopper #4). 30 days covers realistic
  /// offline gaps; widening it is safe because nonce dedup, not this window,
  /// prevents replays.
  static const int _sealedSenderReplayWindowMs = 30 * 24 * 60 * 60 * 1000;

  /// PERF FLAG — run the CPU-heavy Double Ratchet decrypt in a background
  /// isolate (audit 2026-06: bulk decrypt on chat open stalls the UI ~50-200ms
  /// per message). The session is loaded on the main isolate; only the pure
  /// decrypt runs off-thread. Covers BOTH direct type-2 messages AND
  /// sealed-sender inner messages (they route through _decryptMessageInner).
  /// On any decrypt failure we fall back to the inline path on the UNTOUCHED
  /// cached ratchet so typed authentication rejection, replay and skipped-key
  /// handling run on the owning isolate. Default off; enable via DI to test
  /// on-device.
  static bool decryptOffMainThread = false;

  /// In-memory session cache: "recipientId:deviceId" → DoubleRatchet.
  final Map<String, DoubleRatchet> _sessions = {};

  /// Fingerprint of private key-bundle material fully validated in this
  /// manager process. Journal phase/receipt/role writes do not change private
  /// bytes, so repeating all X25519 pair derivations for those metadata-only
  /// transitions made Android login take minutes. The fingerprint includes
  /// the current flat identity/signing slots and every generation private key;
  /// any real material change forces a fresh full validation.
  String? _validatedJournalPrivateMaterialFingerprint;

  /// Drop the in-memory ratchet session cache. Called on panic wipe AND when
  /// the app backgrounds (registered with MemoryGuard) so ratchet state does
  /// not linger in the Dart heap while the device may be inspected. Sessions
  /// reload transparently from secure storage on next use, so this is safe to
  /// call at any idle moment and never loses a message.
  void wipeAllSessions() {
    _sessions.clear();
  }

  /// Logout-grade wipe: drop every piece of in-memory state held by this
  /// manager. Persistent secure-storage keys are wiped separately by the
  /// caller (via prefix scan over `crypto_*`) — we deliberately do NOT call
  /// `_cryptoStorage.wipeAll()` here because the underlying adapter shares
  /// the app's secure storage and `clearAll()` would also nuke device_id
  /// and onboarding flags.
  void wipeAll() {
    _sessions.clear();
    _sessionsMarkedForReestablishment.clear();
    _validatedJournalPrivateMaterialFingerprint = null;
  }

  /// Account-bound wipe for a fresh registration on the same device.
  ///
  /// Drops in-memory state and delegates to the storage adapter's atomic
  /// account wipe. Production uses delete-all plus a tiny device-only
  /// whitelist restore, so dynamic ratchets, pending handshakes, replay state
  /// and sender keys from a previous account cannot remain reachable.
  ///
  /// Call this before [initialize] when the user is creating a new
  /// account so [initialize] regenerates a fresh 20-key bundle instead
  /// of replaying accumulated state from a previous account on the same
  /// device.
  /// This is the break-glass reset and must never be gated on the state it is
  /// about to erase. Both locks are taken with `allowPendingReceive: true` so
  /// neither an unresolved pending receive nor an undecodable receive-WAL blob
  /// can block it: the guard preamble would otherwise read and decode the
  /// journal, and a corrupt journal would make every entry point — including
  /// this reset — throw forever, leaving reinstallation as the only recovery.
  /// `clearAccountScopedValues()` clears the whole account scope, so the
  /// receive WAL key is erased with everything else.
  Future<void> wipeForFreshRegistration() => _withReceiveLock(
    () => _withKeyLifecycleLock(
      () async {
        _sessions.clear();
        _seenNonces.clear();
        _inFlightSealedNonces.clear();
        _sessionsMarkedForReestablishment.clear();
        _validatedJournalPrivateMaterialFingerprint = null;
        await _cryptoStorage.wipeForFreshRegistration();
      },
      allowPendingReceive: true,
      allowPendingSend: true,
    ),
    allowPendingReceive: true,
    allowPendingSend: true,
  );

  /// Sender Key manager for group E2EE.
  late final SenderKeyManager _senderKeyManager;

  /// Optional callback invoked when pre-key replenishment is needed
  /// (legacy source-compatible hook; authentication rejection never invokes
  /// it). Actual low-pool upload signaling uses
  /// [onPreKeyExhaustionWarning] and [SecurityEventType.preKeyReplenishmentNeeded].
  // ignore: unused_field
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

  /// Optional callback for a session that must be re-established (R4-L1,
  /// L1-I2): it has no recorded remote identity, so it can never carry the
  /// identity-bound Double Ratchet v3. Invoked once per session per manager.
  void Function(String peerId, String deviceId)?
  _onSessionReestablishmentNeeded;

  /// Session keys already reported to [_onSessionReestablishmentNeeded].
  final Set<String> _sessionsMarkedForReestablishment = <String>{};

  /// Set the session re-establishment callback (R4-L1). The host should
  /// re-establish that session through its existing reset path, rate-limited,
  /// the next time the user sends to that peer. Never in bulk.
  set onSessionReestablishmentNeeded(
    void Function(String peerId, String deviceId)? callback,
  ) {
    _onSessionReestablishmentNeeded = callback;
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

  /// Hard cap on fresh one-time pre-keys in a versioned registration or full
  /// replacement proposal. Prior generations stay lookup-only in the journal
  /// and never re-enter a later upload.
  static const int maxOneTimePreKeysPerBundle = 100;
  static const String _keyBundleReplacementJournalStorageKey =
      'crypto_e2_bundle_replacement_journal_v1';
  static const String _receiveCommitJournalStorageKey =
      'crypto_e2_receive_commit_journal_v1';
  static const String _sendCommitJournalStorageKey =
      'crypto_e2_send_commit_journal_v1';

  /// Sealed-sender replay-nonce set. Named because the receive WAL must be able
  /// to recognise a mutation of it and reload the in-memory copy; an exact
  /// string collision here silently reopens the replay window.
  static const String _seenNoncesStorageKey = 'crypto_e2_seen_nonces';

  /// Grace period for key expiry checks to tolerate device clock drift.
  /// If a key appears expired by less than this amount, it's still treated
  /// as valid. This prevents false expirations on devices with slightly
  /// fast clocks.
  static const Duration clockDriftGracePeriod = Duration(hours: 1);

  SignalProtocolManager({
    required CryptoSecureStorage secureStorage,
    SecurityEventBus? securityEventBus,
    SealedSenderTrustPolicy sealedSenderTrustPolicy =
        SealedSenderTrustPolicy.legacy,
    Future<IssuedSenderCertificate?> Function()? senderCertificateProvider,
  }) : _cryptoStorage = CryptoStorage(secureStorage: secureStorage),
       _secureStorage = secureStorage,
       _eventBus = securityEventBus,
       _trustPolicy = sealedSenderTrustPolicy,
       _senderCertificateProvider = senderCertificateProvider {
    _senderKeyManager = SenderKeyManager(cryptoStorage: _cryptoStorage);
  }

  /// R4-C3 receive-side trust policy; [SealedSenderTrustPolicy.legacy] keeps
  /// the accept-both rollout behaviour.
  final SealedSenderTrustPolicy _trustPolicy;

  /// R4-C3: host hook that supplies this device's Sender Certificate for
  /// every sealed send that is not given one explicitly. See
  /// [_resolveSenderCertificate].
  final Future<IssuedSenderCertificate?> Function()? _senderCertificateProvider;

  /// The R4-C3 trust policy this manager was built with.
  SealedSenderTrustPolicy get sealedSenderTrustPolicy => _trustPolicy;

  /// Whether a `senderCertificateProvider` was configured.
  bool get hasSenderCertificateProvider => _senderCertificateProvider != null;

  /// R4-C3: the certificate a sealed send uses. Runs BEFORE the send lock and
  /// before any ratchet or journal work, so a slow provider never holds the
  /// lock and a refusal never mutates state.
  ///
  /// An [explicit] certificate always wins and the provider is not called.
  /// Otherwise the provider (if any) is asked once; `null` means a legacy
  /// uncertified send. A provider that throws counts as `null` and emits
  /// [SecurityEventType.senderCertificateProviderFailed]. Under
  /// [SealedSenderTrustPolicy.requireCertifiedSend] a missing certificate
  /// throws [SenderCertificateRequiredError] instead (fail closed, also when
  /// no provider is configured). A provided certificate is then checked by
  /// [_checkSenderCertificateDescribesDevice] exactly like an explicit one: a
  /// stale one throws
  /// `StateError('Sender certificate does not describe this device')` before
  /// any mutation, and the host refetches and retries.
  Future<IssuedSenderCertificate?> _resolveSenderCertificate(
    IssuedSenderCertificate? explicit,
  ) async {
    if (explicit != null) return explicit;
    final provider = _senderCertificateProvider;
    IssuedSenderCertificate? provided;
    if (provider != null) {
      try {
        provided = await provider();
      } on Object {
        _emitTrustEvent(SecurityEventType.senderCertificateProviderFailed);
        provided = null;
      }
    }
    if (provided == null && _trustPolicy.requireCertifiedSend) {
      throw SenderCertificateRequiredError();
    }
    return provided;
  }

  Map<String, String>? get _trustedServerSigningKeys =>
      _trustPolicy.serverCertificateSigningKeys.isEmpty
      ? null
      : _trustPolicy.serverCertificateSigningKeys;

  /// Emit a sanitized R4-C3 event. Telemetry must never be able to suppress
  /// the rejection that follows it.
  void _emitTrustEvent(
    SecurityEventType type, [
    Map<String, dynamic> metadata = const <String, dynamic>{},
  ]) {
    try {
      _eventBus?.emitType(type, metadata: metadata);
    } on Object {
      // Best effort only.
    }
  }

  /// Whether no device of [peerId] — including [deviceId] — has a pinned
  /// identity key yet, i.e. this delivery would seed the contact's FIRST pin.
  /// Uses the same device enumeration as [_contactIdentityIsConsistentUnlocked].
  Future<bool> _isFirstContactUnlocked(String peerId, String deviceId) async {
    if (await _cryptoStorage.getSessionIdentityKey(peerId, deviceId) != null) {
      return false;
    }
    for (final device in await _cryptoStorage.getSessionDevices(peerId)) {
      if (await _cryptoStorage.getSessionIdentityKey(peerId, device) != null) {
        return false;
      }
    }
    return true;
  }

  /// R4-C3 / A1-H1: refuse to seed a NEW identity pin from an unverified first
  /// contact when the policy requires verification. Must run after the pinned
  /// identity checks and BEFORE any X3DH, one-time-prekey or session work.
  ///
  /// `requireCertified` implies this on the direct lane too: a direct envelope
  /// can never carry a certificate, so without it the relay could bypass
  /// enforcement simply by delivering a first contact as type 2.
  Future<void> _authorizeFirstContactUnlocked({
    required _InboundTrust trust,
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
  }) async {
    final firstContact = await _isFirstContactUnlocked(
      senderId,
      senderDeviceId,
    );
    final approval = trust.approval;
    final approved =
        approval != null &&
        approval.matches(
          senderId: senderId,
          senderDeviceId: senderDeviceId,
          senderIdentityKey: senderIdentityKey,
        );
    trust.firstContact = firstContact;
    trust.approvalSource = firstContact && approved ? approval.source : null;
    final required =
        _trustPolicy.requireVerifiedFirstContact ||
        _trustPolicy.requireCertified;
    if (!firstContact || trust.certified || approved || !required) return;
    _emitTrustEvent(SecurityEventType.unverifiedFirstContactRejected, {
      'lane': trust.sealed ? 'sealed' : 'direct',
    });
    throw UnverifiedFirstContactError(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
    );
  }

  /// R4-C3: apply the trust policy to freshly unsealed content, before KEM
  /// routing, identity pins or ratchet state are touched. The caller rolls the
  /// nonce back on any throw.
  Future<_InboundTrust> _admitSealedContentUnlocked(
    SealedSenderContent content,
    FirstContactApproval? approval,
  ) async {
    if (content.certificateIgnored) {
      _emitTrustEvent(SecurityEventType.senderCertificateIgnoredNoPinnedKey);
    }
    if (_trustPolicy.requireCertified && !content.certified) {
      _emitTrustEvent(SecurityEventType.uncertifiedSealedSenderRejected);
      throw UncertifiedSealedSenderError();
    }
    if (content.certified) {
      final pinned = await _cryptoStorage.getPeerSigningKey(
        content.senderId,
        content.senderDeviceId,
      );
      if (pinned != null && pinned != content.senderSigningKey) {
        try {
          _eventBus?.emitType(
            SecurityEventType.peerIdentityKeyChanged,
            sessionId: '${content.senderId}:${content.senderDeviceId}',
            metadata: const <String, dynamic>{
              'reason': 'certificate-signing-key-mismatch',
            },
          );
        } on Object {
          // Telemetry must never be able to suppress the rejection below.
        }
        throw SealedSenderCertificateError(
          SenderCertificateFailure.identityMismatch,
        );
      }
    }
    return _InboundTrust.sealed(content, approval);
  }

  /// Emit [SecurityEventType.senderCertificateRejected] for a certificate
  /// rejection raised anywhere inside [body], then rethrow it unchanged.
  Future<T> _reportingCertificateRejection<T>(Future<T> Function() body) async {
    try {
      return await body();
    } on SealedSenderCertificateError catch (error) {
      _emitTrustEvent(SecurityEventType.senderCertificateRejected, {
        'reason': error.reason.name,
      });
      rethrow;
    }
  }

  static const String _receiveCommitJournalQuarantineKey =
      'crypto_e2_receive_commit_journal_quarantine_v1';

  Future<ReceiveCommitJournal> _readReceiveCommitJournalUnlocked() async {
    final raw = await _secureStorage.read(key: _receiveCommitJournalStorageKey);
    if (raw == null) return ReceiveCommitJournal.empty();
    return ReceiveCommitJournal.decode(raw);
  }

  /// Move an undecodable receive WAL aside so the account is not bricked.
  ///
  /// An undecodable blob — keystore corruption, a partial OS restore, a
  /// downgrade to a build that predates the format — makes every entry point
  /// throw, because the lock preamble decodes the journal. Until now the only
  /// escape was `wipeForFreshRegistration`, which destroys the identity key and
  /// every session: a storage glitch cost the user their account.
  ///
  /// This is safe to do without host confirmation *only* because an undecodable
  /// journal cannot be acted on at all: its pending commit cannot be read, so
  /// no mutation it describes can be applied or rolled back either way. The
  /// blob is preserved under a quarantine key rather than deleted, so it
  /// remains available for diagnosis, and the worst case is that one in-flight
  /// delivery must be resent by the peer.
  ///
  /// Returns true when a corrupt journal was quarantined.
  Future<bool> quarantineCorruptReceiveJournal() => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      final raw = await _secureStorage.read(
        key: _receiveCommitJournalStorageKey,
      );
      if (raw == null) return false;
      try {
        ReceiveCommitJournal.decode(raw);
        return false;
      } on FormatException {
        // Retain only what helps diagnose the corruption, never the blob.
        // A receive WAL's after-images carry the whole key-bundle journal —
        // every remaining one-time prekey private key, the signed-prekey
        // private key, the ML-KEM secret — plus full ratchet state. Keeping
        // the raw blob "for diagnosis" would permanently retain exactly the
        // material the ratchet exists to destroy, in a slot nothing prunes.
        await _secureStorage.write(
          key: _receiveCommitJournalQuarantineKey,
          value: jsonEncode(<String, Object?>{
            'quarantinedAtMs': DateTime.now().millisecondsSinceEpoch,
            'encodedBytes': utf8.encode(raw).length,
            'digest': crypto.sha256.convert(utf8.encode(raw)).toString(),
          }),
        );
        await _secureStorage.delete(key: _receiveCommitJournalStorageKey);
        _emitReceiveJournalQuarantinedBestEffort();
        return true;
      }
    }, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  void _emitReceiveJournalQuarantinedBestEffort() {
    try {
      _eventBus?.emitType(
        SecurityEventType.anomalyDetected,
        metadata: const <String, dynamic>{
          'reason': 'receive-journal-quarantined',
        },
      );
    } on Object {
      // Telemetry must never block recovery.
    }
  }

  Future<void> _writeReceiveCommitJournalUnlocked(
    ReceiveCommitJournal journal,
  ) async {
    journal.requireValid();
    final encoded = journal.encode();
    // A commit that fits at `prepared` must also fit once the phase string
    // grows to `commitDecided`; otherwise `acknowledgeReceive` would throw
    // AFTER the host has durably persisted its row, and the pending would be
    // stuck at `prepared` forever, blocking every later receive.
    final pending = journal.pending;
    if (pending != null && pending.phase == ReceiveCommitPhase.prepared) {
      journal
          .copyWith(
            pending: pending.copyWith(phase: ReceiveCommitPhase.commitDecided),
          )
          .encode();
    }
    await _secureStorage.write(
      key: _receiveCommitJournalStorageKey,
      value: encoded,
    );
    final reread = await _secureStorage.read(
      key: _receiveCommitJournalStorageKey,
    );
    if (reread != encoded) {
      throw StateError('Receive commit journal was not durable');
    }
  }

  Future<SendCommitJournal> _readSendCommitJournalUnlocked() async {
    final raw = await _secureStorage.read(key: _sendCommitJournalStorageKey);
    return raw == null
        ? SendCommitJournal.empty()
        : SendCommitJournal.decode(raw);
  }

  Future<void> _writeSendCommitJournalUnlocked(
    SendCommitJournal journal,
  ) async {
    journal.requireValid();
    final encoded = journal.encode();
    final pending = journal.pending;
    if (pending != null && pending.phase == SendCommitPhase.prepared) {
      journal
          .copyWith(
            pending: pending.copyWith(phase: SendCommitPhase.commitDecided),
          )
          .encode();
    }
    await _secureStorage.write(
      key: _sendCommitJournalStorageKey,
      value: encoded,
    );
    if (await _secureStorage.read(key: _sendCommitJournalStorageKey) !=
        encoded) {
      throw StateError('Send commit journal was not durable');
    }
  }

  Future<ReceiveStorageMutation?> _planReceiveMutationUnlocked(
    String key,
    String? afterValue,
  ) async {
    final beforeValue = await _secureStorage.read(key: key);
    final mutation = ReceiveStorageMutation(
      key: key,
      beforeDigest: ReceiveStorageMutation.digestValue(beforeValue),
      afterValue: afterValue,
    );
    return mutation.beforeDigest == mutation.afterDigest ? null : mutation;
  }

  String _receiveSessionStorageKey(String senderId, String senderDeviceId) =>
      'crypto_e2_session_${senderId}_$senderDeviceId';

  Future<List<ReceiveStorageMutation>> _planNormalReceiveCommitUnlocked({
    required String senderId,
    required String senderDeviceId,
    required DoubleRatchet candidateRatchet,
  }) async {
    final mutation = await _planReceiveMutationUnlocked(
      _receiveSessionStorageKey(senderId, senderDeviceId),
      jsonEncode(candidateRatchet.state.toJson()),
    );
    if (mutation == null) {
      throw StateError('Receive candidate did not advance session state');
    }
    return <ReceiveStorageMutation>[mutation];
  }

  Future<List<ReceiveStorageMutation>> _planPreKeyReceiveCommitUnlocked({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required DoubleRatchet candidateRatchet,
    required String? keyBundleJournalAfter,
    required ReceiveStorageMutation handshakeMutation,
  }) async {
    final sessionDevicesKey = 'crypto_e2_session_devices_$senderId';
    final existingDevicesRaw =
        await _secureStorage.read(key: sessionDevicesKey) ?? '';
    final existingDevices = existingDevicesRaw.isEmpty
        ? <String>[]
        : existingDevicesRaw
              .split(',')
              .where((device) => device.isNotEmpty)
              .toList(growable: true);
    if (!existingDevices.contains(senderDeviceId)) {
      existingDevices.add(senderDeviceId);
    }

    final planned = await Future.wait(<Future<ReceiveStorageMutation?>>[
      _planReceiveMutationUnlocked(
        _receiveSessionStorageKey(senderId, senderDeviceId),
        jsonEncode(candidateRatchet.state.toJson()),
      ),
      _planReceiveMutationUnlocked(
        'crypto_e2_session_ik_${senderId}_$senderDeviceId',
        senderIdentityKey,
      ),
      _planReceiveMutationUnlocked(
        sessionDevicesKey,
        existingDevices.join(','),
      ),
      _planReceiveMutationUnlocked(
        'crypto_e2_peer_cap_${senderId}_$senderDeviceId',
        jsonEncode(const <String, Object>{'supportsPqxdh': true}),
      ),
      _planReceiveMutationUnlocked(
        'crypto_e2_peer_identity_${senderId}_$senderDeviceId',
        senderIdentityKey,
      ),
      _planReceiveMutationUnlocked(
        'crypto_e2_pending_prekey_${senderId}_$senderDeviceId',
        null,
      ),
      if (keyBundleJournalAfter != null)
        _planReceiveMutationUnlocked(
          _keyBundleReplacementJournalStorageKey,
          keyBundleJournalAfter,
        ),
    ]);
    final mutations = planned.whereType<ReceiveStorageMutation>().toList();
    // The handshake tombstone must land in the same atomic mutation set as the
    // session it authorises: committing the session without it would leave the
    // replay window open across a crash.
    mutations.add(handshakeMutation);
    if (mutations.isEmpty) {
      throw StateError('PreKey receive candidate has no durable mutations');
    }
    return mutations;
  }

  Future<ReceiveStorageMutation> _planSealedNonceCommitUnlocked(
    Set<String> candidateNonces,
  ) async {
    final list = candidateNonces.toList();
    final trimmed = list.length > 10000
        ? list.sublist(list.length - 10000)
        : list;
    final mutation = await _planReceiveMutationUnlocked(
      _seenNoncesStorageKey,
      jsonEncode(trimmed),
    );
    if (mutation == null) {
      throw StateError('Sealed nonce was already durable');
    }
    return mutation;
  }

  /// ACCOUNT-GLOBAL, deliberately not keyed by sender.
  ///
  /// The digest already identifies a handshake uniquely — it covers the sender
  /// identity key, the sender ephemeral, the ML-KEM ciphertext and the route.
  /// Keying the tombstone by `(senderId, senderDeviceId)` made the guard
  /// trivially bypassable: on the direct lane both values are supplied by the
  /// relay, so replaying a captured envelope under an invented `senderDeviceId`
  /// landed in an empty namespace and passed. One list, one namespace.
  static const String _preKeyHandshakeStorageKey =
      'crypto_e2_handshake_tombstones';

  /// Stable identity of one X3DH/PQXDH handshake, derived only from the
  /// envelope. Two distinct handshakes cannot collide (the sender ephemeral key
  /// is fresh per handshake), and the same handshake always hashes the same, so
  /// a replay is recognisable no matter what `deliveryId` the relay chooses.
  String _preKeyHandshakeDigest({
    required String senderIdentityKey,
    required String senderEphemeralKey,
    required String kyberCiphertext,
    required PreKeyHandshakeRouting routing,
  }) => crypto.sha256
      .convert(
        utf8.encode(
          jsonEncode(<Object?>[
            'Risaal-PreKey-Handshake-v1',
            senderIdentityKey,
            senderEphemeralKey,
            kyberCiphertext,
            routing.recipientSignedPreKeyId,
            routing.usedOneTimePreKeyId,
            routing.opkRoute.toJson(),
          ]),
        ),
      )
      .toString();

  /// Global across all peers, so the window must be larger than the old
  /// per-peer one. 512 digests is roughly 35 KB.
  static const int _maxRememberedPreKeyHandshakes = 512;

  Future<List<String>> _readPreKeyHandshakesUnlocked() async {
    final raw = await _secureStorage.read(key: _preKeyHandshakeStorageKey);
    if (raw == null || raw.isEmpty) return const <String>[];
    final decoded = jsonDecode(raw);
    if (decoded is! List) {
      throw const FormatException('Corrupt PreKey handshake history');
    }
    return decoded.cast<String>();
  }

  /// Fail closed on a replayed handshake instead of rebuilding the session.
  ///
  /// Rebuilding is what makes the replay dangerous: `initReceiver` produces a
  /// fresh ratchet whose after-image would overwrite the live, advanced one,
  /// destroying the sending chain and diverging the peer permanently.
  Future<void> _requireUnconsumedPreKeyHandshakeUnlocked({
    required String handshakeDigest,
  }) async {
    final seen = await _readPreKeyHandshakesUnlocked();
    if (seen.contains(handshakeDigest)) {
      throw StateError(
        'This PreKey handshake was already completed and cannot be replayed',
      );
    }
  }

  /// A routed PreKey handshake may not replace a session that already exists.
  ///
  /// The tombstone list alone cannot carry this: it is a bounded FIFO, and a
  /// relay can simply flood it with fresh handshakes until a captured one is
  /// evicted, then replay that. Any bounded structure is evictable by whoever
  /// controls delivery volume, so the invariant has to rest on something the
  /// attacker does not control — the presence of a live session.
  ///
  /// A first contact has no session and proceeds. A genuine re-handshake (the
  /// peer reinstalled, or an explicit reset ran) also proceeds, because the
  /// reset path removes the session first. What is refused is exactly the
  /// dangerous case: an old handshake arriving while a live, advanced ratchet
  /// exists, which would otherwise reset the sending chain and diverge the peer.
  Future<void> _requireNoLiveSessionForPreKeyUnlocked({
    required String senderId,
    required String senderDeviceId,
  }) async {
    final existing = await _cryptoStorage.getSession(senderId, senderDeviceId);
    if (existing == null) return;
    // Simultaneous first contact is legitimate: both sides may create a session
    // from their own outbound before either has received anything. That session
    // has consumed no inbound message, so replacing it loses nothing.
    //
    // Once the session HAS received messages, replacing it discards the
    // receiving chain and the replay state that make those messages
    // non-repeatable — which is exactly what an evicted-tombstone replay is
    // trying to achieve. Refuse that, and only that.
    if (existing.receivedMessages.isEmpty) return;
    throw StateError(
      'A PreKey handshake cannot replace a session that has already received '
      'messages; reset the session explicitly first',
    );
  }

  /// Refuse a PreKey handshake that claims an identity key other than the one
  /// already pinned for this peer+device.
  ///
  /// P0-A: the sealed lanes have always done this, but the direct WAL lane and
  /// the legacy responder validated only the FORMAT of `senderIdentityKey` and
  /// then fed it into X3DH and the commit plan. Under this project's threat
  /// model the relay is untrusted, so it can mint a well-formed `prekey`
  /// envelope with its OWN identity key, present it as an established contact,
  /// and silently replace the session, the pinned identity key and the peer
  /// identity record. The victim's next outbound message would then be
  /// encrypted to the attacker, with no error and no UI signal — and because
  /// the takeover rewrites the pin, the sealed-lane guards would afterwards
  /// compare the attacker key against itself and pass.
  ///
  /// Fail closed and raise a security event: an identity change on an
  /// established session must be an explicit, user-visible re-verification, not
  /// something a relay can perform silently.
  Future<void> _requirePinnedSenderIdentityUnlocked({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
  }) async {
    final pinnedIdentityKey = await _cryptoStorage.getSessionIdentityKey(
      senderId,
      senderDeviceId,
    );
    if (pinnedIdentityKey != null) {
      if (pinnedIdentityKey == senderIdentityKey) return;
    } else {
      // No pin for THIS device. Returning here was the hole: `senderDeviceId`
      // is relay-supplied on the direct lane, so an attacker simply invented a
      // device id and landed in an unpinned namespace, bypassing the check
      // entirely.
      //
      // Identity continuity is a property of the CONTACT, not of a device id
      // the relay chooses. If any device already known for this sender has a
      // pinned identity key, a new device claiming a different identity is
      // rejected. A genuinely new contact (no pinned device at all) is still
      // allowed to establish, and a real second device of the same contact
      // presents the same identity key and is allowed too.
      if (await _contactIdentityIsConsistentUnlocked(
        peerId: senderId,
        deviceId: senderDeviceId,
        identityKey: senderIdentityKey,
      )) {
        return;
      }
    }
    try {
      _eventBus?.emitType(
        SecurityEventType.peerIdentityKeyChanged,
        sessionId: '$senderId:$senderDeviceId',
        metadata: const <String, dynamic>{'reason': 'prekey-identity-mismatch'},
      );
    } on Object {
      // Telemetry must never be able to suppress the rejection below.
    }
    throw StateError('PreKey identity mismatch for $senderId');
  }

  /// Whether [identityKey] is consistent with everything already pinned for
  /// [peerId], ignoring [deviceId]'s own pin.
  ///
  /// Identity continuity is a property of the CONTACT, not of a device id the
  /// relay chooses. A contact with no pinned device at all is genuinely new and
  /// allowed to establish; a real second device of a known contact presents the
  /// same identity key and is allowed too. Anything else is a relay inventing a
  /// device id to land in an unpinned namespace.
  Future<bool> _contactIdentityIsConsistentUnlocked({
    required String peerId,
    required String deviceId,
    required String identityKey,
  }) async {
    final knownDevices = await _cryptoStorage.getSessionDevices(peerId);
    var sawPin = false;
    for (final device in knownDevices) {
      if (device == deviceId) continue;
      final pin = await _cryptoStorage.getSessionIdentityKey(peerId, device);
      if (pin == null) continue;
      sawPin = true;
      if (pin == identityKey) return true;
    }
    return !sawPin;
  }

  /// Refuse to use a session whose recorded remote identity disagrees with the
  /// identity pinned for [peerId]:[deviceId] (R4-PKG-SESSION-PIN-CHECK).
  ///
  /// Called on every encrypt and decrypt of an established session, before
  /// any ratchet step, so a refusal leaves the session byte-identical. Both
  /// values must exist to disagree: a pin without a recorded identity is a
  /// record written before the field existed, and it is stamped here (in
  /// memory) with the current pin — the pin it was created under, because the
  /// only sanctioned pin change, [acceptVerifiedPeerIdentity], stamps such
  /// records with the OLD pin before it writes the new one. Returns `true` when
  /// it stamped, so a caller that owns persistence can write the stamp.
  ///
  /// The pin is read on every call rather than cached: the session cache and
  /// the pin live in different stores, and a cached comparison would trust
  /// that no pin ever changes behind it. One secure-storage read per message.
  Future<bool> _requireSessionMatchesPinUnlocked(
    String peerId,
    String deviceId,
    DoubleRatchet ratchet,
  ) async {
    final pin = await _cryptoStorage.getSessionIdentityKey(peerId, deviceId);
    final recorded = ratchet.state.remoteIdentityKey;
    if (recorded == null) {
      if (pin == null) return false;
      ratchet.state.remoteIdentityKey = pin;
      return true;
    }
    if (pin == null || pin == recorded) return false;
    try {
      _eventBus?.emitType(
        SecurityEventType.peerIdentityKeyChanged,
        sessionId: '$peerId:$deviceId',
        metadata: const <String, dynamic>{
          'reason': 'session-identity-mismatch',
        },
      );
    } on Object {
      // Telemetry must never be able to suppress the rejection below.
    }
    throw SessionIdentityMismatchError(peerId, deviceId);
  }

  /// Refuse to build an outbound session whose identity key contradicts what
  /// this device already trusts for that contact.
  ///
  /// This lives here, at the point the pin is written, because every outbound
  /// entry point had the same hole and each was guarded — or not — separately:
  ///
  ///  * `ChatBloc._ensureSession` and `SealedSenderEncoder` compared the pin
  ///    only when a session already existed for the device id the RELAY had
  ///    just named, so naming a fresh device id skipped the comparison;
  ///  * the sender-key redistribution path (`senderkey:request`) performed no
  ///    identity check whatsoever, and would seal the group sender key to a
  ///    relay-chosen device.
  ///
  /// Guarding the caller guards one branch. Guarding the write guards the
  /// invariant: after this, no code path can pin an identity for a contact that
  /// disagrees with a pin that contact already has.
  Future<void> _requireConsistentOutboundIdentityUnlocked(
    PreKeyBundle bundle,
  ) async {
    final existing = await _cryptoStorage.getSessionIdentityKey(
      bundle.userId,
      bundle.deviceId,
    );
    final consistent = existing != null
        ? existing == bundle.identityKey
        : await _contactIdentityIsConsistentUnlocked(
            peerId: bundle.userId,
            deviceId: bundle.deviceId,
            identityKey: bundle.identityKey,
          );
    if (consistent) return;
    try {
      _eventBus?.emitType(
        SecurityEventType.peerIdentityKeyChanged,
        sessionId: '${bundle.userId}:${bundle.deviceId}',
        metadata: const <String, dynamic>{
          'reason': 'outbound-identity-mismatch',
        },
      );
    } on Object {
      // Telemetry must never be able to suppress the rejection below.
    }
    throw StateError(
      'Recipient identity changed; explicit re-verification is required',
    );
  }

  /// Direct (non-WAL) tombstone write for the legacy responder path.
  Future<void> _recordConsumedPreKeyHandshakeUnlocked({
    required String handshakeDigest,
  }) async {
    final seen = await _readPreKeyHandshakesUnlocked();
    if (seen.contains(handshakeDigest)) return;
    final next = <String>[...seen, handshakeDigest];
    final bounded = next.length > _maxRememberedPreKeyHandshakes
        ? next.sublist(next.length - _maxRememberedPreKeyHandshakes)
        : next;
    await _secureStorage.write(
      key: _preKeyHandshakeStorageKey,
      value: jsonEncode(bounded),
    );
  }

  Future<ReceiveStorageMutation> _planPreKeyHandshakeTombstoneUnlocked({
    required String handshakeDigest,
  }) async {
    final seen = await _readPreKeyHandshakesUnlocked();
    final next = <String>[...seen, handshakeDigest];
    final bounded = next.length > _maxRememberedPreKeyHandshakes
        ? next.sublist(next.length - _maxRememberedPreKeyHandshakes)
        : next;
    final mutation = await _planReceiveMutationUnlocked(
      _preKeyHandshakeStorageKey,
      jsonEncode(bounded),
    );
    if (mutation == null) {
      throw StateError('PreKey handshake tombstone did not advance');
    }
    return mutation;
  }

  Future<void> _verifyReceivePreStateUnlocked(
    Iterable<ReceiveStorageMutation> mutations,
  ) async {
    for (final mutation in mutations) {
      mutation.requireValid();
      final current = await _secureStorage.read(key: mutation.key);
      if (ReceiveStorageMutation.digestValue(current) !=
          mutation.beforeDigest) {
        throw StateError('Unacknowledged receive state drift');
      }
    }
  }

  Future<void> _applyReceiveMutationUnlocked(
    ReceiveStorageMutation mutation,
  ) async {
    mutation.requireValid();
    final current = await _secureStorage.read(key: mutation.key);
    final currentDigest = ReceiveStorageMutation.digestValue(current);
    if (currentDigest == mutation.afterDigest) return;
    if (currentDigest != mutation.beforeDigest) {
      throw StateError('Receive commit state drift');
    }
    if (mutation.afterValue == null) {
      await _secureStorage.delete(key: mutation.key);
    } else {
      await _secureStorage.write(
        key: mutation.key,
        value: mutation.afterValue!,
      );
    }
    final durable = await _secureStorage.read(key: mutation.key);
    if (ReceiveStorageMutation.digestValue(durable) != mutation.afterDigest) {
      throw StateError('Receive commit was not durable');
    }
  }

  /// Drop every in-memory copy of state a just-published commit made stale.
  ///
  /// Conservative by design: reloading is always safe, while keeping a stale
  /// entry is not. Keyed on the receipt and the mutation set rather than on the
  /// caller, so it holds for all three commit publishers.
  Future<void> _invalidateCachesForCommittedMutationsUnlocked(
    ReceivePendingCommit pending,
  ) async {
    _sessions.remove(
      _sessionKey(pending.receipt.senderId, pending.receipt.senderDeviceId),
    );
    final mutatedNonces = pending.mutations.any(
      (mutation) => mutation.key == _seenNoncesStorageKey,
    );
    if (mutatedNonces) {
      _seenNonces = await _cryptoStorage.loadSeenNonces();
    }
  }

  Future<void> _recoverReceiveCommitUnlocked() async {
    var journal = await _readReceiveCommitJournalUnlocked();
    final pending = journal.pending;
    if (pending == null) return;

    if (pending.phase == ReceiveCommitPhase.prepared) {
      // Surface the receipt BEFORE verifying, so the host always learns which
      // delivery is blocking it. Verifying first meant drift threw a bare
      // StateError carrying no receipt, and the host could then call neither
      // acknowledge nor abort — the account was stuck with no way to name the
      // thing blocking it.
      throw ReceiveCommitRecoveryRequired(pending.receipt);
    }

    for (final mutation in pending.mutations) {
      await _applyReceiveMutationUnlocked(mutation);
    }
    // Durable state has just moved ahead of memory. Every publisher of a commit
    // must invalidate here, not only `acknowledgeReceive`: the other two callers
    // (`_prepareReceiveCandidateUnlocked` and `_initializeUnlocked`) also apply
    // these mutations, and `_loadSession` is unconditionally cache-first with no
    // CAS on `saveSession`. Publishing without eviction lets the next send write
    // the pre-receive ratchet back over the committed one, and lets a stale
    // whole-set nonce write erase a durably committed replay nonce.
    await _invalidateCachesForCommittedMutationsUnlocked(pending);
    journal = await _readReceiveCommitJournalUnlocked();
    final current = journal.pending;
    if (current == null) {
      final completed = journal.completedForHash(
        pending.receipt.deliveryIdHash,
      );
      if (completed?.matchesExact(pending.receipt) == true) return;
      throw StateError('Receive commit journal changed during recovery');
    }
    if (!current.receipt.matchesExact(pending.receipt) ||
        current.phase != ReceiveCommitPhase.commitDecided) {
      throw StateError('Receive commit journal changed during recovery');
    }
    final completed = <ReceiveReceipt>[...journal.completed, pending.receipt];
    final bounded = completed.length > ReceiveCommitJournal.maxCompletedReceipts
        ? completed.sublist(
            completed.length - ReceiveCommitJournal.maxCompletedReceipts,
          )
        : completed;
    await _writeReceiveCommitJournalUnlocked(
      journal.copyWith(pending: null, completed: bounded),
    );
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
  /// Returns `true` if bootstrap keys were freshly generated. This never grants
  /// upload authority: fresh registration must still pass through the durable
  /// prepare/install/dispatch/receipt journal sequence. Returns `false` when an
  /// accepted journal and its exact current slots were loaded.
  ///
  /// This method is idempotent — calling it multiple times is safe (subsequent
  /// calls load existing keys).
  ///
  /// Example:
  /// ```dart
  /// await manager.wipeForFreshRegistration();
  /// await manager.initialize();
  /// final prepared = await manager.prepareInitialKeyBundleRegistration();
  /// ```
  Future<bool> initialize() => _withReceiveLock(
    () => _withKeyLifecycleLock(_initializeUnlocked, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  /// Durably authorizes recovery of an already-authenticated account whose
  /// local account-scoped crypto storage was erased.
  ///
  /// The receipt is only a monotonic floor. It never claims possession of the
  /// server's old private generation. A fresh local identity and generation
  /// are created and the caller must publish generation N+1 through the normal
  /// durable replacement flow before messaging can start.
  Future<bool> beginAuthenticatedAccountRecovery(
    KeyBundleAcceptedReceipt receipt,
  ) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      receipt.requireValid();
      final existing = await _readKeyBundleReplacementJournalUnlocked();
      if (existing != null) {
        final exactPendingRecovery =
            existing.phase == null &&
            existing.acceptedReceipt == null &&
            existing.adoptedBaselineReceipt == receipt &&
            existing.generations.isEmpty;
        if (exactPendingRecovery) return false;
        if (existing.adoptedBaselineReceipt != null &&
            existing.adoptedBaselineReceipt != receipt) {
          throw const FormatException('Authenticated server receipt drift');
        }
        throw StateError('Local key-bundle history is not empty');
      }

      final hasLocalMaterial =
          await _cryptoStorage.hasCurrentProtocolMarker() ||
          await _cryptoStorage.getIdentityKeyPair() != null ||
          await _cryptoStorage.getSigningKeyPair() != null ||
          await _cryptoStorage.getSignedPreKey() != null ||
          await _cryptoStorage.getKyberKeyPair() != null ||
          (await _cryptoStorage.getOneTimePreKeys()).isNotEmpty;
      if (hasLocalMaterial ||
          await _cryptoStorage.hasInitialRegistrationIntent()) {
        throw StateError(
          'Authenticated recovery requires an empty local crypto store',
        );
      }

      final recovery = KeyBundleReplacementJournal(
        journalRevision: 1,
        phase: null,
        installationApplied: false,
        acceptedReceipt: null,
        pendingAcceptedReceipt: null,
        reservation: null,
        proposal: null,
        generations: const <KeyBundleKeyringGeneration>[],
        adoptedBaselineReceipt: receipt,
      );
      await _persistKeyBundleReplacementJournalUnlocked(recovery);
      return true;
    }, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  /// Replace only an unaccepted generation-1 registration proposal with an
  /// authenticated existing-account recovery baseline.
  ///
  /// The storage adapter's account wipe may also clear host authentication;
  /// callers must preserve and restore their authenticated host credentials
  /// around this explicit transition. No accepted local generation can enter
  /// this path.
  Future<void> replaceUnacceptedFreshRegistrationWithAuthenticatedRecovery(
    KeyBundleAcceptedReceipt receipt,
  ) => _withReceiveLock(
    () => _withKeyLifecycleLock(
      () async {
        receipt.requireValid();
        final journal = await _readKeyBundleReplacementJournalUnlocked();
        final proposal = journal?.proposal;
        final isUnacceptedInitialProposal =
            journal != null &&
            journal.acceptedReceipt == null &&
            journal.adoptedBaselineReceipt == null &&
            proposal != null &&
            proposal.snapshot.expectedBundleRevision == 0 &&
            !receipt.matchesSnapshot(proposal.snapshot);
        if (!isUnacceptedInitialProposal) {
          throw StateError(
            'Only an unaccepted fresh registration can be replaced',
          );
        }

        _sessions.clear();
        _seenNonces.clear();
        _inFlightSealedNonces.clear();
        _sessionsMarkedForReestablishment.clear();
        _validatedJournalPrivateMaterialFingerprint = null;
        await _cryptoStorage.wipeForFreshRegistration();
        await _cryptoStorage.clearInitialRegistrationIntent();
        await _persistKeyBundleReplacementJournalUnlocked(
          KeyBundleReplacementJournal(
            journalRevision: 1,
            phase: null,
            installationApplied: false,
            acceptedReceipt: null,
            pendingAcceptedReceipt: null,
            reservation: null,
            proposal: null,
            generations: const <KeyBundleKeyringGeneration>[],
            adoptedBaselineReceipt: receipt,
          ),
        );
      },
      allowPendingReceive: true,
      allowPendingSend: true,
    ),
    allowPendingReceive: true,
    allowPendingSend: true,
  );

  Future<bool> _initializeUnlocked() async {
    // Warn if storage backend is insecure
    if (_secureStorage.securityLevel == StorageSecurityLevel.insecure) {
      // Always print to console so developers see this even without event bus
      // ignore: avoid_print
      print(
        '[risaal_crypto] ⚠ SECURITY WARNING: Insecure storage backend detected. '
        'Key material is NOT protected by hardware-backed keystore. '
        'Use a CryptoSecureStorage with StorageSecurityLevel.hardwareBacked '
        'or .softwareEncrypted for production.',
      );
      _eventBus?.emitType(SecurityEventType.insecureStorageWarning);
      CryptoDebugLogger.log(
        'SECURITY',
        'WARNING: Insecure storage backend detected',
      );
    }

    // Recover the host-acknowledged receive before loading any session or
    // replay cache. An unacknowledged preparation owns no crypto side effect
    // and is discarded only after its exact pre-state is reverified.
    await _recoverReceiveCommitUnlocked();

    var replacementJournal = await _readKeyBundleReplacementJournalUnlocked();
    if (replacementJournal?.phase == KeyBundleReplacementPhase.installStarted) {
      await _installKeyBundleReplacementUnlocked(
        replacementJournal!.proposal!.snapshot,
      );
      replacementJournal = await _readKeyBundleReplacementJournalUnlocked();
    }
    if (replacementJournal?.phase ==
        KeyBundleReplacementPhase.localAckPending) {
      await _finalizeAcceptedKeyBundleReplacementUnlocked(replacementJournal!);
      replacementJournal = await _readKeyBundleReplacementJournalUnlocked();
    }
    if (replacementJournal != null && replacementJournal.phase != null) {
      throw KeyBundleReplacementRecoveryRequired(replacementJournal.phase);
    }
    final authenticatedRecoveryBootstrap =
        replacementJournal != null &&
        replacementJournal.phase == null &&
        replacementJournal.acceptedReceipt == null &&
        replacementJournal.adoptedBaselineReceipt != null &&
        replacementJournal.generations.isEmpty;
    if (replacementJournal != null &&
        replacementJournal.acceptedReceipt == null &&
        !authenticatedRecoveryBootstrap) {
      throw KeyBundleReplacementRecoveryRequired(null);
    }
    if (replacementJournal == null &&
        !await _cryptoStorage.hasInitialRegistrationIntent()) {
      // An install that predates the journal. Refusing outright was correct
      // while nothing could distinguish it from corruption, but the cost lands
      // entirely on the user: the app fails to start, and the only remedy
      // offered — a fresh-account wipe — destroys the identity key, so every
      // contact sees what looks like an impersonation.
      //
      // Adopt it instead, but only when the local material is complete and
      // self-consistent, and only into QUARANTINE: the imported generation is
      // neither uploadable nor routable, because unreceipted material has no
      // authenticated revision/generation/digest tuple. The identity survives,
      // the keys the device already published survive as provenance, and the
      // device registers a fresh authenticated generation from there.
      //
      // Anything less than complete still throws. A partially-wiped or tampered
      // store must not be adopted as if it were a legitimate history.
      replacementJournal = await _adoptPreJournalInstallUnlocked();
      if (replacementJournal == null) {
        final cleanEmptyStore =
            !await _cryptoStorage.hasCurrentProtocolMarker() &&
            await _cryptoStorage.getIdentityKeyPair() == null &&
            await _cryptoStorage.getSigningKeyPair() == null &&
            await _cryptoStorage.getSignedPreKey() == null &&
            await _cryptoStorage.getKyberKeyPair() == null &&
            (await _cryptoStorage.getOneTimePreKeys()).isEmpty;
        if (cleanEmptyStore) {
          throw MissingKeyBundleJournalRecoveryRequired();
        }
        throw StateError(
          'No immutable key-bundle journal exists; local crypto material is '
          'incomplete or inconsistent',
        );
      }
    }

    // A current marker is an account/identity boundary. Decide it before the
    // existence branches so loss of identity or KEM material can never fall
    // through to first-run generation or legacy cutover under an accepted
    // epoch-2 account.
    final markerCurrent = await _cryptoStorage.hasCurrentProtocolMarker();
    final existing = await _cryptoStorage.getIdentityKeyPair();
    if (markerCurrent && existing == null) {
      if (replacementJournal != null) {
        throw const FormatException('Invalid journal identity material');
      }
      throw StateError(
        'Current protocol identity key is missing; explicit identity '
        'transition is required.',
      );
    }
    if (existing != null) {
      CryptoDebugLogger.log('INIT', 'Identity key pair already exists');
      CryptoDebugLogger.logKeyInfo(
        'INIT',
        'Identity public key',
        existing.publicKey,
      );

      final currentKyber = await _cryptoStorage.getKyberKeyPair();
      if (markerCurrent) {
        if (currentKyber?.isCurrentProtocol != true) {
          throw StateError(
            'Current protocol ML-KEM key is missing or invalid; refusing '
            'legacy cutover of accepted identity state.',
          );
        }
        final signingKeyPair = await _cryptoStorage.getSigningKeyPair();
        if (signingKeyPair == null) {
          if (replacementJournal != null) {
            throw const FormatException('Invalid journal identity material');
          }
          throw StateError(
            'Current protocol signing key is missing; refusing to repair '
            'accepted key material in place.',
          );
        }
        if (replacementJournal != null &&
            (!await SignalKeyHelper.isValidX25519KeyPair(existing) ||
                !await SignalKeyHelper.isValidEd25519KeyPair(signingKeyPair))) {
          throw const FormatException('Invalid journal identity material');
        }
        await _validateCurrentLocalBundleInvariant(
          identityKeyPair: existing,
          signingKeyPair: signingKeyPair,
          kyberKeyPair: currentKyber!,
        );
        if (replacementJournal != null) {
          final authenticatedRecoveryHasGeneratedMaterial =
              replacementJournal.acceptedReceipt == null &&
              replacementJournal.adoptedBaselineReceipt != null &&
              replacementJournal.phase == null &&
              replacementJournal.generations.isEmpty;
          if (authenticatedRecoveryHasGeneratedMaterial) {
            _seenNonces = await _cryptoStorage.loadSeenNonces();
            return true;
          }
          final acceptedReceipt = replacementJournal.acceptedReceipt;
          final acceptedEntries = replacementJournal.generations.where(
            (generation) =>
                generation.role == OpkGenerationRole.acceptedLookupOnly,
          );
          final currentSignedPreKey = await _cryptoStorage.getSignedPreKey();
          if (acceptedReceipt == null ||
              acceptedEntries.length != 1 ||
              jsonEncode(currentSignedPreKey?.toJson()) !=
                  jsonEncode(acceptedEntries.single.signedPreKey!.toJson()) ||
              jsonEncode(currentKyber.toJson()) !=
                  jsonEncode(acceptedEntries.single.kyberKeyPair!.toJson()) ||
              (await _cryptoStorage.getOneTimePreKeys()).isNotEmpty) {
            throw KeyBundleReplacementRecoveryRequired(null);
          }
          // The accepted journal is the authoritative commit point. A crash
          // after that atomic write but before deleting the fresh-registration
          // marker must finish this idempotent cleanup on normal startup.
          await _cryptoStorage.clearInitialRegistrationIntent();
          _seenNonces = await _cryptoStorage.loadSeenNonces();
          return false;
        }
        _seenNonces = await _cryptoStorage.loadSeenNonces();
        final current = await _currentKeyBundleGenerationUnlocked();
        final pending = await _cryptoStorage.getPendingKeyBundleGeneration();
        final revision = await _cryptoStorage.getServerBundleRevision();
        final accepted = await _cryptoStorage
            .getLastAcceptedKeyBundleGeneration();

        if (await _recoverOneTimePreKeyPoolIfNeededUnlocked(
          current: current,
          accepted: accepted,
          revision: revision,
        )) {
          return true;
        }

        // Recover legacy boolean pending records, incomplete rotations and
        // restores where current keys no longer match the last exact ACK.
        // Connecting is forbidden until the coherent current tuple is accepted.
        if (pending != null && pending.matchesExact(current)) return true;
        final currentIsAccepted =
            revision > 0 && accepted != null && accepted.matchesExact(current);
        if (currentIsAccepted) {
          // A proposed generation was persisted before key mutation, but the
          // process died before it became current. The server and current
          // local tuple still agree, so discard only that orphan proposal.
          if (await _cryptoStorage.isKeyBundleUploadPending()) {
            await _cryptoStorage.clearPendingKeyBundleGeneration();
          }
          return false;
        }
        if (await _cryptoStorage.isKeyBundleUploadPending() ||
            revision == 0 ||
            accepted == null ||
            !accepted.matchesExact(current)) {
          await _cryptoStorage.markKeyBundleUploadPending(current);
          return true;
        }
        return false;
      }

      // Hard cutover from unversioned/pqcrypto-0.1 material. Identity and
      // signing keys remain stable, but every derived/session namespace is
      // epoch-2 and therefore old ratchets, pending handshakes, peer
      // capabilities and sender keys are quarantined automatically.
      if (!await _cryptoStorage.hasInitialRegistrationIntent()) {
        throw StateError(
          'Legacy authenticated key material requires an explicit external '
          'migration; refusing destructive local cutover',
        );
      }
      var signingKP = await _cryptoStorage.getSigningKeyPair();
      if (signingKP == null) {
        // Recover an interrupted first initialization from older writers that
        // persisted the identity before the signing key. No current-protocol
        // marker exists, so this material has not been accepted for epoch 2.
        signingKP = await SignalKeyHelper.generateSigningKeyPair();
        await _cryptoStorage.saveSigningKeyPair(signingKP);
      }

      final nextSignedPreKeyId = await _cryptoStorage
          .reserveNextSignedPreKeyId();
      final newSignedPreKey = await SignalKeyHelper.generateSignedPreKey(
        nextSignedPreKeyId,
        signingKP,
      );
      await _cryptoStorage.saveSignedPreKey(newSignedPreKey);
      await _cryptoStorage.saveSignedPreKeyCreatedAt(
        DateTime.now().millisecondsSinceEpoch,
      );

      // Legacy pools may contain key id 0 and are not valid epoch-2 material.
      // Nothing can communicate before this migration completes, so discard
      // the old pool and reserve a fresh positive range. Repeating after a
      // crash only creates safe counter gaps.
      await _cryptoStorage.saveOneTimePreKeys(const <OneTimePreKey>[]);
      final nextPreKeyId = await _cryptoStorage.reserveOneTimePreKeyRange(20);
      final oneTimePreKeys = await SignalKeyHelper.generateOneTimePreKeys(
        nextPreKeyId,
        20,
      );
      await _cryptoStorage.saveOneTimePreKeys(oneTimePreKeys);

      final keyId = await _cryptoStorage.reserveNextKyberKeyId();
      final kyberKP = SignalKeyHelper.generateKyberKeyPair(keyId: keyId);
      await _cryptoStorage.saveKyberKeyPair(kyberKP);
      await _cryptoStorage.saveKyberCreatedAt(
        DateTime.now().millisecondsSinceEpoch,
      );
      await _cryptoStorage.deletePreviousKyberKeyPair();

      // Marker is written last. Any crash before it is treated as an
      // incomplete migration and safely repeated; no communication starts.
      await _markCurrentKeyBundlePendingUnlocked();
      await _cryptoStorage.saveCurrentProtocolMarker();
      _seenNonces = await _cryptoStorage.loadSeenNonces();
      return true;
    }

    CryptoDebugLogger.log('INIT', '═══ First run — generating all keys ═══');

    final authenticatedRecoveryBaseline =
        replacementJournal?.adoptedBaselineReceipt;
    if (authenticatedRecoveryBaseline != null) {
      await _cryptoStorage.advanceKeyIdCountersPast(
        KeyBundleGeneration(
          signedPreKeyId: authenticatedRecoveryBaseline.signedPreKeyId,
          kemKeyId: authenticatedRecoveryBaseline.kemKeyId,
          cryptoProtocolEpoch:
              authenticatedRecoveryBaseline.cryptoProtocolEpoch,
        ),
      );
    }

    // First run — generate both long-term key pairs before persisting either.
    // The signing key is written first: a crash after that write but before
    // identity persistence is safely restartable, while identity-without-
    // signing used to enter an unrecoverable migration loop.
    final identityKP = await SignalKeyHelper.generateIdentityKeyPair();
    final signingKP = await SignalKeyHelper.generateSigningKeyPair();
    await _cryptoStorage.saveSigningKeyPair(signingKP);
    CryptoDebugLogger.logKeyInfo(
      'INIT',
      'Generated Ed25519 signing key',
      signingKP.publicKey,
    );

    await _cryptoStorage.saveIdentityKeyPair(identityKP);
    CryptoDebugLogger.logKeyInfo(
      'INIT',
      'Generated X25519 identity key',
      identityKP.publicKey,
    );

    final signedPreKey = await SignalKeyHelper.generateSignedPreKey(
      await _cryptoStorage.reserveNextSignedPreKeyId(),
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

    final firstPreKeyId = await _cryptoStorage.reserveOneTimePreKeyRange(
      20,
      minimumExclusive: authenticatedRecoveryBaseline?.opkHighWaterKeyId ?? 0,
    );
    final oneTimePreKeys = await SignalKeyHelper.generateOneTimePreKeys(
      firstPreKeyId,
      20,
    );
    await _cryptoStorage.saveOneTimePreKeys(oneTimePreKeys);
    CryptoDebugLogger.log(
      'INIT',
      'Generated ${oneTimePreKeys.length} one-time pre-keys',
    );

    // Kyber (ML-KEM-768) — post-quantum key encapsulation.
    // Post-quantum protection is mandatory: if the FFI binding fails on
    // this platform we abort initialize() rather than silently shipping a
    // classical-only bundle. The caller should surface the error so the
    // user understands the device can't host a Risaal session.
    try {
      final keyId = await _cryptoStorage.reserveNextKyberKeyId();
      final kyberKP = SignalKeyHelper.generateKyberKeyPair(keyId: keyId);
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
        'Kyber key generation failed — aborting initialize()',
        e,
      );
      throw StateError(
        'Kyber-768 key generation failed on this platform: $e. '
        'Post-quantum protection is mandatory.',
      );
    }

    await _markCurrentKeyBundlePendingUnlocked();
    await _cryptoStorage.saveCurrentProtocolMarker();
    CryptoDebugLogger.log('INIT', '═══ Key generation complete ═══');
    return true;
  }

  Future<void> _validateCurrentLocalBundleInvariant({
    required KeyPair identityKeyPair,
    required KeyPair signingKeyPair,
    required KyberKeyPair kyberKeyPair,
  }) async {
    if (!await SignalKeyHelper.isValidX25519KeyPair(identityKeyPair)) {
      throw StateError(
        'Current protocol identity key pair is invalid; refusing realtime '
        'startup until the identity transition is repaired.',
      );
    }
    if (!await SignalKeyHelper.isValidEd25519KeyPair(signingKeyPair)) {
      throw StateError(
        'Current protocol signing key pair is invalid; refusing realtime '
        'startup until the identity transition is repaired.',
      );
    }

    final signedPreKey = await _cryptoStorage.getSignedPreKey();
    if (signedPreKey == null ||
        signedPreKey.keyId <= 0 ||
        signedPreKey.keyId > RisaalCryptoProtocol.maxKeyId ||
        !await SignalKeyHelper.isValidX25519KeyPair(signedPreKey.keyPair)) {
      throw StateError(
        'Current protocol signed pre-key is missing or invalid; refusing '
        'realtime startup.',
      );
    }
    try {
      final signatureBytes = base64Decode(signedPreKey.signature);
      if (signatureBytes.length != 64 ||
          base64Encode(signatureBytes) != signedPreKey.signature ||
          !await SignalKeyHelper.verify(
            signingKeyPair.publicKey,
            base64Decode(signedPreKey.keyPair.publicKey),
            signedPreKey.signature,
          )) {
        throw const FormatException('Invalid signed pre-key signature');
      }
    } on FormatException {
      throw StateError(
        'Current protocol signed pre-key signature is invalid; refusing '
        'realtime startup.',
      );
    } on ArgumentError {
      throw StateError(
        'Current protocol signed pre-key signature is invalid; refusing '
        'realtime startup.',
      );
    }

    if (!SignalKeyHelper.isValidKyberKeyPair(kyberKeyPair)) {
      throw StateError(
        'Current protocol ML-KEM key pair is invalid; refusing realtime '
        'startup.',
      );
    }
  }

  Future<bool> _recoverOneTimePreKeyPoolIfNeededUnlocked({
    required KeyBundleGeneration current,
    required KeyBundleGeneration? accepted,
    required int revision,
  }) async {
    var poolIsUsable = false;
    try {
      final keys = await _cryptoStorage.getOneTimePreKeys();
      await _cryptoStorage.validateOneTimePreKeyPool();
      poolIsUsable = keys.isNotEmpty;
    } on FormatException {
      poolIsUsable = false;
    } on TypeError {
      poolIsUsable = false;
    }

    final recoveryPending = await _cryptoStorage
        .isOneTimePreKeyRecoveryPending();
    if (poolIsUsable && !recoveryPending) return false;

    if (!recoveryPending) {
      // Persist intent before replacing any lost/corrupt pool or rotating the
      // server-visible generation. Every interruption can resume from here.
      await _cryptoStorage.markOneTimePreKeyRecoveryRequested();
    }

    final recoveryTarget = await _cryptoStorage
        .getOneTimePreKeyRecoveryTarget();
    if (poolIsUsable &&
        recoveryTarget != null &&
        revision > 0 &&
        accepted != null &&
        accepted.matchesExact(recoveryTarget) &&
        current.matchesExact(recoveryTarget)) {
      // Authenticated server reconciliation proves the full replacement that
      // carried this target generation committed despite a lost local ACK.
      await _cryptoStorage.clearOneTimePreKeyRecovery();
      return false;
    }

    if (!poolIsUsable) {
      await _cryptoStorage.saveOneTimePreKeys(const <OneTimePreKey>[]);
      final startId = await _cryptoStorage.reserveOneTimePreKeyRange(20);
      await _cryptoStorage.saveOneTimePreKeys(
        await SignalKeyHelper.generateOneTimePreKeys(startId, 20),
      );
    }

    var recoveredCurrent = await _currentKeyBundleGenerationUnlocked();
    if (revision > 0 && accepted != null) {
      if (recoveredCurrent.signedPreKeyId < accepted.signedPreKeyId ||
          recoveredCurrent.kemKeyId < accepted.kemKeyId) {
        throw StateError('Local key ids moved behind the accepted bundle');
      }
      if (recoveredCurrent.signedPreKeyId == accepted.signedPreKeyId) {
        await _rotateSignedPreKeyIfNeededUnlocked(maxAge: Duration.zero);
      }
      if (recoveredCurrent.kemKeyId == accepted.kemKeyId) {
        await _rotateKyberKeyIfNeededUnlocked(maxAge: Duration.zero);
      }
      recoveredCurrent = await _currentKeyBundleGenerationUnlocked();

      // Repair split key/timestamp writes while this durable recovery intent
      // is active, preventing an immediate second age rotation.
      final now = DateTime.now().millisecondsSinceEpoch;
      await _cryptoStorage.saveSignedPreKeyCreatedAt(now);
      await _cryptoStorage.saveKyberCreatedAt(now);
    }

    await _cryptoStorage.saveOneTimePreKeyRecoveryTarget(recoveredCurrent);
    await _cryptoStorage.markKeyBundleUploadPending(recoveredCurrent);
    return true;
  }

  // ── Immutable full key-bundle replacement journal ──────────────

  /// Trusted manager-only raw journal reader. The public storage facade never
  /// returns the private proposal/keyring model, so callers cannot serialize
  /// pre-dispatch upload material by inferring the returned type.
  Future<KeyBundleReplacementJournal?>
  _readKeyBundleReplacementJournalUnlocked({
    bool validateAllPrivateMaterial = false,
  }) async {
    final raw = await _secureStorage.read(
      key: _keyBundleReplacementJournalStorageKey,
    );
    if (raw == null) return null;
    try {
      if (utf8.encode(raw).length >
          KeyBundleReplacementJournal.maxEncodedBytes) {
        throw const FormatException('Oversized key-bundle journal');
      }
      final decoded = jsonDecode(raw);
      if (decoded is! Map) {
        throw const FormatException('Corrupt key-bundle journal');
      }
      final journal = KeyBundleReplacementJournal.fromJson(
        Map<String, dynamic>.from(decoded),
      );
      // Routine startup/reconcile reads verify the journal commitments and
      // current active SPK/KEM separately. Re-deriving every unused OPK pair
      // here made an accepted 100-key journal cost tens of seconds on Android.
      // Any path that persists newly generated/private material still performs
      // the complete cryptographic validation below before writing it.
      if (validateAllPrivateMaterial) {
        await _validateJournalPrivateMaterialOnceUnlocked(journal);
      }
      return journal;
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Corrupt key-bundle journal');
    }
  }

  Future<void> _persistKeyBundleReplacementJournalUnlocked(
    KeyBundleReplacementJournal journal,
  ) async {
    journal.requireValid();
    await _validateJournalPrivateMaterialOnceUnlocked(journal);
    final encoded = jsonEncode(journal.toJson());
    if (utf8.encode(encoded).length >
        KeyBundleReplacementJournal.maxEncodedBytes) {
      throw StateError('Key-bundle journal capacity reached');
    }
    await _secureStorage.write(
      key: _keyBundleReplacementJournalStorageKey,
      value: encoded,
    );
  }

  Future<void> _validateJournalPrivateMaterialOnceUnlocked(
    KeyBundleReplacementJournal journal,
  ) async {
    journal.requireValid();
    final identity = await _cryptoStorage.getIdentityKeyPair();
    final signing = await _cryptoStorage.getSigningKeyPair();
    final generations = journal.generations
        .map(
          (generation) => <Object?>[
            generation.identityKey,
            generation.identitySigningKey,
            generation.kemSignature,
            generation.signedPreKey?.toJson(),
            generation.kyberKeyPair?.toJson(),
            generation.oneTimePreKeys
                .map((key) => key.toJson())
                .toList(growable: false),
          ],
        )
        .toList(growable: false);
    final fingerprint = crypto.sha256
        .convert(
          utf8.encode(
            jsonEncode(<Object?>[
              identity?.toJson(),
              signing?.toJson(),
              generations,
            ]),
          ),
        )
        .toString();
    if (_validatedJournalPrivateMaterialFingerprint == fingerprint) return;
    await _cryptoStorage.validateKeyBundleReplacementJournal(journal);
    _validatedJournalPrivateMaterialFingerprint = fingerprint;
  }

  /// Prepare generation 1 only for an explicit fresh-account registration.
  /// [wipeForFreshRegistration] owns the durable authorization marker; an
  /// existing/legacy account without an immutable server receipt fails closed.
  Future<KeyBundleReplacementSnapshot> prepareInitialKeyBundleRegistration({
    int oneTimePreKeyCount = 20,
  }) => _withKeyLifecycleLock(
    () => _prepareKeyBundleReplacementUnlocked(
      initialRegistration: true,
      acceptedReceipt: null,
      oneTimePreKeyCount: oneTimePreKeyCount,
    ),
  );

  /// Prepare the exact next generation from the journal's accepted receipt.
  /// A caller-supplied receipt is a cross-check only; it cannot bootstrap an
  /// existing account that has no journal provenance.
  Future<KeyBundleReplacementSnapshot> prepareKeyBundleReplacement({
    KeyBundleAcceptedReceipt? acceptedReceipt,
    int oneTimePreKeyCount = 100,
  }) => _withKeyLifecycleLock(
    () => _prepareKeyBundleReplacementUnlocked(
      initialRegistration: false,
      acceptedReceipt: acceptedReceipt,
      oneTimePreKeyCount: oneTimePreKeyCount,
    ),
  );

  Future<KeyBundleReplacementSnapshot> _prepareKeyBundleReplacementUnlocked({
    required bool initialRegistration,
    required KeyBundleAcceptedReceipt? acceptedReceipt,
    required int oneTimePreKeyCount,
  }) async {
    if (oneTimePreKeyCount <= 0 ||
        oneTimePreKeyCount > maxOneTimePreKeysPerBundle) {
      throw ArgumentError.value(
        oneTimePreKeyCount,
        'oneTimePreKeyCount',
        'must be between 1 and $maxOneTimePreKeysPerBundle',
      );
    }

    var journal = await _readKeyBundleReplacementJournalUnlocked();
    if (journal?.phase == KeyBundleReplacementPhase.localAckPending) {
      await _finalizeAcceptedKeyBundleReplacementUnlocked(journal!);
      journal = await _readKeyBundleReplacementJournalUnlocked();
    }
    if (initialRegistration && acceptedReceipt != null) {
      throw StateError('Initial registration cannot accept a prior receipt');
    }
    if (!initialRegistration &&
        acceptedReceipt != null &&
        journal?.acceptedReceipt != null &&
        acceptedReceipt != journal!.acceptedReceipt) {
      throw const FormatException('Authenticated server receipt drift');
    }
    if (journal?.phase != null) {
      final reservation = journal!.reservation!;
      if (reservation.opkSetCount != oneTimePreKeyCount ||
          (initialRegistration != (reservation.expectedBundleRevision == 0))) {
        throw StateError('A different key-bundle replacement is pending');
      }
      if (journal.proposal != null) return journal.proposal!.snapshot;
      return _materializeReservedReplacementUnlocked(journal);
    }

    if (initialRegistration) {
      // An adopted pre-journal install carries an identity but no accepted
      // generation, which is the same shape as a fresh account in every way
      // except the one that matters: the identity is the user's existing one
      // and must not be replaced. It is admitted here rather than being made to
      // set the fresh-account intent, because that intent means "this device
      // has no history" and setting it without a wipe would let stale
      // account-scoped state be replayed into what the rest of the system then
      // treats as a new account.
      final adoptionOnly =
          journal != null &&
          journal.acceptedReceipt == null &&
          journal.generations.length == 1 &&
          journal.generations.single.role ==
              OpkGenerationRole.legacyQuarantined;
      if ((!await _cryptoStorage.hasInitialRegistrationIntent() &&
              !adoptionOnly) ||
          journal?.acceptedReceipt != null ||
          acceptedReceipt != null) {
        throw StateError(
          'Initial registration requires an explicit fresh-account intent',
        );
      }
    } else {
      // An adopted pre-journal install reaches here with no LOCAL receipt,
      // because it never had a journal to record one in. The server still holds
      // the account's authenticated receipt, and handing it in IS the "external
      // authenticated migration" this refusal has always named. It is recorded
      // as the adopted baseline so monotonicity is measured against what the
      // ACCOUNT published rather than a history this device never had.
      //
      // Narrow on purpose: only for a journal that is adoption-only — no
      // accepted receipt and nothing but the legacy quarantine record — so a
      // device with real local history can never have its baseline replaced by
      // a receipt handed in from outside.
      if (journal != null &&
          journal.acceptedReceipt == null &&
          journal.adoptedBaselineReceipt == null &&
          acceptedReceipt != null &&
          journal.generations.length == 1 &&
          journal.generations.single.role ==
              OpkGenerationRole.legacyQuarantined) {
        acceptedReceipt.requireValid();
        journal = KeyBundleReplacementJournal(
          journalRevision: journal.journalRevision + 1,
          phase: journal.phase,
          installationApplied: journal.installationApplied,
          acceptedReceipt: null,
          pendingAcceptedReceipt: journal.pendingAcceptedReceipt,
          reservation: journal.reservation,
          proposal: journal.proposal,
          generations: journal.generations,
          adoptedBaselineReceipt: acceptedReceipt,
        );
        await _persistKeyBundleReplacementJournalUnlocked(journal);
      }
      if (journal?.acceptedReceipt == null &&
          journal?.adoptedBaselineReceipt == null) {
        throw StateError(
          'Immutable server receipt is required; legacy migration is external',
        );
      }
      journal!.acceptedReceipt?.requireValid();
      // Drift is measured against whichever baseline this journal actually has.
      // Comparing only against `acceptedReceipt` made every adopted device
      // drift by construction, because an adopted journal has none — and it
      // also means a second, DIFFERENT receipt cannot silently rebase an
      // already-adopted device onto another account's history.
      final effectiveBaseline =
          journal.acceptedReceipt ?? journal.adoptedBaselineReceipt;
      if (acceptedReceipt != null && acceptedReceipt != effectiveBaseline) {
        throw const FormatException('Authenticated server receipt drift');
      }
    }

    journal ??= KeyBundleReplacementJournal.empty();
    if (journal.generations.isEmpty) {
      journal = await _importFlatPoolAsLegacyQuarantinedUnlocked(journal);
      await _persistKeyBundleReplacementJournalUnlocked(journal);
    }
    if (journal.generations.length >=
        KeyBundleReplacementJournal.maxGenerations) {
      // The keyring is full. Before refusing — which used to be permanent, and
      // meant a device could never rotate or replenish again after eight
      // rotations — retire generations that nothing can still target.
      journal = await _retireExhaustedGenerationsUnlocked(journal);
    }
    if (journal.generations.length >=
        KeyBundleReplacementJournal.maxGenerations) {
      throw StateError(
        'Key-bundle generation keyring is full and no generation is old '
        'enough to retire safely',
      );
    }

    final baseReceipt =
        journal.acceptedReceipt ?? journal.adoptedBaselineReceipt;
    if (baseReceipt != null) {
      await _cryptoStorage.advanceKeyIdCountersPast(
        KeyBundleGeneration(
          signedPreKeyId: baseReceipt.signedPreKeyId,
          kemKeyId: baseReceipt.kemKeyId,
          cryptoProtocolEpoch: baseReceipt.cryptoProtocolEpoch,
        ),
      );
    }
    final signedPreKeyId = await _cryptoStorage.reserveNextSignedPreKeyId();
    final kemKeyId = await _cryptoStorage.reserveNextKyberKeyId();
    final opkFloor = max(
      journal.greatestOneTimePreKeyId,
      baseReceipt?.opkHighWaterKeyId ?? 0,
    );
    final opkStart = await _cryptoStorage.reserveOneTimePreKeyRange(
      oneTimePreKeyCount,
      minimumExclusive: opkFloor,
    );
    final reservation = KeyBundleReplacementReservation(
      expectedBundleRevision: baseReceipt?.bundleRevision ?? 0,
      replacementId: _newReplacementId(),
      opkGeneration: (baseReceipt?.opkGeneration ?? 0) + 1,
      signedPreKeyId: signedPreKeyId,
      kemKeyId: kemKeyId,
      opkStartKeyId: opkStart,
      opkSetCount: oneTimePreKeyCount,
      opkHighWaterKeyId: opkStart + oneTimePreKeyCount - 1,
    );
    journal = KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: KeyBundleReplacementPhase.reserved,
      installationApplied: false,
      acceptedReceipt: journal.acceptedReceipt,
      pendingAcceptedReceipt: null,
      reservation: reservation,
      proposal: null,
      generations: journal.generations,
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
    await _persistKeyBundleReplacementJournalUnlocked(journal);
    return _materializeReservedReplacementUnlocked(journal);
  }

  /// Drop retained generations nothing can still target, and stamp any whose
  /// demotion time is unknown so their grace period starts now.
  ///
  /// Called only when the keyring is full. It is deliberately not a background
  /// sweep: retirement destroys the private material that opens a PreKey
  /// envelope, so it happens at the one moment the alternative is refusing to
  /// rotate at all, and never a moment earlier.
  Future<KeyBundleReplacementJournal> _retireExhaustedGenerationsUnlocked(
    KeyBundleReplacementJournal journal,
  ) async {
    final now = DateTime.now();

    // Journals written before retirement existed carry no demotion time. Their
    // age is genuinely unknown, so it is stamped rather than guessed: the grace
    // period starts at the upgrade, which over-retains and never under-retains.
    final stamped = journal.generations
        .map(
          (generation) =>
              generation.role == OpkGenerationRole.retainedLookupOnly &&
                  generation.demotedAtMillis == null
              ? generation.copyWith(demotedAtMillis: now.millisecondsSinceEpoch)
              : generation,
        )
        .toList(growable: false);

    final retiredIds = retirableGenerationIds(
      generations: [
        for (final generation in stamped)
          (
            opkGeneration: generation.opkGeneration,
            role: generation.role,
            demotedAtMillis: generation.demotedAtMillis,
          ),
      ],
      now: now,
    ).toSet();
    if (retiredIds.isEmpty) {
      if (!_sameGenerationList(stamped, journal.generations)) {
        final restamped = _withGenerations(journal, stamped);
        await _persistKeyBundleReplacementJournalUnlocked(restamped);
        return restamped;
      }
      return journal;
    }

    final kept = stamped
        .where((generation) => !retiredIds.contains(generation.opkGeneration))
        .toList(growable: false);
    final trimmed = _withGenerations(journal, kept);
    await _persistKeyBundleReplacementJournalUnlocked(trimmed);
    CryptoDebugLogger.log(
      'KEYBUNDLE',
      'Retired ${retiredIds.length} generation(s) past the grace window',
    );
    return trimmed;
  }

  bool _sameGenerationList(
    List<KeyBundleKeyringGeneration> a,
    List<KeyBundleKeyringGeneration> b,
  ) {
    if (a.length != b.length) return false;
    for (var index = 0; index < a.length; index++) {
      if (a[index].opkGeneration != b[index].opkGeneration ||
          a[index].demotedAtMillis != b[index].demotedAtMillis) {
        return false;
      }
    }
    return true;
  }

  KeyBundleReplacementJournal _withGenerations(
    KeyBundleReplacementJournal journal,
    List<KeyBundleKeyringGeneration> generations,
  ) => KeyBundleReplacementJournal(
    adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    journalRevision: journal.journalRevision + 1,
    phase: journal.phase,
    installationApplied: journal.installationApplied,
    acceptedReceipt: journal.acceptedReceipt,
    pendingAcceptedReceipt: journal.pendingAcceptedReceipt,
    reservation: journal.reservation,
    proposal: journal.proposal,
    generations: generations,
  );

  /// Adopt an install that predates the replacement journal, or return null if
  /// its material is not complete enough to adopt safely.
  ///
  /// Deliberately quiet about *why* it declines: the caller throws the same
  /// message it always threw, so a tampered store cannot be told apart from an
  /// unsupported one by watching the error.
  Future<KeyBundleReplacementJournal?> _adoptPreJournalInstallUnlocked() async {
    try {
      final adopted = await _importFlatPoolAsLegacyQuarantinedUnlocked(
        KeyBundleReplacementJournal.empty(),
      );
      await _persistKeyBundleReplacementJournalUnlocked(adopted);
      CryptoDebugLogger.log(
        'KEYBUNDLE',
        'Adopted a pre-journal install; legacy material quarantined',
      );
      return adopted;
    } catch (e) {
      // Incomplete, inconsistent, or carrying a legacy ML-KEM key that this
      // epoch refuses to hold. Either way it is not adoptable, and the caller
      // fails closed.
      CryptoDebugLogger.logError(
        'KEYBUNDLE',
        'Pre-journal install is not adoptable',
        e,
      );
      return null;
    }
  }

  Future<KeyBundleReplacementJournal>
  _importFlatPoolAsLegacyQuarantinedUnlocked(
    KeyBundleReplacementJournal journal,
  ) async {
    // This preserves public/private hashes only as uniqueness provenance.
    // Unreceipted flat material has no authenticated revision/generation/
    // digest tuple, so it is deliberately neither uploadable nor routable.
    final identity = await _requireIdentityKeyPair();
    final signing = await _cryptoStorage.getSigningKeyPair();
    final signedPreKey = await _cryptoStorage.getSignedPreKey();
    final kyber = await _cryptoStorage.getKyberKeyPair();
    if (signing == null ||
        signedPreKey == null ||
        kyber?.isCurrentProtocol != true) {
      throw StateError('Current local key material is incomplete');
    }
    final flat = await _cryptoStorage.getOneTimePreKeys();
    await _cryptoStorage.validateOneTimePreKeyPool();
    final kemSignature = await SignalKeyHelper.sign(
      signing.privateKey,
      RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
        keyId: kyber!.keyId!,
        publicKey: kyber.publicKey,
      ),
    );
    return KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: null,
      installationApplied: false,
      acceptedReceipt: null,
      pendingAcceptedReceipt: null,
      reservation: null,
      proposal: null,
      generations: <KeyBundleKeyringGeneration>[
        KeyBundleKeyringGeneration(
          opkGeneration: 0,
          role: OpkGenerationRole.legacyQuarantined,
          identityKey: identity.publicKey,
          identitySigningKey: signing.publicKey,
          kemSignature: kemSignature,
          signedPreKey: signedPreKey,
          kyberKeyPair: kyber,
          publicOneTimePreKeys: flat.map(
            (key) => OneTimePreKeyPublic(
              keyId: key.keyId,
              publicKey: key.keyPair.publicKey,
            ),
          ),
          oneTimePreKeys: flat,
        ),
      ],
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
  }

  Future<KeyBundleReplacementSnapshot> _materializeReservedReplacementUnlocked(
    KeyBundleReplacementJournal journal,
  ) async {
    if (journal.phase != KeyBundleReplacementPhase.reserved ||
        journal.reservation == null ||
        journal.proposal != null) {
      throw StateError('No reserved replacement can be materialized');
    }
    final reservation = journal.reservation!;
    final identity = await _requireIdentityKeyPair();
    final signing = await _cryptoStorage.getSigningKeyPair();
    if (signing == null) {
      throw StateError('Identity signing key is unavailable');
    }
    final signedPreKey = await SignalKeyHelper.generateSignedPreKey(
      reservation.signedPreKeyId,
      signing,
    );
    final kyber = SignalKeyHelper.generateKyberKeyPair(
      keyId: reservation.kemKeyId,
    );
    final oneTimePreKeys = await SignalKeyHelper.generateOneTimePreKeys(
      reservation.opkStartKeyId,
      reservation.opkSetCount,
    );
    final publicOneTimePreKeys =
        KeyBundleReplacementCommitment.canonicalOneTimePreKeys(
          oneTimePreKeys.map(
            (key) => OneTimePreKeyPublic(
              keyId: key.keyId,
              publicKey: key.keyPair.publicKey,
            ),
          ),
        );
    final kemSignature = await SignalKeyHelper.sign(
      signing.privateKey,
      RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
        keyId: kyber.keyId!,
        publicKey: kyber.publicKey,
      ),
    );
    final opkSetDigest = KeyBundleReplacementCommitment.opkSetDigest(
      opkGeneration: reservation.opkGeneration,
      oneTimePreKeys: publicOneTimePreKeys,
    );
    final bundleDigest =
        KeyBundleReplacementCommitment.bundlePublicMaterialDigest(
          identityKey: identity.publicKey,
          identitySigningKey: signing.publicKey,
          signedPreKeyId: signedPreKey.keyId,
          signedPreKeyPublicKey: signedPreKey.keyPair.publicKey,
          signedPreKeySignature: signedPreKey.signature,
          kemKeyId: kyber.keyId!,
          kemPublicKey: kyber.publicKey,
          kemSignature: kemSignature,
          cryptoProtocolEpoch: kyber.cryptoProtocolEpoch!,
          kemSuite: kyber.kemSuite!,
          kemStandard: kyber.kemStandard!,
          kemWireVersion: kyber.kemWireVersion!,
          opkGeneration: reservation.opkGeneration,
          opkSetDigest: opkSetDigest,
          opkSetCount: reservation.opkSetCount,
          opkHighWaterKeyId: reservation.opkHighWaterKeyId,
        );
    final snapshot = KeyBundleReplacementSnapshot(
      expectedBundleRevision: reservation.expectedBundleRevision,
      replacementId: reservation.replacementId,
      opkGeneration: reservation.opkGeneration,
      opkSetDigest: opkSetDigest,
      opkSetCount: reservation.opkSetCount,
      opkHighWaterKeyId: reservation.opkHighWaterKeyId,
      bundlePublicMaterialDigest: bundleDigest,
      signedPreKeyId: signedPreKey.keyId,
      kemKeyId: kyber.keyId!,
      oneTimePreKeyIds: publicOneTimePreKeys.map((key) => key.keyId),
    );
    final proposal = KeyBundleReplacementProposal(
      snapshot: snapshot,
      signedPreKey: signedPreKey,
      kyberKeyPair: kyber,
    );
    final staged = KeyBundleKeyringGeneration(
      opkGeneration: reservation.opkGeneration,
      role: OpkGenerationRole.stagedUploadOnly,
      identityKey: identity.publicKey,
      identitySigningKey: signing.publicKey,
      kemSignature: kemSignature,
      signedPreKey: signedPreKey,
      kyberKeyPair: kyber,
      publicOneTimePreKeys: publicOneTimePreKeys,
      oneTimePreKeys: oneTimePreKeys,
    );
    final prepared = KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: KeyBundleReplacementPhase.prepared,
      installationApplied: false,
      acceptedReceipt: journal.acceptedReceipt,
      pendingAcceptedReceipt: null,
      reservation: reservation,
      proposal: proposal,
      generations: <KeyBundleKeyringGeneration>[...journal.generations, staged],
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
    await _persistKeyBundleReplacementJournalUnlocked(prepared);
    return snapshot;
  }

  Future<void> installKeyBundleReplacement(
    KeyBundleReplacementSnapshot snapshot,
  ) => _withKeyLifecycleLock(
    () => _installKeyBundleReplacementUnlocked(snapshot),
  );

  Future<void> _installKeyBundleReplacementUnlocked(
    KeyBundleReplacementSnapshot snapshot,
  ) async {
    var journal = await _requirePendingReplacementUnlocked(snapshot);
    if (journal.phase == KeyBundleReplacementPhase.prepared) {
      journal = KeyBundleReplacementJournal(
        journalRevision: journal.journalRevision + 1,
        phase: KeyBundleReplacementPhase.installStarted,
        installationApplied: false,
        acceptedReceipt: journal.acceptedReceipt,
        pendingAcceptedReceipt: null,
        reservation: journal.reservation,
        proposal: journal.proposal,
        generations: journal.generations,
        adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
      );
      await _persistKeyBundleReplacementJournalUnlocked(journal);
    }
    if (journal.phase == KeyBundleReplacementPhase.installed ||
        journal.phase == KeyBundleReplacementPhase.dispatchStarted ||
        journal.phase == KeyBundleReplacementPhase.localAckPending) {
      return;
    }
    if (journal.phase != KeyBundleReplacementPhase.installStarted) {
      throw StateError('Replacement is not ready to install');
    }
    await _applyReplacementInstallationUnlocked(journal.proposal!);
    final installed = KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: KeyBundleReplacementPhase.installed,
      installationApplied: true,
      acceptedReceipt: journal.acceptedReceipt,
      pendingAcceptedReceipt: null,
      reservation: journal.reservation,
      proposal: journal.proposal,
      generations: journal.generations,
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
    await _persistKeyBundleReplacementJournalUnlocked(installed);
  }

  Future<void> _applyReplacementInstallationUnlocked(
    KeyBundleReplacementProposal proposal,
  ) async {
    await _cryptoStorage.saveSignedPreKey(proposal.signedPreKey);
    await _cryptoStorage.saveSignedPreKeyCreatedAt(
      proposal.signedPreKey.createdAt.millisecondsSinceEpoch,
    );
    await _cryptoStorage.saveKyberKeyPair(proposal.kyberKeyPair);
    await _cryptoStorage.saveKyberCreatedAt(
      DateTime.now().millisecondsSinceEpoch,
    );
    // The flat pool is migration input only. Upload and exact lookup are owned
    // exclusively by the journal after its legacy copy is durable.
    await _cryptoStorage.saveOneTimePreKeys(const <OneTimePreKey>[]);
  }

  /// Persist dispatch intent, re-read it, and only then return the sole public
  /// payload capability. No pre-intent snapshot exposes a network payload.
  Future<KeyBundleReplacementDispatch> markKeyBundleReplacementDispatchStarted(
    KeyBundleReplacementSnapshot snapshot,
  ) => _withKeyLifecycleLock(() async {
    var journal = await _requirePendingReplacementUnlocked(snapshot);
    if (journal.phase == KeyBundleReplacementPhase.installed) {
      journal = KeyBundleReplacementJournal(
        journalRevision: journal.journalRevision + 1,
        phase: KeyBundleReplacementPhase.dispatchStarted,
        installationApplied: true,
        acceptedReceipt: journal.acceptedReceipt,
        pendingAcceptedReceipt: null,
        reservation: journal.reservation,
        proposal: journal.proposal,
        generations: journal.generations,
        adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
      );
      await _persistKeyBundleReplacementJournalUnlocked(journal);
      journal = (await _readKeyBundleReplacementJournalUnlocked())!;
    }
    if (journal.phase != KeyBundleReplacementPhase.dispatchStarted) {
      throw StateError('Replacement is not ready for dispatch');
    }
    return KeyBundleReplacementDispatch._fromPersistedJournal(journal);
  });

  Future<KeyBundleReplacementSnapshot?> pendingKeyBundleReplacement() =>
      _withKeyLifecycleLock(() async {
        final journal = await _readKeyBundleReplacementJournalUnlocked();
        return journal?.proposal?.snapshot;
      });

  /// Resume only deterministic local work. A dispatched proposal is returned
  /// for byte-identical retry/reconcile; it is never guessed committed.
  Future<KeyBundleReplacementDispatch?> resumeKeyBundleReplacement() =>
      _withKeyLifecycleLock(() async {
        final journal = await _readKeyBundleReplacementJournalUnlocked();
        if (journal == null || journal.phase == null) return null;
        if (journal.phase == KeyBundleReplacementPhase.reserved) {
          await _materializeReservedReplacementUnlocked(journal);
          return null;
        }
        if (journal.phase == KeyBundleReplacementPhase.installStarted) {
          await _installKeyBundleReplacementUnlocked(
            journal.proposal!.snapshot,
          );
          return null;
        }
        if (journal.phase == KeyBundleReplacementPhase.localAckPending) {
          await _finalizeAcceptedKeyBundleReplacementUnlocked(journal);
          return null;
        }
        if (journal.phase == KeyBundleReplacementPhase.dispatchStarted) {
          return KeyBundleReplacementDispatch._fromPersistedJournal(journal);
        }
        return null;
      });

  Future<bool> acknowledgeKeyBundleReplacement({
    required KeyBundleReplacementSnapshot snapshot,
    required KeyBundleAcceptedReceipt acceptance,
  }) => _withKeyLifecycleLock(
    () => _acknowledgeKeyBundleReplacementUnlocked(
      snapshot: snapshot,
      acceptance: acceptance,
    ),
  );

  Future<bool> _acknowledgeKeyBundleReplacementUnlocked({
    required KeyBundleReplacementSnapshot snapshot,
    required KeyBundleAcceptedReceipt acceptance,
  }) async {
    if (!acceptance.matchesSnapshot(snapshot)) {
      throw const FormatException('Server accepted a different replacement');
    }
    var journal = await _readKeyBundleReplacementJournalUnlocked();
    if (journal == null) {
      throw StateError('Key-bundle replacement snapshot is not pending');
    }
    if (journal.phase == null) {
      if (journal.acceptedReceipt == acceptance) {
        // Crash-safe idempotence: the local journal may have finalized before
        // the caller persisted its auth/session token. Exact receipt+snapshot
        // replay is success; any drift remains fail-closed below.
        return false;
      }
      throw StateError('Key-bundle replacement snapshot is not pending');
    }
    if (journal.proposal == null ||
        !journal.proposal!.snapshot.matches(snapshot)) {
      throw StateError('Key-bundle replacement snapshot is not pending');
    }
    if (journal.phase == KeyBundleReplacementPhase.localAckPending) {
      if (journal.pendingAcceptedReceipt != acceptance) {
        throw const FormatException('Pending server acceptance drift');
      }
      await _finalizeAcceptedKeyBundleReplacementUnlocked(journal);
      return true;
    }
    if (journal.phase != KeyBundleReplacementPhase.dispatchStarted) {
      throw StateError('Replacement was not durably dispatched');
    }
    journal = KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: KeyBundleReplacementPhase.localAckPending,
      installationApplied: true,
      acceptedReceipt: journal.acceptedReceipt,
      pendingAcceptedReceipt: acceptance,
      reservation: journal.reservation,
      proposal: journal.proposal,
      generations: journal.generations,
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
    // Receipt durability intentionally precedes role promotion/local ACK.
    await _persistKeyBundleReplacementJournalUnlocked(journal);
    await _finalizeAcceptedKeyBundleReplacementUnlocked(journal);
    return true;
  }

  Future<void> _finalizeAcceptedKeyBundleReplacementUnlocked(
    KeyBundleReplacementJournal journal,
  ) async {
    if (journal.phase != KeyBundleReplacementPhase.localAckPending ||
        journal.pendingAcceptedReceipt == null ||
        journal.proposal == null) {
      throw StateError('No durable server acceptance can be finalized');
    }
    final acceptance = journal.pendingAcceptedReceipt!;
    if (!acceptance.matchesSnapshot(journal.proposal!.snapshot)) {
      throw const FormatException('Pending server acceptance drift');
    }
    await _applyReplacementInstallationUnlocked(journal.proposal!);
    await _cryptoStorage.saveServerBundleRevision(acceptance.bundleRevision);
    await _cryptoStorage.saveLastAcceptedKeyBundleGeneration(
      KeyBundleGeneration(
        signedPreKeyId: acceptance.signedPreKeyId,
        kemKeyId: acceptance.kemKeyId,
        cryptoProtocolEpoch: acceptance.cryptoProtocolEpoch,
        publicMaterialDigest: acceptance.bundlePublicMaterialDigest,
      ),
    );
    await _cryptoStorage.clearPendingKeyBundleGeneration();
    await _cryptoStorage.clearOneTimePreKeyRecovery();
    final promoted = journal.generations
        .map((generation) {
          if (generation.role == OpkGenerationRole.acceptedLookupOnly) {
            // Stamp the moment it stops being current. Retirement is timed from
            // here, never from creation: a bundle fetched while this generation
            // was current can be used to send long afterwards.
            return generation.copyWith(
              role: OpkGenerationRole.retainedLookupOnly,
              demotedAtMillis: DateTime.now().millisecondsSinceEpoch,
            );
          }
          if (generation.role == OpkGenerationRole.stagedUploadOnly) {
            return generation.copyWith(
              role: OpkGenerationRole.acceptedLookupOnly,
              acceptedReceipt: acceptance,
            );
          }
          return generation;
        })
        .toList(growable: false);
    final accepted = KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: null,
      installationApplied: false,
      acceptedReceipt: acceptance,
      pendingAcceptedReceipt: null,
      reservation: null,
      proposal: null,
      generations: promoted,
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
    await _persistKeyBundleReplacementJournalUnlocked(accepted);
    final acceptedGeneration = promoted.singleWhere(
      (generation) => generation.role == OpkGenerationRole.acceptedLookupOnly,
    );
    if (acceptedGeneration.consumedOneTimePreKeyIds.isNotEmpty) {
      _notifyPreKeyGenerationExhaustionBestEffort(
        remaining: acceptedGeneration.oneTimePreKeys.length,
        isLatestAccepted: true,
      );
    }
    await _cryptoStorage.clearInitialRegistrationIntent();
  }

  /// Reconcile an authenticated owner-key-bundle response.
  ///
  /// Parsing happens inside this boundary so the immutable nested receipt is
  /// always cross-checked against the outer revision, generation, digest,
  /// SPK, KEM and public-material commitment. Mutable remaining counts after
  /// a server pop are deliberately ignored.
  Future<bool> reconcileKeyBundleReplacement(
    Map<String, dynamic> ownerKeyBundleData,
  ) => _withKeyLifecycleLock(() async {
    final observed = KeyBundleAcceptedReceipt.fromOwnerKeyBundleData(
      ownerKeyBundleData,
    );
    final journal = await _readKeyBundleReplacementJournalUnlocked();
    if (journal == null) {
      throw StateError('Legacy key-bundle migration is required');
    }
    final effectiveAcceptedReceipt =
        journal.acceptedReceipt ?? journal.adoptedBaselineReceipt;
    if (journal.phase == null) {
      if (effectiveAcceptedReceipt == observed) return false;
      if (effectiveAcceptedReceipt != null &&
          observed.bundleRevision <= effectiveAcceptedReceipt.bundleRevision) {
        throw StateError('Server key-bundle receipt moved backwards');
      }
      throw StateError('Unknown newer server key-bundle receipt');
    }
    final proposal = journal.proposal;
    if (proposal == null) {
      throw StateError('Replacement reservation is not dispatchable');
    }
    if (observed.matchesSnapshot(proposal.snapshot)) {
      return _acknowledgeKeyBundleReplacementUnlocked(
        snapshot: proposal.snapshot,
        acceptance: observed,
      );
    }
    // During authenticated recovery the old server generation is stored as
    // an adopted baseline rather than a locally accepted generation. Seeing
    // that exact receipt means the pending N+1 proposal has not committed yet;
    // preserve it for byte-identical dispatch instead of misclassifying the
    // account's own baseline as an unknown receipt.
    if (effectiveAcceptedReceipt == observed) return false;
    if (observed.replacementId == proposal.snapshot.replacementId) {
      throw const FormatException('Server replacement commitment drift');
    }
    if (effectiveAcceptedReceipt == null &&
        proposal.snapshot.expectedBundleRevision == 0) {
      throw const UnacceptedFreshRegistrationRecoveryRequired();
    }
    assert(() {
      final baseline = effectiveAcceptedReceipt;
      final mismatches = <String>[];
      if (baseline == null) {
        mismatches.add('missingBaseline');
      } else {
        final expected = baseline.toJson();
        final actual = observed.toJson();
        for (final key in expected.keys) {
          if (expected[key] != actual[key]) mismatches.add(key);
        }
      }
      // Field names and monotonic counters only; never print key material,
      // digests, replacement IDs, or payload bytes.
      // ignore: avoid_print
      print(
        '[AUTH_PERF] phase=reconcile.unknown-receipt '
        'fields=${mismatches.join(',')} '
        'baselineRevision=${baseline?.bundleRevision ?? -1} '
        'observedRevision=${observed.bundleRevision} '
        'baselineGeneration=${baseline?.opkGeneration ?? -1} '
        'observedGeneration=${observed.opkGeneration}',
      );
      return true;
    }());
    throw StateError('Unknown server key-bundle receipt');
  });

  Future<KeyBundleReplacementJournal> _requirePendingReplacementUnlocked(
    KeyBundleReplacementSnapshot snapshot,
  ) async {
    final journal = await _readKeyBundleReplacementJournalUnlocked();
    if (journal == null ||
        journal.proposal == null ||
        !journal.proposal!.snapshot.matches(snapshot)) {
      throw StateError('Key-bundle replacement snapshot is not pending');
    }
    return journal;
  }

  void _requireExactGenerationRoute(
    KeyBundleReplacementJournal journal,
    KeyBundleKeyringGeneration generation,
    OpkGenerationRouting route,
  ) {
    final expectedDigest =
        generation.acceptedReceipt?.opkSetDigest ??
        (journal.proposal?.snapshot.opkGeneration == route.opkGeneration
            ? journal.proposal!.snapshot.opkSetDigest
            : null);
    final expectedRevision =
        generation.acceptedReceipt?.opkAcceptedBundleRevision ??
        (journal.proposal?.snapshot.opkGeneration == route.opkGeneration
            ? journal.proposal!.snapshot.expectedBundleRevision + 1
            : null);
    if (expectedRevision != route.bundleRevision ||
        expectedDigest != route.opkSetDigest ||
        generation.role == OpkGenerationRole.legacyQuarantined ||
        (generation.role == OpkGenerationRole.stagedUploadOnly &&
            journal.phase != KeyBundleReplacementPhase.dispatchStarted &&
            journal.phase != KeyBundleReplacementPhase.localAckPending)) {
      throw const FormatException('OPK generation commitment mismatch');
    }
  }

  Future<_RoutedPreKeyMaterial> _resolveRoutedPreKeyMaterialUnlocked(
    PreKeyHandshakeRouting routing,
  ) async {
    routing.requireCurrent();
    final journal = await _readKeyBundleReplacementJournalUnlocked(
      validateAllPrivateMaterial: false,
    );
    if (journal == null) {
      throw StateError('Authenticated OPK generation is unavailable');
    }
    final matches = journal.generations.where(
      (entry) => entry.opkGeneration == routing.opkRoute.opkGeneration,
    );
    if (matches.length != 1) {
      throw StateError('Authenticated OPK generation is unavailable');
    }
    final generation = matches.single;
    _requireExactGenerationRoute(journal, generation, routing.opkRoute);

    final identity = await _cryptoStorage.getIdentityKeyPair();
    final signing = await _cryptoStorage.getSigningKeyPair();
    final signedPreKey = generation.signedPreKey!;
    final kyberKeyPair = generation.kyberKeyPair!;
    final oneTimePreKey = routing.usedOneTimePreKeyId == null
        ? null
        : generation.findOneTimePreKey(routing.usedOneTimePreKeyId!);
    final validX25519Material = identity != null
        ? await SignalKeyHelper.areValidX25519KeyPairs(<KeyPair>[
            identity,
            signedPreKey.keyPair,
            if (oneTimePreKey != null) oneTimePreKey.keyPair,
          ])
        : false;
    if (identity == null ||
        signing == null ||
        generation.identityKey != identity.publicKey ||
        generation.identitySigningKey != signing.publicKey ||
        signedPreKey.keyId != routing.recipientSignedPreKeyId ||
        kyberKeyPair.keyId != routing.kemMetadata.recipientKeyId ||
        (routing.usedOneTimePreKeyId != null && oneTimePreKey == null) ||
        !validX25519Material ||
        !await SignalKeyHelper.isValidEd25519KeyPair(signing) ||
        !SignalKeyHelper.isValidKyberKeyPair(kyberKeyPair)) {
      throw const FormatException('Invalid routed PreKey private material');
    }
    try {
      if (!await SignalKeyHelper.verify(
            signing.publicKey,
            base64Decode(signedPreKey.keyPair.publicKey),
            signedPreKey.signature,
          ) ||
          !await SignalKeyHelper.verify(
            signing.publicKey,
            RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
              keyId: kyberKeyPair.keyId!,
              publicKey: kyberKeyPair.publicKey,
            ),
            generation.kemSignature,
          )) {
        throw const FormatException('Invalid routed PreKey signature');
      }
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Invalid routed PreKey signature');
    }
    return _RoutedPreKeyMaterial(
      journalRevision: journal.journalRevision,
      routing: routing,
      signedPreKey: signedPreKey,
      kyberKeyPair: kyberKeyPair,
      oneTimePreKey: oneTimePreKey,
      role: generation.role,
    );
  }

  /// The sole tombstone authority. The public responder owns the lifecycle
  /// lock and calls this only after the provisional first message authenticates.
  Future<({bool consumed, int remaining, bool isLatestAccepted})>
  _consumeOneTimePreKeyForGenerationUnlocked({
    required _RoutedPreKeyMaterial material,
  }) async {
    if (material.routing.usedOneTimePreKeyId == null) {
      return (consumed: false, remaining: 0, isLatestAccepted: false);
    }
    final plan = await _planOneTimePreKeyConsumptionUnlocked(
      material: material,
    );
    await _secureStorage.write(
      key: _keyBundleReplacementJournalStorageKey,
      value: plan.journalAfter,
    );
    return (
      consumed: true,
      remaining: plan.remaining,
      isLatestAccepted: plan.isLatestAccepted,
    );
  }

  Future<_PlannedOpkConsumption> _planOneTimePreKeyConsumptionUnlocked({
    required _RoutedPreKeyMaterial material,
  }) async {
    final routing = material.routing;
    routing.requireCurrent();
    final keyId = routing.usedOneTimePreKeyId;
    if (keyId == null) {
      throw StateError('No routed one-time pre-key to consume');
    }
    final route = routing.opkRoute;
    final journal = await _readKeyBundleReplacementJournalUnlocked(
      validateAllPrivateMaterial: false,
    );
    if (journal == null ||
        journal.journalRevision != material.journalRevision) {
      throw StateError('Key-bundle journal changed during OPK consume');
    }
    final matches = journal.generations.where(
      (entry) => entry.opkGeneration == route.opkGeneration,
    );
    if (matches.length != 1) {
      throw StateError('Key-bundle journal changed during OPK consume');
    }
    final generation = matches.single;
    _requireExactGenerationRoute(journal, generation, route);
    final currentKey = generation.findOneTimePreKey(keyId);
    if (currentKey == null ||
        generation.role != material.role ||
        jsonEncode(generation.signedPreKey!.toJson()) !=
            jsonEncode(material.signedPreKey.toJson()) ||
        jsonEncode(generation.kyberKeyPair!.toJson()) !=
            jsonEncode(material.kyberKeyPair.toJson()) ||
        jsonEncode(currentKey.toJson()) !=
            jsonEncode(material.oneTimePreKey!.toJson())) {
      throw StateError('Key-bundle journal changed during OPK consume');
    }

    final updatedGeneration = generation.copyWith(
      oneTimePreKeys: generation.oneTimePreKeys.where(
        (value) => value.keyId != keyId,
      ),
      consumedOneTimePreKeyIds: <int>{
        ...generation.consumedOneTimePreKeyIds,
        keyId,
      },
    );
    final updatedJournal = KeyBundleReplacementJournal(
      journalRevision: journal.journalRevision + 1,
      phase: journal.phase,
      installationApplied: journal.installationApplied,
      acceptedReceipt: journal.acceptedReceipt,
      pendingAcceptedReceipt: journal.pendingAcceptedReceipt,
      reservation: journal.reservation,
      proposal: journal.proposal,
      generations: journal.generations.map(
        (entry) => entry.opkGeneration == route.opkGeneration
            ? updatedGeneration
            : entry,
      ),
      adoptedBaselineReceipt: journal.adoptedBaselineReceipt,
    );
    updatedJournal.requireValid();
    final encoded = jsonEncode(updatedJournal.toJson());
    if (utf8.encode(encoded).length >
        KeyBundleReplacementJournal.maxEncodedBytes) {
      throw StateError('Key-bundle journal capacity reached');
    }
    return _PlannedOpkConsumption(
      journalAfter: encoded,
      remaining: updatedGeneration.oneTimePreKeys.length,
      isLatestAccepted: generation.role == OpkGenerationRole.acceptedLookupOnly,
    );
  }

  String _newReplacementId() {
    final random = Random.secure();
    final bytes = List<int>.generate(18, (_) => random.nextInt(256));
    return 'r2.${base64UrlEncode(bytes).replaceAll('=', '')}';
  }

  // ── Key Bundle for Server Upload ──────────────────────────────────

  /// Legacy flat upload builder; always fails closed.
  ///
  /// Only [KeyBundleReplacementDispatch] may produce registration/replacement
  /// bytes, and it is returned only after `dispatchStarted` is durable.
  Future<Map<String, dynamic>> generateKeyBundle() async =>
      throw _legacyKeyBundleApiDisabled();

  Future<Map<String, dynamic>> _generateKeyBundleUnlocked() async {
    final identityKP = await _requireIdentityKeyPair();
    final signingKP = await _cryptoStorage.getSigningKeyPair();
    final signedPreKey = await _cryptoStorage.getSignedPreKey();
    var oneTimePreKeys = await _cryptoStorage.getOneTimePreKeys();

    // SELF-HEAL — the server REQUIRES at least one one-time pre-key
    // (RegisterDto/UploadPreKeysDto: @ArrayMinSize(1)); an empty list is
    // rejected with "oneTimePreKeys must contain at least 1 elements" and blocks
    // account creation. The identity / signed / Kyber keys above loaded fine, so
    // single-value storage works — but the OTPK *list* can come back empty
    // (observed on iOS: a Keychain write may not survive an immediate read, or a
    // wipe/early-return left the pool unfilled). Regenerate + persist a fresh
    // batch here so NO upload path (register / replaceKeyBundle / rotation) can
    // ever ship an empty pool. The in-memory batch is what gets uploaded, and we
    // persist it too so X3DH can consume whichever key the server hands out.
    if (oneTimePreKeys.isEmpty) {
      CryptoDebugLogger.log(
        'KEYBUNDLE',
        'One-time pre-key pool empty at bundle build — regenerating a batch',
      );
      final startId = await _cryptoStorage.reserveOneTimePreKeyRange(20);
      oneTimePreKeys = await SignalKeyHelper.generateOneTimePreKeys(
        startId,
        20,
      );
      await _cryptoStorage.saveOneTimePreKeys(oneTimePreKeys);
    }

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

    if (kyberKP == null) {
      // PQ protection is mandatory: refuse to upload a bundle that would
      // force peers into a classical-only handshake. Callers that catch
      // this must surface a real error to the user — they CANNOT quietly
      // proceed, because the server will reject the upload anyway.
      throw StateError(
        'Kyber key pair not found. Post-quantum protection is mandatory — '
        're-run initialize() on a platform where Kyber key generation '
        'succeeds, or bubble this error up to the UI.',
      );
    }

    if (!kyberKP.isCurrentProtocol) {
      throw StateError(
        'Legacy or unversioned ML-KEM key cannot be uploaded. '
        'Run initialize() to complete the epoch-2 migration.',
      );
    }

    final kyberSignature = await SignalKeyHelper.sign(
      signingKP.privateKey,
      RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
        keyId: kyberKP.keyId!,
        publicKey: kyberKP.publicKey,
      ),
    );

    return {
      'identityKey': identityKP.publicKey, // X25519 DH public key
      'identitySigningKey': signingKP.publicKey, // Ed25519 signing public key
      'signedPreKey': {
        'keyId': signedPreKey.keyId,
        'publicKey': signedPreKey.keyPair.publicKey,
        'signature': signedPreKey.signature,
      },
      // Defensive cap: server rejects bundles with more than
      // [maxOneTimePreKeysPerBundle] one-time pre-keys. Storage can grow
      // beyond that if the replenisher accumulates over a long-lived
      // account. Send the most recent slice — those are the keys most
      // likely to still be live on the server. The full set remains in
      // local storage so we can still answer X3DH from any of them.
      'oneTimePreKeys':
          (oneTimePreKeys.length > maxOneTimePreKeysPerBundle
                  ? oneTimePreKeys.sublist(
                      oneTimePreKeys.length - maxOneTimePreKeysPerBundle,
                    )
                  : oneTimePreKeys)
              .map((k) => {'keyId': k.keyId, 'publicKey': k.keyPair.publicKey})
              .toList(),
      'kyberPreKey': {
        'keyId': kyberKP.keyId,
        'publicKey': kyberKP.publicKey,
        'signature': kyberSignature,
        'cryptoProtocolEpoch': kyberKP.cryptoProtocolEpoch,
        'kemSuite': kyberKP.kemSuite,
        'kemStandard': kyberKP.kemStandard,
        'kemWireVersion': kyberKP.kemWireVersion,
      },
      // NOTE: do NOT add 'createdAt' or other client-only metadata here. This
      // map is the server upload payload (register + replaceKeyBundle + key
      // rotation); the server's KeyBundleDto runs whitelist +
      // forbidNonWhitelisted and rejects any field it does not declare, and it
      // manages its own timestamps. Signed-pre-key age for rotation is tracked
      // locally via getSignedPreKeyCreatedAt(), independent of this map.
    };
  }

  Future<KeyBundleGeneration> _currentKeyBundleGenerationUnlocked() async {
    final signedPreKey = await _cryptoStorage.getSignedPreKey();
    final kyberKeyPair = await _cryptoStorage.getKyberKeyPair();
    if (signedPreKey == null ||
        kyberKeyPair == null ||
        !kyberKeyPair.isCurrentProtocol) {
      throw StateError('Current key-bundle generation is incomplete');
    }
    return _keyBundleGenerationForKeysUnlocked(
      signedPreKey: signedPreKey,
      kyberKeyPair: kyberKeyPair,
    );
  }

  Future<KeyBundleGeneration> _keyBundleGenerationForKeysUnlocked({
    required SignedPreKey signedPreKey,
    required KyberKeyPair kyberKeyPair,
  }) async {
    if (!kyberKeyPair.isCurrentProtocol) {
      throw const FormatException('Legacy ML-KEM key is not uploadable');
    }
    final identityKeyPair = await _requireIdentityKeyPair();
    final signingKeyPair = await _cryptoStorage.getSigningKeyPair();
    if (signingKeyPair == null) {
      throw StateError('Identity signing key is unavailable');
    }
    final kemSignature = await SignalKeyHelper.sign(
      signingKeyPair.privateKey,
      RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
        keyId: kyberKeyPair.keyId!,
        publicKey: kyberKeyPair.publicKey,
      ),
    );
    final generation = KeyBundleGeneration(
      signedPreKeyId: signedPreKey.keyId,
      kemKeyId: kyberKeyPair.keyId ?? -1,
      cryptoProtocolEpoch: kyberKeyPair.cryptoProtocolEpoch ?? -1,
      publicMaterialDigest: RisaalCryptoProtocol.keyBundlePublicMaterialDigest(
        identityKey: identityKeyPair.publicKey,
        identitySigningKey: signingKeyPair.publicKey,
        signedPreKeyId: signedPreKey.keyId,
        signedPreKeyPublicKey: signedPreKey.keyPair.publicKey,
        signedPreKeySignature: signedPreKey.signature,
        kemKeyId: kyberKeyPair.keyId!,
        kemPublicKey: kyberKeyPair.publicKey,
        kemSignature: kemSignature,
        cryptoProtocolEpoch: kyberKeyPair.cryptoProtocolEpoch!,
        kemSuite: kyberKeyPair.kemSuite!,
        kemStandard: kyberKeyPair.kemStandard!,
        kemWireVersion: kyberKeyPair.kemWireVersion!,
      ),
    );
    generation.requireCurrent(requirePublicMaterialDigest: true);
    return generation;
  }

  Future<void> _markCurrentKeyBundlePendingUnlocked() async {
    await _cryptoStorage.markKeyBundleUploadPending(
      await _currentKeyBundleGenerationUnlocked(),
    );
  }

  /// Legacy flat snapshot entry point; always fails closed.
  Future<KeyBundleUploadSnapshot> createKeyBundleUploadSnapshot() async =>
      throw _legacyKeyBundleApiDisabled();

  /// Legacy flat acknowledgement entry point; always fails closed.
  Future<bool> acknowledgeKeyBundleUpload({
    required KeyBundleUploadSnapshot snapshot,
    required KeyBundleUploadAcceptance acceptance,
  }) async => throw _legacyKeyBundleApiDisabled();

  /// Whether a current generation still requires an exact server ACK.
  Future<bool> isKeyBundleUploadPending() =>
      _withKeyLifecycleLock(_cryptoStorage.isKeyBundleUploadPending);

  /// Legacy flat reconciliation entry point; always fails closed.
  Future<void> reconcileObservedServerBundle(
    KeyBundleUploadAcceptance observed,
  ) async => throw _legacyKeyBundleApiDisabled();

  UnsupportedError _legacyKeyBundleApiDisabled() => UnsupportedError(
    'Legacy flat key-bundle upload/mutation is disabled. Use the versioned '
    'replacement journal and exact immutable receipt APIs.',
  );

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
    PqxdhPolicy pqxdhPolicy = PqxdhPolicy.requirePq,
  }) async {
    return _withReceiveLock(() async {
      if (pqxdhPolicy != PqxdhPolicy.requirePq) {
        throw UnsupportedError(
          'Epoch 2 requires PQXDH; downgrade policies are not supported',
        );
      }
      // Parse the immutable consumer receipt before logging, capability events,
      // identity observation, ratchet construction, or any persistent mutation.
      final bundleRouting = recipientBundle.requireCurrentRouting();
      // And refuse outright if this bundle contradicts what we already trust
      // for this contact — before an X3DH is run or a one-time prekey burned.
      await _requireConsistentOutboundIdentityUnlocked(recipientBundle);
      CryptoDebugLogger.log(
        'X3DH',
        '═══ Creating session (initiator/Alice) ═══',
      );
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
            sessionId: _sessionKey(
              recipientBundle.userId,
              recipientBundle.deviceId,
            ),
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
            sessionId: _sessionKey(
              recipientBundle.userId,
              recipientBundle.deviceId,
            ),
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
            'reason':
                'Identity key differs from stored key. '
                'Peer may have reinstalled or this may be a MITM attack.',
          },
        );
      }

      // R4-L1 Part B: initiate with transcript 2 only behind the send flag.
      final transcriptVersion = sendRatchetV3Enabled
          ? PreKeyHandshakeRouting.identityBoundTranscriptVersion
          : 1;
      final X3DHResult x3dhResult;
      try {
        x3dhResult = await _runX3dhInitiator(
          identityKeyPair: identityKP,
          recipientBundle: recipientBundle,
          pqxdhPolicy: pqxdhPolicy,
          transcriptVersion: transcriptVersion,
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
      ratchet.state.remoteIdentityKey = recipientBundle.identityKey;
      // A transcript-2 session speaks v3 both ways from its first message.
      if (transcriptVersion ==
          PreKeyHandshakeRouting.identityBoundTranscriptVersion) {
        ratchet.state
          ..sendV3 = true
          ..peerSpeaksV3 = true;
      }
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
        kyberCiphertext: x3dhResult.kyberCiphertext!,
        // The bundle route plus the transcript version actually derived.
        routing: bundleRouting.withTranscriptVersion(transcriptVersion),
      );
      if (x3dhResult.kyberCiphertext != null) {
        CryptoDebugLogger.log(
          'X3DH',
          'PQXDH: Kyber ciphertext included in pending prekey info',
        );
      }
      CryptoDebugLogger.log('X3DH', '═══ Session created (initiator) ═══');
    });
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
  ///
  /// Subject to [SealedSenderTrustPolicy.requireVerifiedFirstContact]: a first
  /// contact needs a matching [firstContactApproval] when that is required.
  Future<String> processPreKeyMessage({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required String senderEphemeralKey,
    required Map<String, dynamic> encryptedMessage,
    required String kyberCiphertext,
    required PreKeyHandshakeRouting routing,
    FirstContactApproval? firstContactApproval,
  }) => _processPreKeyMessage(
    senderId: senderId,
    senderDeviceId: senderDeviceId,
    senderIdentityKey: senderIdentityKey,
    senderEphemeralKey: senderEphemeralKey,
    encryptedMessage: encryptedMessage,
    kyberCiphertext: kyberCiphertext,
    routing: routing,
    trust: _InboundTrust.direct(firstContactApproval),
  );

  Future<String> _processPreKeyMessage({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required String senderEphemeralKey,
    required Map<String, dynamic> encryptedMessage,
    required String kyberCiphertext,
    required PreKeyHandshakeRouting routing,
    required _InboundTrust trust,
  }) {
    routing.requireCurrent();
    if (senderId.isEmpty || senderDeviceId.isEmpty) {
      throw const FormatException('Invalid PreKey sender routing');
    }
    _requireCanonicalBase64Bytes(
      senderIdentityKey,
      field: 'PreKey sender identity key',
      expectedLength: 32,
    );
    _requireCanonicalBase64Bytes(
      senderEphemeralKey,
      field: 'PreKey sender ephemeral key',
      expectedLength: 32,
    );
    _requireCanonicalBase64Bytes(
      kyberCiphertext,
      field: 'PreKey ML-KEM ciphertext',
      expectedLength: 1088,
    );
    final parsedMessage = EncryptedMessage.fromJson(encryptedMessage);
    parsedMessage.requireCurrentWireVersion();
    return _withReceiveLock(
      () => _withKeyLifecycleLock(
        () => _processPreKeyMessageUnlocked(
          senderId: senderId,
          senderDeviceId: senderDeviceId,
          senderIdentityKey: senderIdentityKey,
          senderEphemeralKey: senderEphemeralKey,
          encryptedMessage: encryptedMessage,
          kyberCiphertext: kyberCiphertext,
          routing: routing,
          trust: trust,
        ),
      ),
    );
  }

  Future<String> _processPreKeyMessageUnlocked({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required String senderEphemeralKey,
    required Map<String, dynamic> encryptedMessage,
    required String kyberCiphertext,
    required PreKeyHandshakeRouting routing,
    required _InboundTrust trust,
  }) async {
    routing.requireCurrent();
    final message = EncryptedMessage.fromJson(encryptedMessage);
    message.requireCurrentWireVersion();

    // P0-1 also applies here, and this is still the production path until every
    // app callsite moves to prepare/acknowledge. Reject a handshake that was
    // already completed instead of rebuilding — an unconditional `saveSession`
    // below would otherwise overwrite the live, advanced ratchet.
    final handshakeDigest = _preKeyHandshakeDigest(
      senderIdentityKey: senderIdentityKey,
      senderEphemeralKey: senderEphemeralKey,
      kyberCiphertext: kyberCiphertext,
      routing: routing,
    );
    await _requireUnconsumedPreKeyHandshakeUnlocked(
      handshakeDigest: handshakeDigest,
    );
    // The tombstone is a bounded FIFO and therefore evictable by whoever
    // controls delivery volume, so it cannot be the only replay defence here
    // either. This lane is what production runs today.
    await _requireNoLiveSessionForPreKeyUnlocked(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
    );
    // P0-A applies here too.
    await _requirePinnedSenderIdentityUnlocked(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
    );
    await _authorizeFirstContactUnlocked(
      trust: trust,
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
    );

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
    CryptoDebugLogger.log(
      'X3DH',
      'Used OTP key ID: ${routing.usedOneTimePreKeyId}',
    );

    final identityKP = await _requireIdentityKeyPair();
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Our identity key',
      identityKP.publicKey,
    );

    final routedMaterial = await _resolveRoutedPreKeyMaterialUnlocked(routing);
    final signedPreKey = routedMaterial.signedPreKey;
    CryptoDebugLogger.logKeyInfo(
      'X3DH',
      'Our signed pre-key',
      signedPreKey.keyPair.publicKey,
    );

    final oneTimePreKey = routedMaterial.oneTimePreKey;

    // Resolve only the exact KEM key selected by the authenticated envelope.
    // v0.1 and v0.4 use identical byte lengths, so key/version inference from
    // ciphertext shape is forbidden.
    final kyberKP = routedMaterial.kyberKeyPair;
    CryptoDebugLogger.log(
      'X3DH',
      'PQXDH: authenticated generation selected exact private material',
    );

    // PQXDH responder (X3DH + Kyber hybrid)
    final sharedSecret = await _runX3dhResponder(
      identityKeyPair: identityKP,
      signedPreKey: signedPreKey,
      oneTimePreKey: oneTimePreKey,
      senderIdentityKey: senderIdentityKey,
      senderEphemeralKey: senderEphemeralKey,
      kyberKeyPair: kyberKP,
      kyberCiphertext: kyberCiphertext,
      routing: routing,
    );

    CryptoDebugLogger.log(
      'X3DH',
      'Shared secret derived (responder, PQXDH): ${sharedSecret.length} bytes',
    );

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

    // Authenticate and unpad the first message entirely in a provisional
    // ratchet. Until this succeeds, no OTP, prior session, pending handshake,
    // peer capability or durable state is mutated.
    CryptoDebugLogger.log(
      'RATCHET',
      'Decrypting first PreKey message: msgNum=${message.messageNumber} prevChain=${message.previousChainLength}',
    );
    CryptoDebugLogger.logKeyInfo(
      'RATCHET',
      'Message DH public key',
      message.dhPublicKey,
    );
    _bindResponderSession(ratchet.state, senderIdentityKey, routing);
    final plainBytes = await ratchet.decrypt(
      message,
      localIdentityKey: identityKP.publicKey,
    );
    final plaintext = MessagePadding.unpadString(plainBytes);

    CryptoDebugLogger.logRatchetState(
      'X3DH',
      'Ratchet after first decrypt',
      ratchet.state.toJson(),
    );

    // Commit only after the first message authenticates. Durable session state
    // is written before the one-time key is consumed, so a storage failure can
    // be retried without irreversibly losing the handshake key.
    //
    // The handshake tombstone is written first: if the process dies between the
    // two writes, the worst case is that an authentic first delivery must be
    // resent, which is recoverable. The reverse order would leave the replay
    // window open against a session that already exists, which is not.
    await _recordConsumedPreKeyHandshakeUnlocked(
      handshakeDigest: handshakeDigest,
    );
    await _cryptoStorage.saveSession(senderId, senderDeviceId, ratchet.state);
    await _cryptoStorage.saveSessionIdentityKey(
      senderId,
      senderDeviceId,
      senderIdentityKey,
    );
    await _cryptoStorage.trackSessionDevice(senderId, senderDeviceId);
    await _cryptoStorage.savePeerPqxdhCapability(
      senderId,
      senderDeviceId,
      true,
    );
    await _cryptoStorage.savePeerIdentityKey(
      senderId,
      senderDeviceId,
      senderIdentityKey,
    );
    await _cryptoStorage.clearPendingPreKeyInfo(senderId, senderDeviceId);
    _sessions[_sessionKey(senderId, senderDeviceId)] = ratchet;
    if (routing.usedOneTimePreKeyId != null) {
      final consumed = await _consumeOneTimePreKeyForGenerationUnlocked(
        material: routedMaterial,
      );
      if (!consumed.consumed) {
        throw StateError(
          'Authenticated routed one-time pre-key could not be tombstoned',
        );
      }
      // Exhaustion observation is post-commit telemetry. Storage reads, event
      // listeners, or app callbacks must never turn authenticated success into
      // a retry after the OPK has been irreversibly tombstoned.
      try {
        _notifyPreKeyGenerationExhaustionBestEffort(
          remaining: consumed.remaining,
          isLatestAccepted: consumed.isLatestAccepted,
        );
      } on Object {
        // Best effort by design. A later authenticated count/reconcile can
        // re-observe the accepted generation without replaying this message.
      }
    }

    CryptoDebugLogger.log(
      'X3DH',
      '═══ PreKey message processed successfully ═══',
    );
    return plaintext;
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
    return _withReceiveLock(() async {
      CryptoDebugLogger.log(
        'ENCRYPT',
        'encryptMessage for $recipientId:$recipientDeviceId',
      );
      // Resolve every local/pending value that can reject the first envelope
      // before advancing the ratchet. A corrupt interrupted-handshake record
      // must never consume a sending-chain step.
      final identityKP = await _requireIdentityKeyPair();
      final pendingPreKey = _validatePendingPreKey(
        await _cryptoStorage.getPendingPreKeyInfo(
          recipientId,
          recipientDeviceId,
        ),
      );

      final persistedRatchet = await _loadSession(
        recipientId,
        recipientDeviceId,
      );
      final ratchet = DoubleRatchet.fromJson(persistedRatchet.state.toJson());
      CryptoDebugLogger.logRatchetState(
        'ENCRYPT',
        'Ratchet BEFORE encrypt',
        ratchet.state.toJson(),
      );
      final encrypted = await ratchet.encrypt(
        MessagePadding.padString(plaintext),
        version: _ratchetSendVersion(
          recipientId,
          recipientDeviceId,
          ratchet.state,
        ),
        localIdentityKey: identityKP.publicKey,
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

      late final Map<String, dynamic> envelope;
      if (pendingPreKey != null) {
        CryptoDebugLogger.log(
          'ENCRYPT',
          'First message — including PreKey handshake data',
        );
        envelope = <String, dynamic>{
          'type': 'prekey',
          'senderIdentityKey': identityKP.publicKey,
          'senderEphemeralKey': pendingPreKey.senderEphemeralKey,
          'kyberCiphertext': pendingPreKey.kyberCiphertext,
          ...pendingPreKey.routing.toEnvelopeJson(),
          'message': encrypted.toJson(),
        };
      } else {
        CryptoDebugLogger.log('ENCRYPT', 'Normal message (session exists)');
        envelope = <String, dynamic>{
          'type': 'message',
          'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
          'senderIdentityKey': identityKP.publicKey,
          'message': encrypted.toJson(),
        };
      }

      // Publish the candidate only after the complete envelope exists. If
      // encryption or envelope construction throws, the cached and persisted
      // ratchet remain byte-for-byte unchanged.
      await _cryptoStorage.saveSession(
        recipientId,
        recipientDeviceId,
        ratchet.state,
      );
      _sessions[_sessionKey(recipientId, recipientDeviceId)] = ratchet;
      if (pendingPreKey != null) {
        // Clearing after construction prevents malformed pending data from
        // destroying the only replayable first-contact handshake.
        await _cryptoStorage.clearPendingPreKeyInfo(
          recipientId,
          recipientDeviceId,
        );
      }
      return envelope;
    }, pendingScope: _sessionKey(recipientId, recipientDeviceId));
  }

  // ── Decrypt ───────────────────────────────────────────────────────

  ({String ciphertext, MlKemEnvelopeMetadata metadata})
  _requireCurrentKemMetadata(Map<String, dynamic> envelope) {
    final ciphertext = _requireCanonicalBase64Bytes(
      envelope['kyberCiphertext'],
      field: 'PreKey ML-KEM ciphertext',
      expectedLength: 1088,
    );
    return (
      ciphertext: ciphertext,
      metadata: MlKemEnvelopeMetadata.fromJson(envelope),
    );
  }

  _ValidatedPendingPreKey? _validatePendingPreKey(
    Map<String, dynamic>? pending,
  ) {
    if (pending == null) return null;

    final ephemeralPublicKey = _requireCanonicalBase64Bytes(
      pending['ephemeralPublicKey'],
      field: 'pending sender ephemeral key',
      expectedLength: 32,
    );
    final kem = _requireCurrentKemMetadata(pending);
    final kemCiphertext = _requireCanonicalBase64Bytes(
      kem.ciphertext,
      field: 'pending ML-KEM ciphertext',
      expectedLength: 1088,
    );

    final routing = PreKeyHandshakeRouting.fromEnvelopeJson(pending);
    return _ValidatedPendingPreKey(
      senderEphemeralKey: ephemeralPublicKey,
      kyberCiphertext: kemCiphertext,
      routing: routing,
    );
  }

  String _requireCanonicalBase64Bytes(
    Object? value, {
    required String field,
    required int expectedLength,
  }) {
    final expectedEncodedLength = ((expectedLength + 2) ~/ 3) * 4;
    if (value is! String || value.length != expectedEncodedLength) {
      throw FormatException('Missing or invalid $field');
    }
    try {
      final decoded = base64Decode(value);
      if (decoded.length != expectedLength || base64Encode(decoded) != value) {
        throw FormatException('Invalid $field');
      }
    } on Object {
      throw FormatException('Invalid $field');
    }
    return value;
  }

  int _requireRecipientSignedPreKeyId(Map<String, dynamic> envelope) {
    final keyId = envelope['recipientSignedPreKeyId'];
    if (keyId is! int || keyId <= 0 || keyId > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException(
        'Epoch-2 PreKey envelope requires a valid recipientSignedPreKeyId',
      );
    }
    return keyId;
  }

  void _validateSealedKemRouting(
    Map<String, dynamic> sealedEnvelope,
    Map<String, dynamic> innerEnvelope,
  ) {
    if (innerEnvelope['cryptoProtocolEpoch'] !=
        RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException(
        'Unsupported or legacy sealed inner protocol',
      );
    }
    final type = innerEnvelope['type'];
    if (type == 'prekey') {
      final outerKem = _requireCurrentKemMetadata(sealedEnvelope);
      final innerKem = _requireCurrentKemMetadata(innerEnvelope);
      final innerRouting = PreKeyHandshakeRouting.fromEnvelopeJson(
        innerEnvelope,
      );
      innerRouting.requireMatchingSealedProjection(sealedEnvelope);
      if (outerKem.ciphertext != innerKem.ciphertext ||
          outerKem.metadata.cryptoProtocolEpoch !=
              innerKem.metadata.cryptoProtocolEpoch) {
        throw const FormatException(
          'Sealed-sender ML-KEM routing does not match protected content',
        );
      }
      return;
    }

    if (type != 'message') {
      throw FormatException('Unsupported sealed inner envelope type: $type');
    }
    _rejectUnexpectedPreKeyRouting(innerEnvelope);
    _rejectUnexpectedPreKeyRouting(sealedEnvelope);
  }

  void _rejectUnexpectedPreKeyRouting(Map<String, dynamic> envelope) {
    const preKeyRoutingFields = <String>{
      'senderEphemeralKey',
      'kyberCiphertext',
      'recipientKeyId',
      'recipientSignedPreKeyId',
      'usedOneTimePreKeyId',
      'kemSuite',
      'kemStandard',
      'kemWireVersion',
      'bundleRevision',
      'opkGeneration',
      'opkSetDigest',
      'transcriptVersion',
    };
    if (preKeyRoutingFields.any(envelope.containsKey)) {
      throw const FormatException(
        'Unexpected PreKey routing on a normal message',
      );
    }
  }

  void _preflightSealedOuterRoutingShape(Map<String, dynamic> sealedEnvelope) {
    if (sealedEnvelope.containsKey('usedOneTimePreKeyId') ||
        sealedEnvelope.containsKey('senderEphemeralKey')) {
      throw const FormatException('Invalid sealed PreKey outer routing');
    }
    const projectedFields = <String>{
      'kyberCiphertext',
      'recipientKeyId',
      'recipientSignedPreKeyId',
      'kemSuite',
      'kemStandard',
      'kemWireVersion',
      'bundleRevision',
      'opkGeneration',
      'opkSetDigest',
    };
    final present = projectedFields.where(sealedEnvelope.containsKey).length;
    if (present == 0) return;
    if (present != projectedFields.length) {
      throw const FormatException('Incomplete sealed PreKey outer routing');
    }
    _requireCurrentKemMetadata(sealedEnvelope);
    _requireRecipientSignedPreKeyId(sealedEnvelope);
    OpkGenerationRouting.fromJson(sealedEnvelope);
  }

  /// Authenticate one direct normal or routed PreKey delivery without
  /// publishing any session/replay/OPK side effect.
  ///
  /// The host must durably persist [PreparedReceive.plaintext] and then call
  /// [acknowledgeReceive]. A different delivery is blocked while this receipt
  /// is pending. The WAL never stores plaintext.
  ///
  /// [firstContactApproval] admits an uncertified first contact under
  /// [SealedSenderTrustPolicy.requireVerifiedFirstContact]; on
  /// [UnverifiedFirstContactError] nothing is persisted and the host may retry
  /// the same [deliveryId] with an approval.
  Future<PreparedReceive> prepareReceive({
    required String deliveryId,
    required String senderId,
    required String senderDeviceId,
    required Map<String, dynamic> envelope,
    FirstContactApproval? firstContactApproval,
  }) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      final digest = receiveEnvelopeDigest(envelope);
      return _prepareReceiveCandidateUnlocked(
        deliveryId: deliveryId,
        envelopeDigest: digest,
        builder: () => _buildDirectReceiveCandidate(
          deliveryId: deliveryId,
          receiptEnvelopeDigest: digest,
          senderId: senderId,
          senderDeviceId: senderDeviceId,
          envelope: envelope,
          trust: _InboundTrust.direct(firstContactApproval),
        ),
      );
    }, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  /// Authenticate one sealed normal or routed PreKey delivery provisionally.
  ///
  /// Applies the [SealedSenderTrustPolicy]; see [prepareReceive] for
  /// [firstContactApproval].
  Future<PreparedReceive> prepareSealedReceive({
    required String deliveryId,
    required Map<String, dynamic> sealedEnvelope,
    FirstContactApproval? firstContactApproval,
  }) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      final digest = receiveEnvelopeDigest(sealedEnvelope);
      return _prepareReceiveCandidateUnlocked(
        deliveryId: deliveryId,
        envelopeDigest: digest,
        builder: () => _reportingCertificateRejection(
          () => _buildSealedReceiveCandidate(
            deliveryId: deliveryId,
            envelopeDigest: digest,
            sealedEnvelope: sealedEnvelope,
            firstContactApproval: firstContactApproval,
          ),
        ),
      );
    }, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  Future<PreparedReceive> _prepareReceiveCandidateUnlocked({
    required String deliveryId,
    required String envelopeDigest,
    required Future<_ReceiveCandidate> Function() builder,
  }) async {
    final deliveryIdHash = ReceiveReceipt.hashDeliveryId(deliveryId);
    var journal = await _readReceiveCommitJournalUnlocked();
    final completed = journal.completedForHash(deliveryIdHash);
    if (completed != null) {
      if (completed.envelopeDigest != envelopeDigest) {
        throw StateError('Receive delivery id was reused with different bytes');
      }
      return PreparedReceive.alreadyAcknowledged(completed);
    }

    final pending = journal.pending;
    if (pending != null) {
      if (pending.receipt.deliveryIdHash != deliveryIdHash) {
        throw StateError('A different durable receive is pending');
      }
      if (pending.receipt.envelopeDigest != envelopeDigest) {
        throw StateError('Receive delivery id was reused with different bytes');
      }
      if (pending.phase == ReceiveCommitPhase.commitDecided) {
        await _recoverReceiveCommitUnlocked();
        journal = await _readReceiveCommitJournalUnlocked();
        final recovered = journal.completedForHash(deliveryIdHash);
        if (recovered == null || recovered.envelopeDigest != envelopeDigest) {
          throw StateError('Receive acknowledgement recovery failed');
        }
        return PreparedReceive.alreadyAcknowledged(recovered);
      }

      await _verifyReceivePreStateUnlocked(pending.mutations);
      final candidate = await builder();
      // A first inbound ratchet step may generate a fresh local DH key while
      // reproducing the same authenticated plaintext. The WAL's original
      // after-image is the stable commit plan; a retry only re-authenticates
      // the exact envelope against the unchanged pre-state and discards its
      // newly generated candidate state.
      if (!candidate.receipt.matchesExact(pending.receipt)) {
        throw StateError('Pending receive candidate drift');
      }
      return PreparedReceive.pending(
        receipt: pending.receipt,
        plaintext: candidate.plaintext,
        senderAuthentication: candidate.senderAuthentication,
      );
    }

    final candidate = await builder();
    journal = await _readReceiveCommitJournalUnlocked();
    if (journal.pending != null ||
        journal.completedForHash(deliveryIdHash) != null) {
      throw StateError('Receive commit journal changed during preparation');
    }
    await _writeReceiveCommitJournalUnlocked(
      journal.copyWith(
        pending: ReceivePendingCommit(
          receipt: candidate.receipt,
          phase: ReceiveCommitPhase.prepared,
          mutations: candidate.mutations,
        ),
      ),
    );
    return PreparedReceive.pending(
      receipt: candidate.receipt,
      plaintext: candidate.plaintext,
      senderAuthentication: candidate.senderAuthentication,
    );
  }

  /// Finalize a prepared receive only after the host's DB/media transaction is
  /// durable. The transition is idempotent across fail-before, commit-then-
  /// throw and process restart at every secure-storage boundary.
  Future<ReceiveReceipt> acknowledgeReceive(
    ReceiveReceipt receipt,
  ) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      receipt.requireValid();
      var journal = await _readReceiveCommitJournalUnlocked();
      final completed = journal.completedForHash(receipt.deliveryIdHash);
      if (completed != null) {
        if (!completed.matchesExact(receipt)) {
          throw StateError('Receive acknowledgement receipt drift');
        }
        return completed;
      }
      final pending = journal.pending;
      if (pending == null || !pending.receipt.matchesExact(receipt)) {
        throw StateError('Receive receipt is not pending');
      }
      // Durably recorded intent: the key-bundle journal is only in this set
      // when the handshake consumed a one-time prekey.
      final consumedOpk = pending.mutations.any(
        (mutation) => mutation.key == _keyBundleReplacementJournalStorageKey,
      );
      if (pending.phase == ReceiveCommitPhase.prepared) {
        await _verifyReceivePreStateUnlocked(pending.mutations);
        await _writeReceiveCommitJournalUnlocked(
          journal.copyWith(
            pending: pending.copyWith(phase: ReceiveCommitPhase.commitDecided),
          ),
        );
      }
      await _recoverReceiveCommitUnlocked();
      journal = await _readReceiveCommitJournalUnlocked();
      final durable = journal.completedForHash(receipt.deliveryIdHash);
      if (durable == null || !durable.matchesExact(receipt)) {
        throw StateError('Receive acknowledgement did not complete');
      }

      // Never publish a candidate ahead of the durable completed receipt.
      // Evicting the pre-state forces the next operation to load the exact
      // committed session, including replay state, from secure storage.
      _sessions.remove(_sessionKey(receipt.senderId, receipt.senderDeviceId));
      _seenNonces = await _cryptoStorage.loadSeenNonces();

      // P1-2: report the pool only now that the consumption is durably
      // committed. Both inputs are read from durable state rather than from an
      // in-memory hand-off, so the signal survives a restart between prepare
      // and acknowledge, and a retry cannot lose or double it: `consumedOpk`
      // comes from the persisted pending mutation set, and the count comes from
      // the accepted generation itself.
      if (consumedOpk) {
        try {
          _notifyPreKeyGenerationExhaustionBestEffort(
            remaining: await oneTimePreKeyCount(),
            isLatestAccepted: true,
          );
        } on Object {
          // Telemetry must never fail a receive that already committed.
        }
      }
      return durable;
    }, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  /// Discard a provisional receive after the host confirms that no durable
  /// DB/media representation exists for [receipt]. This is idempotent across
  /// fail-before and commit-then-throw storage completion.
  /// The receipt of the receive currently awaiting host acknowledgement, if any.
  ///
  /// A host needs this to tell two states apart that look identical from its
  /// side: a receive whose crypto effects were published but whose local status
  /// write was lost, versus one that never completed. Without it, an orphaned
  /// host row is indistinguishable from an in-flight one and cannot be
  /// reconciled.
  Future<ReceiveReceipt?> pendingReceiveReceipt() => _withReceiveLock(
    () => _withKeyLifecycleLock(
      () async => (await _readReceiveCommitJournalUnlocked()).pending?.receipt,
      allowPendingReceive: true,
    ),
    allowPendingReceive: true,
  );

  /// Discard a provisional receive.
  ///
  /// [force] skips the pre-state verification. A `prepared` commit has applied
  /// nothing — that is what `prepared` means — so discarding it is always safe
  /// for durable state. Without an escape, pre-state drift (a host writing a
  /// `crypto_*` key directly, a partial panic wipe, an OS restore) left the
  /// pending permanently unresolvable: `initialize`, `acknowledgeReceive` and
  /// `abortPreparedReceive` all hard-failed on the same drift check, and the
  /// only remaining exit destroyed the identity key. The cost of forcing is at
  /// most one authentic message the peer must resend.
  Future<void> abortPreparedReceive(
    ReceiveReceipt receipt, {
    bool force = false,
  }) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      receipt.requireValid();
      final journal = await _readReceiveCommitJournalUnlocked();
      final completed = journal.completedForHash(receipt.deliveryIdHash);
      if (completed != null) {
        throw StateError('A completed receive cannot be aborted');
      }
      final pending = journal.pending;
      if (pending == null) return;
      if (!pending.receipt.matchesExact(receipt)) {
        throw StateError('Receive abort receipt drift');
      }
      if (pending.phase != ReceiveCommitPhase.prepared) {
        throw StateError('A host-durable receive cannot be aborted');
      }
      if (!force) {
        await _verifyReceivePreStateUnlocked(pending.mutations);
      }
      await _writeReceiveCommitJournalUnlocked(journal.copyWith(pending: null));
    }, allowPendingReceive: true),
    allowPendingReceive: true,
  );

  Future<_ReceiveCandidate> _buildDirectReceiveCandidate({
    required String deliveryId,
    required String receiptEnvelopeDigest,
    required String senderId,
    required String senderDeviceId,
    required Map<String, dynamic> envelope,
    required _InboundTrust trust,
  }) async {
    final type = envelope['type'];
    if (type != 'prekey' && type != 'message') {
      throw FormatException('Unsupported encrypted envelope type: $type');
    }
    if (envelope['cryptoProtocolEpoch'] !=
        RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException(
        'Unsupported or legacy encrypted envelope protocol',
      );
    }
    final routing = type == 'prekey'
        ? PreKeyHandshakeRouting.fromEnvelopeJson(envelope)
        : null;
    if (routing != null) {
      _requireCurrentKemMetadata(envelope);
    } else {
      _rejectUnexpectedPreKeyRouting(envelope);
    }
    final rawMessage = envelope['message'];
    if (rawMessage is! Map) {
      throw const FormatException('Missing encrypted ratchet message');
    }
    EncryptedMessage.fromJson(
      Map<String, dynamic>.from(rawMessage),
    ).requireCurrentWireVersion();

    try {
      // Awaited so the handler below also sees ASYNC authentication failures
      // (before, a tampered normal message escaped as a raw cipher error and
      // no tamper event was raised).
      if (routing != null) {
        return await _withKeyLifecycleLock(
          () => _buildPreKeyReceiveCandidate(
            deliveryId: deliveryId,
            receiptEnvelopeDigest: receiptEnvelopeDigest,
            senderId: senderId,
            senderDeviceId: senderDeviceId,
            envelope: envelope,
            routing: routing,
            trust: trust,
          ),
          allowPendingReceive: true,
        );
      }
      return await _buildNormalReceiveCandidate(
        deliveryId: deliveryId,
        receiptEnvelopeDigest: receiptEnvelopeDigest,
        senderId: senderId,
        senderDeviceId: senderDeviceId,
        envelope: envelope,
        trust: trust,
      );
    } on SecretBoxAuthenticationError {
      if (routing != null) rethrow;
      _eventBus?.emitType(
        SecurityEventType.messageAuthenticationRejected,
        metadata: const {'source': 'double_ratchet'},
      );
      throw const MessageAuthenticationError();
    }
  }

  Future<_ReceiveCandidate> _buildNormalReceiveCandidate({
    required String deliveryId,
    required String receiptEnvelopeDigest,
    required String senderId,
    required String senderDeviceId,
    required Map<String, dynamic> envelope,
    required _InboundTrust trust,
  }) async {
    final sealed = trust.sealed;
    final stored = await _cryptoStorage.getSession(senderId, senderDeviceId);
    if (stored == null) {
      throw NoSessionError(
        senderId,
        senderDeviceId,
        'No session found for $senderId:$senderDeviceId. '
        'Establish a session first via a routed PreKey receive.',
      );
    }
    final candidateRatchet = DoubleRatchet.fromJson(stored.toJson());
    // A legacy stamp stays on the candidate and is committed with it.
    await _requireSessionMatchesPinUnlocked(
      senderId,
      senderDeviceId,
      candidateRatchet,
    );
    final message = EncryptedMessage.fromJson(
      Map<String, dynamic>.from(envelope['message'] as Map),
    );
    message.requireCurrentWireVersion();
    final plainBytes = await candidateRatchet.decrypt(
      message,
      localIdentityKey: await _receiveIdentityKey(
        senderId,
        senderDeviceId,
        candidateRatchet.state,
        message,
      ),
    );
    final plaintext = MessagePadding.unpadString(plainBytes);
    final mutations = await _planNormalReceiveCommitUnlocked(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      candidateRatchet: candidateRatchet,
    );
    final receipt = ReceiveReceipt.create(
      deliveryId: deliveryId,
      envelopeDigest: receiptEnvelopeDigest,
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      kind: sealed
          ? ReceiveEnvelopeKind.sealedMessage
          : ReceiveEnvelopeKind.directMessage,
    );
    return _ReceiveCandidate(
      receipt: receipt,
      plaintext: plaintext,
      mutations: mutations,
      senderAuthentication: trust.authentication,
    );
  }

  Future<_ReceiveCandidate> _buildPreKeyReceiveCandidate({
    required String deliveryId,
    required String receiptEnvelopeDigest,
    required String senderId,
    required String senderDeviceId,
    required Map<String, dynamic> envelope,
    required PreKeyHandshakeRouting routing,
    required _InboundTrust trust,
  }) async {
    final sealed = trust.sealed;
    if (senderId.isEmpty || senderDeviceId.isEmpty) {
      throw const FormatException('Invalid PreKey sender routing');
    }
    final senderIdentityKey = _requireCanonicalBase64Bytes(
      envelope['senderIdentityKey'],
      field: 'PreKey sender identity key',
      expectedLength: 32,
    );
    final senderEphemeralKey = _requireCanonicalBase64Bytes(
      envelope['senderEphemeralKey'],
      field: 'PreKey sender ephemeral key',
      expectedLength: 32,
    );
    final kyberCiphertext = _requireCanonicalBase64Bytes(
      envelope['kyberCiphertext'],
      field: 'PreKey ML-KEM ciphertext',
      expectedLength: 1088,
    );
    final message = EncryptedMessage.fromJson(
      Map<String, dynamic>.from(envelope['message'] as Map),
    );
    message.requireCurrentWireVersion();

    // P0-1: an authentic PreKey envelope stays decryptable forever — X3DH is
    // deterministic and `initReceiver` builds a fresh ratchet whose replay set
    // is empty — so the untrusted relay can re-inject one under a new
    // `deliveryId` and roll the live session back to its first state. The
    // receipt window cannot stop that: `deliveryId` is server-chosen. Only
    // material derived from the envelope itself is a sound identity for a
    // handshake, and an attacker who can only replay can never mint a new one.
    final handshakeDigest = _preKeyHandshakeDigest(
      senderIdentityKey: senderIdentityKey,
      senderEphemeralKey: senderEphemeralKey,
      kyberCiphertext: kyberCiphertext,
      routing: routing,
    );
    await _requireUnconsumedPreKeyHandshakeUnlocked(
      handshakeDigest: handshakeDigest,
    );
    await _requireNoLiveSessionForPreKeyUnlocked(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
    );
    await _requirePinnedSenderIdentityUnlocked(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
    );
    await _authorizeFirstContactUnlocked(
      trust: trust,
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
    );

    final identity = await _requireIdentityKeyPair();
    final material = await _resolveRoutedPreKeyMaterialUnlocked(routing);
    final sharedSecret = await _runX3dhResponder(
      identityKeyPair: identity,
      signedPreKey: material.signedPreKey,
      oneTimePreKey: material.oneTimePreKey,
      senderIdentityKey: senderIdentityKey,
      senderEphemeralKey: senderEphemeralKey,
      kyberKeyPair: material.kyberKeyPair,
      kyberCiphertext: kyberCiphertext,
      routing: routing,
    );
    final candidateRatchet = await DoubleRatchet.initReceiver(
      sharedSecret: sharedSecret,
      dhKeyPair: material.signedPreKey.keyPair,
    );
    _bindResponderSession(candidateRatchet.state, senderIdentityKey, routing);
    final plainBytes = await candidateRatchet.decrypt(
      message,
      localIdentityKey: identity.publicKey,
    );
    final plaintext = MessagePadding.unpadString(plainBytes);
    final consumption = routing.usedOneTimePreKeyId == null
        ? null
        : await _planOneTimePreKeyConsumptionUnlocked(material: material);
    final handshakeMutation = await _planPreKeyHandshakeTombstoneUnlocked(
      handshakeDigest: handshakeDigest,
    );
    final mutations = await _planPreKeyReceiveCommitUnlocked(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
      candidateRatchet: candidateRatchet,
      keyBundleJournalAfter: consumption?.journalAfter,
      handshakeMutation: handshakeMutation,
    );
    final receipt = ReceiveReceipt.create(
      deliveryId: deliveryId,
      envelopeDigest: receiptEnvelopeDigest,
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      kind: sealed
          ? ReceiveEnvelopeKind.sealedPreKey
          : ReceiveEnvelopeKind.directPreKey,
    );
    return _ReceiveCandidate(
      receipt: receipt,
      plaintext: plaintext,
      mutations: mutations,
      senderAuthentication: trust.authentication,
      opkConsumption: consumption,
    );
  }

  Future<_ReceiveCandidate> _buildSealedReceiveCandidate({
    required String deliveryId,
    required String envelopeDigest,
    required Map<String, dynamic> sealedEnvelope,
    required FirstContactApproval? firstContactApproval,
  }) async {
    if (sealedEnvelope['cryptoProtocolEpoch'] !=
        RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException(
        'Unsupported or legacy sealed-sender protocol',
      );
    }
    _preflightSealedOuterRoutingShape(sealedEnvelope);
    final nonce = sealedEnvelope['nonce'];
    if (nonce is! String || nonce.isEmpty) {
      throw const FormatException('Invalid sealed-sender nonce');
    }
    // Multiple manager instances can share one account/storage backend. Their
    // in-memory replay caches may have been initialized at different times, so
    // derive every provisional after-image from the latest durable nonce set.
    // The shared receive lane keeps this read/plan/WAL sequence serialized in
    // this isolate; [_seenNonces] is refreshed only after the durable ACK.
    final persistedNonces = await _cryptoStorage.loadSeenNonces();
    if (persistedNonces.contains(nonce)) {
      throw StateError('Sealed sender nonce already seen — rejecting replay');
    }
    final candidateNonces = Set<String>.from(persistedNonces);
    final identity = await _requireIdentityKeyPair();
    final content = await SealedSenderEnvelope.unseal(
      sealedEnvelope: sealedEnvelope,
      recipientIdentityKeyPair: identity,
      seenNonces: candidateNonces,
      maxReplayWindowMs: _sealedSenderReplayWindowMs,
      trustedServerSigningKeys: _trustedServerSigningKeys,
    );
    final trust = await _admitSealedContentUnlocked(
      content,
      firstContactApproval,
    );
    _validateSealedKemRouting(sealedEnvelope, content.encryptedMessage);
    final innerIdentityKey = content.encryptedMessage['senderIdentityKey'];
    if (innerIdentityKey is! String ||
        innerIdentityKey != content.senderIdentityKey) {
      throw StateError(
        'Sealed sender outer/inner identity mismatch — rejecting spoofed sender',
      );
    }
    final pinnedIdentityKey = await _cryptoStorage.getSessionIdentityKey(
      content.senderId,
      content.senderDeviceId,
    );
    if (pinnedIdentityKey != null &&
        pinnedIdentityKey != content.senderIdentityKey) {
      throw StateError(
        'Sealed sender identity mismatch for ${content.senderId}',
      );
    }
    final inner = await _buildDirectReceiveCandidate(
      deliveryId: deliveryId,
      receiptEnvelopeDigest: envelopeDigest,
      senderId: content.senderId,
      senderDeviceId: content.senderDeviceId,
      envelope: content.encryptedMessage,
      trust: trust,
    );
    final nonceMutation = await _planSealedNonceCommitUnlocked(candidateNonces);
    // R4-C3-V2: a certified receive never seeds the peer signing-key pin. The
    // certificate's signing key is only server-attested (contract v2 has no
    // sender binding); pins come only from a future KT-backed source.
    return _ReceiveCandidate(
      receipt: inner.receipt,
      plaintext: inner.plaintext,
      senderAuthentication: inner.senderAuthentication,
      // P1-2: the sealed lane wraps the direct candidate, so it must carry the
      // inner one-time-prekey consumption forward. Dropping it here made the
      // exhaustion signal dead on the sealed path — which is the path Risaal
      // uses by default.
      opkConsumption: inner.opkConsumption,
      mutations: <ReceiveStorageMutation>[...inner.mutations, nonceMutation],
    );
  }

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
  /// Authentication failures are fail-closed and transactional. A normal
  /// message with an invalid AEAD tag throws [MessageAuthenticationError]
  /// without deleting or advancing the cached/persisted session, clearing its
  /// pinned identity/pending handshake, recording reset timestamps, or
  /// requesting one-time pre-key replenishment. A failed provisional PreKey
  /// message retains its lower-level authentication error and likewise cannot
  /// replace a previously good session.
  ///
  /// Returns the decrypted plaintext string (after unpadding).
  ///
  /// Throws:
  ///   - [StateError] if session doesn't exist and this isn't a PreKey message
  ///   - [MessageAuthenticationError] if a normal message fails authentication
  ///
  /// [firstContactApproval]: see [prepareReceive].
  Future<String> decryptMessage(
    String senderId,
    String senderDeviceId,
    Map<String, dynamic> envelope, {
    FirstContactApproval? firstContactApproval,
  }) => _decryptMessageWithTrust(
    senderId,
    senderDeviceId,
    envelope,
    _InboundTrust.direct(firstContactApproval),
  );

  Future<String> _decryptMessageWithTrust(
    String senderId,
    String senderDeviceId,
    Map<String, dynamic> envelope,
    _InboundTrust trust,
  ) async {
    return _withReceiveLock(() async {
      final type = envelope['type'] as String;
      if (type != 'prekey' && type != 'message') {
        throw FormatException('Unsupported encrypted envelope type: $type');
      }
      if (envelope['cryptoProtocolEpoch'] !=
          RisaalCryptoProtocol.cryptoProtocolEpoch) {
        throw const FormatException(
          'Unsupported or legacy encrypted envelope protocol',
        );
      }
      // Parse the security boundary before the generic authentication/reset
      // handler. Legacy/missing/unknown ML-KEM metadata is a protocol rejection,
      // not a ratchet MAC failure and must never enter a reset/retry loop.
      final preKeyRouting = type == 'prekey'
          ? PreKeyHandshakeRouting.fromEnvelopeJson(envelope)
          : null;
      if (preKeyRouting != null) {
        _requireCurrentKemMetadata(envelope);
      } else {
        _rejectUnexpectedPreKeyRouting(envelope);
      }
      final rawInnerMessage = envelope['message'];
      if (rawInnerMessage is! Map) {
        throw const FormatException('Missing encrypted ratchet message');
      }
      final innerMessage = EncryptedMessage.fromJson(
        Map<String, dynamic>.from(rawInnerMessage),
      );
      innerMessage.requireCurrentWireVersion();
      CryptoDebugLogger.log(
        'DECRYPT_MSG',
        'decryptMessage type=$type from $senderId:$senderDeviceId',
      );

      try {
        return await _decryptMessageInner(
          senderId,
          senderDeviceId,
          envelope,
          preKeyRouting: preKeyRouting,
          trust: trust,
        );
      } on SecretBoxAuthenticationError {
        // A provisional PreKey message owns a separate transactional boundary.
        // Preserve its lower-level typed error so callers can distinguish a
        // failed first-contact attempt from a rejected established-session
        // message. Neither path mutates the prior ratchet.
        if (type == 'prekey') {
          CryptoDebugLogger.log(
            'DECRYPT_MSG',
            'Rejected unauthenticated PreKey message without mutating session',
          );
          rethrow;
        }

        CryptoDebugLogger.log(
          'DECRYPT_MSG',
          'Rejected unauthenticated normal message without mutating session',
        );
        _eventBus?.emitType(
          SecurityEventType.messageAuthenticationRejected,
          metadata: const {'source': 'double_ratchet'},
        );
        throw const MessageAuthenticationError();
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

        rethrow;
      }
    });
  }

  /// The original decrypt logic, extracted so [decryptMessage] can own typed
  /// authentication, replay, and skipped-key error handling.
  Future<String> _decryptMessageInner(
    String senderId,
    String senderDeviceId,
    Map<String, dynamic> envelope, {
    PreKeyHandshakeRouting? preKeyRouting,
    required _InboundTrust trust,
  }) async {
    final type = envelope['type'] as String;

    if (type == 'prekey') {
      CryptoDebugLogger.log(
        'DECRYPT_MSG',
        'PreKey message — establishing session and decrypting',
      );
      return _processPreKeyMessage(
        senderId: senderId,
        senderDeviceId: senderDeviceId,
        senderIdentityKey: envelope['senderIdentityKey'] as String,
        senderEphemeralKey: envelope['senderEphemeralKey'] as String,
        encryptedMessage: envelope['message'] as Map<String, dynamic>,
        kyberCiphertext: envelope['kyberCiphertext'] as String,
        routing: preKeyRouting!,
        trust: trust,
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
    message.requireCurrentWireVersion();
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

    // Off-main-thread decrypt (perf): run the pure ratchet decrypt in a
    // background isolate so a backlog doesn't freeze the UI. On success, commit
    // the new state to the cache + storage. On ANY failure, fall through to the
    // inline path below on the UNTOUCHED cached ratchet so typed auth, replay,
    // and skipped-key error handling fires on the owning isolate.
    final localIdentityKey = await _receiveIdentityKey(
      senderId,
      senderDeviceId,
      ratchet.state,
      message,
    );
    if (decryptOffMainThread) {
      final req = RatchetBatchRequest(
        stateJson: ratchet.toJson(),
        messages: [message.toJson()],
        localIdentityKey: localIdentityKey,
      );
      final res = await _runRatchetBatchDecryptInIsolate(req);
      if (!res.hadFailure) {
        final newRatchet = DoubleRatchet.fromJson(res.finalStateJson);
        _sessions[_sessionKey(senderId, senderDeviceId)] = newRatchet;
        await _cryptoStorage.saveSession(
          senderId,
          senderDeviceId,
          newRatchet.state,
        );
        final offResult = res.plaintexts.first; // engine already unpads
        CryptoDebugLogger.log('DECRYPT_MSG', 'Decrypted off-thread');
        return offResult;
      }
      // Off-thread decrypt failed — the cached ratchet was not touched (the
      // isolate worked on a copy); fall through to inline for proper handling.
    }

    final plainBytes = await ratchet.decrypt(
      message,
      localIdentityKey: localIdentityKey,
    );

    CryptoDebugLogger.logRatchetState(
      'DECRYPT_MSG',
      'Ratchet AFTER decrypt',
      ratchet.state.toJson(),
    );

    await _cryptoStorage.saveSession(senderId, senderDeviceId, ratchet.state);

    final result = MessagePadding.unpadString(plainBytes);
    CryptoDebugLogger.event(CryptoDiagnosticEvent.decryptSucceeded);
    return result;
  }

  /// Decrypt a backlog of NORMAL (type-2) messages from a SINGLE established
  /// session OFF the main isolate (audit 2026-06 performance: bulk decrypt on
  /// chat open stalls the UI ~50–200 ms per message).
  ///
  /// [envelopes] are complete type-2 envelopes in delivery order. Every envelope
  /// is preflighted before session state is loaded; stripped ratchet maps cannot
  /// bypass protocol epoch, type, identity, or no-PreKey-routing gates.
  ///
  /// Persists the post-batch ratchet state (after the LAST successful decrypt)
  /// to both the in-memory cache and storage. If a message fails,
  /// [RatchetBatchResult.failedIndex] marks where to resume: the caller re-runs
  /// that message — and every one after it — through [decryptMessage], which
  /// owns the auth-error / session-reset / replay handling that cannot run in a
  /// storage-less isolate.
  ///
  /// NOT yet wired into the live bulk-decrypt path — gated at the call site so it
  /// can be enabled and verified on a device first. See
  /// docs/performance/CRYPTO_ISOLATE.md for the integration + verification plan.
  Future<RatchetBatchResult> decryptNormalBatch(
    String senderId,
    String senderDeviceId,
    List<Map<String, dynamic>> envelopes, {
    bool useIsolate = true,
  }) async {
    return _withReceiveLock(() async {
      final innerMessages = <Map<String, dynamic>>[];
      EncryptedMessage? identityBound;
      for (final envelope in envelopes) {
        if (envelope['type'] != 'message' ||
            envelope['cryptoProtocolEpoch'] !=
                RisaalCryptoProtocol.cryptoProtocolEpoch) {
          throw const FormatException(
            'Batch requires current normal envelopes',
          );
        }
        _rejectUnexpectedPreKeyRouting(envelope);
        _requireCanonicalBase64Bytes(
          envelope['senderIdentityKey'],
          field: 'normal sender identity key',
          expectedLength: 32,
        );
        final rawMessage = envelope['message'];
        if (rawMessage is! Map) {
          throw const FormatException('Missing batch ratchet message');
        }
        final normalized = Map<String, dynamic>.from(rawMessage);
        final parsed = EncryptedMessage.fromJson(normalized)
          ..requireCurrentWireVersion();
        if (parsed.version == EncryptedMessage.identityBoundWireVersion) {
          identityBound ??= parsed;
        }
        innerMessages.add(normalized);
      }
      final ratchet = await _loadSession(senderId, senderDeviceId);
      final request = RatchetBatchRequest(
        stateJson: ratchet.toJson(),
        messages: innerMessages,
        localIdentityKey: identityBound == null
            ? null
            : await _receiveIdentityKey(
                senderId,
                senderDeviceId,
                ratchet.state,
                identityBound,
              ),
      );

      final result = useIsolate
          ? await _runRatchetBatchDecryptInIsolate(request)
          : await ratchetBatchDecrypt(request);

      // Persist the post-batch state to BOTH the in-memory cache and storage so a
      // subsequent inline decrypt of the failed/remaining messages continues from
      // exactly the right ratchet state.
      final newRatchet = DoubleRatchet.fromJson(result.finalStateJson);
      _sessions[_sessionKey(senderId, senderDeviceId)] = newRatchet;
      await _cryptoStorage.saveSession(
        senderId,
        senderDeviceId,
        newRatchet.state,
      );

      return result;
    });
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
    return _withReceiveLock(() async {
      final key = _sessionKey(userId, deviceId);
      _sessions.remove(key);
      await _cryptoStorage.deleteSession(userId, deviceId);
      await _cryptoStorage.deleteSessionIdentityKey(userId, deviceId);
      await _cryptoStorage.deletePeerSigningKey(userId, deviceId);
      await _cryptoStorage.clearPendingPreKeyInfo(userId, deviceId);
      await _cryptoStorage.clearReceivedMessageNumbers(userId, deviceId);
      CryptoDebugLogger.log('SESSION', 'Removed session $userId:$deviceId');
    });
  }

  /// Deliberately stop trusting [userId] entirely: drop every session AND the
  /// pinned identity keys and device list.
  ///
  /// This is the ONLY sanctioned way to clear a pin, and it must be reachable
  /// only from an explicit user action ("Reset encryption" / re-verify). A
  /// genuine reinstall by a contact, and a pin planted by a malicious relay
  /// before the real contact ever connected, are both resolved here — and both
  /// require the user to re-check the safety number afterwards, which is the
  /// point.
  Future<void> forgetPeerIdentity(String userId) async {
    return _withReceiveLock(() async {
      _sessions.removeWhere((key, _) => key.startsWith('$userId:'));
      await _cryptoStorage.forgetPeerIdentity(userId);
      CryptoDebugLogger.log('SESSION', 'Forgot peer identity for $userId');
    });
  }

  /// Trust EXACTLY [identityKey] for [userId]/[deviceId] after the user
  /// verified it (safety number / QR) — the alternative to [forgetPeerIdentity],
  /// whose next handshake would pin whatever key the untrusted relay serves.
  ///
  /// [identityKey] is the canonical base64 of the 32-byte identity public key,
  /// the same encoding as [getSessionIdentityKey] and `PreKeyBundle`. Invalid
  /// input (key, user id or device id) throws [ArgumentError] before anything
  /// in memory or storage is touched.
  ///
  /// Afterwards the only identity accepted for this contact is [identityKey]:
  /// every session, pin and device entry for [userId] is gone, the device list
  /// is exactly `[deviceId]`, and the next session — outbound [createSession]
  /// or an inbound PreKey, on this or any relay-named device id — succeeds only
  /// with [identityKey] and is refused otherwise.
  ///
  /// Crash safety: under the same lock as [forgetPeerIdentity], (a) the new pin
  /// is written FIRST and the device is tracked, then (b) the old sessions,
  /// other devices' pins and the device list are removed. There is never a
  /// moment with no pin, so an interruption can never let an unpinned next
  /// handshake be trusted. Before (a), every session of [userId] whose record
  /// predates the recorded remote identity is stamped with its OLD pin (one
  /// with no pin at all is removed), so the new pin can never bless it. An
  /// interruption after (a) therefore leaves an old session that disagrees
  /// with the pin, and EVERY use of it — encrypt, normal and sealed decrypt,
  /// prepared send and receive — throws [SessionIdentityMismatchError] before
  /// any ratchet step (R4-PKG-SESSION-PIN-CHECK); inbound handshakes carrying
  /// the old key are refused as before. Calling this again completes the
  /// cleanup; the host treats a failed call as not done.
  Future<void> acceptVerifiedPeerIdentity({
    required String userId,
    required String deviceId,
    required String identityKey,
  }) async {
    try {
      _requireCanonicalBase64Bytes(
        identityKey,
        field: 'verified identity key',
        expectedLength: 32,
      );
    } on FormatException {
      throw ArgumentError(
        'must be the canonical base64 of a 32-byte identity key',
        'identityKey',
      );
    }
    try {
      // Read-only: builds the storage key, which validates both ids.
      await _cryptoStorage.getSessionIdentityKey(userId, deviceId);
    } on FormatException {
      throw ArgumentError('Invalid user id or device id', 'userId/deviceId');
    }
    return _withReceiveLock(() async {
      _sessions.removeWhere((key, _) => key.startsWith('$userId:'));
      // (0) R4-PKG-SESSION-PIN-CHECK: a session record written before sessions
      // carried their identity would be stamped with the NEW pin on its next
      // load, so an interruption below would bless the old session. Stamp it
      // now with the pin it was created under. A record with no pin at all
      // cannot be stamped and is removed (step (b) removes it anyway).
      final known = <String>{
        deviceId,
        ...await _cryptoStorage.getSessionDevices(userId),
      };
      for (final device in known) {
        final RatchetState? state;
        try {
          state = await _cryptoStorage.getSession(userId, device);
        } on FormatException {
          continue; // Unreadable: no path can load it; (b) removes it.
        } on TypeError {
          continue;
        }
        if (state == null || state.remoteIdentityKey != null) continue;
        final oldPin = await _cryptoStorage.getSessionIdentityKey(
          userId,
          device,
        );
        if (oldPin == null) {
          await _cryptoStorage.deleteSession(userId, device);
          continue;
        }
        state.remoteIdentityKey = oldPin;
        await _cryptoStorage.saveSession(userId, device, state);
      }
      // (a) Pin first. Tracking the device keeps the pin visible to the
      // per-contact checks that guard relay-invented device ids.
      await _cryptoStorage.saveSessionIdentityKey(
        userId,
        deviceId,
        identityKey,
      );
      await _cryptoStorage.savePeerIdentityKey(userId, deviceId, identityKey);
      await _cryptoStorage.trackSessionDevice(userId, deviceId);
      // (b) Then drop everything else known for this contact.
      await _cryptoStorage.deleteSession(userId, deviceId);
      await _cryptoStorage.clearPendingPreKeyInfo(userId, deviceId);
      await _cryptoStorage.deletePeerSigningKey(userId, deviceId);
      for (final other in await _cryptoStorage.getSessionDevices(userId)) {
        if (other == deviceId) continue;
        await _cryptoStorage.deleteSession(userId, other);
        await _cryptoStorage.clearPendingPreKeyInfo(userId, other);
        await _cryptoStorage.deleteSessionIdentityKey(userId, other);
        await _cryptoStorage.deletePeerIdentityKey(userId, other);
        await _cryptoStorage.deletePeerSigningKey(userId, other);
      }
      await _cryptoStorage.replaceSessionDevices(userId, <String>[deviceId]);
      CryptoDebugLogger.log(
        'SESSION',
        'Accepted verified identity for $userId',
      );
    });
  }

  /// Remove all sessions for a user (any device). Used when the peer
  /// changes their identity key (logout + re-login).
  Future<void> removeAllSessionsForUser(String userId) async {
    return _withReceiveLock(() async {
      _sessions.removeWhere((key, _) => key.startsWith('$userId:'));
      await _cryptoStorage.deleteAllSessionsForUser(userId);
      CryptoDebugLogger.log('SESSION', 'Removed all sessions for user $userId');
    });
  }

  /// Get the remote identity key stored when the session was created.
  Future<String?> getSessionIdentityKey(String userId, String deviceId) =>
      _cryptoStorage.getSessionIdentityKey(userId, deviceId);

  /// How [identityKey] relates to what this device already trusts for
  /// [userId] (R5-N1): the same rule [createSession] enforces before any
  /// outbound session, asked without writing anything.
  ///
  /// With a [deviceId] that has its own pin, that pin decides. Otherwise the
  /// contact's other pinned devices decide: one equal pin gives
  /// [PeerIdentityPinStatus.matchesPin], pins that all differ give
  /// [PeerIdentityPinStatus.contradictsPin], and no pin at all gives
  /// [PeerIdentityPinStatus.noPin]. Identity continuity belongs to the
  /// contact, not to a device id the relay names. Invalid ids throw
  /// [FormatException], as every storage key built from them does. It answers
  /// while a message commit awaits host acknowledgement.
  Future<PeerIdentityPinStatus> peerIdentityPinStatus({
    required String userId,
    required String identityKey,
    String? deviceId,
  }) {
    return _withReceiveLock(
      () async {
        if (deviceId != null) {
          final pin = await _cryptoStorage.getSessionIdentityKey(
            userId,
            deviceId,
          );
          if (pin != null) {
            return pin == identityKey
                ? PeerIdentityPinStatus.matchesPin
                : PeerIdentityPinStatus.contradictsPin;
          }
        }
        var sawPin = false;
        for (final device in await _cryptoStorage.getSessionDevices(userId)) {
          if (device == deviceId) continue;
          final pin = await _cryptoStorage.getSessionIdentityKey(
            userId,
            device,
          );
          if (pin == null) continue;
          sawPin = true;
          if (pin == identityKey) return PeerIdentityPinStatus.matchesPin;
        }
        return sawPin
            ? PeerIdentityPinStatus.contradictsPin
            : PeerIdentityPinStatus.noPin;
      },
      // Read-only, so a message commit awaiting host acknowledgement does not
      // block it (R5-N1-FIX-R1): a pending receive cannot change a pin that
      // exists, because the inbound guards refuse identity changes.
      allowPendingReceive: true,
      allowPendingSend: true,
    );
  }

  /// The peer's pinned Ed25519 signing key, or `null` if none is pinned.
  /// R4-C3-V2: certified receives no longer seed this pin (a certificate's
  /// signing key is only server-attested); it is kept for a future
  /// KT-backed source and is compared against certified envelopes when set.
  Future<String?> getPeerSigningKey(String userId, String deviceId) =>
      _cryptoStorage.getPeerSigningKey(userId, deviceId);

  /// Device IDs that currently have an established session with [userId].
  /// Lets callers (e.g. safety-number verification) read the identity key the
  /// ratchet actually pinned, rather than one fetched live from the server.
  Future<List<String>> getSessionDevices(String userId) =>
      _cryptoStorage.getSessionDevices(userId);

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
  /// [senderCertificate] (R4-C3): the Sender Certificate the host obtained
  /// from `POST /auth/sender-certificate`. When given, the envelope carries it
  /// and its server signature (contract v2: no sender signature, so the
  /// envelope stays deniable), and a recipient that pins the server key
  /// reports the sender as certified. It must describe THIS device (user id,
  /// device id, identity key, signing key) and be usable now; otherwise
  /// `StateError('Sender certificate does not describe this device')` is
  /// thrown before any ratchet state changes; renew and retry. Omit it for
  /// the legacy (uncertified) envelope, byte-compatible with earlier builds.
  /// When omitted and a `senderCertificateProvider` is configured, the
  /// provider's certificate is used instead (see the constructor); under
  /// [SealedSenderTrustPolicy.requireCertifiedSend] a missing certificate
  /// throws [SenderCertificateRequiredError] before any state changes.
  ///
  /// See also:
  ///   - [decryptSealedSender] to unseal and decrypt
  ///   - [encryptSealedSenderFull] for the preferred variant with explicit sender info
  Future<Map<String, dynamic>> encryptSealedSender(
    String recipientId,
    String recipientDeviceId,
    String recipientIdentityPublicKey,
    String plaintext, {
    IssuedSenderCertificate? senderCertificate,
  }) async {
    final certificate = await _resolveSenderCertificate(senderCertificate);
    return _withReceiveLock(() async {
      CryptoDebugLogger.log('SEAL', '═══ Encrypting Sealed Sender ═══');
      CryptoDebugLogger.log(
        'SEAL',
        'Recipient: $recipientId:$recipientDeviceId',
      );
      CryptoDebugLogger.logKeyInfo(
        'SEAL',
        'Recipient identity key',
        recipientIdentityPublicKey,
      );

      // Resolve and validate every synchronous envelope prerequisite before
      // touching the ratchet. In particular, a malformed pending PQXDH record,
      // missing local sender identity, or malformed recipient identity must not
      // consume the only first-contact chain step.
      _requireCanonicalBase64Bytes(
        recipientIdentityPublicKey,
        field: 'sealed recipient identity key',
        expectedLength: 32,
      );
      final identityKP = await _requireIdentityKeyPair();
      final senderId = await _cryptoStorage.getLocalUserId();
      final senderDeviceId = await _cryptoStorage.getLocalDeviceId();
      if (senderId == null ||
          senderId.isEmpty ||
          senderDeviceId == null ||
          senderDeviceId.isEmpty) {
        throw StateError(
          'Missing user_id or device_id for sealed sender envelope',
        );
      }
      await _checkSenderCertificateDescribesDevice(
        certificate,
        senderId: senderId,
        senderDeviceId: senderDeviceId,
        identityPublicKey: identityKP.publicKey,
      );
      final pendingPreKey = _validatePendingPreKey(
        await _cryptoStorage.getPendingPreKeyInfo(
          recipientId,
          recipientDeviceId,
        ),
      );

      final persistedRatchet = await _loadSession(
        recipientId,
        recipientDeviceId,
      );
      final ratchet = DoubleRatchet.fromJson(persistedRatchet.state.toJson());
      CryptoDebugLogger.logRatchetState(
        'SEAL',
        'Ratchet BEFORE encrypt',
        ratchet.state.toJson(),
      );
      final encrypted = await ratchet.encrypt(
        MessagePadding.padString(plaintext),
        version: _ratchetSendVersion(
          recipientId,
          recipientDeviceId,
          ratchet.state,
        ),
        localIdentityKey: identityKP.publicKey,
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

      Map<String, dynamic> innerEnvelope;
      if (pendingPreKey != null) {
        CryptoDebugLogger.log(
          'SEAL',
          'First message — inner envelope type=prekey',
        );
        innerEnvelope = {
          'type': 'prekey',
          'senderIdentityKey': identityKP.publicKey,
          'senderEphemeralKey': pendingPreKey.senderEphemeralKey,
          'kyberCiphertext': pendingPreKey.kyberCiphertext,
          ...pendingPreKey.routing.toEnvelopeJson(),
          'message': encrypted.toJson(),
        };
      } else {
        CryptoDebugLogger.log(
          'SEAL',
          'Subsequent message — inner envelope type=message',
        );
        innerEnvelope = {
          'type': 'message',
          'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
          'senderIdentityKey': identityKP.publicKey,
          'message': encrypted.toJson(),
        };
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
        senderCertificate: certificate,
      );

      CryptoDebugLogger.log('SEAL', '═══ Sealed Sender envelope created ═══');
      final result = <String, dynamic>{
        ...sealedEnvelope,
        'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
        if (pendingPreKey != null)
          'kyberCiphertext': pendingPreKey.kyberCiphertext,
        if (pendingPreKey != null)
          ...pendingPreKey.routing.toSealedProjectionJson(),
      };

      // Commit the candidate ratchet only after the protected and projected
      // sealed envelope has been built successfully. A seal failure leaves both
      // persistent and cached session state untouched.
      await _cryptoStorage.saveSession(
        recipientId,
        recipientDeviceId,
        ratchet.state,
      );
      _sessions[_sessionKey(recipientId, recipientDeviceId)] = ratchet;
      if (pendingPreKey != null) {
        await _cryptoStorage.clearPendingPreKeyInfo(
          recipientId,
          recipientDeviceId,
        );
      }
      return result;
    }, pendingScope: _sessionKey(recipientId, recipientDeviceId));
  }

  /// Build one sealed ciphertext and a durable ratchet commit plan without
  /// publishing either the new session state or first-contact pending clear.
  /// The host must persist [PreparedSend.envelope] first and then call
  /// [acknowledgeSend].
  ///
  /// [senderCertificate] follows the same rules as in [encryptSealedSender]
  /// (including the provider fallback); a rejected or missing-but-required
  /// certificate throws before the send journal is written. A retry of a
  /// delivery that is already pending returns the journaled envelope
  /// unchanged (with whatever certificate it was sealed with); the provider
  /// is still consulted first, so under `requireCertifiedSend` that retry
  /// also needs a certificate.
  Future<PreparedSend> prepareSealedSend({
    required String deliveryId,
    required String recipientId,
    required String recipientDeviceId,
    required String recipientIdentityPublicKey,
    required String plaintext,
    IssuedSenderCertificate? senderCertificate,
  }) async {
    final certificate = await _resolveSenderCertificate(senderCertificate);
    return _withReceiveLock(
      () => _withKeyLifecycleLock(
        () async {
          final deliveryIdHash = ReceiveReceipt.hashDeliveryId(deliveryId);
          var journal = await _readSendCommitJournalUnlocked();
          final completed = journal.completedForHash(deliveryIdHash);
          if (completed != null) {
            if (completed.recipientId != recipientId ||
                completed.recipientDeviceId != recipientDeviceId ||
                completed.plaintextDigest !=
                    SendReceipt.digestPlaintext(plaintext)) {
              throw StateError(
                'Send delivery id was reused with different input',
              );
            }
            throw StateError('Send delivery is already acknowledged');
          }

          final pending = journal.pending;
          if (pending != null) {
            final receipt = pending.receipt;
            if (receipt.deliveryIdHash != deliveryIdHash ||
                receipt.recipientId != recipientId ||
                receipt.recipientDeviceId != recipientDeviceId ||
                receipt.plaintextDigest !=
                    SendReceipt.digestPlaintext(plaintext)) {
              throw StateError('A different durable send is pending');
            }
            return PreparedSend(receipt: receipt, envelope: pending.envelope);
          }

          final candidate = await _buildSealedSendCandidateUnlocked(
            recipientId: recipientId,
            recipientDeviceId: recipientDeviceId,
            recipientIdentityPublicKey: recipientIdentityPublicKey,
            plaintext: plaintext,
            senderCertificate: certificate,
          );
          final receipt = SendReceipt.create(
            deliveryId: deliveryId,
            envelopeDigest: receiveEnvelopeDigest(candidate.envelope),
            plaintext: plaintext,
            recipientId: recipientId,
            recipientDeviceId: recipientDeviceId,
          );
          journal = await _readSendCommitJournalUnlocked();
          if (journal.pending != null ||
              journal.completedForHash(deliveryIdHash) != null) {
            throw StateError('Send commit journal changed during preparation');
          }
          await _writeSendCommitJournalUnlocked(
            journal.copyWith(
              pending: SendPendingCommit(
                receipt: receipt,
                phase: SendCommitPhase.prepared,
                envelope: candidate.envelope,
                mutations: candidate.mutations,
              ),
            ),
          );
          return PreparedSend(receipt: receipt, envelope: candidate.envelope);
        },
        allowPendingSend: true,
        pendingScope: _sessionKey(recipientId, recipientDeviceId),
      ),
      allowPendingSend: true,
      pendingScope: _sessionKey(recipientId, recipientDeviceId),
    );
  }

  Future<_SendCandidate> _buildSealedSendCandidateUnlocked({
    required String recipientId,
    required String recipientDeviceId,
    required String recipientIdentityPublicKey,
    required String plaintext,
    IssuedSenderCertificate? senderCertificate,
  }) async {
    _requireCanonicalBase64Bytes(
      recipientIdentityPublicKey,
      field: 'sealed recipient identity key',
      expectedLength: 32,
    );
    final identity = await _requireIdentityKeyPair();
    final senderId = await _cryptoStorage.getLocalUserId();
    final senderDeviceId = await _cryptoStorage.getLocalDeviceId();
    if (senderId == null ||
        senderId.isEmpty ||
        senderDeviceId == null ||
        senderDeviceId.isEmpty) {
      throw StateError(
        'Missing user_id or device_id for sealed sender envelope',
      );
    }
    await _checkSenderCertificateDescribesDevice(
      senderCertificate,
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      identityPublicKey: identity.publicKey,
    );
    final pendingPreKey = _validatePendingPreKey(
      await _cryptoStorage.getPendingPreKeyInfo(recipientId, recipientDeviceId),
    );
    final stored = await _cryptoStorage.getSession(
      recipientId,
      recipientDeviceId,
    );
    if (stored == null) {
      throw NoSessionError(
        recipientId,
        recipientDeviceId,
        'No session found for $recipientId:$recipientDeviceId',
      );
    }
    final ratchet = DoubleRatchet.fromJson(stored.toJson());
    // A legacy stamp stays on the candidate and is committed with it.
    await _requireSessionMatchesPinUnlocked(
      recipientId,
      recipientDeviceId,
      ratchet,
    );
    final encrypted = await ratchet.encrypt(
      MessagePadding.padString(plaintext),
      version: _ratchetSendVersion(
        recipientId,
        recipientDeviceId,
        ratchet.state,
      ),
      localIdentityKey: identity.publicKey,
    );
    final innerEnvelope = pendingPreKey == null
        ? <String, dynamic>{
            'type': 'message',
            'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
            'senderIdentityKey': identity.publicKey,
            'message': encrypted.toJson(),
          }
        : <String, dynamic>{
            'type': 'prekey',
            'senderIdentityKey': identity.publicKey,
            'senderEphemeralKey': pendingPreKey.senderEphemeralKey,
            'kyberCiphertext': pendingPreKey.kyberCiphertext,
            ...pendingPreKey.routing.toEnvelopeJson(),
            'message': encrypted.toJson(),
          };
    final sealed = await SealedSenderEnvelope.seal(
      senderId: senderId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: identity.publicKey,
      encryptedMessage: innerEnvelope,
      recipientIdentityPublicKey: recipientIdentityPublicKey,
      senderCertificate: senderCertificate,
    );
    final envelope = <String, dynamic>{
      ...sealed,
      'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
      if (pendingPreKey != null)
        'kyberCiphertext': pendingPreKey.kyberCiphertext,
      if (pendingPreKey != null)
        ...pendingPreKey.routing.toSealedProjectionJson(),
    };
    final sessionMutation = await _planReceiveMutationUnlocked(
      _receiveSessionStorageKey(recipientId, recipientDeviceId),
      jsonEncode(ratchet.state.toJson()),
    );
    if (sessionMutation == null) {
      throw StateError('Send candidate did not advance session state');
    }
    final mutations = <ReceiveStorageMutation>[sessionMutation];
    if (pendingPreKey != null) {
      final pendingMutation = await _planReceiveMutationUnlocked(
        'crypto_e2_pending_prekey_${recipientId}_$recipientDeviceId',
        null,
      );
      if (pendingMutation == null) {
        throw StateError('First-contact send lost its pending handshake');
      }
      mutations.add(pendingMutation);
    }
    return _SendCandidate(envelope: envelope, mutations: mutations);
  }

  /// The exact provisional send, if the host has not completed its queue ACK.
  Future<PreparedSend?> pendingSend() => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      final pending = (await _readSendCommitJournalUnlocked()).pending;
      return pending == null
          ? null
          : PreparedSend(receipt: pending.receipt, envelope: pending.envelope);
    }, allowPendingSend: true),
    allowPendingSend: true,
  );

  /// Publish a prepared ratchet step only after the host queue row is durable.
  Future<SendReceipt> acknowledgeSend(SendReceipt receipt) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      receipt.requireValid();
      var journal = await _readSendCommitJournalUnlocked();
      final completed = journal.completedForHash(receipt.deliveryIdHash);
      if (completed != null) {
        if (!completed.matchesExact(receipt)) {
          throw StateError('Send acknowledgement receipt drift');
        }
        return completed;
      }
      var pending = journal.pending;
      if (pending == null || !pending.receipt.matchesExact(receipt)) {
        throw StateError('Send receipt is not pending');
      }
      if (pending.phase == SendCommitPhase.prepared) {
        await _verifyReceivePreStateUnlocked(pending.mutations);
        await _writeSendCommitJournalUnlocked(
          journal.copyWith(
            pending: pending.copyWith(phase: SendCommitPhase.commitDecided),
          ),
        );
        journal = await _readSendCommitJournalUnlocked();
        pending = journal.pending!;
      }
      for (final mutation in pending.mutations) {
        await _applyReceiveMutationUnlocked(mutation);
      }
      _sessions.remove(
        _sessionKey(receipt.recipientId, receipt.recipientDeviceId),
      );
      journal = await _readSendCommitJournalUnlocked();
      final current = journal.pending;
      if (current == null || !current.receipt.matchesExact(receipt)) {
        throw StateError('Send commit journal changed during acknowledgement');
      }
      final completedReceipts = <SendReceipt>[...journal.completed, receipt];
      final bounded =
          completedReceipts.length > SendCommitJournal.maxCompletedReceipts
          ? completedReceipts.sublist(
              completedReceipts.length - SendCommitJournal.maxCompletedReceipts,
            )
          : completedReceipts;
      await _writeSendCommitJournalUnlocked(
        journal.copyWith(pending: null, completed: bounded),
      );
      return receipt;
    }, allowPendingSend: true),
    allowPendingSend: true,
  );

  /// Discard a ciphertext whose host queue row was never committed.
  Future<void> abortPreparedSend(SendReceipt receipt) => _withReceiveLock(
    () => _withKeyLifecycleLock(() async {
      receipt.requireValid();
      final journal = await _readSendCommitJournalUnlocked();
      final pending = journal.pending;
      if (pending == null) return;
      if (!pending.receipt.matchesExact(receipt)) {
        throw StateError('Send abort receipt drift');
      }
      if (pending.phase != SendCommitPhase.prepared) {
        throw StateError('A host-durable send cannot be aborted');
      }
      await _verifyReceivePreStateUnlocked(pending.mutations);
      await _writeSendCommitJournalUnlocked(journal.copyWith(pending: null));
    }, allowPendingSend: true),
    allowPendingSend: true,
  );

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
    IssuedSenderCertificate? senderCertificate,
  }) async {
    final storedSenderId = await _cryptoStorage.getLocalUserId();
    final storedSenderDeviceId = await _cryptoStorage.getLocalDeviceId();
    if (storedSenderId != senderId || storedSenderDeviceId != senderDeviceId) {
      throw StateError(
        'Explicit sealed-sender identity does not match local account state',
      );
    }

    // One implementation owns both normal and first-contact sealed messages.
    // In particular this preserves and projects the pending PQXDH envelope;
    // the former duplicate implementation always emitted `type: message` and
    // made this public "preferred" API unusable for first contact.
    return encryptSealedSender(
      recipientId,
      recipientDeviceId,
      recipientIdentityPublicKey,
      plaintext,
      senderCertificate: senderCertificate,
    );
  }

  /// R4-C3: checks a host-supplied Sender Certificate against THIS device
  /// before any ratchet or journal work; `null` is a legacy (uncertified)
  /// send. Only PUBLIC keys are compared: contract v2 removed the
  /// per-recipient sender binding, so no private key is read or used.
  ///
  /// The certificate must parse, name exactly the local user id, device id,
  /// identity key and signing key, and be usable now. Anything else throws
  /// `StateError('Sender certificate does not describe this device')`: the
  /// host should fetch a fresh certificate (this is also what an expired
  /// cached certificate produces) and retry the send.
  Future<void> _checkSenderCertificateDescribesDevice(
    IssuedSenderCertificate? certificate, {
    required String senderId,
    required String senderDeviceId,
    required String identityPublicKey,
  }) async {
    if (certificate == null) return;
    final SenderCertificate cert;
    try {
      cert = SenderCertificate.parse(certificate.certificateBytes);
    } on SealedSenderCertificateError {
      throw StateError(_senderCertificateNotThisDevice);
    }
    final signing = await _cryptoStorage.getSigningKeyPair();
    if (signing == null ||
        cert.senderId != senderId ||
        cert.senderDeviceId != senderDeviceId ||
        cert.senderIdentityKey != identityPublicKey ||
        cert.senderSigningKey != signing.publicKey ||
        !SenderCertificate.isCanonicalBase64(
          certificate.serverSignature,
          length: 64,
        ) ||
        !cert.usableAt(DateTime.now().millisecondsSinceEpoch)) {
      throw StateError(_senderCertificateNotThisDevice);
    }
  }

  static const String _senderCertificateNotThisDevice =
      'Sender certificate does not describe this device';

  /// Read-only outer unseal of [sealedEnvelope] (R4-C3).
  ///
  /// Tells the host who CLAIMS to be sending, whether the Sender Certificate
  /// verifies under the pinned server keys (same checks as the receive path,
  /// including the per-device signing-key pin), and whether this would be the
  /// contact's first identity pin. Use it after `prepareSealedReceive` /
  /// `decryptSealedSender` throws [UnverifiedFirstContactError]: resolve a
  /// [FirstContactApproval] for the claimed identity (key bundle / key
  /// transparency / user) and retry the SAME delivery with it.
  ///
  /// It persists nothing: no session, pin, one-time prekey, journal entry or
  /// nonce is written or reserved and no security event is emitted, so the
  /// real receive of the same envelope still succeeds. The inner message is
  /// never decrypted or returned. Cost: one extra X25519 + AES-GCM unseal.
  ///
  /// Throws [FormatException] for a malformed/legacy envelope,
  /// [StateError] for an already-seen nonce or an outer/inner identity
  /// mismatch, [SealedSenderCertificateError] for a rejected certificate,
  /// and `SecretBoxAuthenticationError` if the envelope is not for this
  /// device or was tampered with.
  Future<SealedSenderPeek> peekSealedSender(
    Map<String, dynamic> sealedEnvelope,
  ) => _withReceiveLock(
    () async {
      if (sealedEnvelope['cryptoProtocolEpoch'] !=
          RisaalCryptoProtocol.cryptoProtocolEpoch) {
        throw const FormatException(
          'Unsupported or legacy sealed-sender protocol',
        );
      }
      final nonce = sealedEnvelope['nonce'];
      if (nonce is! String || nonce.isEmpty) {
        throw const FormatException('Invalid sealed-sender nonce');
      }
      // Throwaway copy: unseal records the nonce into it on success.
      final throwawayNonces = Set<String>.from(
        await _cryptoStorage.loadSeenNonces(),
      );
      if (throwawayNonces.contains(nonce)) {
        throw StateError('Sealed sender nonce already seen — rejecting replay');
      }
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealedEnvelope,
        recipientIdentityKeyPair: await _requireIdentityKeyPair(),
        seenNonces: throwawayNonces,
        maxReplayWindowMs: _sealedSenderReplayWindowMs,
        trustedServerSigningKeys: _trustedServerSigningKeys,
      );
      final inner = content.encryptedMessage;
      final innerType = inner['type'];
      if (innerType != 'prekey' && innerType != 'message') {
        throw const FormatException('Unsupported sealed inner envelope type');
      }
      final innerIdentityKey = inner['senderIdentityKey'];
      if (innerIdentityKey is! String ||
          innerIdentityKey != content.senderIdentityKey) {
        throw StateError(
          'Sealed sender outer/inner identity mismatch — rejecting spoofed sender',
        );
      }
      if (content.certified) {
        final pinned = await _cryptoStorage.getPeerSigningKey(
          content.senderId,
          content.senderDeviceId,
        );
        if (pinned != null && pinned != content.senderSigningKey) {
          throw SealedSenderCertificateError(
            SenderCertificateFailure.identityMismatch,
          );
        }
      }
      return SealedSenderPeek(
        senderId: content.senderId,
        senderDeviceId: content.senderDeviceId,
        senderIdentityKey: content.senderIdentityKey,
        certified: content.certified,
        certificateIgnored: content.certificateIgnored,
        certificateKeyId: content.certificateKeyId,
        isFirstContact: await _isFirstContactUnlocked(
          content.senderId,
          content.senderDeviceId,
        ),
        innerType: innerType as String,
      );
    },
    allowPendingReceive: true,
    allowPendingSend: true,
  );

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
  ///   - [MessageAuthenticationError] if an established inner message fails authentication
  ///
  /// Example:
  /// ```dart
  /// final result = await manager.decryptSealedSender(envelope);
  /// print('Message from ${result.senderId}: ${result.plaintext}');
  /// ```
  Future<SealedSenderResult> decryptSealedSender(
    Map<String, dynamic> sealedEnvelope, {
    FirstContactApproval? firstContactApproval,
  }) => _withReceiveLock(
    () => _withSealedDecryptLock(
      () => _decryptSealedSenderUnlocked(sealedEnvelope, firstContactApproval),
    ),
  );

  Future<SealedSenderResult> _decryptSealedSenderUnlocked(
    Map<String, dynamic> sealedEnvelope,
    FirstContactApproval? firstContactApproval,
  ) async {
    CryptoDebugLogger.log('UNSEAL', '═══ Decrypting Sealed Sender ═══');
    CryptoDebugLogger.log(
      'UNSEAL',
      'Envelope keys: ${sealedEnvelope.keys.toList()}',
    );

    if (sealedEnvelope['cryptoProtocolEpoch'] !=
        RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException(
        'Unsupported or legacy sealed-sender protocol',
      );
    }
    _preflightSealedOuterRoutingShape(sealedEnvelope);

    final nonce = sealedEnvelope['nonce'];
    if (nonce is! String || nonce.isEmpty) {
      throw const FormatException('Invalid sealed-sender nonce');
    }
    if (_seenNonces.contains(nonce) || !_inFlightSealedNonces.add(nonce)) {
      _eventBus?.emitType(
        SecurityEventType.replayRejected,
        metadata: const {
          'source': 'sealed_sender',
          'reason': 'duplicate_nonce',
        },
      );
      throw StateError('Sealed sender nonce already seen — rejecting replay');
    }

    try {
      return await _decryptClaimedSealedEnvelope(
        sealedEnvelope,
        nonce,
        firstContactApproval,
      );
    } catch (error) {
      // unseal() records the nonce after outer authentication. Every later gate
      // (routing, identity binding, pinned identity, ratchet auth and replay
      // persistence) is part of one transaction: on any failure the same
      // authentic envelope remains retryable.
      _seenNonces.remove(nonce);
      if (error is SealedSenderCertificateError) {
        _emitTrustEvent(SecurityEventType.senderCertificateRejected, {
          'reason': error.reason.name,
        });
      }
      final message = error.toString();
      if (message.contains('replay window')) {
        _eventBus?.emitType(
          SecurityEventType.replayRejected,
          metadata: {'source': 'sealed_sender', 'reason': message},
        );
      }
      rethrow;
    } finally {
      _inFlightSealedNonces.remove(nonce);
    }
  }

  Future<SealedSenderResult> _decryptClaimedSealedEnvelope(
    Map<String, dynamic> sealedEnvelope,
    String nonce,
    FirstContactApproval? firstContactApproval,
  ) async {
    final identityKP = await _requireIdentityKeyPair();
    final content = await SealedSenderEnvelope.unseal(
      sealedEnvelope: sealedEnvelope,
      recipientIdentityKeyPair: identityKP,
      seenNonces: _seenNonces,
      maxReplayWindowMs: _sealedSenderReplayWindowMs,
      trustedServerSigningKeys: _trustedServerSigningKeys,
    );
    final trust = await _admitSealedContentUnlocked(
      content,
      firstContactApproval,
    );

    _validateSealedKemRouting(sealedEnvelope, content.encryptedMessage);

    // The protected inner PQXDH/ratchet envelope is the cryptographic source of
    // truth. A self-asserted outer certificate must name the exact same identity
    // key before any one-time key or session state can be mutated.
    final innerIdentityKey = content.encryptedMessage['senderIdentityKey'];
    if (innerIdentityKey is! String ||
        innerIdentityKey.isEmpty ||
        innerIdentityKey != content.senderIdentityKey) {
      throw StateError(
        'Sealed sender outer/inner identity mismatch — rejecting spoofed sender',
      );
    }

    final pinnedIdentityKey = await _cryptoStorage.getSessionIdentityKey(
      content.senderId,
      content.senderDeviceId,
    );
    if (pinnedIdentityKey != null &&
        pinnedIdentityKey != content.senderIdentityKey) {
      _eventBus?.emitType(
        SecurityEventType.peerIdentityKeyChanged,
        metadata: {
          'source': 'sealed_sender',
          'senderId': content.senderId,
          'senderDeviceId': content.senderDeviceId,
        },
      );
      throw StateError(
        'Sealed sender identity mismatch for ${content.senderId}: the claimed '
        'identity key does not match the key pinned in the established session '
        '(possible sender spoofing / MITM). Re-verify the safety number.',
      );
    }

    final plaintext = await _decryptMessageWithTrust(
      content.senderId,
      content.senderDeviceId,
      content.encryptedMessage,
      trust,
    );
    // R4-C3-V2: no signing-key pin is seeded from a certificate (see the WAL
    // lane in _buildSealedReceiveCandidate).

    // unseal() already placed the nonce in memory. Persist only after every
    // authentication/state transition succeeds; the outer catch rolls it back
    // if this write itself fails.
    await _cryptoStorage.saveSeenNonces(_seenNonces);
    CryptoDebugLogger.log(
      'UNSEAL',
      '═══ Sealed Sender decrypted successfully ═══',
    );
    return SealedSenderResult(
      senderId: content.senderId,
      senderDeviceId: content.senderDeviceId,
      plaintext: plaintext,
      senderAuthentication: trust.authentication,
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

  /// Legacy standalone signed-pre-key rotation; always fails closed.
  ///
  /// Use [prepareKeyBundleReplacement] so SPK, KEM and OPKs rotate together
  /// under one durable generation and exact server receipt.
  Future<Map<String, dynamic>?> rotateSignedPreKeyIfNeeded({
    Duration maxAge = const Duration(days: 7),
  }) async => throw _legacyKeyBundleApiDisabled();

  Future<Map<String, dynamic>?> _rotateSignedPreKeyIfNeededUnlocked({
    required Duration maxAge,
  }) async {
    // First, clean up any expired previous key from the overlap window
    await _cleanupExpiredPreviousSignedPreKey();

    final createdAt = await _cryptoStorage.getSignedPreKeyCreatedAt();
    final now = DateTime.now().millisecondsSinceEpoch;

    if (createdAt != null && (now - createdAt) < maxAge.inMilliseconds) {
      // Check absolute max lifetime — never use a key past this age.
      // Grace period tolerates small clock drifts (e.g. device clock 30min ahead).
      final maxWithGrace =
          absoluteMaxKeyLifetime.inMilliseconds +
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

    CryptoDebugLogger.log('KEY_LIFECYCLE', '═══ Rotating signed pre-key ═══');

    final signingKP = await _cryptoStorage.getSigningKeyPair();
    if (signingKP == null) {
      throw StateError('Signing key pair not found. Call initialize() first.');
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

    final newKeyId = await _cryptoStorage.reserveNextSignedPreKeyId();

    final newSignedPreKey = await SignalKeyHelper.generateSignedPreKey(
      newKeyId,
      signingKP,
    );
    final currentKyber = await _cryptoStorage.getKyberKeyPair();
    if (currentKyber == null) {
      throw StateError('ML-KEM key pair not found. Call initialize() first.');
    }
    // Publish the intended generation before mutating the current SPK. If the
    // process dies during the following writes, initialize() sees pending
    // state and refuses to connect before a coherent exact bundle is uploaded.
    await _cryptoStorage.markKeyBundleUploadPending(
      await _keyBundleGenerationForKeysUnlocked(
        signedPreKey: newSignedPreKey,
        kyberKeyPair: currentKyber,
      ),
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

    return _generateKeyBundleUnlocked();
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

  /// Legacy standalone ML-KEM rotation; always fails closed.
  ///
  /// Use [prepareKeyBundleReplacement] so SPK, KEM and OPKs rotate together
  /// under one durable generation and exact server receipt.
  Future<bool> rotateKyberKeyIfNeeded({
    Duration maxAge = const Duration(days: 7),
  }) async => throw _legacyKeyBundleApiDisabled();

  Future<bool> _rotateKyberKeyIfNeededUnlocked({
    required Duration maxAge,
  }) async {
    // Clean up expired previous Kyber key
    await _cleanupExpiredPreviousKyberKey();

    final createdAt = await _cryptoStorage.getKyberCreatedAt();
    final now = DateTime.now().millisecondsSinceEpoch;

    if (createdAt != null && (now - createdAt) < maxAge.inMilliseconds) {
      // Check absolute max lifetime with clock drift grace period
      final maxWithGrace =
          absoluteMaxKeyLifetime.inMilliseconds +
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

      final keyId = await _cryptoStorage.reserveNextKyberKeyId();
      final kyberKP = SignalKeyHelper.generateKyberKeyPair(keyId: keyId);
      final currentSignedPreKey = await _cryptoStorage.getSignedPreKey();
      if (currentSignedPreKey == null) {
        throw StateError('Signed pre-key not found. Call initialize() first.');
      }
      await _cryptoStorage.markKeyBundleUploadPending(
        await _keyBundleGenerationForKeysUnlocked(
          signedPreKey: currentSignedPreKey,
          kyberKeyPair: kyberKP,
        ),
      );
      await _cryptoStorage.saveKyberKeyPair(kyberKP);
      await _cryptoStorage.saveKyberCreatedAt(now);

      CryptoDebugLogger.logKeyInfo(
        'KEY_LIFECYCLE',
        'Rotated Kyber-768 public key',
        kyberKP.publicKey,
      );

      _eventBus?.emitType(
        SecurityEventType.keyRotationCompleted,
        metadata: {'keyType': 'kyber', 'keyId': keyId},
      );

      return true;
    } catch (e) {
      CryptoDebugLogger.logError(
        'KEY_LIFECYCLE',
        'Kyber rotation failed — post-quantum unavailable',
        e,
      );
      throw StateError('ML-KEM key rotation failed: $e');
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

  /// Legacy flat rotation entry point; always fails closed.
  ///
  /// Call [prepareKeyBundleReplacement] and drive the durable journal
  /// install/dispatch/ACK sequence instead.
  Future<Map<String, dynamic>?> rotateKeysIfNeeded({
    Duration signedPreKeyMaxAge = const Duration(days: 7),
    Duration kyberKeyMaxAge = const Duration(days: 7),
  }) async => throw _legacyKeyBundleApiDisabled();

  /// Legacy flat force-rotation entry point; always fails closed.
  Future<Map<String, dynamic>> forceKeyRotationNow() async =>
      throw _legacyKeyBundleApiDisabled();

  /// Return the remaining count of the latest authenticated accepted generation.
  /// Legacy/quarantined flat pools are deliberately not counted.
  Future<int> oneTimePreKeyCount() =>
      _cryptoStorage.getAcceptedGenerationOneTimePreKeyCount();

  /// Whether the one-time pre-key count is at or below [threshold].
  ///
  /// Returns `true` if exhaustion is near and a full versioned replacement
  /// should be prepared.
  Future<bool> isPreKeyExhaustionNear({int threshold = 10}) async {
    final count = await oneTimePreKeyCount();
    return count <= threshold;
  }

  /// Best-effort post-commit observation for the latest accepted generation.
  /// Retained/staged generation depletion is silent, and no observer failure
  /// can turn authenticated success into a retry after tombstoning.
  void _notifyPreKeyGenerationExhaustionBestEffort({
    required int remaining,
    required bool isLatestAccepted,
  }) {
    if (!isLatestAccepted || remaining > defaultOtpLowWatermark) return;
    try {
      if (remaining == 0) {
        _eventBus?.emitType(
          SecurityEventType.otpPoolExhausted,
          metadata: {'remaining': 0},
        );
      } else {
        _eventBus?.emitType(
          SecurityEventType.otpPoolLow,
          metadata: {
            'remaining': remaining,
            'threshold': defaultOtpLowWatermark,
          },
        );
      }
      _onPreKeyExhaustionWarning?.call(remaining);
      _eventBus?.emitType(
        SecurityEventType.preKeyReplenishmentNeeded,
        metadata: {
          'generated': 0,
          'previousCount': remaining,
          'newTotal': remaining,
          'requiresFullReplacement': true,
        },
      );
    } on Object {
      // Post-commit observers are explicitly non-authoritative.
    }
  }

  // ── One-Time Pre-Key Replenishment ────────────────────────────────

  /// Legacy standalone OPK replenishment entry point; always fails closed.
  Future<List<Map<String, dynamic>>> generateOneTimePreKeys(int count) =>
      Future<List<Map<String, dynamic>>>.error(_legacyKeyBundleApiDisabled());

  // ── Key Expiry Enforcement ──────────────────────────────────────

  /// Validate that all local keys are within their maximum lifetime.
  ///
  /// Call on app startup (after [initialize]) to ensure no key is being
  /// used past its absolute max lifetime. Returns `true` if all keys are
  /// valid and `false` when the caller must drive a journaled full
  /// replacement. This method never mutates or uploads flat material.
  Future<bool> validateKeyFreshness() async {
    final now = DateTime.now().millisecondsSinceEpoch;
    var allFresh = true;

    // Clock drift grace period for all expiry checks
    final maxWithGrace =
        absoluteMaxKeyLifetime.inMilliseconds +
        clockDriftGracePeriod.inMilliseconds;

    // Check signed pre-key age
    final spkCreatedAt = await _cryptoStorage.getSignedPreKeyCreatedAt();
    if (spkCreatedAt != null) {
      final age = now - spkCreatedAt;
      if (age > maxWithGrace) {
        CryptoDebugLogger.log(
          'KEY_LIFECYCLE',
          'EXPIRED: Signed pre-key age ${age}ms exceeds '
              '${absoluteMaxKeyLifetime.inMilliseconds}ms — replacement required',
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
              '${absoluteMaxKeyLifetime.inMilliseconds}ms — replacement required',
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

  /// Resolve ML-KEM private material by the exact authenticated envelope key id.
  /// Current and retained keys are selected by id; callers must never infer a
  /// key from ciphertext length or silently fall back to the current key.
  Future<KyberKeyPair?> getKyberKeyPairById(int keyId) {
    if (keyId <= 0 || keyId > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('Invalid ML-KEM key id');
    }
    return _withKeyLifecycleLock(
      () => _cryptoStorage.getKyberKeyPairById(keyId),
    );
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
  /// Share the sender key this device already holds for [groupId], without
  /// rotating it. Returns null if there is nothing to share yet.
  ///
  /// Use this to answer a member's request. [generateGroupSenderKey] re-keys,
  /// and re-keying for one requester silently cuts every other member off.
  Future<SenderKeyDistribution?> currentGroupSenderKeyDistribution(
    String groupId,
  ) => _senderKeyManager.currentSenderKeyDistribution(groupId);

  Future<SenderKeyDistribution> generateGroupSenderKey(String groupId) async {
    CryptoDebugLogger.log('GROUP', '═══ Generating group Sender Key ═══');
    CryptoDebugLogger.log('GROUP', 'groupId=$groupId');
    final distribution = await _senderKeyManager.generateSenderKey(groupId);
    CryptoDebugLogger.log('GROUP', '═══ Group Sender Key generated ═══');
    return distribution;
  }

  Future<SenderKeyRotationProposal> prepareGroupSenderKeyRotation(
    String groupId, {
    required String rotationId,
  }) => _senderKeyManager.prepareSenderKeyRotation(
    groupId,
    rotationId: rotationId,
  );

  Future<SenderKeyRotationProposal?> pendingGroupSenderKeyRotation(
    String groupId,
  ) => _senderKeyManager.pendingSenderKeyRotation(groupId);

  Future<void> commitGroupSenderKeyRotation(
    String groupId, {
    required String rotationId,
  }) => _senderKeyManager.commitSenderKeyRotation(
    groupId,
    rotationId: rotationId,
  );

  Future<void> abortGroupSenderKeyRotation(
    String groupId, {
    required String rotationId,
  }) =>
      _senderKeyManager.abortSenderKeyRotation(groupId, rotationId: rotationId);

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
  /// Encrypts [plaintext] with AES-256-GCM using a key derived from your sender
  /// key chain. Epoch and iteration are authenticated, and the blob is signed
  /// with the sender's Ed25519 key.
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
  /// the Ed25519 signature and AES-GCM tag before committing chain state.
  ///
  /// If the message iteration is ahead of the stored chain state, the chain
  /// is fast-forwarded (up to 256 iterations) to catch up. This handles
  /// out-of-order delivery or missed messages.
  ///
  /// Returns the decrypted plaintext string (after unpadding).
  ///
  /// Throws:
  ///   - [StateError] if you don't have the sender's sender key (call [processGroupSenderKey] first)
  ///   - [StateError] if signature or AEAD verification fails
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

  // ── Group Roster (R4-H10) ────────────────────────────────────────

  /// This device as a GroupRoster v1 signer: local user id, device id and
  /// the identity signing PUBLIC key. Throws [StateError] when any is missing.
  Future<GroupRosterSigner> localGroupRosterSigner() async {
    final userId = await _cryptoStorage.getLocalUserId();
    final deviceId = await _cryptoStorage.getLocalDeviceId();
    final signing = await _cryptoStorage.getSigningKeyPair();
    if (userId == null ||
        userId.isEmpty ||
        deviceId == null ||
        deviceId.isEmpty ||
        signing == null) {
      throw StateError('Missing user_id, device_id or signing key for roster');
    }
    return GroupRosterSigner(
      userId: userId,
      deviceId: deviceId,
      signingKey: signing.publicKey,
    );
  }

  /// Signs a GroupRoster v1 string with this device's identity signing key
  /// over `groupRosterDomain || utf8(rosterJson)`; returns canonical base64.
  ///
  /// Parses first ([GroupRosterError] on a malformed roster) and refuses with
  /// `StateError('Roster signer is not this device')` unless `roster.signer`
  /// equals [localGroupRosterSigner]. The private key never leaves the
  /// manager.
  Future<String> signGroupRoster(String rosterJson) async {
    final roster = GroupRoster.parse(rosterJson);
    final local = await localGroupRosterSigner();
    final signing = await _cryptoStorage.getSigningKeyPair();
    if (roster.signer != local ||
        signing == null ||
        signing.publicKey != local.signingKey) {
      throw StateError('Roster signer is not this device');
    }
    final signature = await SignalKeyHelper.sign(
      signing.privateKey,
      GroupRoster.signingInput(rosterJson),
    );
    if (!await GroupRoster.verifySignature(
      rosterJson,
      signature,
      local.signingKey,
    )) {
      throw StateError('Roster signature self-check failed');
    }
    return signature;
  }

  // ── Private Helpers ───────────────────────────────────────────────

  String _sessionKey(String recipientId, String deviceId) =>
      '$recipientId:$deviceId';

  /// R4-L1: the Double Ratchet wire version for the next send on [state].
  ///
  /// A session that already sends v3 ([RatchetState.sendV3], which includes
  /// every session created with PQXDH transcript 2) keeps sending v3 whatever
  /// the flag says, because its peer refuses v2 from it (L1-I1). Otherwise v3
  /// needs [sendRatchetV3Enabled] and both identity keys. A session without a
  /// recorded remote identity is never sent v3 (L1-I2): it keeps v2 and is
  /// marked for re-establishment.
  int _ratchetSendVersion(String peerId, String deviceId, RatchetState state) {
    if (state.sendV3) return EncryptedMessage.identityBoundWireVersion;
    if (!sendRatchetV3Enabled) return EncryptedMessage.currentWireVersion;
    if (state.remoteIdentityKey == null) {
      _markSessionForReestablishment(peerId, deviceId);
      return EncryptedMessage.currentWireVersion;
    }
    return EncryptedMessage.identityBoundWireVersion;
  }

  /// R4-L1: the local identity key a receive of [message] binds, or `null`
  /// for v2, which binds none. A v3 message on a session without a recorded
  /// remote identity marks it for re-establishment; the decrypt then refuses
  /// it (L1-I2).
  Future<String?> _receiveIdentityKey(
    String peerId,
    String deviceId,
    RatchetState state,
    EncryptedMessage message,
  ) async {
    if (message.version != EncryptedMessage.identityBoundWireVersion) {
      return null;
    }
    if (state.remoteIdentityKey == null) {
      _markSessionForReestablishment(peerId, deviceId);
    }
    return (await _requireIdentityKeyPair()).publicKey;
  }

  /// Report [peerId]:[deviceId] to [_onSessionReestablishmentNeeded], once
  /// per session per manager. Never re-establishes anything itself.
  void _markSessionForReestablishment(String peerId, String deviceId) {
    if (!_sessionsMarkedForReestablishment.add(_sessionKey(peerId, deviceId))) {
      return;
    }
    try {
      _onSessionReestablishmentNeeded?.call(peerId, deviceId);
    } on Object {
      // A host callback must never be able to break the send or receive.
    }
  }

  /// Record on a fresh responder session what its PreKey message proved: the
  /// sender's identity (needed before a v3 first message can be opened) and,
  /// for PQXDH transcript 2, that both sides speak v3 from the start (R4-L1).
  void _bindResponderSession(
    RatchetState state,
    String senderIdentityKey,
    PreKeyHandshakeRouting routing,
  ) {
    state.remoteIdentityKey = senderIdentityKey;
    if (routing.transcriptVersion ==
        PreKeyHandshakeRouting.identityBoundTranscriptVersion) {
      state
        ..sendV3 = true
        ..peerSpeaksV3 = true;
    }
  }

  Future<KeyPair> _requireIdentityKeyPair() async {
    final kp = await _cryptoStorage.getIdentityKeyPair();
    if (kp == null) {
      throw StateError('Identity key pair not found. Call initialize() first.');
    }
    return kp;
  }

  /// Sanitized health snapshot for BETA diagnostics — COUNTS and BOOLEANS only,
  /// NEVER key material. Reveals at a glance whether persistent storage has lost
  /// crypto state (e.g. `oneTimePreKeyCount: 0` + `inMemorySessionCount: 0` +
  /// `hasIdentity: false` → the iOS storage-loss bug behind "No session found").
  Future<Map<String, Object>> diagnosticsHealth() async {
    try {
      final identity = await _cryptoStorage.getIdentityKeyPair();
      final signed = await _cryptoStorage.getSignedPreKey();
      final kyber = await _cryptoStorage.getKyberKeyPair();
      final otpks = await _cryptoStorage.getOneTimePreKeys();
      return <String, Object>{
        'hasIdentity': identity != null,
        'hasSignedPreKey': signed != null,
        'hasKyber': kyber != null,
        'oneTimePreKeyCount': otpks.length,
        'inMemorySessionCount': _sessions.length,
        'seenNonceCount': _seenNonces.length,
      };
    } catch (e) {
      return <String, Object>{'healthError': e.runtimeType.toString()};
    }
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
      final cached = _sessions[key]!;
      if (await _requireSessionMatchesPinUnlocked(
        recipientId,
        deviceId,
        cached,
      )) {
        await _cryptoStorage.saveSession(recipientId, deviceId, cached.state);
      }
      return cached;
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
      throw NoSessionError(
        recipientId,
        deviceId,
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
    // Refuse before caching; persist a legacy record's first-load stamp.
    if (await _requireSessionMatchesPinUnlocked(
      recipientId,
      deviceId,
      ratchet,
    )) {
      await _cryptoStorage.saveSession(recipientId, deviceId, ratchet.state);
    }
    _sessions[key] = ratchet;
    return ratchet;
  }
}
