/// Signal Protocol implementation in pure Dart.
///
/// Provides end-to-end encryption with forward secrecy, post-compromise
/// security, deniable authentication, metadata protection (Sealed Sender),
/// and post-quantum resistance (Kyber-768 hybrid).
///
/// Entry point: [SignalProtocolManager]
///
/// Quick start:
/// ```dart
/// import 'package:risaal_crypto/risaal_crypto.dart';
///
/// final manager = SignalProtocolManager(secureStorage: storage);
/// await manager.wipeForFreshRegistration();
/// await manager.initialize();
/// final prepared = await manager.prepareInitialKeyBundleRegistration();
/// await manager.installKeyBundleReplacement(prepared);
/// final dispatch =
///     await manager.markKeyBundleReplacementDispatchStarted(prepared);
/// final receipt = await register(
///   dispatch.toInitialRegistrationKeyBundle(),
/// );
/// await manager.acknowledgeKeyBundleReplacement(
///   snapshot: prepared,
///   acceptance: receipt,
/// );
/// ```
///
/// {@category Encryption}
library;

// ── Storage Interface ──────────────────────────────────────────────────
// Abstract interface for platform-secure key-value storage (Keychain, Keystore).
// Implement this with FlutterSecureStorage or your own adapter.

export 'src/crypto_secure_storage.dart';

// ── Key Models ─────────────────────────────────────────────────────────
// Data models for Signal Protocol keys: identity keys, pre-keys, session state.

export 'src/models/signal_keys.dart';
export 'src/models/session_state.dart';

// ── Key Generation & Helpers ───────────────────────────────────────────
// Low-level cryptographic primitives: X25519, Ed25519, Kyber-768 key generation.

export 'src/key_helper.dart';

// ── Storage Layer ──────────────────────────────────────────────────────
// High-level storage API wrapping CryptoSecureStorage with crypto-specific logic.

export 'src/crypto_storage.dart';
export 'src/crypto_protocol.dart';
export 'src/key_bundle_replacement.dart'
    show
        GenerationRetirementPolicy,
        GenerationRetirementView,
        KeyBundleAcceptedReceipt,
        KeyBundleReplacementCommitment,
        KeyBundleReplacementPhase,
        KeyBundleReplacementSnapshot,
        OpkGenerationRole,
        UnacceptedFreshRegistrationRecoveryRequired,
        retirableGenerationIds;

// ── Signal Protocol Core ───────────────────────────────────────────────
// The main cryptographic protocols:
//   - X3DH: Extended Triple Diffie-Hellman (session establishment)
//   - DoubleRatchet: Forward secrecy + post-compromise security
//   - SealedSender: Metadata protection (hide sender from server)
//   - SenderKey: Group messaging (encrypt-once, decrypt-many)
//   - SignalProtocolManager: High-level API (use this)

export 'src/x3dh.dart';
export 'src/double_ratchet.dart';
export 'src/group_roster.dart';
export 'src/ratchet_batch_decrypt.dart' show RatchetBatchResult;
export 'src/receive_commit.dart'
    show
        PreparedReceive,
        ReceiveCommitRecoveryRequired,
        ReceiveEnvelopeKind,
        ReceiveReceipt,
        // The host must be able to recompute the exact digest the crypto layer
        // binds a delivery id to, or any host-side short-circuit silently drops
        // that binding.
        receiveEnvelopeDigest;
export 'src/send_commit.dart' show PreparedSend, SendReceipt;
export 'src/sealed_sender.dart';
export 'src/sealed_sender_errors.dart';
export 'src/session_errors.dart';
export 'src/sealed_sender_trust_policy.dart';
export 'src/sender_certificate.dart';
export 'src/sender_key.dart';
export 'src/signal_protocol_manager.dart';

// ── Security Utilities ─────────────────────────────────────────────────
// Additional security features:
//   - SafetyNumber: Identity verification fingerprints
//   - MessagePadding: Hide message length (fixed bucket sizes)
//   - SecureMemory: best-effort zeroing of package-owned key copies; native
//     SecureBuffer for host-managed keys
//   - SessionResetErrors: Custom exceptions for session auto-reset

export 'src/safety_number.dart';
export 'src/message_padding.dart';
export 'src/secure_memory.dart';
export 'src/session_reset_errors.dart';
export 'src/security_event_bus.dart';
export 'src/security_anomaly_detector.dart';

// ── Device transfer (R4-M37) ───────────────────────────────────────────
// QR handshake, SAS and chunked archive AEAD between the old and the new
// phone, and the versioned archive codec. Export/import of the crypto store:
// CryptoStorage.exportForTransfer / importForTransfer.

export 'src/transfer/transfer_archive.dart';
export 'src/transfer/transfer_crypto_store.dart'
    show TransferExportBlocked, TransferExportBlockedReason, TransferKeyListing;
export 'src/transfer/transfer_handshake.dart'
    show
        TransferArchiveDecryptFailed,
        TransferConfirmRejected,
        TransferHandshake,
        TransferJoin,
        TransferJoinRejected,
        TransferJoinRequest,
        TransferOffer,
        TransferProtocol,
        TransferSessionKeys;

// ── Debug (stripped in release builds) ──────────────────────────────────
// CryptoDebugLogger: Verbose logging for development (removed in --release builds).

export 'src/crypto_debug_logger.dart';
