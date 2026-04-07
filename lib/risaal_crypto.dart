/// Military-grade Signal Protocol implementation in pure Dart.
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
/// await manager.initialize();
/// final bundle = await manager.generateKeyBundle();
/// // Upload bundle to server...
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

// ── Signal Protocol Core ───────────────────────────────────────────────
// The main cryptographic protocols:
//   - X3DH: Extended Triple Diffie-Hellman (session establishment)
//   - DoubleRatchet: Forward secrecy + post-compromise security
//   - SealedSender: Metadata protection (hide sender from server)
//   - SenderKey: Group messaging (encrypt-once, decrypt-many)
//   - SignalProtocolManager: High-level API (use this)

export 'src/x3dh.dart';
export 'src/double_ratchet.dart';
export 'src/sealed_sender.dart';
export 'src/sender_key.dart';
export 'src/signal_protocol_manager.dart';

// ── Security Utilities ─────────────────────────────────────────────────
// Additional security features:
//   - SafetyNumber: Identity verification fingerprints
//   - MessagePadding: Hide message length (fixed bucket sizes)
//   - StegoService: LSB steganography (hide messages in images)
//   - SecureMemory: Guaranteed memory zeroing (FFI-based)
//   - SessionResetErrors: Custom exceptions for session auto-reset

export 'src/safety_number.dart';
export 'src/message_padding.dart';
export 'src/stego_service.dart';
export 'src/secure_memory.dart';
export 'src/session_reset_errors.dart';
export 'src/security_event_bus.dart';

// ── Debug (stripped in release builds) ──────────────────────────────────
// CryptoDebugLogger: Verbose logging for development (removed in --release builds).

export 'src/crypto_debug_logger.dart';
