# risaal_crypto

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Dart](https://img.shields.io/badge/Dart-%3E%3D3.0-0175C2.svg?logo=dart)](https://dart.dev)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#test-suite)
[![Stability](https://img.shields.io/badge/stability-alpha-orange.svg)](SECURITY.md)

**Signal Protocol implementation in pure Dart with post-quantum hybrid key agreement.**

Provides end-to-end encryption with forward secrecy, post-compromise security, deniable authentication, metadata protection, and Kyber-768 post-quantum resistance. Designed and extracted from the [Risaal](https://risaal.org) secure messenger.

> This library implements the same cryptographic protocols as [libsignal](https://github.com/nickolay/libsignal) (Signal Foundation) and [libsession](https://github.com/nickolay/libsession-util) (Session/Oxen), but written entirely in Dart for Flutter-native integration. See [PROTOCOL.md](PROTOCOL.md) for the full protocol specification.

---

## Protocol Overview

| Protocol | Purpose | Specification |
|----------|---------|---------------|
| [X3DH + PQXDH](PROTOCOL.md#3-x3dh-key-agreement) | Initial key agreement with post-quantum hybrid | [Marlinspike & Perrin 2016](https://signal.org/docs/specifications/x3dh/), [Brendel et al. 2024](https://eprint.iacr.org/2024/131) |
| [Double Ratchet](PROTOCOL.md#4-double-ratchet) | Continuous key renewal per message | [Perrin & Marlinspike 2016](https://signal.org/docs/specifications/doubleratchet/) |
| [Sealed Sender](PROTOCOL.md#5-sealed-sender) | Sender identity hidden from server | [Signal Blog 2018](https://signal.org/blog/sealed-sender/) |
| [Sender Keys](PROTOCOL.md#6-sender-key-group-messaging) | Efficient group E2EE with chain ratchet | [Signal Docs](https://signal.org/docs/specifications/group-v2/) |
| [Safety Numbers](PROTOCOL.md#7-safety-number-verification) | Out-of-band identity verification | [Signal Docs](https://signal.org/docs/specifications/fingerprint/) |
| [Message Padding](PROTOCOL.md#8-message-padding) | Fixed-bucket traffic analysis resistance | Custom (based on PKCS#7 principles) |
| [LSB Steganography](PROTOCOL.md#9-steganographic-messaging) | Covert communication in images | Custom (AES-256-GCM encrypted payloads) |
| [Session Auto-Reset](PROTOCOL.md#11-session-auto-reset) | Transparent recovery from broken sessions | Custom (rate-limited re-negotiation) |

## Cryptographic Primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Key agreement | X25519 (Curve25519) | `cryptography` ^2.7.0 |
| Signatures | Ed25519 | `cryptography` ^2.7.0 |
| Symmetric encryption (1:1) | AES-256-GCM | `cryptography` ^2.7.0 |
| Symmetric encryption (groups) | AES-256-CBC + HMAC-SHA256 | `cryptography` ^2.7.0 |
| Key derivation | HKDF-SHA256 | `cryptography` ^2.7.0 |
| Hash function | SHA-256, SHA-512 | `crypto` ^3.0.5 |
| Message authentication | HMAC-SHA256 | `cryptography` ^2.7.0 |
| Post-quantum KEM | Kyber-768 (ML-KEM-768) | `pqcrypto` ^0.1.0 (FFI) |
| Secure random | Platform CSPRNG | `dart:math` SecureRandom |

## Security Properties

| Property | Mechanism | Verification |
|----------|-----------|--------------|
| Forward secrecy | DH ratchet generates new keys per message exchange | [double_ratchet_test.dart](test/double_ratchet_test.dart) |
| Post-compromise security | New DH ratchet step heals after key compromise | [adversarial_crypto_test.dart](test/adversarial_crypto_test.dart) |
| Deniable authentication | No cryptographic proof of sender identity | Protocol design (X3DH) |
| Metadata protection | Sealed Sender hides sender from server | [sealed_sender_test.dart](test/sealed_sender_test.dart) |
| Post-quantum resistance | Kyber-768 hybrid key agreement (PQXDH) | [x3dh_test.dart](test/x3dh_test.dart) |
| Replay protection | Message numbers + skipped key tracking (max 100) | [adversarial_crypto_test.dart](test/adversarial_crypto_test.dart) |
| Traffic analysis resistance | Fixed bucket padding (256B, 1KB, 4KB, 16KB, 64KB, 256KB) | [message_padding_test.dart](test/message_padding_test.dart) |
| Memory protection | FFI-based `volatile` secure wipe of key material | Platform-specific |
| Integrity (1:1) | AES-256-GCM authenticated encryption | [double_ratchet_test.dart](test/double_ratchet_test.dart) |
| Integrity (groups) | HMAC-SHA256 with Ed25519-signed distributions | [sender_key_test.dart](test/sender_key_test.dart) |

---

## Quick Start

### 1. Implement the storage interface

The package defines `CryptoSecureStorage`, an abstract interface. You provide the platform-specific implementation:

```dart
import 'package:risaal_crypto/risaal_crypto.dart';

class KeychainStorage implements CryptoSecureStorage {
  @override
  Future<void> write({required String key, required String value}) async {
    // iOS: Keychain Services
    // Android: EncryptedSharedPreferences / Keystore
  }

  @override
  Future<String?> read({required String key}) async { /* ... */ }

  @override
  Future<void> delete({required String key}) async { /* ... */ }

  @override
  Future<void> clearAll() async { /* ... */ }
}
```

### 2. Initialize and generate keys

```dart
final manager = SignalProtocolManager(secureStorage: KeychainStorage());
final isNewDevice = await manager.initialize();

if (isNewDevice) {
  // Upload key bundle to your server
  final bundle = await manager.generateKeyBundle();
  await yourApi.uploadKeys(bundle);
}
```

### 3. Establish a session

```dart
// Fetch recipient's pre-key bundle from your server
final serverJson = await yourApi.fetchPreKeyBundle(recipientId);
final bundle = PreKeyBundle.fromServerJson(serverJson);
await manager.createSession(bundle);
```

### 4. Encrypt and decrypt messages

```dart
// Encrypt
final envelope = await manager.encryptMessage(
  recipientId, recipientDeviceId, 'Hello, secure world!',
);

// Decrypt
final plaintext = await manager.decryptMessage(
  senderId, senderDeviceId, receivedEnvelope,
);
```

### 5. Sealed Sender (metadata protection)

```dart
// Encrypt with sender identity hidden from the server
final sealed = await manager.encryptSealedSender(
  recipientId: recipientId,
  recipientDeviceId: recipientDeviceId,
  recipientIdentityKey: recipientPublicKey,
  plaintext: 'Hidden sender message',
);

// Decrypt — sender identity is revealed only to the recipient
final result = await manager.decryptSealedSender(sealedEnvelope);
// result.senderId, result.plaintext
```

### 6. Group E2EE (Sender Keys)

```dart
// Creator generates and distributes sender key
final distribution = await manager.generateGroupSenderKey(groupId);
// Send distribution to all group members via 1:1 encrypted channels

// Members process the distribution
await manager.processGroupSenderKey(groupId, senderId, distribution);

// Encrypt/decrypt group messages
final ciphertext = await manager.encryptGroupMessage(groupId, 'Group message');
final plaintext = await manager.decryptGroupMessage(groupId, senderId, ciphertext);
```

See [`example/`](example/) for complete, runnable examples of each feature.

---

## Architecture

```
                     ┌─────────────────────────────────────────────┐
                     │          SignalProtocolManager               │
                     │  (Orchestrator — single entry point API)     │
                     └────────────┬────────────────────────────────┘
                                  │
          ┌───────────┬───────────┼───────────┬────────────┐
          │           │           │           │            │
    ┌─────┴─────┐ ┌───┴───┐ ┌────┴────┐ ┌────┴───┐ ┌─────┴─────┐
    │   X3DH    │ │Double │ │ Sealed  │ │ Sender │ │  Safety   │
    │ + PQXDH   │ │Ratchet│ │ Sender  │ │  Keys  │ │  Numbers  │
    │           │ │       │ │         │ │        │ │           │
    │ Initial   │ │ Per-  │ │Metadata │ │ Group  │ │ Identity  │
    │ key agree │ │ msg   │ │ hiding  │ │ E2EE   │ │ verify    │
    └─────┬─────┘ └───┬───┘ └────┬────┘ └────┬───┘ └───────────┘
          │           │          │            │
    ┌─────┴───────────┴──────────┴────────────┴──────────────────┐
    │                    CryptoStorage                            │
    │              (Key management layer)                         │
    └─────────────────────────┬──────────────────────────────────┘
                              │
    ┌─────────────────────────┴──────────────────────────────────┐
    │              CryptoSecureStorage (abstract)                 │
    │         Your platform implementation goes here              │
    └─────────────────────────────────────────────────────────────┘
```

For component dependency graphs, data flow sequence diagrams, and integration guides, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## API Reference

### Core Protocol

| Class | Purpose |
|-------|---------|
| `SignalProtocolManager` | Main API — orchestrates all protocol operations |
| `X3DH` | Extended Triple Diffie-Hellman key agreement (+ Kyber-768 hybrid) |
| `DoubleRatchet` | Symmetric-key ratchet with DH ratchet steps |
| `SealedSenderEnvelope` | Metadata-hiding envelope (sender identity encrypted) |
| `SenderKeyManager` | Group E2EE via Sender Key distribution |
| `SafetyNumber` | 60-digit numeric identity verification fingerprints |

### Key Models

| Class | Purpose |
|-------|---------|
| `KeyPair` | X25519 or Ed25519 key pair (public + private base64) |
| `SignedPreKey` | Signed pre-key with Ed25519 signature |
| `OneTimePreKey` | Ephemeral one-time pre-key |
| `KyberKeyPair` | ML-KEM-768 (Kyber) key pair for post-quantum hybrid |
| `PreKeyBundle` | Complete public key bundle for session establishment |
| `SignalSession` / `RatchetState` | Persisted session state |

### Utilities

| Class | Purpose |
|-------|---------|
| `KeyHelper` | Key generation (X25519, Ed25519, Kyber, signing) |
| `MessagePadding` | Fixed-bucket padding to resist traffic analysis |
| `StegoService` | LSB steganography — hide encrypted text in images |
| `SecureMemory` | FFI-based memory zeroing (prevents key recovery from RAM) |
| `CryptoDebugLogger` | `assert()`-wrapped logging (stripped from release builds) |
| `SessionResetError` / `SessionUnstableError` | Error types for session auto-recovery |

### Storage

| Class | Purpose |
|-------|---------|
| `CryptoSecureStorage` | Abstract interface — implement for your platform |
| `CryptoStorage` | Key management layer (key prefixes, serialization) |

---

## Test Suite

222 tests across 12 test files covering protocol correctness, adversarial scenarios, and edge cases.

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `adversarial_crypto_test.dart` | 55 | Bit-flips, replay attacks, cross-session isolation, key reuse detection |
| `signal_protocol_manager_test.dart` | 27 | Full protocol flow, sealed sender, group E2EE, session management |
| `double_ratchet_test.dart` | 28 | Encrypt/decrypt, out-of-order delivery, DH ratchet steps, max skip |
| `sender_key_test.dart` | 24 | Group key generation, multi-member, chain ratchet, HMAC verification |
| `message_padding_test.dart` | 22 | Bucket selection, round-trips, randomness, boundary conditions |
| `x3dh_test.dart` | 18 | Key agreement, signature verification, PQXDH hybrid, wrong key rejection |
| `sealed_sender_test.dart` | 14 | Seal/unseal, metadata hiding, replay window, wrong key rejection |
| `crypto_storage_test.dart` | 11 | Key persistence, session serialization, pending prekey tracking, wipe |
| `key_helper_test.dart` | 8 | X25519, Ed25519, Kyber-768 key generation, signing, verification |
| `safety_number_test.dart` | 6 | Determinism, commutativity, format, QR payload round-trip |
| `stego_service_test.dart` | 5 | Embed/extract, capacity limits, visual imperceptibility |
| `session_auto_reset_test.dart` | 4 | Session reset errors, rate limiting, cooldown, recovery |

```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/adversarial_crypto_test.dart

# Run with verbose output
flutter test --reporter expanded
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [PROTOCOL.md](PROTOCOL.md) | Full protocol specification — X3DH, Double Ratchet, Sealed Sender, Sender Keys, pseudocode, wire formats, and threat model |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component dependency graphs, sequence diagrams (Mermaid), storage architecture, threading model, and integration guide |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, threat model, security invariants, and cryptographic dependency audit status |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development guidelines, testing requirements, PR process, and security-sensitive file list |
| [example/](example/) | Runnable examples: [basic messaging](example/basic_messaging.dart), [sealed sender](example/sealed_sender.dart), [group E2EE](example/group_messaging.dart), [safety numbers](example/safety_numbers.dart), [key generation](example/key_generation.dart) |

---

## Known Limitations

- **No formal security audit.** This library has not been audited by a third-party cryptography firm. Use at your own risk in production systems.
- **Kyber-768 is research-grade.** The `pqcrypto` FFI bindings have not undergone NIST certification. The hybrid design ensures that even if Kyber breaks, X25519 alone provides full security.
- **Dart VM does not guarantee constant-time operations.** Side-channel resistance depends on the underlying `cryptography` package and VM behavior.
- **Steganography is obscurity, not security.** LSB embedding can be detected by statistical steganalysis tools. It provides plausible deniability, not cryptographic hiding.
- **Alpha release (0.1.0).** API surface may change between minor versions. Pin to exact version in `pubspec.yaml`.

See [SECURITY.md](SECURITY.md) for the complete threat model and known limitations.

---

## References

### Signal Protocol Specifications

1. Marlinspike, M. & Perrin, T. (2016). *The X3DH Key Agreement Protocol.* https://signal.org/docs/specifications/x3dh/
2. Perrin, T. & Marlinspike, M. (2016). *The Double Ratchet Algorithm.* https://signal.org/docs/specifications/doubleratchet/
3. Marlinspike, M. (2017). *The Sesame Algorithm: Session Management for Asynchronous Message Encryption.* https://signal.org/docs/specifications/sesame/
4. Signal Foundation. (2018). *Technology Preview: Sealed Sender for Signal.* https://signal.org/blog/sealed-sender/

### Cryptographic Standards

5. Schwabe, P. et al. (2024). *CRYSTALS-Kyber (ML-KEM-768).* NIST Post-Quantum Cryptography Standard. FIPS 203.
6. Brendel, J. et al. (2024). *Post-Quantum Signal Protocol (PQXDH).* https://eprint.iacr.org/2024/131
7. Langley, A. et al. (2016). *X25519.* RFC 7748. https://tools.ietf.org/html/rfc7748

### Security Analysis

8. Cohn-Gordon, K. et al. (2020). *A Formal Security Analysis of the Signal Messaging Protocol.* Journal of Cryptology, 33, 1914-1983.

---

## License

Licensed under [AGPL-3.0-or-later](LICENSE) - the same license used by Signal's [libsignal](https://github.com/nickolay/libsignal).

This means: if you use this library in a network service, you must release your source code under AGPL-3.0. See the full license text in [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, testing requirements, and the PR process. All cryptographic changes require adversarial test cases.

## Reporting Security Vulnerabilities

See [SECURITY.md](SECURITY.md). Do **not** open public issues for security vulnerabilities.
