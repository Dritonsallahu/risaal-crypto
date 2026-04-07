# risaal_crypto Examples

This directory contains comprehensive usage examples for the `risaal_crypto` package.

## Examples

### 1. Basic Messaging (`basic_messaging.dart`)

Demonstrates the complete lifecycle of a two-party encrypted conversation:
- Initialize both parties (generate identity keys)
- Exchange pre-key bundles via server
- Establish an encrypted session using X3DH
- Send and receive encrypted messages using Double Ratchet
- Forward secrecy and post-compromise security

**Concepts:** X3DH, Double Ratchet, session establishment, message encryption

### 2. Sealed Sender (`sealed_sender.dart`)

Shows how to hide sender metadata from the server:
- The server can route messages but cannot determine who sent them
- Only the recipient can unseal the outer envelope to discover the sender
- Prevents social graph analysis even if the server is compromised

**Concepts:** Metadata protection, privacy, sender anonymity

### 3. Group Messaging (`group_messaging.dart`)

Demonstrates end-to-end encrypted group conversations:
- Each member generates a Sender Key
- Keys are distributed via existing 1-to-1 encrypted sessions
- Messages are encrypted once and decrypted by all members
- Forward secrecy within the group via chain ratcheting

**Concepts:** Sender Keys, group E2EE, efficient multicast encryption

### 4. Safety Numbers (`safety_numbers.dart`)

Shows identity verification to prevent man-in-the-middle attacks:
- Both users see the same 60-digit safety number
- Numbers can be compared in person, over the phone, or via QR code
- Based on SHA-512 hashing of identity keys and user IDs
- Commutative algorithm (same result regardless of who initiates)

**Concepts:** Identity verification, MITM prevention, trust establishment

### 5. Key Generation (`key_generation.dart`)

Low-level demonstration of cryptographic primitives:
- X25519 key pairs (Diffie-Hellman key exchange)
- Ed25519 key pairs (digital signatures)
- Signed pre-keys (identity-verified ephemeral keys)
- One-time pre-keys (single-use forward secrecy)
- ML-KEM-768 / Kyber (post-quantum key encapsulation)

**Concepts:** Key management, digital signatures, post-quantum cryptography

## Running the Examples

These examples are NOT runnable programs. They are documentation showing the API structure and typical usage patterns. To run them:

1. Integrate into a Flutter project with proper dependencies
2. Provide a real implementation of `CryptoSecureStorage` (not the in-memory stub)
3. Run in an async context (e.g., from a Flutter widget or integration test)

## Integration Notes

In a production app:

- **Storage:** Use platform-secure storage (iOS Keychain, Android EncryptedSharedPreferences)
- **Server:** Exchange key bundles and messages via REST API and WebSocket
- **Key Management:** Replenish one-time pre-keys when they run low
- **Error Handling:** Handle session resets, rate limits, and network failures
- **Lifecycle:** Initialize SignalProtocolManager once at app startup

## Security Considerations

- Never log key material or plaintext messages
- Always verify identity keys before trusting a session
- Implement proper session reset handling for broken sessions
- Use Sealed Sender for metadata protection when possible
- Rotate pre-keys periodically and after compromise
- Test all crypto code paths with >80% coverage

## Further Reading

- [Signal Protocol Specification](https://signal.org/docs/)
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Sealed Sender Protocol](https://signal.org/docs/specifications/sealedender/)

## License

This package is part of the Risaal project. See the root LICENSE file for details.
