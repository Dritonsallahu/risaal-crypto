# Memory Safety Model — risaal_crypto

This document describes the memory safety constraints inherent to Dart, the mitigations implemented in this package, and the residual risks that cannot be eliminated at the application layer.

---

## 1. Threat: Key Material in Memory

Sensitive cryptographic material (private keys, chain keys, shared secrets, message keys) exists as byte arrays in memory during cryptographic operations. Attackers with physical access, memory dump capabilities (Frida, `/proc/pid/mem`), or forensic tools can recover this material if it persists after use.

## 2. Dart Platform Constraints

Dart imposes fundamental limitations that no application-level code can fully overcome:

### Garbage Collector Copying

The Dart VM uses a **generational, compacting garbage collector**. During compaction, the GC copies objects (including byte arrays containing key material) from one memory region to another. The original bytes remain in the old location until the OS reuses that page. This means:

- A key stored in a `Uint8List` may exist in **multiple memory locations simultaneously**
- Zeroing the current reference only clears **one copy** — stale copies from prior GC cycles may persist
- There is **no Dart API** to enumerate or zero all copies

### JIT Compilation

The Dart JIT may:
- Inline constants derived from key material into machine code
- Reorder or eliminate stores that the optimizer considers "dead" (including zero-writes)
- Cache intermediate values in CPU registers that are never flushed to memory

### No Guaranteed Constant-Time Operations

Dart does not expose constant-time comparison primitives. Operations on `List<int>` may exhibit timing variations based on:
- Value-dependent branch prediction
- GC pauses during cryptographic operations
- JIT tiering (interpreted → compiled transitions)

## 3. Implemented Mitigations

Despite these constraints, we apply defense-in-depth to minimize the window and surface area:

### Tier 1: FFI Secure Memory (Strongest)

**Implementation:** `lib/src/secure_memory.dart`

`SecureMemory` provides native (C) memory operations via FFI:

| API | What It Does |
|-----|-------------|
| `zeroBytes(List<int>)` | Zeros a Dart list in-place + allocates/frees a native buffer (volatile wipe) |
| `zeroUint8List(Uint8List)` | Copies bytes to native buffer, wipes via C, then zeros Dart buffer |
| `allocSecure(int)` | Allocates memory in C heap (outside Dart GC, no copying) |
| `SecureBuffer.dispose()` | Zeros and frees native buffer (volatile function pointer prevents optimizer removal) |

**Native code** (`risaal_security.c`):
- Uses `volatile` function pointer technique (same as libsodium's `sodium_memzero`)
- Compiler cannot optimize away the zero-write
- Memory is zeroed before `free()` — OS cannot reclaim dirty pages

**Platform support:**
- Android: `librisaal_security.so` loaded via `DynamicLibrary.open`
- iOS: Symbols compiled into Runner via `DynamicLibrary.process()`
- Tests/other: Falls back to Dart-only zeroing (best-effort)

### Tier 2: Immediate Zeroing After Use

Every cryptographic operation zeros intermediaries immediately after use:

| Component | What Is Zeroed | Where |
|-----------|---------------|-------|
| X3DH | 4 DH shared secrets concatenated into `dhConcat` | `x3dh.dart:_deriveSecret()` |
| Double Ratchet | DH shared secret from `sharedSecretKey.extractBytes()` | `double_ratchet.dart:_dhRatchetStep()` |
| Double Ratchet | Old chain key after deriving message key | `double_ratchet.dart:_chainKeyStep()` |
| Double Ratchet | Message key after encrypt/decrypt | `double_ratchet.dart:encrypt()/decrypt()` |
| Sender Key | Chain key intermediaries during forward | `sender_key.dart:_advanceChainKey()` |
| Session Wipe | All ratchet state (root key, chain keys, DH keys, skipped keys) | `session_state.dart:wipe()` |

### Tier 3: Defensive Copies

To prevent the `cryptography` package's internal `SecretKey` from corrupting when we zero our copy, all shared secret extractions use defensive copies:

```dart
final rawBytes = await sharedSecret.extractBytes();
final bytes = List<int>.from(rawBytes); // Defensive copy
SecureMemory.zeroBytes(rawBytes);       // Zero the original
// ... use bytes ...
SecureMemory.zeroBytes(bytes);          // Zero our copy
```

This pattern (introduced after `SecretBoxAuthenticationError` flakiness) ensures the crypto library's internal state is never corrupted by our zeroing.

### Tier 4: Anti-Replay State Persistence

The `RatchetState.receivedMessages` set (up to 2000 entries) is persisted across app restarts, preventing replay attacks even after the app is killed and restarted. This is not memory safety per se, but prevents attacks that exploit state loss.

### Tier 5: Panic Wipe

`RatchetState.wipe()` zeros all fields (keys, counters, skipped keys, received messages) and `CryptoStorage.clearReceivedMessageNumbers()` removes persisted anti-replay state. Called during:
- Explicit panic wipe (user-triggered emergency erase)
- Session removal (`removeSession()`)
- Key compromise response

## 4. Test Coverage

Memory safety behavior is verified by:

| Test File | What It Verifies |
|-----------|-----------------|
| `test/memory_hygiene_test.dart` | DH intermediaries zeroed after encrypt/decrypt, sender key chain key zeroing, skip-iteration zeroing |
| `test/adversarial_crypto_test.dart` | Skipped key cap enforcement (2000 max), replay prevention, tampered message rejection |
| `test/fuzz_test.dart` | Malformed input doesn't crash or leak (100 random envelopes, garbage JSON) |
| `test/sealed_sender_hardening_test.dart` | Sealed sender replay window, tampered envelope rejection |

## 5. Residual Risks (Cannot Be Mitigated in Dart)

These risks are inherent to the Dart platform and cannot be fully eliminated:

| Risk | Severity | Mitigation |
|------|----------|-----------|
| GC stale copies | Medium | FFI zeroing reduces window; `SecureBuffer` for long-lived keys avoids GC entirely |
| JIT dead-store elimination | Low | Volatile FFI writes prevent optimizer removal of zero-writes |
| Timing side channels | Low | Not exploitable remotely; local attacker has easier paths (memory dump) |
| Swap/hibernation pages | Low | OS-level; recommend device encryption + no swap on mobile |
| Core dumps | Low | Release builds strip debug info; recommend `prctl(PR_SET_DUMPABLE, 0)` on Android |

### Acceptance Statement

Given Dart's constraints, we provide **best-effort memory safety** that:
1. Eliminates key persistence in the **current live memory** of every crypto operation
2. Provides **native-heap isolation** for long-lived keys via `SecureBuffer`
3. Uses **compiler-resistant zeroing** via volatile FFI function pointers
4. Documents all residual risks transparently

For environments requiring guaranteed constant-time operations and full memory control (e.g., HSMs, TEEs), a native (Rust/C) implementation would be required. Within the Dart ecosystem, this implementation represents the maximum achievable memory safety.

## 6. SecureBuffer Usage Guide

For maximum protection of long-lived keys (identity key, signing key), use `SecureBuffer` instead of Dart `List<int>`:

```dart
// Allocate in native memory (outside Dart GC)
final keyBuf = SecureMemory.allocSecure(32);
if (keyBuf != null) {
  // Write key bytes into native memory
  keyBuf.write(identityPrivateKeyBytes);

  // Zero the Dart copy immediately
  SecureMemory.zeroBytes(identityPrivateKeyBytes);

  // When you need the key:
  final tempKey = keyBuf.read();  // Temporary Dart copy
  final result = await cryptoOp(tempKey);
  SecureMemory.zeroBytes(tempKey); // Zero Dart copy immediately

  // When done with the key forever:
  keyBuf.dispose();  // Native zero + free
}
```

**Key rule:** Minimize the lifetime of Dart copies. Read from `SecureBuffer`, use immediately, zero immediately.
