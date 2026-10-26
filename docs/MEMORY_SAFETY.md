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

### Tier 1: Package-Owned Copies, Zeroed in Place (best-effort, Dart heap)

**Implementation:** `lib/src/secure_memory.dart`

| API | What It Does |
|-----|-------------|
| `ownedCopy(List<int>)` | Copies library-owned key bytes into a new mutable `Uint8List` the package owns |
| `zeroBytes(List<int>)` | Overwrites a mutable Dart list with zeros (plain Dart loop); returns `true` if it did, `false` if the list is unmodifiable or destroyed (nothing wiped) |
| `zeroUint8List(Uint8List)` | Same as `zeroBytes` |

`cryptography` 2.9.0 returns an unmodifiable `SensitiveBytes` view from `SecretKey.extractBytes()`; zeroing that view is impossible (until R4-M1 the call silently did nothing). Every X25519 DH and HKDF output in `x3dh.dart`, `double_ratchet.dart` and `sealed_sender.dart` is therefore copied once with `ownedCopy`, the library `SecretKey` is `destroy()`ed (drops the reference; `cryptography` does **not** overwrite it), and the owned copy is zeroed after use. Debug builds `assert` that each of these zeroings succeeded, so the suite fails if a site regresses to an unzeroable list. ML-KEM shared secrets from `pqcrypto` are returned as mutable copies (`toList()`) and are zeroed the same way.

There is no `volatile` guarantee for these writes: they target heap objects that escape, so the optimizer is not expected to drop them, but nothing proves that it cannot.

### Tier 2: Native Memory for Host-Managed Keys (`SecureBuffer`)

| API | What It Does |
|-----|-------------|
| `allocSecure(int)` | Allocates memory in the C heap (outside the Dart GC, no copying); `null` where the native library is not linked |
| `SecureBuffer.dispose()` | Zeros (`volatile`, native) and frees the buffer |

**Native code** (`risaal_security.c`, linked by the host app):
- Uses the `volatile` function pointer technique (same as libsodium's `sodium_memzero`)
- Memory is zeroed before `free()`

**Platform support:**
- Android: `librisaal_security.so` loaded via `DynamicLibrary.open`
- iOS: Symbols compiled into Runner via `DynamicLibrary.process()`
- Tests/other: `allocSecure` returns `null`

The package itself does not keep ratchet keys in `SecureBuffer`; it is offered to hosts for long-lived keys. `SecureBuffer.read()` returns a Dart-heap copy that is subject to Tier 1 limits.

### Tier 3: Zeroing After Use (package-owned copies only)

| Component | What Is Zeroed | Where |
|-----------|---------------|-------|
| X3DH | Owned copies of each DH output, the ML-KEM shared secret, `dhConcat` and the HKDF input | `x3dh.dart:_dh()`, `_deriveSecret()`, initiator/responder |
| Double Ratchet | Owned copy of the DH output, HKDF input/output copies, intermediate root/chain keys | `double_ratchet.dart:_performDH()`, `_kdfRK()`, `initSender()`, `_dhRatchetStep()` |
| Double Ratchet | Old chain key after deriving message key | `double_ratchet.dart` chain step |
| Double Ratchet | Message key after encrypt/decrypt | `double_ratchet.dart:encrypt()/decrypt()` |
| Sealed Sender | Owned copies of the raw DH output and HKDF input | `sealed_sender.dart:_deriveSharedKey()` |
| Sender Key | Chain key intermediaries during forward | `sender_key.dart` |
| Session Wipe | All ratchet state (root key, chain keys, DH keys, skipped keys) | `session_state.dart:wipe()` |

**Not zeroed:** the `cryptography` library's own `SensitiveBytes` buffers behind every `SecretKeyData` (X25519 DH outputs, HKDF outputs) and `pqcrypto`'s internal buffers. They are unreachable from this package and are reclaimed only by the GC.

### Defensive Copies

Copies are taken so that zeroing never corrupts a `SecretKey` that is still in use (the v0.1.1 `SecretBoxAuthenticationError` flakiness). `ownedCopy` is never aliased with the library's buffer; `test/memory_hygiene_test.dart` ("SecretKey corruption regression (v0.1.1)") guards this.

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
| `test/memory_hygiene_test.dart` | DH intermediaries zeroed after encrypt/decrypt, sender key chain key zeroing, skip-iteration zeroing; `zeroBytes` returns `false` on `cryptography` `extractBytes()` output and `true` on an `ownedCopy`; ML-KEM secrets and HMAC chain/message keys are mutable (zeroable) |
| `test/secure_memory_zeroing_sites_test.dart` | Source pin: every X25519/HKDF `extractBytes()` in `x3dh.dart`, `double_ratchet.dart`, `sealed_sender.dart` is wrapped by `SecureMemory.ownedCopy` and the library key destroyed; `zeroBytes` no longer wipes a fresh native buffer |
| `test/adversarial_crypto_test.dart` | Skipped key cap enforcement (2000 max), replay prevention, tampered message rejection |
| `test/fuzz_test.dart` | Malformed input doesn't crash or leak (100 random envelopes, garbage JSON) |
| `test/sealed_sender_hardening_test.dart` | Sealed sender replay window, tampered envelope rejection |

## 5. Residual Risks (Cannot Be Mitigated in Dart)

These risks are inherent to the Dart platform and cannot be fully eliminated:

| Risk | Severity | Mitigation |
|------|----------|-----------|
| GC stale copies | Medium | Zeroing the owned copy shortens the window for that copy only; `SecureBuffer` for host-managed long-lived keys avoids GC copying |
| Library-internal key copies (`SensitiveBytes`) | Medium | Unwipeable in `cryptography` 2.9.0 (created without overwrite-on-destroy); reclaimed by GC; tracked as R4-L3/R4-M2 |
| DH sending key pair String residue | Medium | `_dhRatchetStep` generates a new X25519 key pair whose `KeyPair.privateKey` is a base64 `String`. Dart `String` is immutable and cannot be zeroed — the private key bytes persist on the Dart heap until GC reclaims the page. The serialized `Uint8List` copy is zeroed, but the original `String` representation is structurally unwipeable. Mitigation: minimize key pair lifetime; future fix requires upstream `cryptography` package to expose raw `Uint8List` key pairs. |
| JIT dead-store elimination | Low | Dart-heap zeroing has no `volatile` guarantee (writes target escaping heap objects); only `SecureBuffer.dispose()` uses `volatile` native zeroing |
| Timing side channels | Low | Not exploitable remotely; local attacker has easier paths (memory dump) |
| Swap/hibernation pages | Low | OS-level; recommend device encryption + no swap on mobile |
| Core dumps | Low | Release builds strip debug info; recommend `prctl(PR_SET_DUMPABLE, 0)` on Android |

### Acceptance Statement

Given Dart's constraints, we provide **best-effort memory safety** that:
1. Zeroes the **package-owned** copies of DH/HKDF/chain/message keys after each crypto operation (Dart heap, best-effort)
2. Provides **native-heap isolation** with `volatile` zeroing for host-managed long-lived keys via `SecureBuffer`
3. Does **not** wipe the `cryptography`/`pqcrypto` libraries' internal copies, GC compaction copies or base64 `String` private keys
4. Documents all residual risks transparently

For environments requiring guaranteed constant-time operations and full memory control (e.g., HSMs, TEEs), a native (Rust/C) implementation would be required. 

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
