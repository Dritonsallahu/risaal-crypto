import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

/// Best-effort zeroing of key copies this package owns, plus an optional
/// native buffer for host-managed long-lived keys.
///
/// What is and is not wiped (R4-M1):
///   - [zeroBytes] overwrites a **mutable** Dart list in place with a plain Dart
///     loop and returns whether it could. Every DH / HKDF output the package
///     keeps is first copied into a package-owned [Uint8List] ([ownedCopy]) so
///     that this zeroing really happens.
///   - The `cryptography` and `pqcrypto` implementations keep their **own**
///     internal copies (e.g. the `SensitiveBytes` behind `SecretKeyData`, which
///     `cryptography` 2.9.0 creates without overwrite-on-destroy). This package
///     cannot reach those buffers: they are **never overwritten** and stay in
///     RAM until the garbage collector reclaims and the allocator reuses them.
///   - The Dart GC may have moved (copied) a buffer before it is zeroed; stale
///     copies left behind are not wiped.
///   - There is no `volatile` guarantee on the Dart heap. The loop writes to a
///     heap object that escapes, so it is not expected to be optimized away,
///     but nothing proves that it cannot be.
///
/// Native memory ([allocSecure] / [SecureBuffer]): keeps bytes outside the Dart
/// heap and wipes them on [SecureBuffer.dispose] via `risaal_secure_free`
/// (`volatile` zeroing in C). Available only where the host app links the
/// native library:
///   - **Android**: `librisaal_security.so`
///   - **iOS**: symbols compiled into the Runner process (DynamicLibrary.process)
///   - **Other platforms / tests**: [allocSecure] returns `null`.
///
/// Usage patterns:
///   1. **Package-owned copies**: copy, use, zero:
///      ```dart
///      final key = SecureMemory.ownedCopy(await secret.extractBytes());
///      // ... use key ...
///      SecureMemory.zeroBytes(key);  // true: the copy is now all zeros
///      ```
///
///   2. **Native-managed keys** (host-chosen, long-lived):
///      ```dart
///      final buf = SecureMemory.allocSecure(32);
///      buf.write(keyBytes);
///      // ... use key via buf.read() ...
///      buf.dispose();  // Zero (volatile, native) and free
///      ```
///
/// See also:
///   - [zeroBytes] to wipe a mutable Dart list in place
///   - [ownedCopy] to take a zeroable copy of library-owned bytes
///   - [allocSecure] / [SecureBuffer] for native memory
class SecureMemory {
  SecureMemory._();

  static final DynamicLibrary? _lib = _loadLibrary();

  static DynamicLibrary? _loadLibrary() {
    try {
      if (Platform.isAndroid) {
        return DynamicLibrary.open('librisaal_security.so');
      } else if (Platform.isIOS) {
        // On iOS, C symbols compiled into the Runner target are in the process.
        return DynamicLibrary.process();
      }
    } catch (_) {
      // Library not found or unsupported platform
    }
    return null;
  }

  // ── Native function signatures ────────────────────────────────────

  static final _secureAlloc = _lib
      ?.lookupFunction<
        Pointer<Uint8> Function(Int64),
        Pointer<Uint8> Function(int)
      >('risaal_secure_alloc');

  static final _secureFree = _lib
      ?.lookupFunction<
        Void Function(Pointer<Uint8>, Int64),
        void Function(Pointer<Uint8>, int)
      >('risaal_secure_free');

  // ── Public API ────────────────────────────────────────────────────

  /// Zero a Dart byte list in place (best-effort, Dart heap only).
  ///
  /// Returns `true` when every element is now zero, `false` when the list
  /// could not be written: unmodifiable (e.g. `SensitiveBytes` returned by
  /// `cryptography`'s `extractBytes()`) or already destroyed. A `false` result
  /// means **nothing was wiped**; take an [ownedCopy] up front instead.
  ///
  /// Caveats: the GC may already have copied the list (stale copies are not
  /// wiped), and there is no `volatile` guarantee on the Dart heap.
  static bool zeroBytes(List<int> bytes) {
    try {
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = 0;
      }
      return true;
    } on UnsupportedError {
      return false;
    } on StateError {
      return false;
    }
  }

  /// Zero a [Uint8List] in place. Same semantics as [zeroBytes].
  static bool zeroUint8List(Uint8List bytes) => zeroBytes(bytes);

  /// Copy [bytes] into a new, mutable, package-owned [Uint8List].
  ///
  /// Use on library-owned key bytes (e.g. `SecretKey.extractBytes()`) so the
  /// copy can later be zeroed with [zeroBytes]. The source is left untouched.
  static Uint8List ownedCopy(List<int> bytes) => Uint8List.fromList(bytes);

  /// Allocate a native buffer for sensitive data (advanced usage).
  ///
  /// Returns a [SecureBuffer] that keeps key material in native (C) memory
  /// outside the Dart heap. This prevents:
  ///   - GC copying (no stale copies left behind)
  ///   - Dart heap dumps from capturing the key
  ///   - Compiler optimizations from removing the zero
  ///
  /// The buffer is allocated via `risaal_secure_alloc` (zeroed on allocation)
  /// and freed via `risaal_secure_free` (zeroed before free).
  ///
  /// You must call [SecureBuffer.dispose] when done to securely zero and free
  /// the memory. Failing to dispose leaks native memory.
  ///
  /// Returns `null` if allocation fails (e.g., out of memory, FFI unavailable).
  ///
  /// Example:
  /// ```dart
  /// final buf = SecureMemory.allocSecure(32);
  /// if (buf != null) {
  ///   buf.write(keyBytes);
  ///   // ... use key via buf.read() ...
  ///   buf.dispose();  // MUST call to avoid memory leak
  /// }
  /// ```
  static SecureBuffer? allocSecure(int length) {
    if (length <= 0) return null;
    final alloc = _secureAlloc;
    if (alloc == null) return null;
    final ptr = alloc(length);
    if (ptr == nullptr) return null;
    return SecureBuffer._(ptr, length);
  }
}

/// A buffer in native memory for sensitive data (crypto keys).
///
/// Allocated via [SecureMemory.allocSecure], this buffer provides maximum
/// security for long-lived keys:
///
/// Advantages over Dart Lists:
///   - **No GC copying**: The buffer lives in native memory, not on the Dart heap.
///     The GC cannot move it, so there are no stale copies left behind.
///   - **Guaranteed zeroing**: On [dispose], the native code zeros the memory
///     using a volatile function pointer (cannot be optimized away).
///   - **Harder to find**: Memory dumps of the Dart heap won't capture this buffer.
///
/// Disadvantages:
///   - **Manual memory management**: You must call [dispose] to avoid leaks.
///   - **Copy to use**: Calling [read] copies the buffer into Dart heap memory
///     (subject to GC copying). Minimize the lifetime of the Dart copy.
///
/// Use this for long-lived keys (e.g., identity private key) that persist across
/// multiple operations. Short-lived package-owned copies use the best-effort
/// Dart-heap [SecureMemory.zeroBytes] instead.
///
/// Example:
/// ```dart
/// final buf = SecureMemory.allocSecure(32)!;
/// buf.write(identityPrivateKey);
///
/// // Later, use the key:
/// final keyBytes = buf.read();
/// final result = await performCryptoOp(keyBytes);
/// SecureMemory.zeroBytes(keyBytes);  // Wipe the Dart copy
///
/// // When done with the key:
/// buf.dispose();
/// ```
class SecureBuffer {
  Pointer<Uint8> _ptr;
  final int length;
  bool _disposed = false;

  SecureBuffer._(this._ptr, this.length);

  /// Read the buffer contents as a Uint8List.
  ///
  /// **WARNING**: This copies the data into Dart heap memory. The copy is
  /// subject to GC and may be copied again during compaction. After using
  /// the returned bytes, wipe them immediately with [SecureMemory.zeroBytes].
  ///
  /// Minimize the lifetime of the Dart copy to reduce the window for memory
  /// dumps or GC copying.
  ///
  /// Throws [StateError] if the buffer has been disposed.
  Uint8List read() {
    if (_disposed) throw StateError('SecureBuffer already disposed');
    final bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = _ptr[i];
    }
    return bytes;
  }

  /// Write data into the secure buffer.
  ///
  /// Copies up to [length] bytes from [data] into the native buffer. If [data]
  /// is shorter than the buffer, the remaining bytes are left as-is (zeroed
  /// during allocation).
  ///
  /// Throws [StateError] if the buffer has been disposed.
  void write(List<int> data) {
    if (_disposed) throw StateError('SecureBuffer already disposed');
    final writeLen = data.length < length ? data.length : length;
    for (int i = 0; i < writeLen; i++) {
      _ptr[i] = data[i] & 0xFF;
    }
  }

  /// Securely zero and free the native memory.
  ///
  /// Calls `risaal_secure_free(ptr, length)` which:
  ///   1. Zeros the memory using a volatile function pointer (cannot be optimized away)
  ///   2. Frees the memory
  ///
  /// After calling this, the buffer is unusable. Calling [read] or [write] throws.
  ///
  /// You **must** call this method when done with the buffer to avoid memory leaks.
  /// Idempotent — calling multiple times is safe (no-op after the first call).
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    SecureMemory._secureFree?.call(_ptr, length);
    _ptr = nullptr;
  }
}
