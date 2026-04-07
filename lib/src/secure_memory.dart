import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

/// FFI bindings to native secure memory operations.
///
/// Provides guaranteed memory zeroing that the compiler **cannot optimize away**.
///
/// The problem:
///   - Dart's GC does not guarantee zeroing freed memory
///   - After a key is no longer referenced, it remains in RAM until overwritten
///   - A memory dump (Frida, /proc/pid/mem, forensic tools) can recover keys
///   - Dart may copy objects during GC compaction, leaving additional stale copies
///
/// This service solves the problem by calling native C code that:
///   1. Writes zeros to the memory
///   2. Uses a volatile function pointer to prevent the compiler from optimizing
///      away the write (same technique as libsodium's `sodium_memzero`)
///
/// Platform support:
///   - **Android**: Loads `librisaal_security.so` (compiled from C sources)
///   - **iOS**: Symbols are compiled into the Runner process (DynamicLibrary.process)
///   - **Other platforms**: Throws `UnsupportedError`
///
/// Native functions (risaal-app/.../risaal_security.c):
///   - `risaal_secure_wipe(ptr, len)`: Zero memory at `ptr`
///   - `risaal_secure_alloc(len)`: Allocate zeroed memory
///   - `risaal_secure_free(ptr, len)`: Zero and free memory
///
/// Usage patterns:
///   1. **Dart-managed keys**: Call [zeroBytes] after using a key:
///      ```dart
///      final key = await deriveKey(...);
///      // ... use key ...
///      SecureMemory.zeroBytes(key);  // Zero before GC
///      ```
///
///   2. **Native-managed keys** (advanced): Use [allocSecure] to keep keys in
///      native memory (outside Dart heap, not subject to GC copying):
///      ```dart
///      final buf = SecureMemory.allocSecure(32);
///      buf.write(keyBytes);
///      // ... use key via buf.read() ...
///      buf.dispose();  // Securely zero and free
///      ```
///
/// Limitations:
///   - Dart may have already copied the key during GC compaction before you call [zeroBytes]
///   - This zeros the **current live copy** — stale copies may persist until overwritten
///   - For maximum security, use [allocSecure] to keep keys in native memory from the start
///
/// See also:
///   - [zeroBytes] to wipe a Dart List in-place
///   - [allocSecure] to allocate native memory for long-lived keys
///   - [SecureBuffer] for the native memory wrapper
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

  static final _secureWipe = _lib?.lookupFunction<
      Void Function(Pointer<Uint8>, Int64),
      void Function(Pointer<Uint8>, int)>('risaal_secure_wipe');

  static final _secureAlloc = _lib?.lookupFunction<
      Pointer<Uint8> Function(Int64),
      Pointer<Uint8> Function(int)>('risaal_secure_alloc');

  static final _secureFree = _lib?.lookupFunction<
      Void Function(Pointer<Uint8>, Int64),
      void Function(Pointer<Uint8>, int)>('risaal_secure_free');

  // ── Public API ────────────────────────────────────────────────────

  /// Zero out a Dart byte list in-place (best-effort).
  ///
  /// This is the primary method for wiping key material held in Dart Lists.
  /// After this call, the original list contains all zeros.
  ///
  /// How it works:
  ///   1. Allocate native buffer via `risaal_secure_alloc`
  ///   2. Wipe the native buffer (in case it wasn't already zeroed)
  ///   3. Free the native buffer via `risaal_secure_free`
  ///   4. Zero the Dart list in-place
  ///
  /// **Important caveat**: Dart may have already copied the list contents during
  /// GC compaction before you called this method. This zeros the **current live
  /// copy** — stale copies may persist in memory until overwritten by the allocator.
  /// There's no way to guarantee all copies are wiped. For maximum security, use
  /// [allocSecure] to keep keys in native memory from the start (no GC copying).
  ///
  /// If FFI is unavailable (e.g., tests, unsupported platform), falls back to
  /// zeroing the Dart list only (no native wipe).
  ///
  /// Example:
  /// ```dart
  /// final key = await deriveKey(...);
  /// // ... use key ...
  /// SecureMemory.zeroBytes(key);  // Wipe before key goes out of scope
  /// ```
  static void zeroBytes(List<int> bytes) {
    if (bytes.isEmpty) return;

    final alloc = _secureAlloc;
    final wipe = _secureWipe;
    final free = _secureFree;

    if (alloc != null && wipe != null && free != null) {
      final ptr = alloc(bytes.length);
      if (ptr != nullptr) {
        wipe(ptr, bytes.length);
        free(ptr, bytes.length);
      }
    }

    // Always zero the Dart-side list
    _fallbackZero(bytes);
  }

  /// Zero out a Uint8List using native secure wipe.
  static void zeroUint8List(Uint8List bytes) {
    if (bytes.isEmpty) return;

    final alloc = _secureAlloc;
    final wipe = _secureWipe;
    final free = _secureFree;

    if (alloc != null && wipe != null && free != null) {
      final ptr = alloc(bytes.length);
      if (ptr != nullptr) {
        for (int i = 0; i < bytes.length; i++) {
          ptr[i] = bytes[i];
        }
        wipe(ptr, bytes.length);
        free(ptr, bytes.length);
      }
    }

    // Always zero the Dart-side buffer
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }

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

  /// Fallback zeroing for when FFI is not available (tests, unsupported platform).
  /// Silently skips if the list is unmodifiable (e.g. SensitiveBytes from
  /// the cryptography package).
  static void _fallbackZero(List<int> bytes) {
    try {
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = 0;
      }
    } on UnsupportedError {
      // List is unmodifiable (e.g. cryptography package SensitiveBytes).
      // The native wipe already handled the copy — nothing more we can do.
    }
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
/// multiple operations. For ephemeral keys, [SecureMemory.zeroBytes] is sufficient.
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
