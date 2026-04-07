import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Generates a Signal-style safety number (numeric fingerprint) from two
/// users' identity public keys.
///
/// The fingerprint is a 60-digit numeric code (12 groups of 5 digits)
/// derived from SHA-512 hashes of each user's identity key concatenated
/// with their stable identifier (userId). The result is commutative —
/// both users see the same number regardless of who initiates.
class SafetyNumber {
  SafetyNumber._();

  /// The version byte prepended to each fingerprint hash input.
  /// Bump this when changing the algorithm.
  static const int _version = 0x00;

  /// Number of hash iterations for key stretching.
  static const int _iterations = 5200;

  /// Generate a 60-digit safety number for two users.
  ///
  /// [myUserId] and [theirUserId] are stable user identifiers.
  /// [myIdentityKey] and [theirIdentityKey] are base64-encoded X25519
  /// public keys.
  ///
  /// Returns a 60-character string of digits (e.g. "12345 67890 ...").
  static String generate({
    required String myUserId,
    required String myIdentityKey,
    required String theirUserId,
    required String theirIdentityKey,
  }) {
    final myFingerprint = _computeFingerprint(myUserId, myIdentityKey);
    final theirFingerprint = _computeFingerprint(theirUserId, theirIdentityKey);

    // Sort lexicographically to ensure both sides produce the same number
    final List<String> fingerprints = [myFingerprint, theirFingerprint];
    fingerprints.sort();

    return '${fingerprints[0]}${fingerprints[1]}';
  }

  /// Generate a formatted display string with groups of 5 digits
  /// separated by spaces (12 groups × 5 digits = 60 digits).
  static String generateFormatted({
    required String myUserId,
    required String myIdentityKey,
    required String theirUserId,
    required String theirIdentityKey,
  }) {
    final raw = generate(
      myUserId: myUserId,
      myIdentityKey: myIdentityKey,
      theirUserId: theirUserId,
      theirIdentityKey: theirIdentityKey,
    );
    return _formatDigits(raw);
  }

  /// Compute a 30-digit fingerprint for one user's identity key.
  ///
  /// Algorithm (matches Signal's NumericFingerprint v2):
  /// 1. Input = version ‖ identityKeyBytes ‖ userIdBytes
  /// 2. Hash = SHA-512(input)
  /// 3. Iterate: hash = SHA-512(hash ‖ identityKeyBytes) × _iterations
  /// 4. Take the first 30 bytes and convert each to 5-digit decimal
  ///    groups (mod 100000), yielding 30 digits (6 groups of 5).
  static String _computeFingerprint(String userId, String identityKeyB64) {
    final identityKeyBytes = base64Decode(identityKeyB64);
    final userIdBytes = utf8.encode(userId);

    // Initial hash input: version + identityKey + userId
    final initialInput =
        Uint8List(1 + identityKeyBytes.length + userIdBytes.length);
    initialInput[0] = _version;
    initialInput.setRange(1, 1 + identityKeyBytes.length, identityKeyBytes);
    initialInput.setRange(
      1 + identityKeyBytes.length,
      initialInput.length,
      userIdBytes,
    );

    // First hash
    var hashBytes = sha512.convert(initialInput).bytes;

    // Iterated hashing for key stretching
    for (var i = 0; i < _iterations; i++) {
      final iterInput = Uint8List(hashBytes.length + identityKeyBytes.length);
      iterInput.setRange(0, hashBytes.length, hashBytes);
      iterInput.setRange(hashBytes.length, iterInput.length, identityKeyBytes);
      hashBytes = sha512.convert(iterInput).bytes;
    }

    // Extract 30 digits from the first 30 bytes
    // Each pair of bytes → mod 100000 → 5-digit string
    // We need 6 groups × 5 digits = 30 digits
    final buffer = StringBuffer();
    for (var i = 0; i < 6; i++) {
      // Use 5 bytes per group for better entropy distribution
      final offset = i * 5;
      final value = (hashBytes[offset] << 32) |
          (hashBytes[offset + 1] << 24) |
          (hashBytes[offset + 2] << 16) |
          (hashBytes[offset + 3] << 8) |
          hashBytes[offset + 4];
      buffer.write((value % 100000).toString().padLeft(5, '0'));
    }

    return buffer.toString();
  }

  /// Format a 60-digit string into 12 groups of 5 digits.
  static String _formatDigits(String digits) {
    final buffer = StringBuffer();
    for (var i = 0; i < digits.length; i += 5) {
      if (i > 0) buffer.write(' ');
      buffer.write(digits.substring(i, i + 5));
    }
    return buffer.toString();
  }

  /// Generate QR code data for safety number verification.
  ///
  /// The QR payload contains version + both fingerprints so the
  /// scanner can compare against their locally computed value.
  static String generateQrPayload({
    required String myUserId,
    required String myIdentityKey,
    required String theirUserId,
    required String theirIdentityKey,
  }) {
    final safetyNumber = generate(
      myUserId: myUserId,
      myIdentityKey: myIdentityKey,
      theirUserId: theirUserId,
      theirIdentityKey: theirIdentityKey,
    );
    // QR payload: "risaal-verify:v0:<60-digit-safety-number>"
    return 'risaal-verify:v0:$safetyNumber';
  }

  /// Parse and validate a scanned QR payload.
  ///
  /// Returns the 60-digit safety number if valid, null otherwise.
  static String? parseQrPayload(String payload) {
    if (!payload.startsWith('risaal-verify:v0:')) return null;
    final number = payload.substring('risaal-verify:v0:'.length);
    if (number.length != 60) return null;
    if (!RegExp(r'^\d{60}$').hasMatch(number)) return null;
    return number;
  }
}
