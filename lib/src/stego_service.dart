import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// LSB (Least Significant Bit) steganography service.
///
/// Hides encrypted text inside image pixel data using the least significant bit
/// of each RGB color channel. The secret is encrypted with AES-256-GCM before
/// embedding, so even if the image is discovered, the plaintext is protected.
///
/// How it works:
///   1. Encrypt plaintext with AES-256-GCM (produces ciphertext + 16-byte MAC)
///   2. Build payload: 4-byte length header + 12-byte nonce + ciphertext + MAC
///   3. Embed each bit of the payload into the LSB of pixel RGB channels
///   4. Return the modified image (visually identical to the original)
///
/// To extract:
///   1. Read LSBs from pixel RGB channels to recover payload bytes
///   2. Parse: length header, nonce, ciphertext, MAC
///   3. Decrypt with AES-256-GCM using the provided key
///
/// Wire format embedded in pixels (bit-level encoding):
/// ```
/// [4-byte big-endian payload length] [12-byte AES-GCM nonce] [ciphertext] [16-byte MAC]
/// ```
///
/// **Security caveats**:
///   - LSB steganography is detectable via statistical analysis (e.g., chi-square test)
///   - Image compression (JPEG, WebP) destroys LSB data
///   - Only use with lossless formats (PNG, BMP)
///   - The AES key must be shared out-of-band (not embedded in the image)
///
/// Capacity: `(width * height * 3) / 8 - 32` bytes of plaintext (approx).
/// Example: 1024x1024 image = ~393 KB capacity.
///
/// Alpha channel is never modified (some apps discard alpha, breaking extraction).
///
/// See also:
///   - [embed] to hide a secret in an image
///   - [extract] to recover the secret
///   - [capacity] to calculate max message size
class StegoService {
  StegoService() : _algorithm = AesGcm.with256bits();

  final AesGcm _algorithm;

  // ── Public API ──────────────────────────────────────────────────────

  /// Embed encrypted plaintext into image pixel LSBs.
  ///
  /// Encrypts [plaintext] with AES-256-GCM and embeds the result into the least
  /// significant bits of the RGB channels in [imageRgba]. The alpha channel is
  /// never modified.
  ///
  /// Parameters:
  ///   - [imageRgba]: Raw RGBA pixel data (4 bytes per pixel, row-major order)
  ///   - [width]: Image width in pixels
  ///   - [height]: Image height in pixels
  ///   - [plaintext]: Secret text to hide (UTF-8)
  ///   - [aesKey]: 32-byte AES-256 encryption key (shared out-of-band)
  ///
  /// Returns a **new** RGBA buffer with the secret embedded. The original buffer
  /// is not modified. The output image is visually identical (LSB changes are
  /// imperceptible to the human eye).
  ///
  /// Throws [StateError] if the message is too large for the image capacity.
  ///
  /// Example:
  /// ```dart
  /// final image = await loadImageRgba('photo.png');
  /// final key = Uint8List(32); // Generate a random key
  /// final stegoImage = await stego.embed(image, 1024, 1024, 'Secret!', key);
  /// await saveImagePng('stego.png', stegoImage);
  /// ```
  Future<Uint8List> embed(
    Uint8List imageRgba,
    int width,
    int height,
    String plaintext,
    Uint8List aesKey,
  ) async {
    assert(aesKey.length == 32, 'AES key must be 32 bytes');

    // 1. Encrypt plaintext with AES-256-GCM
    final secretKey = SecretKey(aesKey);
    final plaintextBytes = utf8.encode(plaintext);

    final secretBox = await _algorithm.encrypt(
      plaintextBytes,
      secretKey: secretKey,
    );

    // 2. Build payload: nonce (12B) + ciphertext + mac (16B)
    final nonce = Uint8List.fromList(secretBox.nonce); // 12 bytes
    final ciphertext = Uint8List.fromList(secretBox.cipherText);
    final mac = Uint8List.fromList(secretBox.mac.bytes); // 16 bytes

    final payload = Uint8List(nonce.length + ciphertext.length + mac.length);
    payload.setRange(0, nonce.length, nonce);
    payload.setRange(nonce.length, nonce.length + ciphertext.length, ciphertext);
    payload.setRange(
      nonce.length + ciphertext.length,
      payload.length,
      mac,
    );

    // 3. Prepend 4-byte big-endian length header
    final payloadLen = payload.length;
    final header = Uint8List(4)
      ..[0] = (payloadLen >> 24) & 0xFF
      ..[1] = (payloadLen >> 16) & 0xFF
      ..[2] = (payloadLen >> 8) & 0xFF
      ..[3] = payloadLen & 0xFF;

    final fullData = Uint8List(header.length + payload.length);
    fullData.setRange(0, header.length, header);
    fullData.setRange(header.length, fullData.length, payload);

    // 4. Check capacity
    final maxBytes = (width * height * 3) ~/ 8;
    if (fullData.length > maxBytes) {
      throw StateError(
        'Message too large: ${fullData.length} bytes, '
        'capacity is $maxBytes bytes',
      );
    }

    // 5. Embed bits into LSBs of RGB channels
    final output = Uint8List.fromList(imageRgba);
    final totalBits = fullData.length * 8;

    for (var bitIdx = 0; bitIdx < totalBits; bitIdx++) {
      final byteIdx = bitIdx ~/ 8;
      final bitPos = 7 - (bitIdx % 8); // MSB first
      final bit = (fullData[byteIdx] >> bitPos) & 1;

      // 3 bits per pixel (R, G, B), skip alpha
      final pixelIdx = bitIdx ~/ 3;
      final channelOffset = bitIdx % 3; // 0=R, 1=G, 2=B
      final rgbaOffset = pixelIdx * 4 + channelOffset;

      // Clear LSB, then set it
      output[rgbaOffset] = (output[rgbaOffset] & 0xFE) | bit;
    }

    return output;
  }

  /// Extract and decrypt hidden text from image pixel LSBs.
  ///
  /// Reads the LSBs of RGB channels in [imageRgba] to recover the encrypted
  /// payload, then decrypts with AES-256-GCM using [aesKey].
  ///
  /// Parameters:
  ///   - [imageRgba]: Raw RGBA pixel data (must be the output of [embed])
  ///   - [width]: Image width in pixels
  ///   - [height]: Image height in pixels
  ///   - [aesKey]: 32-byte AES-256 decryption key (same as used in [embed])
  ///
  /// Returns the plaintext string if successful, or `null` if:
  ///   - No hidden data found (length header is invalid)
  ///   - Wrong AES key (MAC verification fails)
  ///   - Image was modified or compressed (LSB data corrupted)
  ///
  /// Example:
  /// ```dart
  /// final stegoImage = await loadImageRgba('stego.png');
  /// final key = loadKey(); // Same key used in embed
  /// final secret = await stego.extract(stegoImage, 1024, 1024, key);
  /// if (secret != null) {
  ///   print('Hidden message: $secret');
  /// } else {
  ///   print('No hidden message or wrong key');
  /// }
  /// ```
  Future<String?> extract(
    Uint8List imageRgba,
    int width,
    int height,
    Uint8List aesKey,
  ) async {
    try {
      assert(aesKey.length == 32, 'AES key must be 32 bytes');

      // 1. Read 4-byte length header from LSBs
      final headerBytes = _readBitsFromPixels(imageRgba, 0, 4);
      final payloadLen = (headerBytes[0] << 24) |
          (headerBytes[1] << 16) |
          (headerBytes[2] << 8) |
          headerBytes[3];

      // Sanity check: payload must fit in image
      final maxBytes = (width * height * 3) ~/ 8;
      if (payloadLen <= 0 || payloadLen > maxBytes - 4) {
        return null;
      }

      // Minimum payload: 12 (nonce) + 0 (ciphertext) + 16 (mac) = 28
      if (payloadLen < 28) return null;

      // 2. Read payload bytes
      final payload = _readBitsFromPixels(imageRgba, 4, payloadLen);

      // 3. Split: nonce (12) + ciphertext (variable) + mac (16)
      final nonce = payload.sublist(0, 12);
      final ciphertext = payload.sublist(12, payloadLen - 16);
      final macBytes = payload.sublist(payloadLen - 16);

      // 4. Decrypt
      final secretKey = SecretKey(aesKey);
      final secretBox = SecretBox(
        ciphertext,
        nonce: nonce,
        mac: Mac(macBytes),
      );

      final decrypted = await _algorithm.decrypt(
        secretBox,
        secretKey: secretKey,
      );

      return utf8.decode(decrypted);
    } catch (_) {
      return null;
    }
  }

  /// Calculate the maximum plaintext capacity for an image.
  ///
  /// Returns the maximum number of plaintext bytes that can be hidden in an
  /// image of the given dimensions. The actual capacity is less than the raw
  /// bit capacity due to AES-GCM overhead:
  ///   - 4 bytes: Length header
  ///   - 12 bytes: AES-GCM nonce
  ///   - 16 bytes: AES-GCM MAC
  ///
  /// Formula: `(width * height * 3) / 8 - 32` bytes.
  ///
  /// Example capacities:
  ///   - 512x512: ~98 KB
  ///   - 1024x1024: ~393 KB
  ///   - 2048x2048: ~1.5 MB
  ///
  /// For embedding large files, consider:
  ///   - Compression (gzip the plaintext first)
  ///   - Multiple images (split across several images)
  ///   - Higher resolution images
  int capacity(int width, int height) {
    return (width * height * 3) ~/ 8 - 4 - 12 - 16; // minus header, nonce, mac
  }

  // ── Private helpers ─────────────────────────────────────────────────

  /// Read [count] bytes starting at byte offset [startByte] from pixel LSBs.
  Uint8List _readBitsFromPixels(
    Uint8List imageRgba,
    int startByte,
    int count,
  ) {
    final result = Uint8List(count);
    final startBit = startByte * 8;
    final totalBits = count * 8;

    for (var bitIdx = 0; bitIdx < totalBits; bitIdx++) {
      final globalBitIdx = startBit + bitIdx;

      final pixelIdx = globalBitIdx ~/ 3;
      final channelOffset = globalBitIdx % 3; // 0=R, 1=G, 2=B
      final rgbaOffset = pixelIdx * 4 + channelOffset;

      final bit = imageRgba[rgbaOffset] & 1;

      final byteIdx = bitIdx ~/ 8;
      final bitPos = 7 - (bitIdx % 8); // MSB first
      result[byteIdx] |= (bit << bitPos);
    }

    return result;
  }
}
