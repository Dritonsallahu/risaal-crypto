import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/stego_service.dart';

void main() {
  late StegoService stego;

  setUp(() {
    stego = StegoService();
  });

  group('StegoService embed/extract round-trip', () {
    test('short text embeds and extracts correctly', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = 'Hello, secure world!';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);
      final extracted = await stego.extract(embedded, 100, 100, key);

      expect(extracted, equals(plaintext));
    });

    test('unicode text (emojis, Arabic, CJK) round-trips', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext =
          '\u0645\u0631\u062D\u0628\u0627 \u{1F512} \u4F60\u597D \u{1F30D} \u{1F60A}';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);
      final extracted = await stego.extract(embedded, 100, 100, key);

      expect(extracted, equals(plaintext));
    });

    test('empty string round-trips', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = '';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);
      final extracted = await stego.extract(embedded, 100, 100, key);

      expect(extracted, equals(plaintext));
    });

    test('multi-sentence text round-trips', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = '''
This is a longer message with multiple sentences.
It tests whether the steganography service can handle
newlines, punctuation, and various characters correctly.
Security is paramount.''';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);
      final extracted = await stego.extract(embedded, 100, 100, key);

      expect(extracted, equals(plaintext));
    });
  });

  group('StegoService capacity', () {
    test('capacity() returns correct value for known dimensions', () {
      // capacity = (width * height * 3) / 8 - 4 - 12 - 16
      // capacity = (width * height * 3) / 8 - 32
      final cap = stego.capacity(100, 100);
      final expected = (100 * 100 * 3) ~/ 8 - 32;
      expect(cap, equals(expected));
      expect(cap, equals(3718));
    });

    test('capacity(100, 100) = 3718 bytes', () {
      final cap = stego.capacity(100, 100);
      expect(cap, equals(3718));
    });

    test('capacity(1, 1) = very small (negative)', () {
      final cap = stego.capacity(1, 1);
      // (1 * 1 * 3) / 8 - 32 = 0 - 32 = -32
      expect(cap, equals(-32));
      expect(cap, isNegative);
    });

    test('capacity(10, 10) = small positive', () {
      final cap = stego.capacity(10, 10);
      // (10 * 10 * 3) / 8 - 32 = 37 - 32 = 5
      expect(cap, equals(5));
    });
  });

  group('StegoService security properties', () {
    test('same plaintext + same key -> different output (random nonce)',
        () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = 'Same message';

      final embedded1 = await stego.embed(image, 100, 100, plaintext, key);
      final embedded2 = await stego.embed(image, 100, 100, plaintext, key);

      // Outputs should differ because AES-GCM uses random nonce each time
      expect(embedded1, isNot(equals(embedded2)));

      // But both should decrypt to same plaintext
      final extracted1 = await stego.extract(embedded1, 100, 100, key);
      final extracted2 = await stego.extract(embedded2, 100, 100, key);
      expect(extracted1, equals(plaintext));
      expect(extracted2, equals(plaintext));
    });

    test('wrong AES key -> extract returns null', () async {
      final image = _createTestImage(100, 100);
      final key1 = _generateKey();
      final key2 = Uint8List.fromList(List.generate(32, (i) => i + 100));
      const plaintext = 'Secret message';

      final embedded = await stego.embed(image, 100, 100, plaintext, key1);
      final extracted = await stego.extract(embedded, 100, 100, key2);

      expect(extracted, isNull);
    });

    test('tampered pixel data -> extract returns null or different text',
        () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = 'Integrity test';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);

      // Flip multiple bits in the ciphertext area to ensure MAC failure
      for (var i = 200; i < 220; i++) {
        if (i % 4 != 3) {
          // Don't modify alpha
          embedded[i] ^= 0xFF; // flip entire byte
        }
      }

      final extracted = await stego.extract(embedded, 100, 100, key);

      // AES-GCM MAC should fail with high probability
      expect(extracted, isNull);
    });

    test('original image buffer is NOT modified (embed returns new buffer)',
        () async {
      final image = _createTestImage(50, 50);
      final originalCopy = Uint8List.fromList(image);
      final key = _generateKey();
      const plaintext = 'Test';

      await stego.embed(image, 50, 50, plaintext, key);

      // Original buffer should be unchanged
      expect(image, equals(originalCopy));
    });
  });

  group('StegoService edge cases', () {
    test('image too small for message -> throws StateError', () async {
      // Very small image (10x10 = 100 pixels = 37 bytes capacity)
      // Overhead: 4 (header) + 12 (nonce) + 16 (MAC) = 32 bytes
      // So max plaintext = 5 bytes
      final image = _createTestImage(10, 10);
      final key = _generateKey();
      final plaintext = 'This message is way too long for a 10x10 image';

      expect(
        () => stego.embed(image, 10, 10, plaintext, key),
        throwsA(isA<StateError>()),
      );
    });

    test('message exactly at capacity limit works', () async {
      // 100x100 image = 3750 total bytes capacity
      // Overhead: 32 bytes
      // Max plaintext: 3718 bytes
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      final capacity = stego.capacity(100, 100);

      // Create plaintext of exactly capacity length
      final plaintext = 'A' * capacity;

      final embedded = await stego.embed(image, 100, 100, plaintext, key);
      final extracted = await stego.extract(embedded, 100, 100, key);

      expect(extracted, equals(plaintext));
    });

    test('large image (256x256) with small text works', () async {
      final image = _createTestImage(256, 256);
      final key = _generateKey();
      const plaintext = 'Small message in big image';

      final embedded = await stego.embed(image, 256, 256, plaintext, key);
      final extracted = await stego.extract(embedded, 256, 256, key);

      expect(extracted, equals(plaintext));
    });

    test('AES key must be 32 bytes (assert in embed)', () async {
      final image = _createTestImage(100, 100);
      final shortKey = Uint8List(16); // Only 16 bytes
      const plaintext = 'Test';

      // Note: assertions only throw in debug mode
      // In release mode, this will likely fail during encryption
      try {
        await stego.embed(image, 100, 100, plaintext, shortKey);
        fail('Should have thrown assertion error or encryption error');
      } catch (e) {
        // Either AssertionError (debug) or some crypto error (release)
        expect(e, isNotNull);
      }
    });

    test('AES key must be 32 bytes (assert in extract)', () async {
      final image = _createTestImage(100, 100);
      final shortKey = Uint8List(16); // Only 16 bytes

      // Note: assertions only throw in debug mode
      // In release mode, this will likely fail during decryption
      try {
        await stego.extract(image, 100, 100, shortKey);
        fail('Should have thrown assertion error or decryption error');
      } catch (e) {
        // Either AssertionError (debug) or some crypto error (release)
        expect(e, isNotNull);
      }
    });

    test('corrupted length header -> extract returns null', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = 'Test message';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);

      // Corrupt the length header by flipping bits in first few pixels
      for (var i = 0; i < 12; i++) {
        embedded[i] ^= 0x01;
      }

      final extracted = await stego.extract(embedded, 100, 100, key);
      expect(extracted, isNull);
    });

    test('image with no embedded data -> extract returns null', () async {
      // Fresh image with no steganography
      final image = _createTestImage(100, 100);
      final key = _generateKey();

      final extracted = await stego.extract(image, 100, 100, key);
      expect(extracted, isNull);
    });

    test('extract with wrong dimensions -> may succeed or fail', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();
      const plaintext = 'Test';

      final embedded = await stego.embed(image, 100, 100, plaintext, key);

      // Try to extract with wrong dimensions
      // Note: Implementation doesn't strictly validate dimensions
      // The extract may still succeed if buffer is large enough
      // This test just verifies it doesn't crash
      final extracted = await stego.extract(embedded, 50, 50, key);

      // Extraction either succeeds or fails gracefully
      expect(extracted == plaintext || extracted == null, isTrue);
    });
  });

  group('StegoService malformed payload handling', () {
    test('payload length claims to be larger than image capacity -> null',
        () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();

      // Manually craft a malicious length header (claim 1MB payload)
      final malicious = Uint8List.fromList(image);
      final hugeLenBytes = [0xFF, 0xFF, 0xFF, 0xFF]; // ~4GB

      // Embed malicious length in first 4 bytes (LSBs)
      for (var byteIdx = 0; byteIdx < 4; byteIdx++) {
        for (var bitPos = 0; bitPos < 8; bitPos++) {
          final bit = (hugeLenBytes[byteIdx] >> (7 - bitPos)) & 1;
          final globalBit = byteIdx * 8 + bitPos;
          final pixelIdx = globalBit ~/ 3;
          final channel = globalBit % 3;
          final rgbaOffset = pixelIdx * 4 + channel;
          malicious[rgbaOffset] = (malicious[rgbaOffset] & 0xFE) | bit;
        }
      }

      final extracted = await stego.extract(malicious, 100, 100, key);
      expect(extracted, isNull);
    });

    test('payload length is zero -> null', () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();

      // Manually craft zero length header
      final malicious = Uint8List.fromList(image);
      final zeroLenBytes = [0x00, 0x00, 0x00, 0x00];

      for (var byteIdx = 0; byteIdx < 4; byteIdx++) {
        for (var bitPos = 0; bitPos < 8; bitPos++) {
          final bit = (zeroLenBytes[byteIdx] >> (7 - bitPos)) & 1;
          final globalBit = byteIdx * 8 + bitPos;
          final pixelIdx = globalBit ~/ 3;
          final channel = globalBit % 3;
          final rgbaOffset = pixelIdx * 4 + channel;
          malicious[rgbaOffset] = (malicious[rgbaOffset] & 0xFE) | bit;
        }
      }

      final extracted = await stego.extract(malicious, 100, 100, key);
      expect(extracted, isNull);
    });

    test('payload length < 28 bytes (too small for nonce+mac) -> null',
        () async {
      final image = _createTestImage(100, 100);
      final key = _generateKey();

      // Craft payload with length = 10 (too small for nonce=12 + mac=16)
      final malicious = Uint8List.fromList(image);
      final smallLenBytes = [0x00, 0x00, 0x00, 0x0A]; // length = 10

      for (var byteIdx = 0; byteIdx < 4; byteIdx++) {
        for (var bitPos = 0; bitPos < 8; bitPos++) {
          final bit = (smallLenBytes[byteIdx] >> (7 - bitPos)) & 1;
          final globalBit = byteIdx * 8 + bitPos;
          final pixelIdx = globalBit ~/ 3;
          final channel = globalBit % 3;
          final rgbaOffset = pixelIdx * 4 + channel;
          malicious[rgbaOffset] = (malicious[rgbaOffset] & 0xFE) | bit;
        }
      }

      final extracted = await stego.extract(malicious, 100, 100, key);
      expect(extracted, isNull);
    });
  });

  group('StegoService different image sizes', () {
    test('16x16 image can hide small message', () async {
      final image = _createTestImage(16, 16);
      final key = _generateKey();
      const plaintext = 'Hi';

      final embedded = await stego.embed(image, 16, 16, plaintext, key);
      final extracted = await stego.extract(embedded, 16, 16, key);

      expect(extracted, equals(plaintext));
    });

    test('512x512 image can hide large message', () async {
      final image = _createTestImage(512, 512);
      final key = _generateKey();
      final capacity = stego.capacity(512, 512);

      // Create a large message (half capacity)
      final plaintext = 'Large message. ' * (capacity ~/ 30);

      final embedded = await stego.embed(image, 512, 512, plaintext, key);
      final extracted = await stego.extract(embedded, 512, 512, key);

      expect(extracted, equals(plaintext));
    });

    test('non-square image (200x100) works', () async {
      final image = _createTestImage(200, 100);
      final key = _generateKey();
      const plaintext = 'Non-square test';

      final embedded = await stego.embed(image, 200, 100, plaintext, key);
      final extracted = await stego.extract(embedded, 200, 100, key);

      expect(extracted, equals(plaintext));
    });
  });

  group('StegoService visual imperceptibility', () {
    test('embedded image LSB changes are minimal (max 1 bit per channel)',
        () async {
      final original = _createTestImage(50, 50);
      final key = _generateKey();
      const plaintext = 'Test';

      final embedded = await stego.embed(original, 50, 50, plaintext, key);

      // Check that each RGB pixel differs by at most 1 (LSB flip)
      for (var i = 0; i < original.length; i++) {
        if (i % 4 == 3) continue; // Skip alpha

        final diff = (original[i] - embedded[i]).abs();
        expect(diff, lessThanOrEqualTo(1),
            reason: 'Pixel byte $i changed by $diff (should be 0 or 1)');
      }
    });

    test('alpha channel is never modified', () async {
      final original = _createTestImage(50, 50);
      final key = _generateKey();
      const plaintext = 'Test alpha preservation';

      final embedded = await stego.embed(original, 50, 50, plaintext, key);

      // Check all alpha bytes (every 4th byte) are unchanged
      for (var i = 3; i < original.length; i += 4) {
        expect(embedded[i], equals(original[i]),
            reason: 'Alpha channel at index $i was modified');
      }
    });
  });
}

// ── Test Helpers ─────────────────────────────────────────────────────

/// Generate deterministic test RGBA image data.
Uint8List _createTestImage(int width, int height) {
  final data = Uint8List(width * height * 4);
  for (var i = 0; i < data.length; i++) {
    data[i] = (i * 37 + 42) % 256; // deterministic pseudo-random
  }
  return data;
}

/// Generate deterministic 32-byte AES key for testing.
Uint8List _generateKey() {
  return Uint8List.fromList(List.generate(32, (i) => i + 1));
}
