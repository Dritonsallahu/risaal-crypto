import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/message_padding.dart';

void main() {
  // ── Pad / Unpad round-trip ─────────────────────────────────────────

  group('MessagePadding pad and unpad', () {
    test('round-trip for short text', () {
      final original = utf8.encode('Hello');
      final padded = MessagePadding.pad(original);
      final recovered = MessagePadding.unpad(padded);

      expect(recovered, equals(original));
    });

    test('round-trip for various lengths', () {
      final lengths = [
        1,
        10,
        50,
        100,
        200,
        251,
        252,
        500,
        1000,
        4000,
        16000,
        60000,
      ];
      for (final len in lengths) {
        final original = List<int>.generate(len, (i) => i % 256);
        final padded = MessagePadding.pad(original);
        final recovered = MessagePadding.unpad(padded);

        expect(
          recovered,
          equals(original),
          reason: 'Round-trip failed for length $len',
        );
      }
    });

    test('padString / unpadString round-trip', () {
      const original = 'Risaal end-to-end encryption test!';
      final padded = MessagePadding.padString(original);
      final recovered = MessagePadding.unpadString(padded);

      expect(recovered, original);
    });

    test('round-trip with unicode text', () {
      const original =
          'Shqip: Pershendetje! Arabic: \u0645\u0631\u062D\u0628\u0627';
      final padded = MessagePadding.padString(original);
      final recovered = MessagePadding.unpadString(padded);

      expect(recovered, original);
    });
  });

  // ── Padded output properties ───────────────────────────────────────

  group('MessagePadding output properties', () {
    test('padded output is always larger than input', () {
      final inputs = <List<int>>[
        [],
        [0],
        List<int>.generate(100, (i) => i),
        List<int>.generate(250, (i) => i % 256),
      ];

      for (final input in inputs) {
        final padded = MessagePadding.pad(input);
        expect(
          padded.length,
          greaterThan(input.length),
          reason: 'Padded length should exceed input length of ${input.length}',
        );
      }
    });

    test('padded output matches a bucket size', () {
      const buckets = [256, 1024, 4096, 16384, 65536, 262144];
      const lengths = [
        0,
        1,
        100,
        252,
        253,
        1000,
        1020,
        4000,
        16000,
        60000,
        200000,
      ];

      for (final len in lengths) {
        final input = List<int>.generate(len, (i) => i % 256);
        final padded = MessagePadding.pad(input);

        expect(
          buckets.contains(padded.length),
          isTrue,
          reason: 'Padded length ${padded.length} for input length $len '
              'is not a valid bucket size',
        );
      }
    });

    test('uses smallest bucket that fits', () {
      // 4 bytes length prefix + data must fit in bucket
      // Input of 100 bytes => 104 total needed => fits in 256 bucket
      final padded100 = MessagePadding.pad(List<int>.generate(100, (i) => i));
      expect(padded100.length, 256);

      // Input of 252 bytes => 256 total needed => fits exactly in 256 bucket
      final padded252 = MessagePadding.pad(List<int>.generate(252, (i) => i));
      expect(padded252.length, 256);

      // Input of 253 bytes => 257 total needed => needs 1024 bucket
      final padded253 = MessagePadding.pad(List<int>.generate(253, (i) => i));
      expect(padded253.length, 1024);

      // Input of 1020 bytes => 1024 total needed => fits exactly in 1024 bucket
      final padded1020 = MessagePadding.pad(List<int>.generate(1020, (i) => i));
      expect(padded1020.length, 1024);

      // Input of 1021 bytes => 1025 total needed => needs 4096 bucket
      final padded1021 = MessagePadding.pad(List<int>.generate(1021, (i) => i));
      expect(padded1021.length, 4096);
    });
  });

  // ── Empty message ──────────────────────────────────────────────────

  group('MessagePadding empty message', () {
    test('empty message pads to smallest bucket', () {
      final padded = MessagePadding.pad([]);
      expect(padded.length, 256);
    });

    test('empty message round-trips correctly', () {
      final padded = MessagePadding.pad([]);
      final recovered = MessagePadding.unpad(padded);
      expect(recovered, isEmpty);
    });

    test('empty string round-trips correctly', () {
      final padded = MessagePadding.padString('');
      final recovered = MessagePadding.unpadString(padded);
      expect(recovered, '');
    });
  });

  // ── Large message ──────────────────────────────────────────────────

  group('MessagePadding large messages', () {
    test('large message pads to largest bucket', () {
      // 200 KB data => needs 262144 bucket
      final data = List<int>.generate(200000, (i) => i % 256);
      final padded = MessagePadding.pad(data);
      expect(padded.length, 262144);
    });

    test('large message round-trips correctly', () {
      final data = List<int>.generate(200000, (i) => i % 256);
      final padded = MessagePadding.pad(data);
      final recovered = MessagePadding.unpad(padded);
      expect(recovered, equals(data));
    });

    test('message exceeding largest bucket still uses largest bucket', () {
      // Data that exceeds all buckets (> 262140 bytes with 4-byte prefix)
      // The implementation uses the last bucket for anything too large
      final data = List<int>.generate(262140, (i) => i % 256);
      final padded = MessagePadding.pad(data);
      expect(padded.length, 262144);
    });
  });

  // ── bucketSizeFor ──────────────────────────────────────────────────

  group('MessagePadding.bucketSizeFor', () {
    test('returns correct bucket for various plaintext lengths', () {
      // 0 bytes => 4 total => 256
      expect(MessagePadding.bucketSizeFor(0), 256);

      // 100 bytes => 104 total => 256
      expect(MessagePadding.bucketSizeFor(100), 256);

      // 252 bytes => 256 total => 256
      expect(MessagePadding.bucketSizeFor(252), 256);

      // 253 bytes => 257 total => 1024
      expect(MessagePadding.bucketSizeFor(253), 1024);

      // 1020 bytes => 1024 total => 1024
      expect(MessagePadding.bucketSizeFor(1020), 1024);

      // 1021 bytes => 1025 total => 4096
      expect(MessagePadding.bucketSizeFor(1021), 4096);

      // 60000 bytes => 60004 total => 65536
      expect(MessagePadding.bucketSizeFor(60000), 65536);

      // 200000 bytes => 200004 total => 262144
      expect(MessagePadding.bucketSizeFor(200000), 262144);
    });
  });

  // ── Error handling ─────────────────────────────────────────────────

  group('MessagePadding error handling', () {
    test('unpad throws FormatException for too-short input', () {
      expect(
        () => MessagePadding.unpad([0, 0, 0]),
        throwsA(isA<FormatException>()),
      );
    });

    test('unpad throws FormatException for invalid length prefix', () {
      // Length prefix claims 255 bytes, but only 4 bytes of padding follow
      final bad = Uint8List(8);
      bad[0] = 0;
      bad[1] = 0;
      bad[2] = 0;
      bad[3] = 255; // claims 255 bytes of data
      // Only 4 bytes follow the prefix — not enough

      expect(() => MessagePadding.unpad(bad), throwsA(isA<FormatException>()));
    });
  });

  // ── Padding randomness ─────────────────────────────────────────────

  group('MessagePadding randomness', () {
    test('padding bytes differ between calls (random fill)', () {
      final data = utf8.encode('test');

      final padded1 = MessagePadding.pad(data);
      final padded2 = MessagePadding.pad(data);

      // The first 4 + data.length bytes should be identical (length prefix + data)
      final headerLen = 4 + data.length;
      expect(
        padded1.sublist(0, headerLen),
        equals(padded2.sublist(0, headerLen)),
      );

      // The random padding region should differ (with overwhelming probability)
      final tail1 = padded1.sublist(headerLen);
      final tail2 = padded2.sublist(headerLen);
      expect(
        tail1,
        isNot(equals(tail2)),
        reason: 'Random padding should differ between calls',
      );
    });
  });
}
