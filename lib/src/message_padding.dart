import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Pads and unpads messages to fixed bucket sizes so that an observer
/// cannot infer content type or length from ciphertext size.
///
/// Bucket sizes: 256B, 1KB, 4KB, 16KB, 64KB, 256KB.
/// Messages are padded to the smallest bucket that fits, with random
/// fill so identical plaintexts produce different padded outputs.
class MessagePadding {
  MessagePadding._();

  /// Bucket sizes in bytes, ascending.
  static const List<int> _buckets = [
    256, // short text
    1024, // normal text
    4096, // long text
    16384, // voice notes
    65536, // images
    262144, // video/file
  ];

  static final _random = Random.secure();

  // 4-byte big-endian length prefix
  static const _lengthPrefixSize = 4;

  /// Pad [plaintext] bytes to the nearest bucket size.
  ///
  /// Format: `[4-byte big-endian length] [plaintext] [random padding]`
  /// Total output length equals the chosen bucket size.
  static Uint8List pad(List<int> plaintext) {
    final dataLen = plaintext.length;
    final totalNeeded = dataLen + _lengthPrefixSize;

    // Find the smallest bucket that fits
    var bucketSize = _buckets.last;
    for (final size in _buckets) {
      if (totalNeeded <= size) {
        bucketSize = size;
        break;
      }
    }

    final output = Uint8List(bucketSize);

    // Write 4-byte big-endian length prefix
    output[0] = (dataLen >> 24) & 0xFF;
    output[1] = (dataLen >> 16) & 0xFF;
    output[2] = (dataLen >> 8) & 0xFF;
    output[3] = dataLen & 0xFF;

    // Copy plaintext after length prefix
    output.setRange(_lengthPrefixSize, _lengthPrefixSize + dataLen, plaintext);

    // Fill remaining bytes with random data (not zeros — prevents
    // compression-based side channels)
    for (var i = _lengthPrefixSize + dataLen; i < bucketSize; i++) {
      output[i] = _random.nextInt(256);
    }

    return output;
  }

  /// Pad a UTF-8 string to the nearest bucket size.
  static Uint8List padString(String plaintext) {
    return pad(utf8.encode(plaintext));
  }

  /// Remove padding and recover the original plaintext bytes.
  static Uint8List unpad(List<int> padded) {
    if (padded.length < _lengthPrefixSize) {
      throw FormatException('Padded message too short: ${padded.length} bytes');
    }

    // Read 4-byte big-endian length prefix
    final dataLen = (padded[0] << 24) |
        (padded[1] << 16) |
        (padded[2] << 8) |
        padded[3];

    if (dataLen < 0 || dataLen > padded.length - _lengthPrefixSize) {
      throw FormatException('Invalid padding length: $dataLen');
    }

    return Uint8List.fromList(
      padded.sublist(_lengthPrefixSize, _lengthPrefixSize + dataLen),
    );
  }

  /// Remove padding and recover the original plaintext string.
  static String unpadString(List<int> padded) {
    return utf8.decode(unpad(padded));
  }

  /// Returns the bucket size that would be used for a given plaintext length.
  static int bucketSizeFor(int plaintextLength) {
    final totalNeeded = plaintextLength + _lengthPrefixSize;
    for (final size in _buckets) {
      if (totalNeeded <= size) return size;
    }
    return _buckets.last;
  }
}
