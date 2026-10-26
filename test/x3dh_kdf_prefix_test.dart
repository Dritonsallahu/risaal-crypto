import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// A2-4 — the X3DH / PQXDH KDF input must be prefixed with F = 32 bytes of 0xFF
/// (one X25519 public-key length) per the Signal spec, for domain separation /
/// downgrade resistance. Round-trip tests can't lock this (both sides would move
/// together if it were removed), so pin it at the source.
void main() {
  test('the X3DH/PQXDH KDF prepends F = 32 bytes of 0xFF', () {
    final src = File('lib/src/x3dh.dart').readAsStringSync();
    final i = src.indexOf('static Future<List<int>> _deriveSecret(');
    expect(i, greaterThan(-1));
    final end = i + 700 > src.length ? src.length : i + 700;
    final body = src.substring(i, end);
    expect(
      body.contains('List<int>.filled(32, 0xFF)'),
      isTrue,
      reason: 'Signal X3DH/PQXDH requires the 0xFF F-prefix in the KDF input',
    );
    expect(
      body.contains('info: routing.canonicalTranscript()'),
      isTrue,
      reason: 'the authenticated generation route must remain HKDF-bound',
    );
  });
}
