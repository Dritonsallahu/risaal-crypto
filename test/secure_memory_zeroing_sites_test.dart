import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// R4-M1 — `cryptography` 2.9.0 returns unmodifiable `SensitiveBytes` from
/// `extractBytes()`, so zeroing that list is a silent no-op. Every DH / HKDF
/// output the package keeps must be copied once into a package-owned buffer
/// (`SecureMemory.ownedCopy`) so the later `zeroBytes` really wipes it.
/// Round-trip tests cannot see this (zeroed or not, the protocol works), so
/// pin it at the source.
const _sites = [
  'lib/src/x3dh.dart',
  'lib/src/double_ratchet.dart',
  'lib/src/sealed_sender.dart',
];

/// Body of the static method starting at [start] (up to the closing `  }`).
String _methodFrom(String src, int start) {
  final end = src.indexOf('\n  }\n', start);
  return src.substring(start, end == -1 ? src.length : end);
}

String _method(String src, String signature) {
  final i = src.indexOf(signature);
  expect(i, greaterThan(-1), reason: 'missing $signature');
  return _methodFrom(src, i);
}

void main() {
  test(
    'every sharedSecretKey( result is copied with ownedCopy and destroyed',
    () {
      for (final path in _sites) {
        final src = File(path).readAsStringSync();
        var from = 0;
        var hits = 0;
        while (true) {
          final i = src.indexOf('sharedSecretKey(', from);
          if (i == -1) break;
          hits++;
          final body = _methodFrom(src, i);
          expect(
            body.contains('SecureMemory.ownedCopy('),
            isTrue,
            reason:
                '$path: DH output must be copied into a package-owned buffer',
          );
          expect(
            body.contains('.destroy();'),
            isTrue,
            reason: '$path: the library SecretKey must be destroyed after copy',
          );
          from = i + 1;
        }
        expect(hits, greaterThan(0), reason: '$path has no DH site');
      }
    },
  );

  test('every extractBytes() in the DH/HKDF sites is wrapped by ownedCopy', () {
    final wrapped = RegExp(
      r'SecureMemory\.ownedCopy\(\s*await\s+\w+\.extractBytes\(\)',
    );
    for (final path in _sites) {
      final src = File(path).readAsStringSync();
      final all = 'extractBytes()'.allMatches(src).length;
      expect(all, greaterThan(0), reason: path);
      expect(
        wrapped.allMatches(src).length,
        all,
        reason: '$path: an extractBytes() result is used without ownedCopy',
      );
      expect(src.contains('return secret.extractBytes();'), isFalse);
      expect(src.contains('return secretKey.extractBytes();'), isFalse);
    }
  });

  test('_deriveSecret and _deriveSharedKey return an owned copy', () {
    final x3dh = File('lib/src/x3dh.dart').readAsStringSync();
    final ss = File('lib/src/sealed_sender.dart').readAsStringSync();
    for (final body in [
      _method(x3dh, 'static Future<List<int>> _deriveSecret('),
      _method(ss, 'static Future<List<int>> _deriveSharedKey('),
    ]) {
      expect(body.contains('SecureMemory.ownedCopy('), isTrue);
      expect(body.contains('.destroy();'), isTrue);
    }
  });

  test('zeroBytes does not wipe a fresh native buffer (no _secureAlloc)', () {
    final src = File('lib/src/secure_memory.dart').readAsStringSync();
    final body = _method(src, 'static bool zeroBytes(List<int> bytes)');
    expect(body.contains('_secureAlloc'), isFalse);
    expect(body.contains('_secureWipe'), isFalse);
    expect(src.contains('static Uint8List ownedCopy(List<int> bytes)'), isTrue);
  });
}
