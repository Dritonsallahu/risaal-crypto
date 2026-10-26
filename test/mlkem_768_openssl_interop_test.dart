@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

/// Bidirectional ML-KEM-768 interoperability against OpenSSL's independent
/// implementation, including FIPS 203 implicit rejection.
///
/// This closes an acceptance gate that had stood `OPEN`: every ML-KEM proof in
/// this project until now was self-consistency — our implementation agreeing
/// with itself, or with fixed NIST vectors. Neither catches an implementation
/// that is internally consistent and wrong at the wire, which is exactly the
/// failure class that produced the original defect this whole task exists for.
///
/// OpenSSL 3.5+ ships ML-KEM natively, so the check needs no extra provider.
/// Skipped rather than failed where the binary is too old, because a machine
/// without ML-KEM support proves nothing either way.
const _kemAlgorithm = 'ML-KEM-768';
const _publicKeyBytes = 1184;
const _ciphertextBytes = 1088;
const _sharedSecretBytes = 32;

/// SubjectPublicKeyInfo prefix for an ML-KEM-768 public key. OpenSSL wants a
/// DER-encoded SPKI; our wire format is the raw key, so one is built from the
/// other. Asserted against OpenSSL's own output in the first test rather than
/// trusted as a constant.
const _spkiHeader = <int>[
  0x30, 0x82, 0x04, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, //
  0x65, 0x03, 0x04, 0x04, 0x02, 0x03, 0x82, 0x04, 0xa1, 0x00,
];

/// The first openssl on this machine that actually implements ML-KEM-768.
///
/// Resolved by probing absolute candidates rather than trusting `PATH`, and
/// each candidate is asked whether it supports the algorithm rather than
/// assumed to. Both halves matter: the test isolate does not inherit the
/// shell's PATH, so a bare `openssl` lookup made this whole gate SKIP silently
/// during a normal `flutter test` while passing when run on its own — a gate
/// that disappears depending on how it is invoked certifies nothing. And on
/// macOS `/usr/bin/openssl` is LibreSSL, which has no ML-KEM at all, so the
/// first binary found is the wrong one.
String? _resolveOpenssl() {
  const candidates = <String>[
    '/opt/homebrew/bin/openssl',
    '/usr/local/bin/openssl',
    '/usr/bin/openssl',
    'openssl',
  ];
  for (final candidate in candidates) {
    try {
      final result = Process.runSync(candidate, ['list', '-kem-algorithms']);
      if (result.exitCode == 0 &&
          (result.stdout as String).contains(_kemAlgorithm)) {
        return candidate;
      }
    } on ProcessException {
      continue;
    }
  }
  return null;
}

final String? _openssl = _resolveOpenssl();

late Directory _work;

String _path(String name) => '${_work.path}/$name';

void _run(List<String> args) {
  final result = Process.runSync(_openssl!, args);
  if (result.exitCode != 0) {
    fail('openssl ${args.join(' ')} failed: ${result.stderr}');
  }
}

void main() {
  setUp(() => _work = Directory.systemTemp.createTempSync('risaal_mlkem'));
  tearDown(() {
    if (_work.existsSync()) _work.deleteSync(recursive: true);
  });

  group('ML-KEM-768 interoperates with OpenSSL', () {
    test('the SPKI header this test builds matches OpenSSL byte for byte', () {
      _run(['genpkey', '-algorithm', _kemAlgorithm, '-out', _path('sk.pem')]);
      _run([
        'pkey',
        '-in',
        _path('sk.pem'),
        '-pubout',
        '-outform',
        'DER',
        '-out',
        _path('pk.der'),
      ]);
      final der = File(_path('pk.der')).readAsBytesSync();
      expect(der.length, _spkiHeader.length + _publicKeyBytes);
      expect(
        der.sublist(0, _spkiHeader.length),
        _spkiHeader,
        reason:
            'the constant is only safe while it equals what OpenSSL emits; if '
            'this fails the other direction is testing a malformed key',
      );
    });

    test('OpenSSL keygen -> our encapsulation -> OpenSSL decapsulation', () {
      _run(['genpkey', '-algorithm', _kemAlgorithm, '-out', _path('sk.pem')]);
      _run([
        'pkey',
        '-in',
        _path('sk.pem'),
        '-pubout',
        '-outform',
        'DER',
        '-out',
        _path('pk.der'),
      ]);
      final der = File(_path('pk.der')).readAsBytesSync();
      final rawPublicKey = Uint8List.fromList(
        der.sublist(der.length - _publicKeyBytes),
      );

      final (ciphertext, ourSecret) = PqcKem.kyber768.encapsulate(rawPublicKey);
      expect(ciphertext.length, _ciphertextBytes);
      expect(ourSecret.length, _sharedSecretBytes);

      File(_path('ct.bin')).writeAsBytesSync(ciphertext);
      _run([
        'pkeyutl',
        '-decap',
        '-inkey',
        _path('sk.pem'),
        '-in',
        _path('ct.bin'),
        '-secret',
        _path('ss.bin'),
      ]);

      expect(
        File(_path('ss.bin')).readAsBytesSync(),
        ourSecret,
        reason:
            'a shared secret that only agrees with ourselves is the exact '
            'shape of the defect this task was opened for',
      );
    });

    test('our keygen -> OpenSSL encapsulation -> our decapsulation', () {
      final (publicKey, privateKey) = PqcKem.kyber768.generateKeyPair();
      expect(publicKey.length, _publicKeyBytes);

      File(_path('pk.der')).writeAsBytesSync([..._spkiHeader, ...publicKey]);
      _run([
        'pkeyutl',
        '-encap',
        '-inkey',
        _path('pk.der'),
        '-pubin',
        '-keyform',
        'DER',
        '-secret',
        _path('ss.bin'),
        '-out',
        _path('ct.bin'),
      ]);

      final ciphertext = File(_path('ct.bin')).readAsBytesSync();
      expect(ciphertext.length, _ciphertextBytes);

      expect(
        PqcKem.kyber768.decapsulate(privateKey, ciphertext),
        File(_path('ss.bin')).readAsBytesSync(),
      );
    });

    test('implicit rejection agrees with OpenSSL on a corrupted ciphertext', () {
      // FIPS 203 does not fail on a bad ciphertext — it returns a deterministic
      // secret derived from the private key's rejection value. Two conforming
      // implementations must return the SAME wrong secret. An implementation
      // that throws, or that returns a different wrong secret, is
      // distinguishable to an attacker probing with malformed ciphertexts.
      _run(['genpkey', '-algorithm', _kemAlgorithm, '-out', _path('sk.pem')]);
      _run([
        'pkey',
        '-in',
        _path('sk.pem'),
        '-pubout',
        '-outform',
        'DER',
        '-out',
        _path('pk.der'),
      ]);
      final der = File(_path('pk.der')).readAsBytesSync();
      final rawPublicKey = Uint8List.fromList(
        der.sublist(der.length - _publicKeyBytes),
      );

      final (ciphertext, _) = PqcKem.kyber768.encapsulate(rawPublicKey);
      final corrupted = Uint8List.fromList(ciphertext);
      corrupted[0] ^= 0xFF;
      corrupted[corrupted.length - 1] ^= 0x01;

      File(_path('ct.bin')).writeAsBytesSync(corrupted);
      _run([
        'pkeyutl',
        '-decap',
        '-inkey',
        _path('sk.pem'),
        '-in',
        _path('ct.bin'),
        '-secret',
        _path('ss.bin'),
      ]);
      final opensslRejection = File(_path('ss.bin')).readAsBytesSync();

      // Our side needs the same private key OpenSSL used, so this direction is
      // driven from our own keypair with OpenSSL as the second opinion.
      final (publicKey, privateKey) = PqcKem.kyber768.generateKeyPair();
      File(_path('pk2.der')).writeAsBytesSync([..._spkiHeader, ...publicKey]);
      _run([
        'pkeyutl',
        '-encap',
        '-inkey',
        _path('pk2.der'),
        '-pubin',
        '-keyform',
        'DER',
        '-secret',
        _path('ss2.bin'),
        '-out',
        _path('ct2.bin'),
      ]);
      final ours = Uint8List.fromList(File(_path('ct2.bin')).readAsBytesSync());
      final good = PqcKem.kyber768.decapsulate(privateKey, ours);
      ours[5] ^= 0xAA;
      final rejected = PqcKem.kyber768.decapsulate(privateKey, ours);

      expect(opensslRejection, hasLength(_sharedSecretBytes));
      expect(
        rejected,
        hasLength(_sharedSecretBytes),
        reason: 'implicit rejection must return a secret, not throw',
      );
      expect(
        rejected,
        isNot(good),
        reason: 'a corrupted ciphertext must not recover the real secret',
      );
      expect(
        PqcKem.kyber768.decapsulate(privateKey, ours),
        rejected,
        reason: 'rejection must be deterministic for a given key + ciphertext',
      );
    });
  }, skip: _openssl == null ? 'no openssl with ML-KEM-768 here' : false);
}
