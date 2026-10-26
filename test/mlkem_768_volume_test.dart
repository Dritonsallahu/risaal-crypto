@TestOn('vm')
@Timeout(Duration(minutes: 20))
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashes;
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

/// Volume proof for ML-KEM-768: 10,000 blocking cases on every run, and a
/// 100,000-case soak behind `RISAAL_MLKEM_SOAK=1`.
///
/// Fixed NIST vectors prove the implementation matches the standard on the
/// inputs someone chose in advance. They cannot see a defect that appears once
/// in ten thousand keys — and the defect this whole task exists for was exactly
/// that shape: valid operations deriving different secrets, reproducible only at
/// a specific case index. Volume is the only thing that finds that class.
///
/// Every failure prints its case index, so a failure is reproducible rather
/// than "it went red once on CI".
const _blockingCases = 10000;
const _soakCases = 100000;
const _publicKeyBytes = 1184;
const _privateKeyBytes = 2400;
const _ciphertextBytes = 1088;
const _sharedSecretBytes = 32;

/// Runs [cases] full keygen → encapsulate → decapsulate cycles.
///
/// Returns the number of distinct public keys seen. Kept as a digest set rather
/// than the keys themselves so 100,000 cases stay inside a sane memory budget.
int _runCycles(int cases) {
  final kem = PqcKem.kyber768;
  final publicKeyDigests = <String>{};

  for (var index = 0; index < cases; index++) {
    final (publicKey, privateKey) = kem.generateKeyPair();
    expect(publicKey, hasLength(_publicKeyBytes), reason: 'case $index');
    expect(privateKey, hasLength(_privateKeyBytes), reason: 'case $index');

    final (ciphertext, senderSecret) = kem.encapsulate(publicKey);
    expect(ciphertext, hasLength(_ciphertextBytes), reason: 'case $index');
    expect(senderSecret, hasLength(_sharedSecretBytes), reason: 'case $index');

    final receiverSecret = kem.decapsulate(privateKey, ciphertext);
    expect(
      receiverSecret,
      senderSecret,
      reason:
          'case $index derived two different secrets from one valid exchange — '
          'this is the original defect, and at this index it is reproducible',
    );

    publicKeyDigests.add(hashes.sha256.convert(publicKey).toString());
  }

  return publicKeyDigests.length;
}

void main() {
  test(
    '$_blockingCases valid exchanges all agree, and every key is distinct',
    () {
      final distinct = _runCycles(_blockingCases);
      expect(
        distinct,
        _blockingCases,
        reason:
            'a repeated public key means the RNG is degenerate — two users would '
            'hold the same identity, which is worse than any decrypt failure',
      );
    },
  );

  test('a corrupted ciphertext never recovers the real secret', () {
    // Swept across every byte position class rather than a single fixed byte:
    // a packing/arithmetic boundary defect shows up at specific offsets, and
    // one hard-coded index walks past it.
    final kem = PqcKem.kyber768;
    for (var index = 0; index < 512; index++) {
      final (publicKey, privateKey) = kem.generateKeyPair();
      final (ciphertext, realSecret) = kem.encapsulate(publicKey);

      final corrupted = Uint8List.fromList(ciphertext);
      final position = (index * 7) % corrupted.length;
      corrupted[position] ^= 1 << (index % 8);

      final rejected = kem.decapsulate(privateKey, corrupted);
      expect(
        rejected,
        hasLength(_sharedSecretBytes),
        reason: 'implicit rejection returns a secret, it does not throw',
      );
      expect(
        rejected,
        isNot(realSecret),
        reason:
            'case $index flipped byte $position and still recovered the '
            'real secret — the ciphertext is not fully bound',
      );
      expect(
        kem.decapsulate(privateKey, corrupted),
        rejected,
        reason: 'case $index rejection is not deterministic',
      );
    }
  });

  test('a ciphertext from one key never opens under another', () {
    final kem = PqcKem.kyber768;
    for (var index = 0; index < 512; index++) {
      final (publicKeyA, _) = kem.generateKeyPair();
      final (_, privateKeyB) = kem.generateKeyPair();
      final (ciphertext, secretForA) = kem.encapsulate(publicKeyA);
      expect(
        kem.decapsulate(privateKeyB, ciphertext),
        isNot(secretForA),
        reason: 'case $index: a wrong key recovered the right secret',
      );
    }
  });

  test(
    '$_soakCases exchanges',
    () {
      final distinct = _runCycles(_soakCases);
      expect(distinct, _soakCases);
    },
    skip: Platform.environment['RISAAL_MLKEM_SOAK'] == '1'
        ? false
        : 'set RISAAL_MLKEM_SOAK=1 to run the soak',
  );
}
