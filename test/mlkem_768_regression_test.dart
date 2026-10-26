@Retry(0)
library;

import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

Uint8List _deterministicBytes(int length, int caseIndex, int domain) {
  var state = (caseIndex ^ (domain * 0x9E3779B9)) & 0xFFFFFFFF;
  final output = Uint8List(length);
  for (var index = 0; index < length; index++) {
    state ^= (state << 13) & 0xFFFFFFFF;
    state ^= state >> 17;
    state ^= (state << 5) & 0xFFFFFFFF;
    state &= 0xFFFFFFFF;
    output[index] = state & 0xFF;
  }
  return output;
}

void main() {
  test('ML-KEM-768 deterministic regression case 324 round-trips', () {
    final kem = PqcKem.kyber768;
    final seed = _deterministicBytes(64, 324, 1);
    final nonce = _deterministicBytes(32, 324, 2);

    final (publicKey, privateKey) = kem.generateKeyPair(seed);
    final (ciphertext, senderSecret) = kem.encapsulate(publicKey, nonce);
    final recipientSecret = kem.decapsulate(privateKey, ciphertext);

    var difference = senderSecret.length ^ recipientSecret.length;
    if (senderSecret.length == recipientSecret.length) {
      for (var index = 0; index < senderSecret.length; index++) {
        difference |= senderSecret[index] ^ recipientSecret[index];
      }
    }

    expect(
      difference,
      0,
      reason:
          'A valid deterministic ML-KEM-768 round trip must never '
          'fall into implicit rejection and derive a different secret.',
    );
  });
}
