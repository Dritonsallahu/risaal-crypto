@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';

/// R4-M5: `encrypt` and `decrypt` must serialize on one mutex.
///
/// `decrypt` is transactional: it clones the ratchet state, awaits the AEAD
/// work, then commits the clone wholesale. An `encrypt` interleaved with that
/// window advanced the live sending chain, and the commit silently discarded
/// the advance, so the next `encrypt` reused the same message number and key.
/// Two concurrent `encrypt` calls likewise read the same chain key.
Future<(DoubleRatchet alice, DoubleRatchet bob)> _session() async {
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
  final sharedSecret = List<int>.generate(32, (i) => i + 1);
  final alice = await DoubleRatchet.initSender(
    sharedSecret: sharedSecret,
    recipientPublicKey: bobPreKey.publicKey,
  );
  final bob = await DoubleRatchet.initReceiver(
    sharedSecret: sharedSecret,
    dhKeyPair: bobPreKey,
  );
  return (alice, bob);
}

/// A session where both parties have ratcheted once, so Bob's next message
/// stays in Alice's current receiving chain (no DH ratchet step on decrypt).
Future<(DoubleRatchet alice, DoubleRatchet bob)> _warmSession() async {
  final (alice, bob) = await _session();
  await bob.decrypt(await alice.encrypt(utf8.encode('A0')));
  await alice.decrypt(await bob.encrypt(utf8.encode('B0')));
  return (alice, bob);
}

void main() {
  test('decrypt racing encrypt never loses the sending-chain advance '
      '(50 iterations, alternating order)', () async {
    for (var i = 0; i < 50; i++) {
      final (alice, bob) = await _warmSession();
      final bobMsg = await bob.encrypt(utf8.encode('B$i'));
      final sentBefore = alice.state.sendMessageNumber;

      final decryptF = alice.decrypt(bobMsg);
      final encryptF = alice.encrypt(utf8.encode('A1'));
      final List<Object> results;
      if (i.isEven) {
        results = await Future.wait<Object>([decryptF, encryptF]);
      } else {
        results = (await Future.wait<Object>([
          encryptF,
          decryptF,
        ])).reversed.toList();
      }
      expect(utf8.decode(results[0] as List<int>), 'B$i');
      final a1 = results[1] as EncryptedMessage;
      final a2 = await alice.encrypt(utf8.encode('A2'));

      expect(
        alice.state.sendMessageNumber,
        sentBefore + 2,
        reason: 'iteration $i: encrypt advance lost by decrypt commit',
      );
      expect(a2.messageNumber, a1.messageNumber + 1, reason: 'iteration $i');
      expect(utf8.decode(await bob.decrypt(a1)), 'A1', reason: 'iter $i');
      expect(utf8.decode(await bob.decrypt(a2)), 'A2', reason: 'iter $i');
    }
  });

  test('two concurrent encrypts get distinct consecutive numbers', () async {
    final (alice, bob) = await _session();
    final msgs = await Future.wait([
      alice.encrypt(utf8.encode('X')),
      alice.encrypt(utf8.encode('Y')),
    ]);
    expect(msgs.map((m) => m.messageNumber).toList(), [0, 1]);
    expect(alice.state.sendMessageNumber, 2);
    expect(utf8.decode(await bob.decrypt(msgs[0])), 'X');
    expect(utf8.decode(await bob.decrypt(msgs[1])), 'Y');
  });
}
