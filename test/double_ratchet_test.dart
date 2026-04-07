import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';

/// Helper: set up a paired Alice (sender) and Bob (receiver) Double Ratchet
/// session using a simulated X3DH shared secret.
Future<(DoubleRatchet alice, DoubleRatchet bob)> _createSession() async {
  // Bob generates his signed pre-key (X25519 key pair used as the initial
  // ratchet key on the receiver side).
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();

  // Simulate an X3DH shared secret (32 random bytes).
  // In production this comes from the X3DH key agreement, but for testing
  // we just need both sides to share the same bytes.
  final sharedSecretBytes = List<int>.generate(32, (i) => i + 1);

  final alice = await DoubleRatchet.initSender(
    sharedSecret: sharedSecretBytes,
    recipientPublicKey: bobPreKey.publicKey,
  );

  final bob = await DoubleRatchet.initReceiver(
    sharedSecret: sharedSecretBytes,
    dhKeyPair: bobPreKey,
  );

  return (alice, bob);
}

void main() {
  // ── Basic encrypt / decrypt ─────────────────────────────────────────

  group('DoubleRatchet basic messaging', () {
    test('Alice sends one message, Bob decrypts it correctly', () async {
      final (alice, bob) = await _createSession();

      final plaintext = utf8.encode('Hello Bob!');
      final encrypted = await alice.encrypt(plaintext);
      final decrypted = await bob.decrypt(encrypted);

      expect(decrypted, equals(plaintext));
      expect(utf8.decode(decrypted), 'Hello Bob!');
    });

    test('Alice sends multiple sequential messages, Bob decrypts all', () async {
      final (alice, bob) = await _createSession();

      final messages = [
        'First message',
        'Second message',
        'Third message',
      ];

      for (final msg in messages) {
        final encrypted = await alice.encrypt(utf8.encode(msg));
        final decrypted = await bob.decrypt(encrypted);
        expect(utf8.decode(decrypted), msg);
      }
    });

    test('bidirectional conversation works', () async {
      final (alice, bob) = await _createSession();

      // Alice -> Bob
      final enc1 = await alice.encrypt(utf8.encode('Hello Bob'));
      final dec1 = await bob.decrypt(enc1);
      expect(utf8.decode(dec1), 'Hello Bob');

      // Bob -> Alice (triggers DH ratchet on Bob's side)
      final enc2 = await bob.encrypt(utf8.encode('Hello Alice'));
      final dec2 = await alice.decrypt(enc2);
      expect(utf8.decode(dec2), 'Hello Alice');

      // Alice -> Bob again (another DH ratchet step)
      final enc3 = await alice.encrypt(utf8.encode('How are you?'));
      final dec3 = await bob.decrypt(enc3);
      expect(utf8.decode(dec3), 'How are you?');

      // Bob -> Alice again
      final enc4 = await bob.encrypt(utf8.encode('Fine thanks!'));
      final dec4 = await alice.decrypt(enc4);
      expect(utf8.decode(dec4), 'Fine thanks!');
    });
  });

  // ── Out-of-order messages ──────────────────────────────────────────

  group('DoubleRatchet out-of-order messages', () {
    test('Bob decrypts messages received out of order', () async {
      final (alice, bob) = await _createSession();

      // Alice sends three messages
      final enc1 = await alice.encrypt(utf8.encode('Message 1'));
      final enc2 = await alice.encrypt(utf8.encode('Message 2'));
      final enc3 = await alice.encrypt(utf8.encode('Message 3'));

      // Bob receives them out of order: 3, 1, 2
      final dec3 = await bob.decrypt(enc3);
      expect(utf8.decode(dec3), 'Message 3');

      final dec1 = await bob.decrypt(enc1);
      expect(utf8.decode(dec1), 'Message 1');

      final dec2 = await bob.decrypt(enc2);
      expect(utf8.decode(dec2), 'Message 2');
    });

    test('skipped message keys are stored and consumed', () async {
      final (alice, bob) = await _createSession();

      // Alice sends two messages
      final enc1 = await alice.encrypt(utf8.encode('Message 1'));
      final enc2 = await alice.encrypt(utf8.encode('Message 2'));

      // Bob skips message 1, decrypts message 2 first
      final dec2 = await bob.decrypt(enc2);
      expect(utf8.decode(dec2), 'Message 2');

      // Message 1's key should have been stored as a skipped key
      // Now Bob decrypts message 1
      final dec1 = await bob.decrypt(enc1);
      expect(utf8.decode(dec1), 'Message 1');
    });
  });

  // ── Ciphertext properties ──────────────────────────────────────────

  group('DoubleRatchet ciphertext properties', () {
    test('same plaintext produces different ciphertexts', () async {
      final (alice, bob) = await _createSession();

      final plaintext = utf8.encode('Identical message');
      final enc1 = await alice.encrypt(plaintext);
      final enc2 = await alice.encrypt(plaintext);

      expect(enc1.ciphertext, isNot(equals(enc2.ciphertext)));
    });

    test('different sessions produce different ciphertexts for same plaintext',
        () async {
      final (alice1, _) = await _createSession();
      final (alice2, _) = await _createSession();

      final plaintext = utf8.encode('Same message');
      final enc1 = await alice1.encrypt(plaintext);
      final enc2 = await alice2.encrypt(plaintext);

      expect(enc1.ciphertext, isNot(equals(enc2.ciphertext)));
    });

    test('encrypted message contains correct message numbers', () async {
      final (alice, _) = await _createSession();

      final enc0 = await alice.encrypt(utf8.encode('msg 0'));
      final enc1 = await alice.encrypt(utf8.encode('msg 1'));
      final enc2 = await alice.encrypt(utf8.encode('msg 2'));

      expect(enc0.messageNumber, 0);
      expect(enc1.messageNumber, 1);
      expect(enc2.messageNumber, 2);
    });

    test('encrypted message has non-empty fields', () async {
      final (alice, _) = await _createSession();

      final enc = await alice.encrypt(utf8.encode('test'));

      expect(enc.dhPublicKey.isNotEmpty, isTrue);
      expect(enc.ciphertext.isNotEmpty, isTrue);
      expect(enc.nonce.isNotEmpty, isTrue);
      expect(base64Decode(enc.dhPublicKey).length, 32); // X25519 public key
    });
  });

  // ── EncryptedMessage serialisation ─────────────────────────────────

  group('EncryptedMessage JSON serialisation', () {
    test('toJson / fromJson round-trip', () async {
      final (alice, bob) = await _createSession();

      final enc = await alice.encrypt(utf8.encode('Serialise me'));
      final json = enc.toJson();
      final restored = EncryptedMessage.fromJson(json);

      expect(restored.dhPublicKey, enc.dhPublicKey);
      expect(restored.messageNumber, enc.messageNumber);
      expect(restored.previousChainLength, enc.previousChainLength);
      expect(restored.ciphertext, enc.ciphertext);
      expect(restored.nonce, enc.nonce);

      // Verify the restored message can still be decrypted
      final decrypted = await bob.decrypt(restored);
      expect(utf8.decode(decrypted), 'Serialise me');
    });
  });

  // ── State serialisation ────────────────────────────────────────────

  group('DoubleRatchet state serialisation', () {
    test('toJson / fromJson round-trip preserves ratchet state', () async {
      final (alice, bob) = await _createSession();

      // Exchange a few messages to advance the ratchet
      final enc1 = await alice.encrypt(utf8.encode('Before serialise'));
      await bob.decrypt(enc1);

      // Serialise and restore Alice
      final aliceJson = alice.toJson();
      final aliceRestored = DoubleRatchet.fromJson(aliceJson);

      // Alice (restored) sends another message, Bob can still decrypt
      final enc2 = await aliceRestored.encrypt(utf8.encode('After serialise'));
      final dec2 = await bob.decrypt(enc2);
      expect(utf8.decode(dec2), 'After serialise');
    });
  });

  // ── DH ratchet advancement ─────────────────────────────────────────

  group('DoubleRatchet DH ratchet step', () {
    test('DH ratchet key changes after direction switch', () async {
      final (alice, bob) = await _createSession();

      // Alice sends — uses her first ratchet key
      final enc1 = await alice.encrypt(utf8.encode('from alice'));
      final dhKey1 = enc1.dhPublicKey;

      await bob.decrypt(enc1);

      // Bob sends back — triggers DH ratchet on Bob
      final enc2 = await bob.encrypt(utf8.encode('from bob'));
      await alice.decrypt(enc2);

      // Alice sends again — triggers DH ratchet on Alice, new key
      final enc3 = await alice.encrypt(utf8.encode('from alice again'));
      final dhKey2 = enc3.dhPublicKey;

      expect(dhKey1, isNot(equals(dhKey2)),
          reason: 'DH ratchet key should change after direction switch');

      final dec3 = await bob.decrypt(enc3);
      expect(utf8.decode(dec3), 'from alice again');
    });

    test('multiple direction switches all decrypt correctly', () async {
      final (alice, bob) = await _createSession();

      for (var round = 0; round < 5; round++) {
        // Alice -> Bob
        final encAB =
            await alice.encrypt(utf8.encode('A->B round $round'));
        final decAB = await bob.decrypt(encAB);
        expect(utf8.decode(decAB), 'A->B round $round');

        // Bob -> Alice
        final encBA =
            await bob.encrypt(utf8.encode('B->A round $round'));
        final decBA = await alice.decrypt(encBA);
        expect(utf8.decode(decBA), 'B->A round $round');
      }
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────

  group('DoubleRatchet edge cases', () {
    test('empty plaintext encrypts and decrypts', () async {
      final (alice, bob) = await _createSession();

      final encrypted = await alice.encrypt([]);
      final decrypted = await bob.decrypt(encrypted);

      expect(decrypted, isEmpty);
    });

    test('large plaintext encrypts and decrypts', () async {
      final (alice, bob) = await _createSession();

      // 64 KB of data
      final largePlaintext = List<int>.generate(65536, (i) => i % 256);
      final encrypted = await alice.encrypt(largePlaintext);
      final decrypted = await bob.decrypt(encrypted);

      expect(decrypted, equals(largePlaintext));
    });

    test('out-of-order across DH ratchet boundary', () async {
      final (alice, bob) = await _createSession();

      // Alice sends two messages (same ratchet key)
      final enc1 = await alice.encrypt(utf8.encode('A1'));
      final enc2 = await alice.encrypt(utf8.encode('A2'));

      // Bob receives only enc1, then replies (triggers DH ratchet)
      await bob.decrypt(enc1);
      final encBob = await bob.encrypt(utf8.encode('B1'));
      await alice.decrypt(encBob);

      // Now Bob receives enc2 (from the old ratchet)
      final dec2 = await bob.decrypt(enc2);
      expect(utf8.decode(dec2), 'A2');
    });
  });
}
