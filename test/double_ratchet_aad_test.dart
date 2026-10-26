import 'dart:convert';

import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';

/// PR-SEC-004 Slice A — AEAD header binding + versioned/migrated envelopes.
///
/// Exercises the new API surface (`EncryptedMessage.version`,
/// `encrypt(..., version:)`) and asserts that each canonical header field
/// (version, dhPublicKey, messageNumber N, previousChainLength PN) is bound
/// into the AES-GCM AAD so tampering it fails authentication.
Future<(DoubleRatchet alice, DoubleRatchet bob)> _createSession() async {
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
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

String _flipFirstByte(String b64) {
  final bytes = base64Decode(b64);
  bytes[0] ^= 0xFF;
  return base64Encode(bytes);
}

/// Rebuild an [EncryptedMessage] after mutating its wire JSON.
EncryptedMessage _tamper(
  EncryptedMessage m,
  void Function(Map<String, dynamic> j) mutate,
) {
  final j = m.toJson();
  mutate(j);
  return EncryptedMessage.fromJson(j);
}

void main() {
  group('versioning + round-trip', () {
    test('encrypt defaults to v2 and round-trips', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('hello v2'));
      expect(enc.version, 2);
      expect(enc.toJson()['version'], 2);
      final dec = await bob.decrypt(enc);
      expect(utf8.decode(dec), 'hello v2');
    });

    test('explicit v2 round-trips', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('explicit v2'), version: 2);
      expect(enc.version, 2);
      final dec = await bob.decrypt(enc);
      expect(utf8.decode(dec), 'explicit v2');
    });

    test('public encrypt rejects v1 before ratchet mutation', () async {
      final (alice, _) = await _createSession();
      final before = alice.toJson();
      await expectLater(
        alice.encrypt(utf8.encode('legacy v1'), version: 1),
        throwsA(isA<FormatException>()),
      );
      expect(alice.toJson(), before);
    });

    test('absent version parses as v1', () async {
      final (alice, _) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('x'));
      final json = enc.toJson()..remove('version');
      final parsed = EncryptedMessage.fromJson(json);
      expect(parsed.version, 1);
    });

    test('public decrypt rejects parsed v1 before ratchet mutation', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('x'));
      final parsed = EncryptedMessage.fromJson(enc.toJson()..remove('version'));
      final before = bob.toJson();
      await expectLater(bob.decrypt(parsed), throwsA(isA<FormatException>()));
      expect(bob.toJson(), before);
    });

    test('toJson/fromJson preserves version for v2', () async {
      final (alice, _) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('x'));
      final parsed = EncryptedMessage.fromJson(enc.toJson());
      expect(parsed.version, 2);
    });
  });

  group('AAD binds each canonical header field (v2)', () {
    test('tampering version (downgrade to v1) fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(enc, (j) => j['version'] = 1);
      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(isA<FormatException>()),
      );
    });

    test('stripping version (implicit downgrade) fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(enc, (j) => j.remove('version'));
      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(isA<FormatException>()),
      );
    });

    test('bumping version (forward tamper to v3) fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(enc, (j) => j['version'] = 3);
      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(isA<FormatException>()),
      );
    });

    test('tampering dhPublicKey fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(
        enc,
        (j) => j['dhPublicKey'] = _flipFirstByte(enc.dhPublicKey),
      );
      await expectLater(() => bob.decrypt(tampered), throwsA(anything));
    });

    test('tampering messageNumber (N) fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(enc, (j) => j['messageNumber'] = 3);
      await expectLater(() => bob.decrypt(tampered), throwsA(anything));
    });

    test('tampering previousChainLength (PN) fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(enc, (j) => j['previousChainLength'] = 9);
      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test('tampering ciphertext fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(
        enc,
        (j) => j['ciphertext'] = _flipFirstByte(enc.ciphertext),
      );
      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test('tampering nonce fails auth', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('m'));
      final tampered = _tamper(
        enc,
        (j) => j['nonce'] = _flipFirstByte(enc.nonce),
      );
      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test(
      'a genuine v2 message still decrypts after a tampered attempt',
      () async {
        final (alice, bob) = await _createSession();
        final enc = await alice.encrypt(utf8.encode('genuine'));
        final tampered = _tamper(enc, (j) => j['previousChainLength'] = 42);
        await expectLater(() => bob.decrypt(tampered), throwsA(anything));
        final dec = await bob.decrypt(enc);
        expect(utf8.decode(dec), 'genuine');
      },
    );
  });

  group('interop / offline with AAD bound (v2)', () {
    test('out-of-order delivery works with AAD bound', () async {
      final (alice, bob) = await _createSession();
      final enc1 = await alice.encrypt(utf8.encode('Message 1'));
      final enc2 = await alice.encrypt(utf8.encode('Message 2'));
      final enc3 = await alice.encrypt(utf8.encode('Message 3'));

      expect(utf8.decode(await bob.decrypt(enc3)), 'Message 3');
      expect(utf8.decode(await bob.decrypt(enc1)), 'Message 1');
      expect(utf8.decode(await bob.decrypt(enc2)), 'Message 2');
    });

    test('skipped-key delivery works with AAD bound', () async {
      final (alice, bob) = await _createSession();
      final enc1 = await alice.encrypt(utf8.encode('m1'));
      final enc2 = await alice.encrypt(utf8.encode('m2'));
      expect(utf8.decode(await bob.decrypt(enc2)), 'm2');
      expect(utf8.decode(await bob.decrypt(enc1)), 'm1');
    });

    test(
      'out-of-order across a DH ratchet boundary works with AAD bound',
      () async {
        final (alice, bob) = await _createSession();
        final enc1 = await alice.encrypt(utf8.encode('A1'));
        final enc2 = await alice.encrypt(utf8.encode('A2'));
        await bob.decrypt(enc1);
        final encBob = await bob.encrypt(utf8.encode('B1'));
        await alice.decrypt(encBob);
        final dec2 = await bob.decrypt(enc2);
        expect(utf8.decode(dec2), 'A2');
      },
    );

    test(
      'multi-round bidirectional conversation works with AAD bound',
      () async {
        final (alice, bob) = await _createSession();
        for (var round = 0; round < 4; round++) {
          final encAB = await alice.encrypt(utf8.encode('A->B $round'));
          expect(utf8.decode(await bob.decrypt(encAB)), 'A->B $round');
          final encBA = await bob.encrypt(utf8.encode('B->A $round'));
          expect(utf8.decode(await alice.decrypt(encBA)), 'B->A $round');
        }
      },
    );
  });
}
