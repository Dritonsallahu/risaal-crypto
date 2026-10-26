import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';

/// Slice-A gap-reproduction + regression tests for PR-SEC-004.
///
/// These tests use ONLY the pre-existing public API (JSON envelope
/// manipulation + [DoubleRatchet.state]) so they COMPILE and RUN against the
/// unmodified `double_ratchet.dart`. On the unmodified code they FAIL, proving
/// two concrete gaps:
///   1. The canonical header (previousChainLength) is NOT bound into the AEAD,
///      so tampering it is undetected (integrity gap).
///   2. `decrypt()` mutates ratchet state (chain advance + skipped-key
///      removal) BEFORE AEAD authentication, so a tampered message corrupts /
///      desynchronises the session (non-transactional gap).
/// After Slice A they PASS.
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

/// Flip the first byte of a base64 blob (tamper the underlying bytes).
String _flipFirstByte(String b64) {
  final bytes = base64Decode(b64);
  bytes[0] ^= 0xFF;
  return base64Encode(bytes);
}

/// Canonical byte-image of a ratchet's persisted state, for byte-identity
/// comparison across a failed decrypt.
String _snapshot(DoubleRatchet r) => jsonEncode(r.state.toJson());

void main() {
  group('PR-SEC-004 Slice A — envelope versioning', () {
    test('encrypt() emits a versioned (v2) envelope by default', () async {
      final (alice, _) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('hi'));
      final json = enc.toJson();
      expect(
        json.containsKey('version'),
        isTrue,
        reason: 'v2 envelope must carry an explicit version field',
      );
      expect(json['version'], 2);
    });
  });

  group('PR-SEC-004 Slice A — canonical header bound into AEAD AAD', () {
    test('tampering previousChainLength (PN) is detected and throws', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('hi'));

      // Tamper PN on the wire. On the first message this field does NOT affect
      // key derivation (no old chain to skip), so WITHOUT AAD binding it is a
      // silent no-op — the message still decrypts. WITH AAD binding, the
      // reconstructed AAD differs and AES-GCM authentication fails.
      final j = enc.toJson();
      j['previousChainLength'] = 7;
      final tampered = EncryptedMessage.fromJson(j);

      await expectLater(
        () => bob.decrypt(tampered),
        throwsA(anything),
        reason: 'PN tamper must fail AEAD auth once bound into AAD',
      );
    });
  });

  group('PR-SEC-004 Slice A — transactional decrypt (no state mutation on '
      'failure)', () {
    test('tampered ciphertext leaves ratchet state byte-identical, and a '
        'subsequent valid message still decrypts', () async {
      final (alice, bob) = await _createSession();
      final enc = await alice.encrypt(utf8.encode('hi'));

      final before = _snapshot(bob);

      final j = enc.toJson();
      j['ciphertext'] = _flipFirstByte(enc.ciphertext);
      final tampered = EncryptedMessage.fromJson(j);

      await expectLater(() => bob.decrypt(tampered), throwsA(anything));

      final after = _snapshot(bob);
      expect(
        after,
        before,
        reason: 'a failed decrypt must not mutate ratchet state',
      );

      // The failed attempt must not have half-advanced the chain: the original
      // valid message must still decrypt.
      final dec = await bob.decrypt(enc);
      expect(utf8.decode(dec), 'hi');
    });

    test('tampered out-of-order message preserves the stored skipped key, so '
        'the genuine message still decrypts', () async {
      final (alice, bob) = await _createSession();
      final enc1 = await alice.encrypt(utf8.encode('m1'));
      final enc2 = await alice.encrypt(utf8.encode('m2'));

      // Bob decrypts m2 first -> m1's key is stored as a skipped key.
      final dec2 = await bob.decrypt(enc2);
      expect(utf8.decode(dec2), 'm2');

      final before = _snapshot(bob);

      // Tamper m1's ciphertext and attempt decrypt.
      final j = enc1.toJson();
      j['ciphertext'] = _flipFirstByte(enc1.ciphertext);
      final tamperedM1 = EncryptedMessage.fromJson(j);

      await expectLater(() => bob.decrypt(tamperedM1), throwsA(anything));

      final after = _snapshot(bob);
      expect(
        after,
        before,
        reason:
            'a failed out-of-order decrypt must not consume the '
            'stored skipped key',
      );

      // The genuine m1 must still decrypt using the preserved skipped key.
      final dec1 = await bob.decrypt(enc1);
      expect(utf8.decode(dec1), 'm1');
    });
  });
}
