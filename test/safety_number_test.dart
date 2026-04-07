import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/safety_number.dart';

void main() {
  // ── Deterministic output ───────────────────────────────────────────

  group('SafetyNumber deterministic output', () {
    test('same inputs produce same safety number', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final number1 = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      final number2 = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      expect(number1, equals(number2));
    });

    test('output is exactly 60 digits', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final number = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      expect(number.length, 60);
      expect(RegExp(r'^\d{60}$').hasMatch(number), isTrue);
    });
  });

  // ── Different keys produce different numbers ───────────────────────

  group('SafetyNumber different keys', () {
    test('different identity keys produce different safety numbers', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp1 = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp2 = await SignalKeyHelper.generateX25519KeyPair();

      final number1 = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp1.publicKey,
      );

      final number2 = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp2.publicKey,
      );

      expect(number1, isNot(equals(number2)));
    });

    test('different user IDs produce different safety numbers', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final number1 = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      final number2 = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'charlie',
        theirIdentityKey: bobKp.publicKey,
      );

      expect(number1, isNot(equals(number2)));
    });
  });

  // ── Commutativity ──────────────────────────────────────────────────

  group('SafetyNumber commutativity', () {
    test('A,B produces same number as B,A', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final numberFromAlice = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      final numberFromBob = SafetyNumber.generate(
        myUserId: 'bob',
        myIdentityKey: bobKp.publicKey,
        theirUserId: 'alice',
        theirIdentityKey: aliceKp.publicKey,
      );

      expect(numberFromAlice, equals(numberFromBob));
    });

    test('formatted version is also commutative', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final formatted1 = SafetyNumber.generateFormatted(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      final formatted2 = SafetyNumber.generateFormatted(
        myUserId: 'bob',
        myIdentityKey: bobKp.publicKey,
        theirUserId: 'alice',
        theirIdentityKey: aliceKp.publicKey,
      );

      expect(formatted1, equals(formatted2));
    });
  });

  // ── Formatted output ───────────────────────────────────────────────

  group('SafetyNumber formatted output', () {
    test('formatted output has 12 groups of 5 digits separated by spaces',
        () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final formatted = SafetyNumber.generateFormatted(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      final groups = formatted.split(' ');
      expect(groups.length, 12);
      for (final group in groups) {
        expect(group.length, 5);
        expect(RegExp(r'^\d{5}$').hasMatch(group), isTrue);
      }
    });
  });

  // ── QR payload ─────────────────────────────────────────────────────

  group('SafetyNumber QR payload', () {
    test('generateQrPayload has correct prefix', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final payload = SafetyNumber.generateQrPayload(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      expect(payload.startsWith('risaal-verify:v0:'), isTrue);
    });

    test('parseQrPayload round-trip', () async {
      final aliceKp = await SignalKeyHelper.generateX25519KeyPair();
      final bobKp = await SignalKeyHelper.generateX25519KeyPair();

      final payload = SafetyNumber.generateQrPayload(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );

      final parsed = SafetyNumber.parseQrPayload(payload);
      expect(parsed, isNotNull);
      expect(parsed!.length, 60);

      final expected = SafetyNumber.generate(
        myUserId: 'alice',
        myIdentityKey: aliceKp.publicKey,
        theirUserId: 'bob',
        theirIdentityKey: bobKp.publicKey,
      );
      expect(parsed, equals(expected));
    });

    test('parseQrPayload rejects invalid payloads', () {
      expect(SafetyNumber.parseQrPayload('invalid'), isNull);
      expect(SafetyNumber.parseQrPayload('risaal-verify:v0:short'), isNull);
      expect(SafetyNumber.parseQrPayload('risaal-verify:v0:${'a' * 60}'), isNull);
      expect(SafetyNumber.parseQrPayload('risaal-verify:v1:${'0' * 60}'), isNull);
    });
  });
}
