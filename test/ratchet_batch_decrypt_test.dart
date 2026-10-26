import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/message_padding.dart';
import 'package:risaal_crypto/src/ratchet_batch_decrypt.dart';

/// Audit 2026-06 performance: off-main-thread batch decrypt of a session
/// backlog. The engine must (a) decrypt a backlog correctly and leave the
/// ratchet state EXACTLY where an inline decrypt would, and (b) on a bad
/// message, stop and return the state after the LAST SUCCESS (decrypt() mutates
/// before it can throw, so the half-mutated state must never escape).

Future<(DoubleRatchet alice, DoubleRatchet bob)> _session() async {
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
  final shared = List<int>.generate(32, (i) => i + 7);
  final alice = await DoubleRatchet.initSender(
    sharedSecret: shared,
    recipientPublicKey: bobPreKey.publicKey,
  );
  final bob = await DoubleRatchet.initReceiver(
    sharedSecret: shared,
    dhKeyPair: bobPreKey,
  );
  return (alice, bob);
}

void main() {
  test(
    'decrypts a backlog correctly and advances state like an inline decrypt',
    () async {
      final (alice, bob) = await _session();

      final texts = ['one', 'two', 'three', 'four', 'five'];
      final wire = <Map<String, dynamic>>[];
      for (final t in texts) {
        final enc = await alice.encrypt(MessagePadding.padString(t));
        wire.add(enc.toJson());
      }

      final result = await ratchetBatchDecrypt(
        RatchetBatchRequest(stateJson: bob.toJson(), messages: wire),
      );

      expect(result.hadFailure, isFalse);
      expect(result.plaintexts, texts);

      // State continuity: a ratchet rebuilt from finalState must decrypt the NEXT
      // message — proving the batch left state exactly where it should.
      final bobAfter = DoubleRatchet.fromJson(result.finalStateJson);
      final next = await alice.encrypt(MessagePadding.padString('six'));
      final six = await bobAfter.decrypt(next);
      expect(MessagePadding.unpadString(six), 'six');
    },
  );

  test(
    'stops at the first bad message and returns the last-good state',
    () async {
      final (alice, bob) = await _session();

      final m0 = await alice.encrypt(MessagePadding.padString('m0'));
      final m1 = await alice.encrypt(MessagePadding.padString('m1'));
      final m2 = await alice.encrypt(MessagePadding.padString('m2'));

      // Corrupt m1's ciphertext so its MAC check throws.
      final badM1 = Map<String, dynamic>.of(m1.toJson());
      final ct = base64Decode(badM1['ciphertext'] as String);
      ct[0] ^= 0xFF;
      badM1['ciphertext'] = base64Encode(ct);

      final result = await ratchetBatchDecrypt(
        RatchetBatchRequest(
          stateJson: bob.toJson(),
          messages: [m0.toJson(), badM1, m2.toJson()],
        ),
      );

      expect(result.hadFailure, isTrue);
      expect(result.failedIndex, 1);
      expect(result.plaintexts, ['m0']);
      expect(result.failedError, isNotNull);

      // The returned state must be EXACTLY after m0 (not the half-mutated state of
      // the failed m1) — so a fresh ratchet can decrypt the REAL m1 inline.
      final bobResume = DoubleRatchet.fromJson(result.finalStateJson);
      final realM1 = await bobResume.decrypt(m1);
      expect(MessagePadding.unpadString(realM1), 'm1');
    },
  );

  test(
    'failure on the very first message returns the untouched session state',
    () async {
      final (alice, bob) = await _session();
      final m0 = await alice.encrypt(MessagePadding.padString('hello'));
      final bad = Map<String, dynamic>.of(m0.toJson());
      final ct = base64Decode(bad['ciphertext'] as String);
      ct[0] ^= 0xFF;
      bad['ciphertext'] = base64Encode(ct);

      final before = bob.toJson();
      final result = await ratchetBatchDecrypt(
        RatchetBatchRequest(stateJson: before, messages: [bad]),
      );

      expect(result.failedIndex, 0);
      expect(result.plaintexts, isEmpty);
      expect(
        result.finalStateJson,
        before,
        reason: 'first-message failure must leave the session untouched',
      );
    },
  );

  test('empty backlog is a no-op', () async {
    final (_, bob) = await _session();
    final before = bob.toJson();
    final result = await ratchetBatchDecrypt(
      RatchetBatchRequest(stateJson: before, messages: const []),
    );
    expect(result.hadFailure, isFalse);
    expect(result.plaintexts, isEmpty);
    expect(result.finalStateJson, before);
  });

  test(
    'preflights every wire version before decrypting any plaintext',
    () async {
      final (alice, bob) = await _session();
      final current = await alice.encrypt(MessagePadding.padString('current'));
      final legacy = (await alice.encrypt(
        MessagePadding.padString('legacy'),
      )).toJson()..remove('version');
      final before = bob.toJson();

      await expectLater(
        ratchetBatchDecrypt(
          RatchetBatchRequest(
            stateJson: before,
            messages: [current.toJson(), legacy],
          ),
        ),
        throwsA(isA<FormatException>()),
      );
      expect(bob.toJson(), before);
    },
  );
}
