@Retry(0)
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/session_state.dart';

/// R4-L2: skipped message keys carry an age and expire after the relay's
/// 30-day retention window, so an out-of-order key whose message never
/// arrives does not stay in session storage forever.
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

/// Alice sends m0..m3; Bob receives only m3 at [t0], skipping m0..m2.
Future<(DoubleRatchet bob, List<EncryptedMessage> msgs)> _skippedAt(
  DateTime t0,
) async {
  final (alice, bob) = await _session();
  final msgs = <EncryptedMessage>[
    for (var i = 0; i < 4; i++) await alice.encrypt(utf8.encode('m$i')),
  ];
  bob.clock = () => t0;
  expect(utf8.decode(await bob.decrypt(msgs[3])), 'm3');
  expect(bob.state.skippedKeys.length, 3);
  return (bob, msgs);
}

void main() {
  final t0 = DateTime.utc(2026, 1, 1);

  test('skipped keys are stamped with the store time', () async {
    final (bob, _) = await _skippedAt(t0);
    expect(
      bob.state.skippedKeyAges.keys.toSet(),
      bob.state.skippedKeys.keys.toSet(),
    );
    for (final age in bob.state.skippedKeyAges.values) {
      expect(age, t0.millisecondsSinceEpoch);
    }
  });

  test('a skipped key is still usable at t0 + 29 days and its age is '
      'removed on consume', () async {
    final (bob, msgs) = await _skippedAt(t0);
    bob.clock = () => t0.add(const Duration(days: 29));
    expect(utf8.decode(await bob.decrypt(msgs[1])), 'm1');
    final consumed = '${msgs[1].dhPublicKey}:1';
    expect(bob.state.skippedKeys.containsKey(consumed), isFalse);
    expect(bob.state.skippedKeyAges.containsKey(consumed), isFalse);
    expect(bob.state.skippedKeys.length, 2);
    expect(bob.state.skippedKeyAges.length, 2);
  });

  test('at t0 + 31 days the keys are purged, zeroed, and the late message '
      'no longer decrypts', () async {
    final (bob, msgs) = await _skippedAt(t0);
    final held = <Uint8List>[...bob.state.skippedKeys.values];
    expect(held.every((k) => k.any((b) => b != 0)), isTrue);

    bob.clock = () => t0.add(const Duration(days: 31));
    await expectLater(bob.decrypt(msgs[0]), throwsA(anything));

    expect(bob.state.skippedKeys, isEmpty);
    expect(bob.state.skippedKeyAges, isEmpty);
    for (final k in held) {
      expect(k.every((b) => b == 0), isTrue);
    }
  });

  test('toJson -> fromJson keeps the ages', () async {
    final (bob, _) = await _skippedAt(t0);
    final restored = RatchetState.fromJson(bob.state.toJson());
    expect(restored.skippedKeyAges, bob.state.skippedKeyAges);
    expect(
      restored.skippedKeys.keys.toSet(),
      bob.state.skippedKeys.keys.toSet(),
    );
  });

  test('legacy JSON without skippedKeyAges loads every key stamped at load '
      'time, none dropped', () async {
    final (bob, _) = await _skippedAt(t0);
    final json = bob.state.toJson()..remove('skippedKeyAges');
    final before = DateTime.now().millisecondsSinceEpoch;
    final restored = RatchetState.fromJson(json);
    final after = DateTime.now().millisecondsSinceEpoch;
    expect(restored.skippedKeys.length, 3);
    expect(
      restored.skippedKeyAges.keys.toSet(),
      restored.skippedKeys.keys.toSet(),
    );
    for (final age in restored.skippedKeyAges.values) {
      expect(age, inInclusiveRange(before, after));
    }
  });

  test('wipe zeroes keys and clears ages', () async {
    final (bob, _) = await _skippedAt(t0);
    bob.state.wipe();
    expect(bob.state.skippedKeys, isEmpty);
    expect(bob.state.skippedKeyAges, isEmpty);
  });

  test('the 2000 skipped-key cap still throws', () async {
    final (alice, bob) = await _session();
    final m = await alice.encrypt(utf8.encode('x'));
    final forged = EncryptedMessage.fromJson(
      m.toJson()..['messageNumber'] = 2500,
    );
    await expectLater(
      bob.decrypt(forged),
      throwsA(
        predicate(
          (e) => e.toString().contains('Too many skipped message keys'),
        ),
      ),
    );
  });
}
