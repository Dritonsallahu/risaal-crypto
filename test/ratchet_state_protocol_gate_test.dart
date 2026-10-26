@Retry(0)
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/ratchet_batch_decrypt.dart';

Future<(DoubleRatchet alice, DoubleRatchet bob)> _session() async {
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
  final shared = List<int>.generate(32, (index) => index + 1);
  return (
    await DoubleRatchet.initSender(
      sharedSecret: shared,
      recipientPublicKey: bobPreKey.publicKey,
    ),
    await DoubleRatchet.initReceiver(
      sharedSecret: shared,
      dhKeyPair: bobPreKey,
    ),
  );
}

void main() {
  test('ratchet state round-trip carries the exact epoch-2 schema', () async {
    final (_, bob) = await _session();
    final json = bob.toJson();

    expect(json['v'], 2);
    expect(
      json['cryptoProtocolEpoch'],
      RisaalCryptoProtocol.cryptoProtocolEpoch,
    );
    expect(DoubleRatchet.fromJson(json).toJson(), json);
  });

  test('missing, legacy, and future state markers reject before use', () async {
    final (_, bob) = await _session();
    final current = bob.toJson();

    for (final state in <Map<String, dynamic>>[
      Map<String, dynamic>.of(current)..remove('cryptoProtocolEpoch'),
      <String, dynamic>{...current, 'cryptoProtocolEpoch': 1},
      <String, dynamic>{...current, 'cryptoProtocolEpoch': 3},
      Map<String, dynamic>.of(current)..remove('v'),
      <String, dynamic>{...current, 'v': 1},
      <String, dynamic>{...current, 'v': 3},
    ]) {
      expect(
        () => DoubleRatchet.fromJson(state),
        throwsA(isA<FormatException>()),
      );
    }
  });

  test(
    'legacy raw DH state is rejected even with forged current markers',
    () async {
      final (_, bob) = await _session();
      final legacy = Map<String, dynamic>.of(bob.toJson())
        ..['dhSendingKeyPair'] = '{"publicKey":"legacy"}';

      expect(
        () => DoubleRatchet.fromJson(legacy),
        throwsA(isA<FormatException>()),
      );
    },
  );

  test('empty batch still rejects a legacy session state', () async {
    final (_, bob) = await _session();
    final legacy = Map<String, dynamic>.of(bob.toJson())
      ..remove('cryptoProtocolEpoch');

    await expectLater(
      ratchetBatchDecrypt(
        RatchetBatchRequest(stateJson: legacy, messages: const []),
      ),
      throwsA(isA<FormatException>()),
    );
  });
}
