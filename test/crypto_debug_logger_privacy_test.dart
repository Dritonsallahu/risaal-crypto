import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_debug_logger.dart';

import 'helpers/crypto_test_fixtures.dart';

class _SecretBearingError implements Exception {
  const _SecretBearingError(this.secret);

  final String secret;

  @override
  String toString() => 'decrypt failed for plaintext=$secret';
}

class _ThrowingStringError implements Exception {
  @override
  String toString() => throw StateError('diagnostics stringified an error');
}

void main() {
  tearDown(() => CryptoDebugLogger.sink = null);

  test('generic log never reaches runtime sink', () {
    const secret = 'violet-synthetic-message-42';
    final received = <String>[];
    CryptoDebugLogger.sink = (tag, event) => received.add('$tag|$event');

    CryptoDebugLogger.log(
      'SYNTHETIC_SECRET_TAG_72',
      'Decrypted: "$secret\nsecond synthetic line"',
    );

    expect(received, isEmpty);
  });

  test(
    'generic error log never reaches runtime sink or stringifies errors',
    () {
      const secret = 'synthetic-error-secret-93';
      final received = <String>[];
      CryptoDebugLogger.sink = (tag, event) => received.add('$tag|$event');

      CryptoDebugLogger.logError(
        'SYNTHETIC_SECRET_TAG_73',
        'Incoming message failed',
        const _SecretBearingError(secret),
      );

      expect(received, isEmpty);
    },
  );

  test('debug helpers never stringify errors, keys, or session values', () {
    expect(
      () => CryptoDebugLogger.logError(
        'DECRYPT_MSG',
        'decrypt failed',
        _ThrowingStringError(),
      ),
      returnsNormally,
    );
    expect(
      () => CryptoDebugLogger.logKeyInfo('X3DH', 'key', 'not-base64'),
      returnsNormally,
    );
    expect(
      () => CryptoDebugLogger.logSessionInfo('SESSION', 'state', {
        'danger': _ThrowingStringError(),
      }),
      returnsNormally,
    );
  });

  test(
    'debug logger source contains no key previews or dynamic console text',
    () {
      final source = File(
        'lib/src/crypto_debug_logger.dart',
      ).readAsStringSync();

      expect(source, isNot(contains('first4=')));
      expect(source, isNot(contains(r'dhRecvKey=$dhPreview')));
      expect(source, isNot(contains(r'— $error')));
      expect(source, isNot(contains(r'entry.value')));
    },
  );

  test('successful decrypt source never interpolates plaintext into logs', () {
    final source = File(
      'lib/src/signal_protocol_manager.dart',
    ).readAsStringSync();

    expect(source, isNot(contains(r'''Decrypted: "$result"''')));
    expect(
      source,
      contains(
        'CryptoDebugLogger.event(CryptoDiagnosticEvent.decryptSucceeded)',
      ),
    );
  });

  test('real inline decrypt emits only its fixed event code', () async {
    const secret = 'synthetic-real-decrypt-secret-94';
    final pair = await CryptoTestFixtures.createPairedManagers();

    final initial = await pair.alice.encryptMessage(
      'bob-id',
      'bob-device',
      'initial',
    );
    await pair.bob.decryptMessage('alice-id', 'alice-device', initial);
    final reply = await pair.bob.encryptMessage(
      'alice-id',
      'alice-device',
      'reply',
    );
    await pair.alice.decryptMessage('bob-id', 'bob-device', reply);

    final received = <String>[];
    CryptoDebugLogger.sink = (tag, event) => received.add('$tag|$event');
    final envelope = await pair.alice.encryptMessage(
      'bob-id',
      'bob-device',
      secret,
    );
    final plaintext = await pair.bob.decryptMessage(
      'alice-id',
      'alice-device',
      envelope,
    );

    expect(plaintext, secret);
    expect(received.join('\n'), isNot(contains(secret)));
    expect(received, contains('DECRYPT_MSG|decrypt_succeeded'));
  });

  test('a throwing diagnostic sink cannot fail a successful decrypt', () async {
    const secret = 'synthetic-sink-failure-plaintext-95';
    final pair = await CryptoTestFixtures.createPairedManagers();

    final initial = await pair.alice.encryptMessage(
      'bob-id',
      'bob-device',
      'initial',
    );
    await pair.bob.decryptMessage('alice-id', 'alice-device', initial);
    final reply = await pair.bob.encryptMessage(
      'alice-id',
      'alice-device',
      'reply',
    );
    await pair.alice.decryptMessage('bob-id', 'bob-device', reply);

    CryptoDebugLogger.sink = (_, __) => throw StateError('sink failed');
    final envelope = await pair.alice.encryptMessage(
      'bob-id',
      'bob-device',
      secret,
    );
    final plaintext = await pair.bob.decryptMessage(
      'alice-id',
      'alice-device',
      envelope,
    );

    expect(plaintext, secret);
  });
}
