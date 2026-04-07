import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';

void main() {
  group('SessionResetError', () {
    test('toString includes sender info and original error', () {
      const error = SessionResetError(
        senderId: 'user123',
        senderDeviceId: 'device456',
        originalError: 'SecretBoxAuthenticationError: GCM MAC failure',
      );

      expect(error.toString(), contains('user123'));
      expect(error.toString(), contains('device456'));
      expect(error.toString(), contains('SecretBoxAuthenticationError'));
    });

    test('implements Exception', () {
      const error = SessionResetError(
        senderId: 'u',
        senderDeviceId: 'd',
        originalError: 'test',
      );
      expect(error, isA<Exception>());
    });
  });

  group('SessionUnstableError', () {
    test('toString includes sender info and reset count', () {
      const error = SessionUnstableError(
        senderId: 'user123',
        senderDeviceId: 'device456',
        resetCount: 4,
      );

      expect(error.toString(), contains('user123'));
      expect(error.toString(), contains('device456'));
      expect(error.toString(), contains('4'));
      expect(error.toString(), contains('unstable'));
    });

    test('implements Exception', () {
      const error = SessionUnstableError(
        senderId: 'u',
        senderDeviceId: 'd',
        resetCount: 3,
      );
      expect(error, isA<Exception>());
    });
  });
}
