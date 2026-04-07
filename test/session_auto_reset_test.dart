import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/fake_secure_storage.dart';

/// Build a [PreKeyBundle] from the map returned by [generateKeyBundle()].
PreKeyBundle _bundleFromMap(
  Map<String, dynamic> bundle, {
  required String userId,
  required String deviceId,
}) {
  final signedPreKey = bundle['signedPreKey'] as Map<String, dynamic>;
  final oneTimePreKeys = bundle['oneTimePreKeys'] as List<dynamic>;

  return PreKeyBundle(
    userId: userId,
    deviceId: deviceId,
    identityKey: bundle['identityKey'] as String,
    identitySigningKey: bundle['identitySigningKey'] as String,
    signedPreKey: SignedPreKeyPublic(
      keyId: signedPreKey['keyId'] as int,
      publicKey: signedPreKey['publicKey'] as String,
      signature: signedPreKey['signature'] as String,
    ),
    oneTimePreKey: oneTimePreKeys.isNotEmpty
        ? OneTimePreKeyPublic(
            keyId:
                (oneTimePreKeys.first as Map<String, dynamic>)['keyId'] as int,
            publicKey: (oneTimePreKeys.first
                as Map<String, dynamic>)['publicKey'] as String,
          )
        : null,
    kyberPreKey: bundle.containsKey('kyberPreKey')
        ? KyberPreKeyPublic(
            keyId:
                (bundle['kyberPreKey'] as Map<String, dynamic>)['keyId'] as int,
            publicKey: (bundle['kyberPreKey']
                as Map<String, dynamic>)['publicKey'] as String,
          )
        : null,
  );
}

/// Establish a full bidirectional session between Alice and Bob.
Future<
    ({
      SignalProtocolManager alice,
      FakeSecureStorage aliceStorage,
      SignalProtocolManager bob,
      FakeSecureStorage bobStorage,
    })> _createFullSession() async {
  final aliceStorage = FakeSecureStorage();
  final bobStorage = FakeSecureStorage();
  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);
  await alice.initialize();
  await bob.initialize();

  await aliceStorage.write(key: 'user_id', value: 'alice-id');
  await aliceStorage.write(key: 'device_id', value: 'alice-device');
  await bobStorage.write(key: 'user_id', value: 'bob-id');
  await bobStorage.write(key: 'device_id', value: 'bob-device');

  final bobBundle = await bob.generateKeyBundle();
  final bundle =
      _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-device');
  await alice.createSession(bundle);

  // Alice sends first message (prekey) to establish Bob's side
  final preKeyEnvelope =
      await alice.encryptMessage('bob-id', 'bob-device', 'session-init');
  await bob.decryptMessage('alice-id', 'alice-device', preKeyEnvelope);

  return (
    alice: alice,
    aliceStorage: aliceStorage,
    bob: bob,
    bobStorage: bobStorage,
  );
}

void main() {
  // ── SessionResetError model tests ────────────────────────────────────

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

  // ── SessionUnstableError model tests ─────────────────────────────────

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

  // ── Identity key persistence across session reset ────────────────────

  group('Identity key persistence across session reset', () {
    test(
        'identity key stored for peer does NOT change after session auto-reset',
        () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Verify baseline: a normal message works
      final envelope1 =
          await alice.encryptMessage('bob-id', 'bob-device', 'before reset');
      final plain1 =
          await bob.decryptMessage('alice-id', 'alice-device', envelope1);
      expect(plain1, equals('before reset'));

      // Record the identity key Bob stored for Alice BEFORE reset
      final identityKeyBefore =
          await bob.getSessionIdentityKey('alice-id', 'alice-device');
      expect(identityKeyBefore, isNotNull);

      // Produce a corrupted envelope that will cause SecretBoxAuthenticationError
      // on Bob's side. This simulates message corruption / desync.
      final envelope2 =
          await alice.encryptMessage('bob-id', 'bob-device', 'to be corrupted');
      final messageMap = envelope2['message'] as Map<String, dynamic>;
      final ciphertextB64 = messageMap['ciphertext'] as String;
      final ciphertextBytes = base64Decode(ciphertextB64);
      // Flip a byte in the ciphertext to break the GCM MAC
      ciphertextBytes[0] ^= 0xFF;
      messageMap['ciphertext'] = base64Encode(ciphertextBytes);

      // Attempt decryption -- should trigger auto-reset and throw SessionResetError
      try {
        await bob.decryptMessage('alice-id', 'alice-device', envelope2);
        fail('Expected SessionResetError to be thrown');
      } on SessionResetError {
        // Expected: session was auto-reset
      }

      // After auto-reset, the session is deleted on Bob's side.
      // But the identity key from the ORIGINAL session should still be
      // accessible via getSessionIdentityKey -- OR if it was cleared as
      // part of removeSession, at least verify the principle:
      // The identity key must not silently change to a different value.

      // Now re-establish a session (Alice sends a fresh PreKey message)
      final aliceBundle = await alice.generateKeyBundle();
      final alicePreKeyBundle = _bundleFromMap(
        aliceBundle,
        userId: 'alice-id',
        deviceId: 'alice-device',
      );
      await bob.createSession(alicePreKeyBundle);

      // After re-establishing, verify the stored identity key matches Alice's
      // ACTUAL current identity key
      final aliceActualKey = await alice.getIdentityPublicKey();
      final identityKeyAfter =
          await bob.getSessionIdentityKey('alice-id', 'alice-device');
      expect(identityKeyAfter, isNotNull);
      expect(identityKeyAfter, equals(aliceActualKey));

      // The key must be the same as before the reset (Alice didn't change identity)
      expect(identityKeyAfter, equals(identityKeyBefore));
    });

    test(
        'identity key stored on initiator side persists across session re-establishment',
        () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Record Alice's stored identity key for Bob
      final identityKeyBefore =
          await alice.getSessionIdentityKey('bob-id', 'bob-device');
      expect(identityKeyBefore, isNotNull);

      // Remove and re-establish session
      await alice.removeSession('bob-id', 'bob-device');
      expect(await alice.hasSession('bob-id', 'bob-device'), isFalse);

      // Re-create session from Bob's bundle
      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-device');
      await alice.createSession(bundle);

      // Bob's identity key should be the same as before
      final identityKeyAfter =
          await alice.getSessionIdentityKey('bob-id', 'bob-device');
      expect(identityKeyAfter, isNotNull);

      // Bob's identity key is unchanged (no re-install happened)
      final bobActualKey = await bob.getIdentityPublicKey();
      expect(identityKeyAfter, equals(bobActualKey));
      expect(identityKeyAfter, equals(identityKeyBefore));
    });

    test(
        'corrupted message triggers auto-reset without changing stored identity key',
        () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Get identity key Alice stored for Bob before any corruption
      final storedKeyBefore =
          await alice.getSessionIdentityKey('bob-id', 'bob-device');
      expect(storedKeyBefore, isNotNull);

      // Bob sends a message, then we corrupt it before Alice decrypts
      final envelope =
          await bob.encryptMessage('alice-id', 'alice-device', 'corrupted msg');
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[ct.length ~/ 2] ^= 0xFF; // flip a middle byte
      msgMap['ciphertext'] = base64Encode(ct);

      try {
        await alice.decryptMessage('bob-id', 'bob-device', envelope);
        fail('Expected SessionResetError');
      } on SessionResetError {
        // Expected
      }

      // Re-establish session from Bob's bundle
      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-device');
      await alice.createSession(bundle);

      final storedKeyAfter =
          await alice.getSessionIdentityKey('bob-id', 'bob-device');
      // Identity key must match Bob's actual key (unchanged)
      expect(storedKeyAfter, equals(storedKeyBefore));
    });
  });

  // ── Auto-reset rate limiting ─────────────────────────────────────────

  group('Auto-reset rate limiting', () {
    test(
        'after 3 resets within window, 4th throws SessionUnstableError instead of resetting',
        () async {
      final bobStorage = FakeSecureStorage();
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await bob.initialize();
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');

      // Pre-seed 3 recent reset timestamps (within the 1-hour window)
      final now = DateTime.now().millisecondsSinceEpoch;
      final cryptoStorage = CryptoStorage(secureStorage: bobStorage);
      await cryptoStorage.saveResetTimestamps(
        'alice-id',
        'alice-device',
        [
          now - 1000, // 1 second ago
          now - 2000, // 2 seconds ago
          now - 3000, // 3 seconds ago
        ],
      );

      // Create a session so we have something to corrupt
      final aliceStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      await alice.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await aliceStorage.write(key: 'device_id', value: 'alice-device');

      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-device');
      await alice.createSession(bundle);

      // Establish Bob's side
      final initEnvelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'init');
      await bob.decryptMessage('alice-id', 'alice-device', initEnvelope);

      // Now send a corrupted message to trigger a 4th reset attempt
      final envelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'corrupt me');
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[0] ^= 0xFF;
      msgMap['ciphertext'] = base64Encode(ct);

      // The 4th attempt should throw SessionUnstableError, not SessionResetError
      expect(
        () => bob.decryptMessage('alice-id', 'alice-device', envelope),
        throwsA(isA<SessionUnstableError>()),
      );
    });

    test('resets outside the 1-hour window do not count toward rate limit',
        () async {
      final bobStorage = FakeSecureStorage();
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await bob.initialize();
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');

      // Pre-seed old reset timestamps (outside the 1-hour window but within 24h cooldown)
      // The rate limiter checks if recent resets >= 3 within the window.
      // Old resets outside the window but within cooldown period still require cooldown check.
      // Place them > 24 hours ago so the cooldown has expired and they get cleared.
      final now = DateTime.now().millisecondsSinceEpoch;
      final cryptoStorage = CryptoStorage(secureStorage: bobStorage);
      await cryptoStorage.saveResetTimestamps(
        'alice-id',
        'alice-device',
        [
          now - (25 * 60 * 60 * 1000), // 25 hours ago (outside cooldown)
          now - (26 * 60 * 60 * 1000), // 26 hours ago
          now - (27 * 60 * 60 * 1000), // 27 hours ago
        ],
      );

      // Create session
      final aliceStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      await alice.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await aliceStorage.write(key: 'device_id', value: 'alice-device');

      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-device');
      await alice.createSession(bundle);

      // Establish Bob's side
      final initEnvelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'init');
      await bob.decryptMessage('alice-id', 'alice-device', initEnvelope);

      // Corrupt message -- should trigger SessionResetError (NOT unstable)
      // because old timestamps are outside cooldown and get cleared
      final envelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'corrupt me');
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[0] ^= 0xFF;
      msgMap['ciphertext'] = base64Encode(ct);

      expect(
        () => bob.decryptMessage('alice-id', 'alice-device', envelope),
        throwsA(isA<SessionResetError>()),
      );
    });

    test('reset timestamps are stored and accumulate correctly', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      // Initially empty
      var timestamps =
          await cryptoStorage.loadResetTimestamps('user-a', 'device-a');
      expect(timestamps, isEmpty);

      // Save some timestamps
      final now = DateTime.now().millisecondsSinceEpoch;
      await cryptoStorage.saveResetTimestamps(
        'user-a',
        'device-a',
        [now - 3000, now - 2000, now - 1000],
      );

      timestamps =
          await cryptoStorage.loadResetTimestamps('user-a', 'device-a');
      expect(timestamps.length, equals(3));

      // Clear them
      await cryptoStorage.clearResetTimestamps('user-a', 'device-a');
      timestamps =
          await cryptoStorage.loadResetTimestamps('user-a', 'device-a');
      expect(timestamps, isEmpty);
    });

    test('reset timestamps are trimmed to last 10 entries', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      // Save 15 timestamps -- should be trimmed to 10
      final now = DateTime.now().millisecondsSinceEpoch;
      final timestamps = List.generate(15, (i) => now - (15 - i) * 1000);
      await cryptoStorage.saveResetTimestamps('user-a', 'device-a', timestamps);

      final loaded =
          await cryptoStorage.loadResetTimestamps('user-a', 'device-a');
      expect(loaded.length, equals(10));
      // Should have the LAST 10 (most recent)
      expect(loaded.first, equals(timestamps[5]));
      expect(loaded.last, equals(timestamps[14]));
    });
  });

  // ── Session state cleanup after reset ────────────────────────────────

  group('Session state cleanup after reset', () {
    test('after auto-reset, old session is fully removed', () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Verify session exists
      expect(await bob.hasSession('alice-id', 'alice-device'), isTrue);

      // Corrupt a message to trigger auto-reset
      final envelope = await alice.encryptMessage(
          'bob-id', 'bob-device', 'will be corrupted');
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[0] ^= 0xFF;
      msgMap['ciphertext'] = base64Encode(ct);

      try {
        await bob.decryptMessage('alice-id', 'alice-device', envelope);
        fail('Expected SessionResetError');
      } on SessionResetError {
        // Expected
      }

      // After auto-reset, the session should be gone
      expect(await bob.hasSession('alice-id', 'alice-device'), isFalse);
    });

    test(
        'after session reset, a new session from fresh PreKey bundle works correctly',
        () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Trigger a reset by corrupting a message
      final envelope = await alice.encryptMessage(
          'bob-id', 'bob-device', 'will be corrupted');
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[0] ^= 0xFF;
      msgMap['ciphertext'] = base64Encode(ct);

      try {
        await bob.decryptMessage('alice-id', 'alice-device', envelope);
      } on SessionResetError {
        // Expected
      }

      // Session is gone on Bob's side
      expect(await bob.hasSession('alice-id', 'alice-device'), isFalse);

      // Alice also removes her stale session and creates a fresh one
      await alice.removeSession('bob-id', 'bob-device');
      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-device');
      await alice.createSession(bundle);

      // Send a fresh PreKey message
      final freshEnvelope = await alice.encryptMessage(
          'bob-id', 'bob-device', 'hello after reset');
      expect(freshEnvelope['type'], equals('prekey'));

      // Bob decrypts the fresh PreKey message -- establishes new session
      final plaintext =
          await bob.decryptMessage('alice-id', 'alice-device', freshEnvelope);
      expect(plaintext, equals('hello after reset'));

      // Both sides should now have valid sessions
      expect(await alice.hasSession('bob-id', 'bob-device'), isTrue);
      expect(await bob.hasSession('alice-id', 'alice-device'), isTrue);

      // Verify bidirectional messaging works on the new session
      final e1 =
          await bob.encryptMessage('alice-id', 'alice-device', 'Bob reply');
      final p1 = await alice.decryptMessage('bob-id', 'bob-device', e1);
      expect(p1, equals('Bob reply'));

      final e2 = await alice.encryptMessage(
          'bob-id', 'bob-device', 'Alice follows up');
      final p2 = await bob.decryptMessage('alice-id', 'alice-device', e2);
      expect(p2, equals('Alice follows up'));
    });

    test(
        'removeSession clears in-memory cache, storage session, identity key, and pending prekey',
        () async {
      final session = await _createFullSession();
      final alice = session.alice;

      // Everything exists before removal
      expect(await alice.hasSession('bob-id', 'bob-device'), isTrue);
      expect(
        await alice.getSessionIdentityKey('bob-id', 'bob-device'),
        isNotNull,
      );

      // Remove session
      await alice.removeSession('bob-id', 'bob-device');

      // Everything cleared after removal
      expect(await alice.hasSession('bob-id', 'bob-device'), isFalse);
      expect(
        await alice.getSessionIdentityKey('bob-id', 'bob-device'),
        isNull,
      );
    });
  });

  // ── Pre-key replenishment callback on reset ──────────────────────────

  group('Pre-key replenishment callback', () {
    test('onPreKeyReplenishmentNeeded fires when session auto-resets',
        () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      var callbackFired = false;
      bob.onPreKeyReplenishmentNeeded = () {
        callbackFired = true;
      };

      // Corrupt a message to trigger auto-reset
      final envelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'trigger reset');
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[0] ^= 0xFF;
      msgMap['ciphertext'] = base64Encode(ct);

      try {
        await bob.decryptMessage('alice-id', 'alice-device', envelope);
      } on SessionResetError {
        // Expected
      }

      expect(callbackFired, isTrue);
    });
  });
}
