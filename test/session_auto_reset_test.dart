import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

PreKeyBundle _withoutKyber(PreKeyBundle bundle) {
  return PreKeyBundle(
    opkRoute: bundle.opkRoute,
    userId: bundle.userId,
    deviceId: bundle.deviceId,
    identityKey: bundle.identityKey,
    identitySigningKey: bundle.identitySigningKey,
    signedPreKey: bundle.signedPreKey,
    oneTimePreKey: bundle.oneTimePreKey,
    kyberPreKey: null,
  );
}

/// Establish a full bidirectional session between Alice and Bob.
Future<
  ({
    SignalProtocolManager alice,
    FakeSecureStorage aliceStorage,
    SignalProtocolManager bob,
    FakeSecureStorage bobStorage,
    AcceptedTestGeneration bobGeneration,
  })
>
_createFullSession() async {
  final aliceStorage = FakeSecureStorage();
  final bobStorage = FakeSecureStorage();
  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);
  await alice.wipeForFreshRegistration();
  await bob.wipeForFreshRegistration();
  await alice.initialize();
  await bob.initialize();

  await aliceStorage.write(key: 'user_id', value: 'alice-id');
  await aliceStorage.write(key: 'device_id', value: 'alice-device');
  await bobStorage.write(key: 'user_id', value: 'bob-id');
  await bobStorage.write(key: 'device_id', value: 'bob-device');

  final bobGeneration = await CryptoTestFixtures.acceptInitialGeneration(bob);
  final bundle = bobGeneration.consumerBundle(
    userId: 'bob-id',
    deviceId: 'bob-device',
  );
  await alice.createSession(bundle);

  // Alice sends first message (prekey) to establish Bob's side
  final preKeyEnvelope = await alice.encryptMessage(
    'bob-id',
    'bob-device',
    'session-init',
  );
  await bob.decryptMessage('alice-id', 'alice-device', preKeyEnvelope);

  return (
    alice: alice,
    aliceStorage: aliceStorage,
    bob: bob,
    bobStorage: bobStorage,
    bobGeneration: bobGeneration,
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

  // ── Identity key persistence across authentication rejection ────────

  group('Identity key persistence across authentication rejection', () {
    test('identity key and session survive a rejected normal message', () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Verify baseline: a normal message works
      final envelope1 = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'before reset',
      );
      final plain1 = await bob.decryptMessage(
        'alice-id',
        'alice-device',
        envelope1,
      );
      expect(plain1, equals('before reset'));

      // Record the identity key Bob stored for Alice BEFORE reset
      final identityKeyBefore = await bob.getSessionIdentityKey(
        'alice-id',
        'alice-device',
      );
      expect(identityKeyBefore, isNotNull);

      // Produce a corrupted envelope that will cause SecretBoxAuthenticationError
      // on Bob's side. This simulates message corruption / desync.
      final envelope2 = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'to be corrupted',
      );
      final messageMap = envelope2['message'] as Map<String, dynamic>;
      final ciphertextB64 = messageMap['ciphertext'] as String;
      final ciphertextBytes = base64Decode(ciphertextB64);
      // Flip a byte in the ciphertext to break the GCM MAC
      ciphertextBytes[0] ^= 0xFF;
      messageMap['ciphertext'] = base64Encode(ciphertextBytes);

      // Authentication failure is typed and must not reset the session.
      try {
        await bob.decryptMessage('alice-id', 'alice-device', envelope2);
        fail('Expected MessageAuthenticationError to be thrown');
      } on MessageAuthenticationError {
        // Expected: candidate ratchet state was rejected transactionally.
      }

      expect(await bob.hasSession('alice-id', 'alice-device'), isTrue);
      final identityKeyAfter = await bob.getSessionIdentityKey(
        'alice-id',
        'alice-device',
      );
      expect(identityKeyAfter, equals(identityKeyBefore));
    });

    test(
      'identity key stored on initiator side persists across session re-establishment',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;
        final bob = session.bob;

        // Record Alice's stored identity key for Bob
        final identityKeyBefore = await alice.getSessionIdentityKey(
          'bob-id',
          'bob-device',
        );
        expect(identityKeyBefore, isNotNull);

        // Remove and re-establish session
        await alice.removeSession('bob-id', 'bob-device');
        expect(await alice.hasSession('bob-id', 'bob-device'), isFalse);

        // Re-create session from Bob's bundle
        final bundle = session.bobGeneration.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        await alice.createSession(bundle);

        // Bob's identity key should be the same as before
        final identityKeyAfter = await alice.getSessionIdentityKey(
          'bob-id',
          'bob-device',
        );
        expect(identityKeyAfter, isNotNull);

        // Bob's identity key is unchanged (no re-install happened)
        final bobActualKey = await bob.getIdentityPublicKey();
        expect(identityKeyAfter, equals(bobActualKey));
        expect(identityKeyAfter, equals(identityKeyBefore));
      },
    );

    test(
      'corrupted message is rejected without changing stored identity key',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;
        final bob = session.bob;

        // Get identity key Alice stored for Bob before any corruption
        final storedKeyBefore = await alice.getSessionIdentityKey(
          'bob-id',
          'bob-device',
        );
        expect(storedKeyBefore, isNotNull);

        // Bob sends a message, then we corrupt it before Alice decrypts
        final envelope = await bob.encryptMessage(
          'alice-id',
          'alice-device',
          'corrupted msg',
        );
        final msgMap = envelope['message'] as Map<String, dynamic>;
        final ct = base64Decode(msgMap['ciphertext'] as String);
        ct[ct.length ~/ 2] ^= 0xFF; // flip a middle byte
        msgMap['ciphertext'] = base64Encode(ct);

        try {
          await alice.decryptMessage('bob-id', 'bob-device', envelope);
          fail('Expected MessageAuthenticationError');
        } on MessageAuthenticationError {
          // Expected
        }

        final storedKeyAfter = await alice.getSessionIdentityKey(
          'bob-id',
          'bob-device',
        );
        expect(await alice.hasSession('bob-id', 'bob-device'), isTrue);
        expect(storedKeyAfter, equals(storedKeyBefore));
      },
    );
  });

  // ── Legacy reset timestamp isolation ─────────────────────────────────

  group('Legacy reset timestamp isolation', () {
    test(
      'recent legacy timestamps do not alter typed authentication rejection',
      () async {
        final bobStorage = FakeSecureStorage();
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await bob.wipeForFreshRegistration();
        await bob.initialize();
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // Pre-seed 3 recent reset timestamps (within the 1-hour window)
        final now = DateTime.now().millisecondsSinceEpoch;
        final cryptoStorage = CryptoStorage(secureStorage: bobStorage);
        await cryptoStorage.saveResetTimestamps('alice-id', 'alice-device', [
          now - 1000, // 1 second ago
          now - 2000, // 2 seconds ago
          now - 3000, // 3 seconds ago
        ]);

        // Create a session so we have something to corrupt
        final aliceStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        await alice.wipeForFreshRegistration();
        await alice.initialize();
        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');

        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        await alice.createSession(bundle);

        // Establish Bob's side
        final initEnvelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'init',
        );
        await bob.decryptMessage('alice-id', 'alice-device', initEnvelope);

        // Now send a corrupted message to trigger a 4th reset attempt
        final envelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'corrupt me',
        );
        final msgMap = envelope['message'] as Map<String, dynamic>;
        final ct = base64Decode(msgMap['ciphertext'] as String);
        ct[0] ^= 0xFF;
        msgMap['ciphertext'] = base64Encode(ct);

        final timestampsBefore = await cryptoStorage.loadResetTimestamps(
          'alice-id',
          'alice-device',
        );
        expect(
          () => bob.decryptMessage('alice-id', 'alice-device', envelope),
          throwsA(isA<MessageAuthenticationError>()),
        );
        expect(
          await cryptoStorage.loadResetTimestamps('alice-id', 'alice-device'),
          timestampsBefore,
        );
      },
    );

    test(
      'old legacy timestamps remain untouched by authentication failure',
      () async {
        final bobStorage = FakeSecureStorage();
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await bob.wipeForFreshRegistration();
        await bob.initialize();
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // Pre-seed old reset timestamps (outside the 1-hour window but within 24h cooldown)
        // The rate limiter checks if recent resets >= 3 within the window.
        // Old resets outside the window but within cooldown period still require cooldown check.
        // Place them > 24 hours ago so the cooldown has expired and they get cleared.
        final now = DateTime.now().millisecondsSinceEpoch;
        final cryptoStorage = CryptoStorage(secureStorage: bobStorage);
        await cryptoStorage.saveResetTimestamps('alice-id', 'alice-device', [
          now - (25 * 60 * 60 * 1000), // 25 hours ago (outside cooldown)
          now - (26 * 60 * 60 * 1000), // 26 hours ago
          now - (27 * 60 * 60 * 1000), // 27 hours ago
        ]);

        // Create session
        final aliceStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        await alice.wipeForFreshRegistration();
        await alice.initialize();
        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');

        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        await alice.createSession(bundle);

        // Establish Bob's side
        final initEnvelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'init',
        );
        await bob.decryptMessage('alice-id', 'alice-device', initEnvelope);

        // Corrupt message; legacy reset timestamps are no longer consulted or
        // cleared by the normal-message authentication path.
        final envelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'corrupt me',
        );
        final msgMap = envelope['message'] as Map<String, dynamic>;
        final ct = base64Decode(msgMap['ciphertext'] as String);
        ct[0] ^= 0xFF;
        msgMap['ciphertext'] = base64Encode(ct);

        final timestampsBefore = await cryptoStorage.loadResetTimestamps(
          'alice-id',
          'alice-device',
        );
        expect(
          () => bob.decryptMessage('alice-id', 'alice-device', envelope),
          throwsA(isA<MessageAuthenticationError>()),
        );
        expect(
          await cryptoStorage.loadResetTimestamps('alice-id', 'alice-device'),
          timestampsBefore,
        );
      },
    );

    test('reset timestamps are stored and accumulate correctly', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      // Initially empty
      var timestamps = await cryptoStorage.loadResetTimestamps(
        'user-a',
        'device-a',
      );
      expect(timestamps, isEmpty);

      // Save some timestamps
      final now = DateTime.now().millisecondsSinceEpoch;
      await cryptoStorage.saveResetTimestamps('user-a', 'device-a', [
        now - 3000,
        now - 2000,
        now - 1000,
      ]);

      timestamps = await cryptoStorage.loadResetTimestamps(
        'user-a',
        'device-a',
      );
      expect(timestamps.length, equals(3));

      // Clear them
      await cryptoStorage.clearResetTimestamps('user-a', 'device-a');
      timestamps = await cryptoStorage.loadResetTimestamps(
        'user-a',
        'device-a',
      );
      expect(timestamps, isEmpty);
    });

    test('reset timestamps are trimmed to last 10 entries', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      // Save 15 timestamps -- should be trimmed to 10
      final now = DateTime.now().millisecondsSinceEpoch;
      final timestamps = List.generate(15, (i) => now - (15 - i) * 1000);
      await cryptoStorage.saveResetTimestamps('user-a', 'device-a', timestamps);

      final loaded = await cryptoStorage.loadResetTimestamps(
        'user-a',
        'device-a',
      );
      expect(loaded.length, equals(10));
      // Should have the LAST 10 (most recent)
      expect(loaded.first, equals(timestamps[5]));
      expect(loaded.last, equals(timestamps[14]));
    });
  });

  // ── Session preservation and explicit cleanup ────────────────────────

  group('Session preservation and explicit cleanup', () {
    test('authentication failure keeps the established session', () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Verify session exists
      expect(await bob.hasSession('alice-id', 'alice-device'), isTrue);

      // Corrupt a message to trigger auto-reset
      final envelope = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'will be corrupted',
      );
      final msgMap = envelope['message'] as Map<String, dynamic>;
      final ct = base64Decode(msgMap['ciphertext'] as String);
      ct[0] ^= 0xFF;
      msgMap['ciphertext'] = base64Encode(ct);

      try {
        await bob.decryptMessage('alice-id', 'alice-device', envelope);
        fail('Expected MessageAuthenticationError');
      } on MessageAuthenticationError {
        // Expected
      }

      expect(await bob.hasSession('alice-id', 'alice-device'), isTrue);
    });

    test(
      'authentic message remains decryptable after its tampered copy is rejected',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;
        final bob = session.bob;

        // Trigger a reset by corrupting a message
        final envelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'will be corrupted',
        );
        final tamperedEnvelope = Map<String, dynamic>.from(
          jsonDecode(jsonEncode(envelope)) as Map,
        );
        final msgMap = tamperedEnvelope['message'] as Map<String, dynamic>;
        final ct = base64Decode(msgMap['ciphertext'] as String);
        ct[0] ^= 0xFF;
        msgMap['ciphertext'] = base64Encode(ct);

        try {
          await bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          );
        } on MessageAuthenticationError {
          // Expected
        }

        expect(await bob.hasSession('alice-id', 'alice-device'), isTrue);
        final plaintext = await bob.decryptMessage(
          'alice-id',
          'alice-device',
          envelope,
        );
        expect(plaintext, equals('will be corrupted'));

        final e2 = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'Alice follows up without reset',
        );
        final p2 = await bob.decryptMessage('alice-id', 'alice-device', e2);
        expect(p2, equals('Alice follows up without reset'));
      },
    );

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
      },
    );
  });

  // ── Pre-key replenishment callback isolation ─────────────────────────

  group('Pre-key replenishment callback', () {
    test(
      'authentication rejection does not request pre-key replenishment',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;
        final bob = session.bob;

        var callbackFired = false;
        bob.onPreKeyReplenishmentNeeded = () {
          callbackFired = true;
        };

        // Corrupt a message to trigger auto-reset
        final envelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'trigger reset',
        );
        final msgMap = envelope['message'] as Map<String, dynamic>;
        final ct = base64Decode(msgMap['ciphertext'] as String);
        ct[0] ^= 0xFF;
        msgMap['ciphertext'] = base64Encode(ct);

        try {
          await bob.decryptMessage('alice-id', 'alice-device', envelope);
        } on MessageAuthenticationError {
          // Expected
        }

        expect(callbackFired, isFalse);
      },
    );
  });

  // ── PqxdhDowngradeError model tests ──────────────────────────────────

  group('PqxdhDowngradeError', () {
    test('toString includes peer info', () {
      const error = PqxdhDowngradeError(
        userId: 'user123',
        deviceId: 'device456',
      );

      expect(error.toString(), contains('user123'));
      expect(error.toString(), contains('device456'));
      expect(error.toString(), contains('PQXDH'));
      expect(error.toString(), contains('downgrade'));
    });

    test('implements Exception', () {
      const error = PqxdhDowngradeError(userId: 'u', deviceId: 'd');
      expect(error, isA<Exception>());
    });
  });

  // ── Anti-downgrade enforcement ──────────────────────────────────────

  group('PQXDH anti-downgrade enforcement', () {
    test(
      'rejects missing ML-KEM before legacy downgrade state is consulted',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // First session: Bob has PQXDH support (Kyber key present)
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle1 = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        expect(bundle1.kyberPreKey, isNotNull, reason: 'Bob should have Kyber');

        // Alice creates session — records Bob as PQXDH-capable
        await alice.createSession(bundle1);

        // Second session: Simulate Bob's bundle WITHOUT Kyber key (downgrade)
        final bundleNoKyber = _withoutKyber(bundle1);

        await expectLater(
          alice.createSession(bundleNoKyber),
          throwsA(
            isA<FormatException>().having(
              (error) => error.message,
              'message',
              contains('requires current ML-KEM material'),
            ),
          ),
        );
      },
    );

    test(
      'rejects classicalOnly override after a prior PQXDH session',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // First session with PQXDH
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle1 = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        await alice.createSession(bundle1);

        // Simulate downgraded bundle
        final bundleNoKyber = _withoutKyber(bundle1);

        await expectLater(
          alice.createSession(
            bundleNoKyber,
            pqxdhPolicy: PqxdhPolicy.classicalOnly,
          ),
          throwsA(isA<UnsupportedError>()),
        );
      },
    );

    test(
      'missing ML-KEM is rejected before downgrade events mutate state',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final eventBus = SecurityEventBus();
        final alice = SignalProtocolManager(
          secureStorage: aliceStorage,
          securityEventBus: eventBus,
        );
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // First session with PQXDH
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final fullBundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        await alice.createSession(fullBundle);

        // Track events
        SecurityEvent? downgradeEvent;
        eventBus.events.listen((event) {
          if (event.type == SecurityEventType.antiDowngradeTriggered) {
            downgradeEvent = event;
          }
        });

        // Downgraded bundle
        final bundleNoKyber = _withoutKyber(fullBundle);
        await expectLater(
          alice.createSession(bundleNoKyber),
          throwsA(isA<FormatException>()),
        );

        // Allow stream microtask to deliver the event
        await Future<void>.delayed(Duration.zero);

        expect(downgradeEvent, isNull);
      },
    );

    test(
      'rejects classicalOnly even when peer capability is unknown',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // First session without PQXDH (classical only)
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundleNoKyber = _withoutKyber(
          acceptedBob.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
        );

        await expectLater(
          alice.createSession(
            bundleNoKyber,
            pqxdhPolicy: PqxdhPolicy.classicalOnly,
          ),
          throwsA(isA<UnsupportedError>()),
        );
        expect(await alice.hasSession('bob-id', 'bob-device'), isFalse);
      },
    );

    test(
      'a rejected classical attempt can be followed by current PQXDH',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // First session: classical only (no Kyber)
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final fullBundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );
        final bundleNoKyber = _withoutKyber(fullBundle);

        await expectLater(
          alice.createSession(
            bundleNoKyber,
            pqxdhPolicy: PqxdhPolicy.classicalOnly,
          ),
          throwsA(isA<UnsupportedError>()),
        );

        // Second session: Bob now has PQXDH (upgrade — this is GOOD)
        await alice.createSession(fullBundle);
        expect(await alice.hasSession('bob-id', 'bob-device'), isTrue);
      },
    );
  });

  // ── Anti-replay persistence tests ──────────────────────────────────

  group('anti-replay state persistence', () {
    test('replay detected across session restore', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();

      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await aliceStorage.write(key: 'device_id', value: 'alice-device');
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');

      // Establish session
      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final bundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );
      await alice.createSession(bundle);

      final env = await alice.encryptMessage('bob-id', 'bob-device', 'Hello!');
      await bob.decryptMessage('alice-id', 'alice-device', env);

      // Send another message and save envelope for replay
      final env2 = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'Second msg',
      );
      await bob.decryptMessage('alice-id', 'alice-device', env2);

      // Simulate app restart — create new Bob instance with same storage
      final bob2 = SignalProtocolManager(secureStorage: bobStorage);
      await bob2.initialize();

      // Replay env2 — should fail even after "restart" because state is persisted
      expect(
        () => bob2.decryptMessage('alice-id', 'alice-device', env2),
        throwsA(anything),
      );
    });
  });
}
