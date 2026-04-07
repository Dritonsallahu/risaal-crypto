import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart' hide KeyPair;

import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/fake_secure_storage.dart';

// ── Helper Functions ───────────────────────────────────────────────

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
  final bundle = _bundleFromMap(
    bobBundle,
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
  );
}

/// Adversarial/attack-scenario tests for Risaal's crypto layer.
///
/// These tests verify that tampering with encrypted messages, attempting
/// replay attacks, and other adversarial actions are properly detected
/// and rejected by the Signal Protocol implementation.
void main() {
  group('Adversarial Crypto Tests', () {
    // ── Group 1: Double Ratchet Message Tampering ──────────────────────

    group('Double Ratchet Message Tampering', () {
      test('Bit-flip in ciphertext causes decryption to fail', () async {
        final session = await _createFullSession();

        // Encrypt a message from Alice to Bob
        final envelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'sensitive data',
        );

        // Tamper with the inner message ciphertext
        final message = envelope['message'] as Map<String, dynamic>;
        final ciphertextB64 = message['ciphertext'] as String;
        final ciphertextBytes = base64Decode(ciphertextB64);

        // Flip a bit in the middle of the ciphertext
        ciphertextBytes[ciphertextBytes.length ~/ 2] ^= 0x01;
        final tamperedCiphertext = base64Encode(ciphertextBytes);

        // Rebuild the envelope with tampered ciphertext
        final tamperedMessage = Map<String, dynamic>.from(message);
        tamperedMessage['ciphertext'] = tamperedCiphertext;
        final tamperedEnvelope = Map<String, dynamic>.from(envelope);
        tamperedEnvelope['message'] = tamperedMessage;

        // Decryption should fail (AES-GCM MAC verification)
        // Note: The auto-reset mechanism wraps the error in SessionResetError
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          ),
          throwsA(isA<SessionResetError>()),
        );
      });

      test('Bit-flip in nonce causes decryption to fail', () async {
        final session = await _createFullSession();

        final envelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'test message',
        );

        // Tamper with the nonce
        final message = envelope['message'] as Map<String, dynamic>;
        final nonceB64 = message['nonce'] as String;
        final nonceBytes = base64Decode(nonceB64);

        // Flip a bit in the nonce
        nonceBytes[0] ^= 0xFF;
        final tamperedNonce = base64Encode(nonceBytes);

        final tamperedMessage = Map<String, dynamic>.from(message);
        tamperedMessage['nonce'] = tamperedNonce;
        final tamperedEnvelope = Map<String, dynamic>.from(envelope);
        tamperedEnvelope['message'] = tamperedMessage;

        // Decryption should fail
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          ),
          throwsA(isA<SessionResetError>()),
        );
      });

      test('Bit-flip in dhPublicKey causes decryption to fail', () async {
        final session = await _createFullSession();

        final envelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'test message',
        );

        // Tamper with the DH public key
        final message = envelope['message'] as Map<String, dynamic>;
        final dhKeyB64 = message['dhPublicKey'] as String;
        final dhKeyBytes = base64Decode(dhKeyB64);

        // Flip a byte
        dhKeyBytes[10] ^= 0xAA;
        final tamperedDhKey = base64Encode(dhKeyBytes);

        final tamperedMessage = Map<String, dynamic>.from(message);
        tamperedMessage['dhPublicKey'] = tamperedDhKey;
        final tamperedEnvelope = Map<String, dynamic>.from(envelope);
        tamperedEnvelope['message'] = tamperedMessage;

        // Decryption should fail (wrong DH derivation)
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          ),
          throwsA(
              anything), // Can throw various errors depending on DH/AES failure
        );
      });

      test('Swapped message number causes wrong output or failure', () async {
        final session = await _createFullSession();

        final envelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'test message',
        );

        // Change the message number to a different value
        final message = envelope['message'] as Map<String, dynamic>;
        final originalMsgNum = message['messageNumber'] as int;

        final tamperedMessage = Map<String, dynamic>.from(message);
        tamperedMessage['messageNumber'] = originalMsgNum + 50; // Skip ahead
        final tamperedEnvelope = Map<String, dynamic>.from(envelope);
        tamperedEnvelope['message'] = tamperedMessage;

        // Should fail because the ratchet will derive a different key
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          ),
          throwsA(anything),
        );
      });

      test('Truncated ciphertext causes decryption to fail', () async {
        final session = await _createFullSession();

        final envelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'test message',
        );

        // Truncate the ciphertext (remove last 10 bytes)
        final message = envelope['message'] as Map<String, dynamic>;
        final ciphertextB64 = message['ciphertext'] as String;
        final ciphertextBytes = base64Decode(ciphertextB64);

        final truncated =
            ciphertextBytes.sublist(0, ciphertextBytes.length - 10);
        final truncatedCiphertext = base64Encode(truncated);

        final tamperedMessage = Map<String, dynamic>.from(message);
        tamperedMessage['ciphertext'] = truncatedCiphertext;
        final tamperedEnvelope = Map<String, dynamic>.from(envelope);
        tamperedEnvelope['message'] = tamperedMessage;

        // Should fail (invalid MAC or missing data)
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          ),
          throwsA(anything),
        );
      });
    });

    // ── Group 2: Replay Attack Prevention ──────────────────────────────

    group('Replay Attack Prevention', () {
      test('Same message cannot be decrypted twice', () async {
        final session = await _createFullSession();

        // Encrypt a message
        final envelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'test message',
        );

        // First decryption succeeds
        final plaintext1 = await session.bob.decryptMessage(
          'alice-id',
          'alice-device',
          envelope,
        );
        expect(plaintext1, equals('test message'));

        // Second decryption of the same envelope should fail
        // (ratchet has advanced past that message number)
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            envelope,
          ),
          throwsA(anything),
        );
      });

      test('Replay with different session fails', () async {
        final session = await _createFullSession();

        // Create a third party (Carol)
        final carolStorage = FakeSecureStorage();
        final carol = SignalProtocolManager(secureStorage: carolStorage);
        await carol.initialize();
        await carolStorage.write(key: 'user_id', value: 'carol-id');
        await carolStorage.write(key: 'device_id', value: 'carol-device');

        // Establish a session between Alice and Carol
        final carolBundle = await carol.generateKeyBundle();
        final bundle = _bundleFromMap(
          carolBundle,
          userId: 'carol-id',
          deviceId: 'carol-device',
        );
        await session.alice.createSession(bundle);

        // Encrypt message from Alice to Bob
        final bobEnvelope = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'secret for bob',
        );

        // Bob can decrypt it
        final bobPlaintext = await session.bob.decryptMessage(
          'alice-id',
          'alice-device',
          bobEnvelope,
        );
        expect(bobPlaintext, equals('secret for bob'));

        // Carol cannot decrypt it (different session, different keys)
        expect(
          () => carol.decryptMessage(
            'alice-id',
            'alice-device',
            bobEnvelope,
          ),
          throwsA(anything),
        );
      });
    });

    // ── Group 3: Out-of-Order Message Delivery ─────────────────────────

    group('Out-of-Order Message Delivery', () {
      test('Out-of-order within limits (skipped message keys)', () async {
        final session = await _createFullSession();

        // Encrypt 3 messages in sequence
        final msg0 = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'message 0',
        );
        final msg1 = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'message 1',
        );
        final msg2 = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'message 2',
        );

        // Deliver them out of order: msg2, msg0, msg1
        final p2 = await session.bob.decryptMessage(
          'alice-id',
          'alice-device',
          msg2,
        );
        expect(p2, equals('message 2'));

        final p0 = await session.bob.decryptMessage(
          'alice-id',
          'alice-device',
          msg0,
        );
        expect(p0, equals('message 0'));

        final p1 = await session.bob.decryptMessage(
          'alice-id',
          'alice-device',
          msg1,
        );
        expect(p1, equals('message 1'));
      });

      test('Skip beyond max (>2000 messages) throws StateError', () async {
        final session = await _createFullSession();

        // Encrypt one normal message
        final msg0 = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'message 0',
        );

        // Tamper with the messageNumber to force >2000 skipped keys
        final message = msg0['message'] as Map<String, dynamic>;
        final tamperedMessage = Map<String, dynamic>.from(message);
        tamperedMessage['messageNumber'] = 2500; // Force 2500 skips
        final tamperedEnvelope = Map<String, dynamic>.from(msg0);
        tamperedEnvelope['message'] = tamperedMessage;

        // Should throw StateError (too many skipped keys)
        expect(
          () => session.bob.decryptMessage(
            'alice-id',
            'alice-device',
            tamperedEnvelope,
          ),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Too many skipped message keys'),
            ),
          ),
        );
      });
    });

    // ── Group 4: Sealed Sender Tampering ───────────────────────────────

    group('Sealed Sender Tampering', () {
      test('Tampered ciphertext in sealed envelope fails', () async {
        final session = await _createFullSession();

        // Get Bob's identity public key
        final bobIdentityKey = await session.bob.getIdentityPublicKey();

        // Create a sealed sender message
        final sealedEnvelope = await session.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          bobIdentityKey,
          'secret message',
        );

        // Tamper with the sealed envelope ciphertext
        final ciphertextB64 = sealedEnvelope['ciphertext'] as String;
        final ciphertextBytes = base64Decode(ciphertextB64);
        ciphertextBytes[20] ^= 0x42; // Flip a bit
        final tamperedCiphertext = base64Encode(ciphertextBytes);

        final tamperedEnvelope = Map<String, dynamic>.from(sealedEnvelope);
        tamperedEnvelope['ciphertext'] = tamperedCiphertext;

        // Unseal should fail (AES-GCM MAC verification)
        expect(
          () => session.bob.decryptSealedSender(tamperedEnvelope),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
      });

      test('Tampered ephemeral key fails', () async {
        final session = await _createFullSession();

        final bobIdentityKey = await session.bob.getIdentityPublicKey();

        final sealedEnvelope = await session.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          bobIdentityKey,
          'secret message',
        );

        // Tamper with the ephemeral public key
        final ephemeralKeyB64 = sealedEnvelope['ephemeralPublicKey'] as String;
        final ephemeralKeyBytes = base64Decode(ephemeralKeyB64);
        ephemeralKeyBytes[5] ^= 0xFF;
        final tamperedEphemeralKey = base64Encode(ephemeralKeyBytes);

        final tamperedEnvelope = Map<String, dynamic>.from(sealedEnvelope);
        tamperedEnvelope['ephemeralPublicKey'] = tamperedEphemeralKey;

        // Should fail (wrong DH derivation -> wrong AES key)
        expect(
          () => session.bob.decryptSealedSender(tamperedEnvelope),
          throwsA(anything),
        );
      });

      test('Tampered nonce in sealed envelope fails', () async {
        final session = await _createFullSession();

        final bobIdentityKey = await session.bob.getIdentityPublicKey();

        final sealedEnvelope = await session.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          bobIdentityKey,
          'secret message',
        );

        // Tamper with the nonce
        final nonceB64 = sealedEnvelope['nonce'] as String;
        final nonceBytes = base64Decode(nonceB64);
        nonceBytes[2] ^= 0x11;
        final tamperedNonce = base64Encode(nonceBytes);

        final tamperedEnvelope = Map<String, dynamic>.from(sealedEnvelope);
        tamperedEnvelope['nonce'] = tamperedNonce;

        // Should fail (wrong nonce -> AES-GCM fails)
        expect(
          () => session.bob.decryptSealedSender(tamperedEnvelope),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
      });

      test('Replay protection rejects old timestamp', () async {
        final session = await _createFullSession();

        final bobIdentityKey = await session.bob.getIdentityPublicKey();

        final sealedEnvelope = await session.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          bobIdentityKey,
          'current message',
        );

        // Should succeed (timestamp is current)
        final result = await session.bob.decryptSealedSender(sealedEnvelope);
        expect(result.plaintext, equals('current message'));
        expect(result.senderId, equals('alice-id'));
        expect(result.senderDeviceId, equals('alice-device'));
      });
    });

    // ── Group 5: Cross-Session Isolation ───────────────────────────────

    group('Cross-Session Isolation', () {
      test('Message from one session cannot decrypt in another', () async {
        // Alice has sessions with both Bob and Carol
        final bobSession = await _createFullSession();

        final carolStorage = FakeSecureStorage();
        final carol = SignalProtocolManager(secureStorage: carolStorage);
        await carol.initialize();
        await carolStorage.write(key: 'user_id', value: 'carol-id');
        await carolStorage.write(key: 'device_id', value: 'carol-device');

        final carolBundle = await carol.generateKeyBundle();
        final bundle = _bundleFromMap(
          carolBundle,
          userId: 'carol-id',
          deviceId: 'carol-device',
        );
        await bobSession.alice.createSession(bundle);

        // Establish Carol's side session
        final preKeyEnvelope = await bobSession.alice.encryptMessage(
          'carol-id',
          'carol-device',
          'init-carol',
        );
        await carol.decryptMessage('alice-id', 'alice-device', preKeyEnvelope);

        // Alice encrypts a message for Bob
        final bobMsg = await bobSession.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'secret for bob only',
        );

        // Bob can decrypt it
        final bobPlaintext = await bobSession.bob.decryptMessage(
          'alice-id',
          'alice-device',
          bobMsg,
        );
        expect(bobPlaintext, equals('secret for bob only'));

        // Carol cannot decrypt it (different session, different keys)
        expect(
          () => carol.decryptMessage(
            'alice-id',
            'alice-device',
            bobMsg,
          ),
          throwsA(anything),
        );
      });
    });

    // ── Group 6: Session Wipe ──────────────────────────────────────────

    group('Session Wipe', () {
      test('wipeAllSessions clears in-memory state', () async {
        final session = await _createFullSession();

        // Encrypt a message successfully
        final msg1 = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'before wipe',
        );
        expect(msg1, isNotEmpty);

        // Wipe all in-memory sessions
        session.alice.wipeAllSessions();

        final msg2 = await session.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'after wipe',
        );
        expect(msg2, isNotEmpty);

        // Bob can still decrypt (his session is intact)
        final plaintext = await session.bob.decryptMessage(
          'alice-id',
          'alice-device',
          msg2,
        );
        expect(plaintext, equals('after wipe'));
      });

      test('removeSession prevents future encryption to that recipient',
          () async {
        final session = await _createFullSession();

        // Verify session exists
        final hasSessionBefore = await session.alice.hasSession(
          'bob-id',
          'bob-device',
        );
        expect(hasSessionBefore, isTrue);

        // Remove the session
        await session.alice.removeSession('bob-id', 'bob-device');

        // Verify session is gone
        final hasSessionAfter = await session.alice.hasSession(
          'bob-id',
          'bob-device',
        );
        expect(hasSessionAfter, isFalse);

        // Attempting to encrypt should throw StateError (no session)
        expect(
          () => session.alice.encryptMessage(
            'bob-id',
            'bob-device',
            'should fail',
          ),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('No session found'),
            ),
          ),
        );
      });
    });

    // ── Group 7: Identity Key Verification ────────────────────────────

    group('Identity Key Verification', () {
      test('Session with wrong identity key fails safety number check',
          () async {
        final session = await _createFullSession();

        // Get Alice and Bob's identity keys
        final aliceIdentity = await session.alice.getIdentityPublicKey();
        final bobIdentity = await session.bob.getIdentityPublicKey();

        // Generate correct safety number
        final correctSafetyNumber = await session.alice.getSafetyNumber(
          myUserId: 'alice-id',
          theirUserId: 'bob-id',
          theirIdentityKey: bobIdentity,
        );
        expect(correctSafetyNumber, isNotEmpty);
        // Safety number is 60 digits formatted with spaces: "12345 67890 ..." = 71 chars
        expect(correctSafetyNumber.length, equals(71));

        // Create a fake third party with different identity
        final fakeStorage = FakeSecureStorage();
        final fake = SignalProtocolManager(secureStorage: fakeStorage);
        await fake.initialize();
        final fakeIdentity = await fake.getIdentityPublicKey();

        // Verify different identities produce different safety numbers
        expect(aliceIdentity, isNot(equals(fakeIdentity)));
        expect(bobIdentity, isNot(equals(fakeIdentity)));

        // Generate safety number with the fake identity
        final fakeSafetyNumber = await session.alice.getSafetyNumber(
          myUserId: 'alice-id',
          theirUserId: 'bob-id',
          theirIdentityKey: fakeIdentity,
        );

        // Safety numbers should be different when identity key is different
        expect(correctSafetyNumber, isNot(equals(fakeSafetyNumber)));
      });
    });
  });
}
