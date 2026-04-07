import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';

void main() {
  // ── Backwards compatibility ─────────────────────────────────────────

  group('Backwards compatibility', () {
    test('unseal without new params still works (no regressions)', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final innerMessage = {
        'type': 'message',
        'ciphertext': 'encrypted_payload',
        'nonce': 'nonce_value',
      };

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice-123',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: innerMessage,
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Unseal with no optional params — must work identically to before
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
      );

      expect(content.senderId, 'alice-123');
      expect(content.senderDeviceId, 'device-1');
      expect(content.senderIdentityKey, senderKp.publicKey);
      expect(content.encryptedMessage['type'], 'message');
      expect(content.encryptedMessage['ciphertext'], 'encrypted_payload');
      expect(content.timestamp, isA<int>());
      expect(content.serverToken, isNull);
    });

    test('seal without serverToken produces 3-field envelope', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      expect(sealed.length, 3);
      expect(sealed.containsKey('ephemeralPublicKey'), isTrue);
      expect(sealed.containsKey('ciphertext'), isTrue);
      expect(sealed.containsKey('nonce'), isTrue);
    });
  });

  // ── Sender identity verification ────────────────────────────────────

  group('Sender identity verification (knownSenderIdentityKeys)', () {
    test('known sender identity key passes verification', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice-123',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'type': 'message', 'data': 'hello'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // The recipient knows Alice's real identity key
      final knownKeys = {'alice-123': senderKp.publicKey};

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
        knownSenderIdentityKeys: knownKeys,
      );

      expect(content.senderId, 'alice-123');
      expect(content.senderIdentityKey, senderKp.publicKey);
    });

    test('unknown sender identity key mismatch is detected', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();
      final fakeKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice-123',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'type': 'message', 'data': 'hello'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // The recipient has a DIFFERENT key on file for alice-123
      // (simulates MitM injecting a fake identity)
      final knownKeys = {'alice-123': fakeKp.publicKey};

      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          knownSenderIdentityKeys: knownKeys,
        ),
        throwsA(
          allOf(
            isA<StateError>(),
            predicate<StateError>(
              (e) =>
                  e.message.contains('identity key mismatch') &&
                  e.message.contains('alice-123') &&
                  e.message.contains('man-in-the-middle'),
              'error message mentions identity mismatch and MitM',
            ),
          ),
        ),
      );
    });

    test('sender not in knownKeys map is allowed through', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'bob-456',
        senderDeviceId: 'device-2',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'type': 'message', 'data': 'hello'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Known keys only has alice, not bob — bob should pass through
      final otherKp = await SignalKeyHelper.generateX25519KeyPair();
      final knownKeys = {'alice-123': otherKp.publicKey};

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
        knownSenderIdentityKeys: knownKeys,
      );

      expect(content.senderId, 'bob-456');
    });
  });

  // ── Configurable replay window ──────────────────────────────────────

  group('Configurable replay window (maxReplayWindowMs)', () {
    test('custom replay window of 1 second rejects old messages', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Wait for the 1-second window to expire
      await Future<void>.delayed(const Duration(milliseconds: 1200));

      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          maxReplayWindowMs: 1000, // 1 second window
        ),
        throwsA(
          allOf(
            isA<StateError>(),
            predicate<StateError>(
              (e) => e.message.contains('timestamp outside allowed window'),
              'error message mentions timestamp window',
            ),
          ),
        ),
      );
    });

    test('default 5-minute window accepts recent messages', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Immediate unseal with default window should succeed
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
      );

      expect(content.senderId, 'alice');
    });

    test('very large replay window accepts all messages', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Large window should accept even with slight delay
      await Future<void>.delayed(const Duration(milliseconds: 100));

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
        maxReplayWindowMs: 60 * 60 * 1000, // 1 hour
      );

      expect(content.senderId, 'alice');
    });
  });

  // ── Nonce replay detection ──────────────────────────────────────────

  group('Nonce replay detection (seenNonces)', () {
    test('nonce replay is detected and rejected', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      final seenNonces = <String>{};

      // First unseal should succeed and record the nonce
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
        seenNonces: seenNonces,
      );
      expect(content.senderId, 'alice');
      expect(seenNonces.length, 1);

      // Second unseal of the SAME envelope should fail (replay)
      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          seenNonces: seenNonces,
        ),
        throwsA(
          allOf(
            isA<StateError>(),
            predicate<StateError>(
              (e) => e.message.contains('nonce already seen'),
              'error message mentions nonce replay',
            ),
          ),
        ),
      );
    });

    test('different messages have different nonces and both succeed', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed1 = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'message-1'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      final sealed2 = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'message-2'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      final seenNonces = <String>{};

      final content1 = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed1,
        recipientIdentityKeyPair: recipientKp,
        seenNonces: seenNonces,
      );
      expect(content1.encryptedMessage['data'], 'message-1');
      expect(seenNonces.length, 1);

      final content2 = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed2,
        recipientIdentityKeyPair: recipientKp,
        seenNonces: seenNonces,
      );
      expect(content2.encryptedMessage['data'], 'message-2');
      expect(seenNonces.length, 2);
    });

    test('seenNonces set is not mutated if unseal is not provided it',
        () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Without seenNonces, replaying is allowed (backwards compat)
      final content1 = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
      );
      expect(content1.senderId, 'alice');

      final content2 = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
      );
      expect(content2.senderId, 'alice');
    });
  });

  // ── Server token validation ─────────────────────────────────────────

  group('Server token validation (validateServerToken)', () {
    test('valid server token passes validation callback', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      const validToken = 'server-issued-token-abc123';

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
        serverToken: validToken,
      );

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
        validateServerToken: (token) => token == validToken,
      );

      expect(content.senderId, 'alice');
      expect(content.serverToken, validToken);
    });

    test('invalid server token is rejected by callback', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
        serverToken: 'forged-token',
      );

      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          validateServerToken: (token) => token == 'real-token-xyz',
        ),
        throwsA(
          allOf(
            isA<StateError>(),
            predicate<StateError>(
              (e) => e.message.contains('server token validation failed'),
              'error message mentions token validation failure',
            ),
          ),
        ),
      );
    });

    test('missing server token when validation is required throws', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      // Seal WITHOUT a server token
      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // But recipient requires token validation
      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          validateServerToken: (token) => true,
        ),
        throwsA(
          allOf(
            isA<StateError>(),
            predicate<StateError>(
              (e) => e.message.contains('missing server token'),
              'error message mentions missing token',
            ),
          ),
        ),
      );
    });

    test('server token without validation callback is ignored', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      // Seal WITH a server token but don't validate
      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
        serverToken: 'some-token',
      );

      // Unseal without validation callback — token is just passed through
      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
      );

      expect(content.senderId, 'alice');
      expect(content.serverToken, 'some-token');
    });
  });

  // ── Combined hardening ──────────────────────────────────────────────

  group('Combined hardening features', () {
    test('all hardening features work together', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      const validToken = 'valid-server-token';

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice-123',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'type': 'message', 'data': 'secret'},
        recipientIdentityPublicKey: recipientKp.publicKey,
        serverToken: validToken,
      );

      final seenNonces = <String>{};
      final knownKeys = {'alice-123': senderKp.publicKey};

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
        knownSenderIdentityKeys: knownKeys,
        validateServerToken: (token) => token == validToken,
        maxReplayWindowMs: 60000, // 1 minute
        seenNonces: seenNonces,
      );

      expect(content.senderId, 'alice-123');
      expect(content.senderIdentityKey, senderKp.publicKey);
      expect(content.serverToken, validToken);
      expect(content.encryptedMessage['data'], 'secret');
      expect(seenNonces.length, 1);

      // Replaying should now fail
      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          knownSenderIdentityKeys: knownKeys,
          validateServerToken: (token) => token == validToken,
          maxReplayWindowMs: 60000,
          seenNonces: seenNonces,
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('sender identity is still hidden in the wire envelope', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'secret-sender-id',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
        serverToken: 'server-token-value',
      );

      // Neither sender ID nor token should appear in plaintext envelope
      final envelopeJson = jsonEncode(sealed);
      expect(envelopeJson.contains('secret-sender-id'), isFalse);
      expect(envelopeJson.contains('server-token-value'), isFalse);
    });
  });
}
