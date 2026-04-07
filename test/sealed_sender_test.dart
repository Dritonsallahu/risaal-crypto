import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';

void main() {
  // ── Seal / Unseal round-trip ────────────────────────────────────────

  group('SealedSenderEnvelope seal and unseal', () {
    test('seal then unseal recovers sender identity and message', () async {
      final senderIdentityKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientIdentityKp = await SignalKeyHelper.generateX25519KeyPair();

      final innerMessage = {
        'type': 'prekey',
        'ciphertext': 'base64_cipher_data',
        'nonce': 'base64_nonce_data',
      };

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice-123',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderIdentityKp.publicKey,
        encryptedMessage: innerMessage,
        recipientIdentityPublicKey: recipientIdentityKp.publicKey,
      );

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientIdentityKp,
      );

      expect(content.senderId, 'alice-123');
      expect(content.senderDeviceId, 'device-1');
      expect(content.senderIdentityKey, senderIdentityKp.publicKey);
      expect(content.encryptedMessage['type'], 'prekey');
      expect(content.encryptedMessage['ciphertext'], 'base64_cipher_data');
      expect(content.timestamp, isA<int>());
      expect(content.timestamp, greaterThan(0));
    });

    test('sender identity is hidden in the envelope', () async {
      final senderIdentityKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientIdentityKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'secret-sender',
        senderDeviceId: 'device-1',
        senderIdentityKey: senderIdentityKp.publicKey,
        encryptedMessage: {'payload': 'test'},
        recipientIdentityPublicKey: recipientIdentityKp.publicKey,
      );

      // The sealed envelope should NOT contain the sender ID in plaintext
      final envelopeJson = jsonEncode(sealed);
      expect(envelopeJson.contains('secret-sender'), isFalse);

      // It should only contain: ephemeralPublicKey, ciphertext, nonce
      expect(sealed.containsKey('ephemeralPublicKey'), isTrue);
      expect(sealed.containsKey('ciphertext'), isTrue);
      expect(sealed.containsKey('nonce'), isTrue);
      expect(sealed.length, 3); // only these 3 fields
    });

    test('envelope fields are valid base64', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'test'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // All fields should be valid base64
      expect(
        () => base64Decode(sealed['ephemeralPublicKey'] as String),
        returnsNormally,
      );
      expect(
        () => base64Decode(sealed['ciphertext'] as String),
        returnsNormally,
      );
      expect(
        () => base64Decode(sealed['nonce'] as String),
        returnsNormally,
      );

      // Ephemeral public key should be 32 bytes (X25519)
      final ephPubBytes = base64Decode(sealed['ephemeralPublicKey'] as String);
      expect(ephPubBytes.length, 32);
    });
  });

  // ── Wrong recipient key ────────────────────────────────────────────

  group('SealedSenderEnvelope wrong key', () {
    test('unseal with wrong recipient key pair fails', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();
      final wrongRecipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: {'data': 'secret'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Attempting to unseal with the wrong key pair should throw
      expect(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: wrongRecipientKp,
        ),
        throwsA(isA<Exception>()),
      );
    });
  });

  // ── Uniqueness ─────────────────────────────────────────────────────

  group('SealedSenderEnvelope uniqueness', () {
    test('sealing the same content twice produces different envelopes',
        () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final message = {'data': 'identical payload'};

      final sealed1 = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: message,
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      final sealed2 = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: message,
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Different ephemeral keys mean different ciphertexts
      expect(sealed1['ephemeralPublicKey'],
          isNot(equals(sealed2['ephemeralPublicKey'])));
      expect(sealed1['ciphertext'], isNot(equals(sealed2['ciphertext'])));
    });
  });

  // ── Complex inner message ──────────────────────────────────────────

  group('SealedSenderEnvelope with complex payloads', () {
    test('nested encrypted message survives seal/unseal', () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();

      final innerMessage = {
        'dhPublicKey': 'some_base64_key',
        'messageNumber': 42,
        'previousChainLength': 3,
        'ciphertext': 'encrypted_data_base64',
        'nonce': 'nonce_base64',
      };

      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice-789',
        senderDeviceId: 'device-3',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: innerMessage,
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      final content = await SealedSenderEnvelope.unseal(
        sealedEnvelope: sealed,
        recipientIdentityKeyPair: recipientKp,
      );

      expect(content.encryptedMessage['dhPublicKey'], 'some_base64_key');
      expect(content.encryptedMessage['messageNumber'], 42);
      expect(content.encryptedMessage['previousChainLength'], 3);
      expect(content.encryptedMessage['ciphertext'], 'encrypted_data_base64');
      expect(content.encryptedMessage['nonce'], 'nonce_base64');
    });
  });
}
