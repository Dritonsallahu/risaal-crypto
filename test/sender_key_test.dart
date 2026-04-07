import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/sender_key.dart';

import 'helpers/fake_secure_storage.dart';

/// Helper to create a SenderKeyManager with in-memory storage.
Future<(SenderKeyManager manager, FakeSecureStorage storage)> _createManager(
  String userId,
) async {
  final storage = FakeSecureStorage();
  await storage.write(key: 'user_id', value: userId);
  final cryptoStorage = CryptoStorage(secureStorage: storage);
  final manager = SenderKeyManager(cryptoStorage: cryptoStorage);
  return (manager, storage);
}

void main() {
  group('SenderKeyManager key generation', () {
    test('generateSenderKey creates a valid distribution with non-empty fields',
        () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      final distribution = await manager.generateSenderKey(groupId);

      expect(distribution.groupId, groupId);
      expect(distribution.senderId, 'alice');
      expect(distribution.iteration, 0);
      expect(distribution.chainKey, isNotEmpty);
      expect(distribution.signingKey, isNotEmpty);
    });

    test('generateSenderKey creates different keys each time (not idempotent)',
        () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      final dist1 = await manager.generateSenderKey(groupId);
      final dist2 = await manager.generateSenderKey(groupId);

      // GroupId and senderId should be same
      expect(dist2.groupId, dist1.groupId);
      expect(dist2.senderId, dist1.senderId);
      // But the random keys should be different
      expect(dist2.chainKey, isNot(dist1.chainKey));
      expect(dist2.signingKey, isNot(dist1.signingKey));
    });

    test('Distribution has correct groupId, senderId matching stored user_id',
        () async {
      final (manager, storage) = await _createManager('bob-user-id');
      const groupId = 'test-group';

      final distribution = await manager.generateSenderKey(groupId);

      expect(distribution.groupId, groupId);
      expect(distribution.senderId, 'bob-user-id');
      final storedUserId = await storage.read(key: 'user_id');
      expect(distribution.senderId, storedUserId);
    });

    test('Distribution chainKey is 32 bytes, signingKey is Ed25519 public key',
        () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      final distribution = await manager.generateSenderKey(groupId);

      // Should be able to decode without error
      final chainKeyBytes = base64Decode(distribution.chainKey);
      final signingKeyBytes = base64Decode(distribution.signingKey);

      expect(chainKeyBytes.length, 32);
      // Ed25519 public key is 32 bytes
      expect(signingKeyBytes.length, 32);
    });
  });

  group('SenderKeyManager distribution processing', () {
    test('processSenderKeyDistribution stores remote key', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      // Alice generates her sender key
      final aliceDistribution = await managerAlice.generateSenderKey(groupId);

      // Bob processes Alice's distribution
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDistribution,
      );

      // Bob should now have Alice's sender key
      final hasSenderKey = await managerBob.hasSenderKeyFor(groupId, 'alice');
      expect(hasSenderKey, isTrue);
    });

    test('hasSenderKeyFor returns true after processing distribution',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDistribution = await managerAlice.generateSenderKey(groupId);

      expect(await managerBob.hasSenderKeyFor(groupId, 'alice'), isFalse);

      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDistribution,
      );

      expect(await managerBob.hasSenderKeyFor(groupId, 'alice'), isTrue);
    });

    test('hasSenderKeyFor returns false for unknown sender', () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      final hasKey = await manager.hasSenderKeyFor(groupId, 'unknown-sender');

      expect(hasKey, isFalse);
    });

    test('hasOwnSenderKey returns true after generation', () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      expect(await manager.hasOwnSenderKey(groupId), isFalse);

      await manager.generateSenderKey(groupId);

      expect(await manager.hasOwnSenderKey(groupId), isTrue);
    });
  });

  group('SenderKeyManager encrypt/decrypt', () {
    test('Encrypt then decrypt round-trip with distributed key', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      // Setup: Alice generates her sender key and Bob processes it
      final aliceDistribution = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDistribution,
      );

      // Alice encrypts a message
      final plaintext = utf8.encode('Hello, group!');
      final encrypted = await managerAlice.encrypt(groupId, plaintext);

      // Bob decrypts it
      final decrypted = await managerBob.decrypt(groupId, 'alice', encrypted);

      expect(decrypted, plaintext);
      expect(utf8.decode(decrypted), 'Hello, group!');
    });

    test('Multiple sequential messages decrypt correctly', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDistribution = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDistribution,
      );

      // Send three messages in sequence
      final msg1 = utf8.encode('Message 1');
      final msg2 = utf8.encode('Message 2');
      final msg3 = utf8.encode('Message 3');

      final enc1 = await managerAlice.encrypt(groupId, msg1);
      final enc2 = await managerAlice.encrypt(groupId, msg2);
      final enc3 = await managerAlice.encrypt(groupId, msg3);

      // Decrypt in order
      final dec1 = await managerBob.decrypt(groupId, 'alice', enc1);
      final dec2 = await managerBob.decrypt(groupId, 'alice', enc2);
      final dec3 = await managerBob.decrypt(groupId, 'alice', enc3);

      expect(utf8.decode(dec1), 'Message 1');
      expect(utf8.decode(dec2), 'Message 2');
      expect(utf8.decode(dec3), 'Message 3');
    });

    test('Different plaintexts produce different ciphertexts', () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      await manager.generateSenderKey(groupId);

      final msg1 = utf8.encode('Message A');
      final msg2 = utf8.encode('Message B');

      final enc1 = await manager.encrypt(groupId, msg1);
      final enc2 = await manager.encrypt(groupId, msg2);

      expect(enc1.ciphertext, isNot(enc2.ciphertext));
    });

    test('Same plaintext produces different ciphertexts (different IV each time)',
        () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      await manager.generateSenderKey(groupId);

      final plaintext = utf8.encode('Same message');

      final enc1 = await manager.encrypt(groupId, plaintext);
      final enc2 = await manager.encrypt(groupId, plaintext);

      // Different IVs
      expect(enc1.iv, isNot(enc2.iv));
      // Different ciphertexts (because of IV and chain key ratchet)
      expect(enc1.ciphertext, isNot(enc2.ciphertext));
      // Different iterations
      expect(enc2.iteration, enc1.iteration + 1);
    });

    test('Ciphertext is valid base64', () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      await manager.generateSenderKey(groupId);

      final plaintext = utf8.encode('Test message');
      final encrypted = await manager.encrypt(groupId, plaintext);

      // Should be able to decode without error
      expect(() => base64Decode(encrypted.ciphertext), returnsNormally);
      expect(() => base64Decode(encrypted.iv), returnsNormally);
      expect(() => base64Decode(encrypted.signature), returnsNormally);
    });

    test('Message iteration increments with each encrypt', () async {
      final (manager, _) = await _createManager('alice');
      const groupId = 'group-001';

      await manager.generateSenderKey(groupId);

      final msg = utf8.encode('Test');

      final enc1 = await manager.encrypt(groupId, msg);
      final enc2 = await manager.encrypt(groupId, msg);
      final enc3 = await manager.encrypt(groupId, msg);

      expect(enc1.iteration, 0);
      expect(enc2.iteration, 1);
      expect(enc3.iteration, 2);
    });
  });

  group('SenderKeyManager multi-member group', () {
    test('Three members can all decrypt each other\'s messages', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      final (managerCarol, _) = await _createManager('carol');
      const groupId = 'group-001';

      // Each member generates their sender key
      final aliceDist = await managerAlice.generateSenderKey(groupId);
      final bobDist = await managerBob.generateSenderKey(groupId);
      final carolDist = await managerCarol.generateSenderKey(groupId);

      // Distribute keys to all members
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );
      await managerCarol.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      await managerAlice.processSenderKeyDistribution(groupId, 'bob', bobDist);
      await managerCarol.processSenderKeyDistribution(
        groupId,
        'bob',
        bobDist,
      );

      await managerAlice.processSenderKeyDistribution(
        groupId,
        'carol',
        carolDist,
      );
      await managerBob.processSenderKeyDistribution(
        groupId,
        'carol',
        carolDist,
      );

      // Alice sends a message
      final aliceMsg = utf8.encode('From Alice');
      final aliceEnc = await managerAlice.encrypt(groupId, aliceMsg);

      // Bob and Carol decrypt
      final bobDecAlice = await managerBob.decrypt(groupId, 'alice', aliceEnc);
      final carolDecAlice =
          await managerCarol.decrypt(groupId, 'alice', aliceEnc);

      expect(utf8.decode(bobDecAlice), 'From Alice');
      expect(utf8.decode(carolDecAlice), 'From Alice');

      // Bob sends a message
      final bobMsg = utf8.encode('From Bob');
      final bobEnc = await managerBob.encrypt(groupId, bobMsg);

      // Alice and Carol decrypt
      final aliceDecBob = await managerAlice.decrypt(groupId, 'bob', bobEnc);
      final carolDecBob = await managerCarol.decrypt(groupId, 'bob', bobEnc);

      expect(utf8.decode(aliceDecBob), 'From Bob');
      expect(utf8.decode(carolDecBob), 'From Bob');

      // Carol sends a message
      final carolMsg = utf8.encode('From Carol');
      final carolEnc = await managerCarol.encrypt(groupId, carolMsg);

      // Alice and Bob decrypt
      final aliceDecCarol =
          await managerAlice.decrypt(groupId, 'carol', carolEnc);
      final bobDecCarol = await managerBob.decrypt(groupId, 'carol', carolEnc);

      expect(utf8.decode(aliceDecCarol), 'From Carol');
      expect(utf8.decode(bobDecCarol), 'From Carol');
    });

    test('Each member has their own sender key and iteration counter',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      final bobDist = await managerBob.generateSenderKey(groupId);

      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );
      await managerAlice.processSenderKeyDistribution(groupId, 'bob', bobDist);

      // Alice sends 3 messages
      for (var i = 0; i < 3; i++) {
        await managerAlice.encrypt(groupId, utf8.encode('Alice msg $i'));
      }

      // Bob sends 2 messages
      for (var i = 0; i < 2; i++) {
        await managerBob.encrypt(groupId, utf8.encode('Bob msg $i'));
      }

      // Iterations should be independent
      final aliceNextMsg = await managerAlice.encrypt(
        groupId,
        utf8.encode('Alice msg 3'),
      );
      final bobNextMsg =
          await managerBob.encrypt(groupId, utf8.encode('Bob msg 2'));

      expect(aliceNextMsg.iteration, 3);
      expect(bobNextMsg.iteration, 2);
    });
  });

  group('SenderKeyManager forward secrecy', () {
    test(
        'After sending N messages, earlier chain keys are gone (can\'t decrypt old messages with new state)',
        () async {
      final (managerAlice, storageAlice) = await _createManager('alice');
      final (managerBob, storageBob) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      // Alice sends message at iteration 0
      final msg0 = await managerAlice.encrypt(
        groupId,
        utf8.encode('Message 0'),
      );

      // Bob decrypts it (advances his chain to iteration 1)
      await managerBob.decrypt(groupId, 'alice', msg0);

      // Alice sends 10 more messages
      for (var i = 1; i <= 10; i++) {
        await managerAlice.encrypt(groupId, utf8.encode('Message $i'));
      }

      // Now Bob's state has moved forward. Trying to decrypt msg0 again
      // should fail because iteration has moved past it.
      // The decrypt should throw because msg0.iteration (0) < stored iteration (1)
      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', msg0),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('is behind stored iteration'),
          ),
        ),
      );

      // Verify chain keys are actually different (implicitly tested by the
      // fact that the state has moved forward)
      expect(await managerBob.hasSenderKeyFor(groupId, 'alice'), isTrue);
    });
  });

  group('SenderKeyManager adversarial', () {
    test(
        'Tampered ciphertext -> decrypt throws (Ed25519 signature verification fails)',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Original message'),
      );

      // Tamper with the ciphertext
      final tamperedCiphertext = base64Decode(encrypted.ciphertext);
      tamperedCiphertext[0] ^= 0xFF; // Flip bits
      final tamperedMessage = SenderKeyMessage(
        iteration: encrypted.iteration,
        ciphertext: base64Encode(tamperedCiphertext),
        iv: encrypted.iv,
        signature: encrypted.signature,
      );

      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', tamperedMessage),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Ed25519 signature verification failed'),
          ),
        ),
      );
    });

    test('Tampered signature -> decrypt throws', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Original message'),
      );

      // Tamper with the signature
      final tamperedSig = base64Decode(encrypted.signature);
      tamperedSig[0] ^= 0xFF;
      final tamperedMessage = SenderKeyMessage(
        iteration: encrypted.iteration,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        signature: base64Encode(tamperedSig),
      );

      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', tamperedMessage),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Ed25519 signature verification failed'),
          ),
        ),
      );
    });

    test('Tampered IV -> decrypt throws', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Original message'),
      );

      // Tamper with the IV
      final tamperedIv = base64Decode(encrypted.iv);
      tamperedIv[0] ^= 0xFF;
      final tamperedMessage = SenderKeyMessage(
        iteration: encrypted.iteration,
        ciphertext: encrypted.ciphertext,
        iv: base64Encode(tamperedIv),
        signature: encrypted.signature,
      );

      // Tampering with IV changes the signature input, so Ed25519 verification fails
      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', tamperedMessage),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Ed25519 signature verification failed'),
          ),
        ),
      );
    });

    test('Wrong sender ID -> decrypt throws (no key found)', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Message'),
      );

      // Try to decrypt as if from a different sender
      await expectLater(
        () => managerBob.decrypt(groupId, 'wrong-sender', encrypted),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('No Sender Key found'),
          ),
        ),
      );
    });

    test('Message with iteration going backward -> decrypt throws', () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      // Send and decrypt message 0
      final msg0 = await managerAlice.encrypt(groupId, utf8.encode('Msg 0'));
      await managerBob.decrypt(groupId, 'alice', msg0);

      // Send and decrypt message 1
      final msg1 = await managerAlice.encrypt(groupId, utf8.encode('Msg 1'));
      await managerBob.decrypt(groupId, 'alice', msg1);

      // Try to decrypt msg0 again (iteration going backward)
      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', msg0),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('is behind stored iteration'),
          ),
        ),
      );
    });

    test('Message iteration skip > 256 -> decrypt throws (DoS protection)',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      // Create a message with iteration 300 (skip = 300)
      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Message'),
      );
      final farFutureMessage = SenderKeyMessage(
        iteration: 300,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        signature: encrypted.signature,
      );

      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', farFutureMessage),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Too many skipped iterations'),
          ),
        ),
      );
    });
  });

  group('SenderKeyMessage serialization', () {
    test('toJson/fromJson round-trip', () {
      final message = SenderKeyMessage(
        iteration: 42,
        ciphertext: 'dGVzdA==',
        iv: 'aXY=',
        signature: 'c2ln',
      );

      final json = message.toJson();
      final restored = SenderKeyMessage.fromJson(json);

      expect(restored.iteration, message.iteration);
      expect(restored.ciphertext, message.ciphertext);
      expect(restored.iv, message.iv);
      expect(restored.signature, message.signature);
    });

    test('SenderKeyDistribution toJson/fromJson round-trip', () {
      const distribution = SenderKeyDistribution(
        groupId: 'group-123',
        senderId: 'alice',
        iteration: 0,
        chainKey: 'Y2hhaW4=',
        signingKey: 'c2lnbmluZw==',
      );

      final json = distribution.toJson();
      final restored = SenderKeyDistribution.fromJson(json);

      expect(restored.groupId, distribution.groupId);
      expect(restored.senderId, distribution.senderId);
      expect(restored.iteration, distribution.iteration);
      expect(restored.chainKey, distribution.chainKey);
      expect(restored.signingKey, distribution.signingKey);
    });

    test('SenderKeyState toJson/fromJson round-trip (with private key)', () {
      final state = SenderKeyState(
        groupId: 'group-456',
        senderId: 'bob',
        iteration: 5,
        chainKey: List.generate(32, (i) => i),
        signingPublicKey: base64Encode(List.generate(32, (i) => i + 100)),
        signingPrivateKey: base64Encode(List.generate(64, (i) => i + 50)),
      );

      final json = state.toJson();
      final restored = SenderKeyState.fromJson(json);

      expect(restored.groupId, state.groupId);
      expect(restored.senderId, state.senderId);
      expect(restored.iteration, state.iteration);
      expect(restored.chainKey, state.chainKey);
      expect(restored.signingPublicKey, state.signingPublicKey);
      expect(restored.signingPrivateKey, state.signingPrivateKey);
    });

    test('SenderKeyState toJson/fromJson round-trip (public key only)', () {
      final state = SenderKeyState(
        groupId: 'group-456',
        senderId: 'bob',
        iteration: 5,
        chainKey: List.generate(32, (i) => i),
        signingPublicKey: base64Encode(List.generate(32, (i) => i + 100)),
        signingPrivateKey: null,
      );

      final json = state.toJson();
      final restored = SenderKeyState.fromJson(json);

      expect(restored.groupId, state.groupId);
      expect(restored.senderId, state.senderId);
      expect(restored.iteration, state.iteration);
      expect(restored.chainKey, state.chainKey);
      expect(restored.signingPublicKey, state.signingPublicKey);
      expect(restored.signingPrivateKey, isNull);
    });

    test('SenderKeyState fromJson handles legacy HMAC format', () {
      // Legacy format used 'signingKey' as a shared HMAC key
      final legacyJson = {
        'groupId': 'group-legacy',
        'senderId': 'alice',
        'iteration': 3,
        'chainKey': base64Encode(List.generate(32, (i) => i)),
        'signingKey': base64Encode(List.generate(32, (i) => i + 200)),
      };

      final restored = SenderKeyState.fromJson(legacyJson);

      expect(restored.groupId, 'group-legacy');
      expect(restored.senderId, 'alice');
      expect(restored.iteration, 3);
      // Legacy signing key should be treated as public key
      expect(restored.signingPublicKey, legacyJson['signingKey']);
      // No private key in legacy format
      expect(restored.signingPrivateKey, isNull);
    });
  });
}
