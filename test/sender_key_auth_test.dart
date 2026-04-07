import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/key_helper.dart';
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
  group('Ed25519 sender authentication — basic round-trip', () {
    test('Sender can encrypt and recipient can decrypt with Ed25519 signatures',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-auth-001';

      // Alice generates her sender key (Ed25519 key pair internally)
      final aliceDistribution = await managerAlice.generateSenderKey(groupId);

      // Bob processes Alice's distribution (receives Ed25519 public key only)
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDistribution,
      );

      // Alice encrypts (signs with Ed25519 private key)
      final plaintext = utf8.encode('Hello from Alice with Ed25519!');
      final encrypted = await managerAlice.encrypt(groupId, plaintext);

      // Bob decrypts (verifies with Ed25519 public key)
      final decrypted = await managerBob.decrypt(groupId, 'alice', encrypted);

      expect(decrypted, plaintext);
      expect(utf8.decode(decrypted), 'Hello from Alice with Ed25519!');
    });
  });

  group('Ed25519 sender authentication — anti-forgery', () {
    test(
        'Recipient CANNOT forge messages — no signing private key available',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, storeBob) = await _createManager('bob');
      final (managerCarol, _) = await _createManager('carol');
      const groupId = 'group-forgery-001';

      // Setup: Alice distributes her sender key to Bob and Carol
      final aliceDist = await managerAlice.generateSenderKey(groupId);
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

      // Verify that Bob's stored state does NOT have a private signing key
      final bobCryptoStorage = CryptoStorage(secureStorage: storeBob);
      final bobStateJson =
          await bobCryptoStorage.getSenderKeyRaw(groupId, 'alice');
      expect(bobStateJson, isNotNull);
      expect(bobStateJson!.containsKey('signingPrivateKey'), isFalse,
          reason: 'Recipient must NOT have the sender\'s private signing key');

      // Bob attempts to encrypt with Alice's key (should fail — no private key)
      // This simulates a forgery attempt: Bob tries to pretend to be Alice
      // by overriding his user_id to match Alice's stored key
      await storeBob.write(key: 'user_id', value: 'alice');
      final forgedManager = SenderKeyManager(
        cryptoStorage: CryptoStorage(secureStorage: storeBob),
      );

      await expectLater(
        () => forgedManager.encrypt(groupId, utf8.encode('Forged by Bob!')),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('no signing private key'),
          ),
        ),
      );
    });

    test(
        'Signature verification detects tampering — modified ciphertext fails',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-tamper-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Original sensitive message'),
      );

      // Tamper with ciphertext
      final tamperedCiphertext = base64Decode(encrypted.ciphertext);
      for (var i = 0; i < 4; i++) {
        tamperedCiphertext[i] ^= 0xFF;
      }

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

    test(
        'Different sender\'s key CANNOT forge for another sender — cross-sender forgery',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      final (managerCarol, _) = await _createManager('carol');
      const groupId = 'group-cross-forgery-001';

      // Both Alice and Bob generate their sender keys
      final aliceDist = await managerAlice.generateSenderKey(groupId);
      final bobDist = await managerBob.generateSenderKey(groupId);

      // Carol processes both distributions
      await managerCarol.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );
      await managerCarol.processSenderKeyDistribution(
        groupId,
        'bob',
        bobDist,
      );

      // Bob encrypts a message with his own sender key
      final bobEncrypted = await managerBob.encrypt(
        groupId,
        utf8.encode('Message from Bob'),
      );

      // Carol tries to decrypt Bob's message as if it came from Alice
      // This should fail because the signature was made with Bob's Ed25519
      // private key, but Carol would try to verify with Alice's public key
      await expectLater(
        () => managerCarol.decrypt(groupId, 'alice', bobEncrypted),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Ed25519 signature verification failed'),
          ),
        ),
      );

      // But decrypting correctly with Bob's identity works fine
      final decrypted =
          await managerCarol.decrypt(groupId, 'bob', bobEncrypted);
      expect(utf8.decode(decrypted), 'Message from Bob');
    });
  });

  group('Ed25519 sender authentication — distribution security', () {
    test('Distribution contains only public key, NOT private key', () async {
      final (manager, storage) = await _createManager('alice');
      const groupId = 'group-dist-001';

      final distribution = await manager.generateSenderKey(groupId);

      // The distribution JSON should contain signingKey
      final distJson = distribution.toJson();
      expect(distJson.containsKey('signingKey'), isTrue);

      // The signing key in distribution should be a valid Ed25519 public key
      final signingKeyBytes = base64Decode(distribution.signingKey);
      expect(signingKeyBytes.length, 32,
          reason: 'Ed25519 public key must be 32 bytes');

      // Verify no private key field exists in the distribution
      expect(distJson.containsKey('signingPrivateKey'), isFalse,
          reason: 'Distribution must NEVER contain private signing key');

      // Cross-check: the locally stored state DOES have the private key
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final stateJson = await cryptoStorage.getSenderKeyRaw(groupId, 'alice');
      expect(stateJson, isNotNull);
      expect(stateJson!.containsKey('signingPrivateKey'), isTrue,
          reason: 'Local state must contain private key for signing');
      expect(stateJson['signingPublicKey'], distribution.signingKey,
          reason: 'Public key in state must match distribution');

      // The private key should be different from the public key
      final privateKeyBytes =
          base64Decode(stateJson['signingPrivateKey'] as String);
      // Ed25519 private key is 32 bytes (seed) or 64 bytes (seed + public)
      expect(privateKeyBytes.length >= 32, isTrue);
      expect(
        base64Encode(privateKeyBytes),
        isNot(distribution.signingKey),
        reason: 'Private key must differ from public key',
      );
    });

    test('Recipient state does NOT contain private key after processing',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, storageBob) = await _createManager('bob');
      const groupId = 'group-dist-002';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      // Check Bob's stored state for Alice's sender key
      final bobCryptoStorage = CryptoStorage(secureStorage: storageBob);
      final bobStateJson =
          await bobCryptoStorage.getSenderKeyRaw(groupId, 'alice');
      expect(bobStateJson, isNotNull);

      // signingPrivateKey should NOT be present (or should be null)
      expect(bobStateJson!['signingPrivateKey'], isNull,
          reason: 'Recipient must NOT store sender\'s private signing key');

      // signingPublicKey should match the distribution
      expect(bobStateJson['signingPublicKey'], aliceDist.signingKey);
    });
  });

  group('Ed25519 sender authentication — multi-member group', () {
    test(
        'Three members — each member\'s messages authenticated independently',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      final (managerCarol, _) = await _createManager('carol');
      const groupId = 'group-multi-auth-001';

      // Generate sender keys
      final aliceDist = await managerAlice.generateSenderKey(groupId);
      final bobDist = await managerBob.generateSenderKey(groupId);
      final carolDist = await managerCarol.generateSenderKey(groupId);

      // Full distribution
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
      await managerAlice.processSenderKeyDistribution(
        groupId,
        'bob',
        bobDist,
      );
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

      // Each member sends and all can decrypt
      final aliceEnc =
          await managerAlice.encrypt(groupId, utf8.encode('Alice says hi'));
      final bobEnc =
          await managerBob.encrypt(groupId, utf8.encode('Bob says hi'));
      final carolEnc =
          await managerCarol.encrypt(groupId, utf8.encode('Carol says hi'));

      // Bob and Carol decrypt Alice
      expect(
        utf8.decode(await managerBob.decrypt(groupId, 'alice', aliceEnc)),
        'Alice says hi',
      );
      expect(
        utf8.decode(await managerCarol.decrypt(groupId, 'alice', aliceEnc)),
        'Alice says hi',
      );

      // Alice and Carol decrypt Bob
      expect(
        utf8.decode(await managerAlice.decrypt(groupId, 'bob', bobEnc)),
        'Bob says hi',
      );
      expect(
        utf8.decode(await managerCarol.decrypt(groupId, 'bob', bobEnc)),
        'Bob says hi',
      );

      // Alice and Bob decrypt Carol
      expect(
        utf8.decode(await managerAlice.decrypt(groupId, 'carol', carolEnc)),
        'Carol says hi',
      );
      expect(
        utf8.decode(await managerBob.decrypt(groupId, 'carol', carolEnc)),
        'Carol says hi',
      );

      // Cross-sender verification: Create a fresh message from Alice at a later
      // iteration so the iteration check doesn't fire first (Bob's key for
      // Carol is at iteration 1 now, and Alice's next message is at iteration 1)
      final aliceEnc2 =
          await managerAlice.encrypt(groupId, utf8.encode('Alice msg 2'));
      // Bob's next expected iteration for Carol is 1, and alice's iteration
      // is also 1, so the Ed25519 check is what should fail here
      await expectLater(
        () => managerCarol.decrypt(groupId, 'bob', aliceEnc2),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Ed25519 signature verification failed'),
          ),
        ),
      );
    });

    test(
        'Each member has unique Ed25519 signing keys — distributions differ',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-unique-keys-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      final bobDist = await managerBob.generateSenderKey(groupId);

      // Each member gets a different signing public key
      expect(aliceDist.signingKey, isNot(bobDist.signingKey),
          reason: 'Each member must have a unique Ed25519 key pair');
    });
  });

  group('Ed25519 sender authentication — chain ratchet with signatures', () {
    test('Chain ratchet still works with Ed25519 signing — multiple messages',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-ratchet-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      // Send 10 messages — each with advancing chain key but same Ed25519 key
      final messages = <SenderKeyMessage>[];
      for (var i = 0; i < 10; i++) {
        final enc =
            await managerAlice.encrypt(groupId, utf8.encode('Message $i'));
        messages.add(enc);
      }

      // Verify iterations increment correctly
      for (var i = 0; i < 10; i++) {
        expect(messages[i].iteration, i);
      }

      // Decrypt all in order — all signatures should verify
      for (var i = 0; i < 10; i++) {
        final dec =
            await managerBob.decrypt(groupId, 'alice', messages[i]);
        expect(utf8.decode(dec), 'Message $i');
      }
    });

    test('Out-of-order delivery works — skip iterations + Ed25519 verification',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-ooo-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      // Alice sends 5 messages
      final msg0 =
          await managerAlice.encrypt(groupId, utf8.encode('Message 0'));
      final msg1 =
          await managerAlice.encrypt(groupId, utf8.encode('Message 1'));
      final msg2 =
          await managerAlice.encrypt(groupId, utf8.encode('Message 2'));
      final msg3 =
          await managerAlice.encrypt(groupId, utf8.encode('Message 3'));
      final msg4 =
          await managerAlice.encrypt(groupId, utf8.encode('Message 4'));

      // Bob receives them out of order: msg0, then msg3 (skipping 1 and 2)
      final dec0 = await managerBob.decrypt(groupId, 'alice', msg0);
      expect(utf8.decode(dec0), 'Message 0');

      // Skip to msg3 — should fast-forward chain key 3 times and still verify
      final dec3 = await managerBob.decrypt(groupId, 'alice', msg3);
      expect(utf8.decode(dec3), 'Message 3');

      // msg4 should still work (sequential after 3)
      final dec4 = await managerBob.decrypt(groupId, 'alice', msg4);
      expect(utf8.decode(dec4), 'Message 4');

      // msg1 and msg2 are now behind stored iteration — should fail
      await expectLater(
        () => managerBob.decrypt(groupId, 'alice', msg1),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('is behind stored iteration'),
          ),
        ),
      );
    });
  });

  group('Ed25519 sender authentication — signature correctness', () {
    test(
        'Signature is valid Ed25519 — can be independently verified with SignalKeyHelper',
        () async {
      final (managerAlice, storageAlice) = await _createManager('alice');
      final (managerBob, _) = await _createManager('bob');
      const groupId = 'group-sig-verify-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);
      await managerBob.processSenderKeyDistribution(
        groupId,
        'alice',
        aliceDist,
      );

      final encrypted = await managerAlice.encrypt(
        groupId,
        utf8.encode('Verify my signature!'),
      );

      // Manually reconstruct the signature input and verify with SignalKeyHelper
      final iv = base64Decode(encrypted.iv);
      final ciphertext = base64Decode(encrypted.ciphertext);
      final iteration = encrypted.iteration;

      final signatureInput = <int>[
        ...iv,
        ...ciphertext,
        ...[
          (iteration >> 24) & 0xFF,
          (iteration >> 16) & 0xFF,
          (iteration >> 8) & 0xFF,
          iteration & 0xFF,
        ],
      ];

      // Verify using the public key from the distribution
      final isValid = await SignalKeyHelper.verify(
        aliceDist.signingKey,
        signatureInput,
        encrypted.signature,
      );
      expect(isValid, isTrue,
          reason: 'Ed25519 signature must be independently verifiable');

      // Verify with a DIFFERENT (random) public key — must fail
      final randomKeyPair = await SignalKeyHelper.generateSigningKeyPair();
      final isValidWithWrongKey = await SignalKeyHelper.verify(
        randomKeyPair.publicKey,
        signatureInput,
        encrypted.signature,
      );
      expect(isValidWithWrongKey, isFalse,
          reason: 'Signature must fail with wrong public key');
    });

    test(
        'Bob cannot sign a message that verifies as Alice — asymmetric guarantee',
        () async {
      final (managerAlice, _) = await _createManager('alice');
      final (_, storageBob) = await _createManager('bob');
      const groupId = 'group-asym-001';

      final aliceDist = await managerAlice.generateSenderKey(groupId);

      // Bob generates his own Ed25519 key pair (different from Alice's)
      final bobSigningKeyPair = await SignalKeyHelper.generateSigningKeyPair();

      // Bob crafts a message and signs it with his own private key
      final forgedData = utf8.encode('Forged message claiming to be Alice');
      final forgedSignature = await SignalKeyHelper.sign(
        bobSigningKeyPair.privateKey,
        forgedData,
      );

      // This signature should NOT verify against Alice's public key
      final isValid = await SignalKeyHelper.verify(
        aliceDist.signingKey,
        forgedData,
        forgedSignature,
      );
      expect(isValid, isFalse,
          reason:
              'Bob\'s signature must NOT verify with Alice\'s public key — '
              'this is the core asymmetric guarantee');
    });
  });
}
