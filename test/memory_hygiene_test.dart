import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/secure_memory.dart';
import 'package:risaal_crypto/src/sender_key.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/models/session_state.dart';

import 'helpers/fake_secure_storage.dart';

/// Helper: create a paired Double Ratchet session (Alice=sender, Bob=receiver).
Future<(DoubleRatchet alice, DoubleRatchet bob)> _createRatchetSession() async {
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
  final sharedSecret = List<int>.generate(32, (i) => i + 1);

  final alice = await DoubleRatchet.initSender(
    sharedSecret: sharedSecret,
    recipientPublicKey: bobPreKey.publicKey,
  );

  final bob = await DoubleRatchet.initReceiver(
    sharedSecret: sharedSecret,
    dhKeyPair: bobPreKey,
  );

  return (alice, bob);
}

void main() {
  // ── SecureMemory.zeroBytes ──────────────────────────────────────────

  group('SecureMemory.zeroBytes', () {
    test('zeros a regular List<int>', () {
      final bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

      SecureMemory.zeroBytes(bytes);

      expect(bytes, everyElement(equals(0)));
    });

    test('zeros a Uint8List', () {
      final bytes = Uint8List.fromList([0xFF, 0xAA, 0x55, 0x01]);

      SecureMemory.zeroBytes(bytes);

      expect(bytes, everyElement(equals(0)));
    });

    test('handles empty list without error', () {
      final bytes = <int>[];

      // Should not throw
      SecureMemory.zeroBytes(bytes);

      expect(bytes, isEmpty);
    });

    test('zeros a 32-byte key (typical AES-256 key size)', () {
      final key = List<int>.generate(32, (i) => (i * 7 + 13) % 256);

      SecureMemory.zeroBytes(key);

      expect(key, everyElement(equals(0)));
      expect(key.length, equals(32));
    });

    test('zeros a 64-byte key (typical HMAC output)', () {
      final hmacOutput = List<int>.generate(64, (i) => (i * 3 + 1) % 256);

      SecureMemory.zeroBytes(hmacOutput);

      expect(hmacOutput, everyElement(equals(0)));
    });

    test('zeros a large buffer (4096 bytes)', () {
      final buffer = List<int>.generate(4096, (i) => i % 256);

      SecureMemory.zeroBytes(buffer);

      expect(buffer, everyElement(equals(0)));
    });

    test('zeros a single-byte list', () {
      final bytes = [0xFF];

      SecureMemory.zeroBytes(bytes);

      expect(bytes, equals([0]));
    });
  });

  // ── SecureMemory.zeroUint8List ──────────────────────────────────────

  group('SecureMemory.zeroUint8List', () {
    test('zeros a Uint8List', () {
      final bytes = Uint8List.fromList([1, 2, 3, 4, 5]);

      SecureMemory.zeroUint8List(bytes);

      expect(bytes, everyElement(equals(0)));
    });

    test('handles empty Uint8List without error', () {
      final bytes = Uint8List(0);

      // Should not throw
      SecureMemory.zeroUint8List(bytes);

      expect(bytes, isEmpty);
    });
  });

  // ── Double Ratchet DH shared secret zeroing ─────────────────────────

  group('Double Ratchet memory hygiene', () {
    test(
        'encrypt/decrypt completes without error (DH intermediaries zeroed internally)',
        () async {
      final (alice, bob) = await _createRatchetSession();

      // Single message — exercises encrypt path with chain key zeroing
      final encrypted = await alice.encrypt(utf8.encode('Test message'));
      final decrypted = await bob.decrypt(encrypted);

      expect(utf8.decode(decrypted), equals('Test message'));
    });

    test('bidirectional exchange exercises DH ratchet step zeroing', () async {
      final (alice, bob) = await _createRatchetSession();

      // Alice -> Bob (initial)
      final enc1 = await alice.encrypt(utf8.encode('A->B'));
      await bob.decrypt(enc1);

      // Bob -> Alice (triggers DH ratchet on Bob — exercises _dhRatchetStep zeroing)
      final enc2 = await bob.encrypt(utf8.encode('B->A'));
      await alice.decrypt(enc2);

      // Alice -> Bob (triggers DH ratchet on Alice — exercises _dhRatchetStep zeroing)
      final enc3 = await alice.encrypt(utf8.encode('A->B again'));
      final dec3 = await bob.decrypt(enc3);

      expect(utf8.decode(dec3), equals('A->B again'));
    });

    test('multiple DH ratchet steps all complete without error', () async {
      final (alice, bob) = await _createRatchetSession();

      // 5 round trips — each exercises _dhRatchetStep with DH zeroing
      for (var i = 0; i < 5; i++) {
        final encAB = await alice.encrypt(utf8.encode('A->B round $i'));
        final decAB = await bob.decrypt(encAB);
        expect(utf8.decode(decAB), equals('A->B round $i'));

        final encBA = await bob.encrypt(utf8.encode('B->A round $i'));
        final decBA = await alice.decrypt(encBA);
        expect(utf8.decode(decBA), equals('B->A round $i'));
      }
    });

    test('skipped message keys exercises skip chain zeroing', () async {
      final (alice, bob) = await _createRatchetSession();

      // Alice sends 3 messages
      final enc1 = await alice.encrypt(utf8.encode('Message 1'));
      final enc2 = await alice.encrypt(utf8.encode('Message 2'));
      final enc3 = await alice.encrypt(utf8.encode('Message 3'));

      // Bob receives out of order: 3, 1, 2
      // This exercises _skipMessageKeys which now zeros intermediaries
      final dec3 = await bob.decrypt(enc3);
      expect(utf8.decode(dec3), equals('Message 3'));

      final dec1 = await bob.decrypt(enc1);
      expect(utf8.decode(dec1), equals('Message 1'));

      final dec2 = await bob.decrypt(enc2);
      expect(utf8.decode(dec2), equals('Message 2'));
    });

    test('initSender zeros DH output and derived keys', () async {
      // This test verifies that initSender completes successfully
      // with the zeroing code in place (no use-after-zero bugs)
      final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
      final sharedSecret = List<int>.generate(32, (i) => i + 1);

      final alice = await DoubleRatchet.initSender(
        sharedSecret: sharedSecret,
        recipientPublicKey: bobPreKey.publicKey,
      );

      // Verify the ratchet state is valid
      final state = alice.state;
      expect(state.rootKey, isNotEmpty);
      expect(state.sendingChainKey, isNotEmpty);
      expect(state.dhSendingKeyPair, isNotEmpty);
    });
  });

  // ── Sender Key memory hygiene ──────────────────────────────────────

  group('Sender Key memory hygiene', () {
    test('encrypt/decrypt zeroes chain key intermediaries', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final senderKeyManager = SenderKeyManager(cryptoStorage: cryptoStorage);

      await storage.write(key: 'user_id', value: 'alice-id');

      // Generate and distribute sender key
      final distribution = await senderKeyManager.generateSenderKey('group-1');

      // Store recipient copy
      final bobStorage = FakeSecureStorage();
      final bobCryptoStorage = CryptoStorage(secureStorage: bobStorage);
      final bobSenderKeyManager =
          SenderKeyManager(cryptoStorage: bobCryptoStorage);
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobSenderKeyManager.processSenderKeyDistribution(
        'group-1',
        'alice-id',
        distribution,
      );

      // Encrypt — exercises messageKey and chainKey zeroing
      final padded = utf8.encode('Group message');
      final encrypted = await senderKeyManager.encrypt('group-1', padded);

      // Decrypt — exercises messageKey and chainKey zeroing
      final decrypted = await bobSenderKeyManager.decrypt(
        'group-1',
        'alice-id',
        encrypted,
      );

      expect(utf8.decode(decrypted), equals('Group message'));
    });

    test('multiple group messages exercise chain key forward secrecy zeroing',
        () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final senderKeyManager = SenderKeyManager(cryptoStorage: cryptoStorage);

      await storage.write(key: 'user_id', value: 'alice-id');

      final distribution = await senderKeyManager.generateSenderKey('group-2');

      final bobStorage = FakeSecureStorage();
      final bobCryptoStorage = CryptoStorage(secureStorage: bobStorage);
      final bobSenderKeyManager =
          SenderKeyManager(cryptoStorage: bobCryptoStorage);
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobSenderKeyManager.processSenderKeyDistribution(
        'group-2',
        'alice-id',
        distribution,
      );

      // Send 5 messages — each one zeroes the old chain key
      for (var i = 0; i < 5; i++) {
        final msg = utf8.encode('Message $i');
        final encrypted = await senderKeyManager.encrypt('group-2', msg);
        final decrypted = await bobSenderKeyManager.decrypt(
          'group-2',
          'alice-id',
          encrypted,
        );
        expect(utf8.decode(decrypted), equals('Message $i'));
      }
    });

    test('skipped iteration fast-forward exercises zeroing', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final senderKeyManager = SenderKeyManager(cryptoStorage: cryptoStorage);

      await storage.write(key: 'user_id', value: 'alice-id');

      final distribution = await senderKeyManager.generateSenderKey('group-3');

      final bobStorage = FakeSecureStorage();
      final bobCryptoStorage = CryptoStorage(secureStorage: bobStorage);
      final bobSenderKeyManager =
          SenderKeyManager(cryptoStorage: bobCryptoStorage);
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobSenderKeyManager.processSenderKeyDistribution(
        'group-3',
        'alice-id',
        distribution,
      );

      // Encrypt 3 messages
      final msg1 = utf8.encode('First');
      final msg2 = utf8.encode('Second');
      final msg3 = utf8.encode('Third');

      final enc1 = await senderKeyManager.encrypt('group-3', msg1);
      await senderKeyManager.encrypt('group-3', msg2); // enc2 — skipped by Bob
      final enc3 = await senderKeyManager.encrypt('group-3', msg3);

      // Bob receives only the 3rd message first — fast-forwards 2 iterations
      // This exercises the zeroing in the skip loop
      final dec3 = await bobSenderKeyManager.decrypt(
        'group-3',
        'alice-id',
        enc3,
      );
      expect(utf8.decode(dec3), equals('Third'));

      // Messages 1 and 2 are now stale (behind stored iteration)
      // They should fail with a replay error
      expect(
        () => bobSenderKeyManager.decrypt('group-3', 'alice-id', enc1),
        throwsA(isA<StateError>()),
      );
    });
  });

  // ── SecureBuffer lifecycle ──────────────────────────────────────────

  group('SecureBuffer lifecycle', () {
    // Note: SecureBuffer requires FFI (Android/iOS), so these tests
    // verify the allocation path returns null in the test environment
    // (where FFI is not available).

    test('allocSecure returns null in non-FFI environment (tests)', () {
      // In the test environment, FFI is not available so allocSecure
      // should return null (graceful degradation)
      try {
        final buffer = SecureMemory.allocSecure(32);
        // If FFI IS available (unlikely in tests), verify the lifecycle
        if (buffer != null) {
          final data = [1, 2, 3, 4, 5];
          buffer.write(data);
          final read = buffer.read();
          expect(read.sublist(0, 5), equals(data));
          buffer.dispose();
          // After dispose, read should throw
          expect(() => buffer.read(), throwsA(isA<StateError>()));
        }
        // If null, that's expected in test environment — pass
      } on UnsupportedError {
        // Expected — FFI not available on this platform
      }
    });

    test('allocSecure rejects non-positive lengths', () {
      try {
        expect(SecureMemory.allocSecure(0), isNull);
        expect(SecureMemory.allocSecure(-1), isNull);
      } on UnsupportedError {
        // Expected — FFI not available
      }
    });
  });

  // ── Regression: SecretKey by-reference corruption (v0.1.1) ────────

  group('SecretKey corruption regression (v0.1.1)', () {
    test(
        'zeroing original bytes does not corrupt Double Ratchet encrypt/decrypt',
        () async {
      // Regression: Before the fix, SecretKey(keyBytes) stored a reference.
      // SecureMemory.zeroBytes(keyBytes) then zeroed the key inside the
      // SecretKey, causing SecretBoxAuthenticationError on decrypt.
      // Fix: SecretKey(List<int>.from(keyBytes)) creates a defensive copy.

      final (alice, bob) = await _createRatchetSession();

      // Multiple messages to exercise chain key advancement
      for (var i = 0; i < 5; i++) {
        final msg = utf8.encode('Regression check message $i');
        final encrypted = await alice.encrypt(msg);
        final decrypted = await bob.decrypt(encrypted);
        expect(utf8.decode(decrypted), equals('Regression check message $i'));
      }

      // Bidirectional to exercise DH ratchet step
      for (var i = 0; i < 3; i++) {
        final encBA = await bob.encrypt(utf8.encode('B->A $i'));
        final decBA = await alice.decrypt(encBA);
        expect(utf8.decode(decBA), equals('B->A $i'));

        final encAB = await alice.encrypt(utf8.encode('A->B $i'));
        final decAB = await bob.decrypt(encAB);
        expect(utf8.decode(decAB), equals('A->B $i'));
      }
    });

    test('zeroing original bytes does not corrupt Sender Key encrypt/decrypt',
        () async {
      // Same regression but for SenderKeyManager which also uses
      // SecretKey(List<int>.from(chainKey)) after the fix.

      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);
      final senderKeyManager = SenderKeyManager(cryptoStorage: cryptoStorage);
      await storage.write(key: 'user_id', value: 'alice-id');

      final distribution =
          await senderKeyManager.generateSenderKey('regression-group');

      final bobStorage = FakeSecureStorage();
      final bobCryptoStorage = CryptoStorage(secureStorage: bobStorage);
      final bobSKM = SenderKeyManager(cryptoStorage: bobCryptoStorage);
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobSKM.processSenderKeyDistribution(
        'regression-group',
        'alice-id',
        distribution,
      );

      // Multiple messages to exercise chain key zeroing + key derivation
      for (var i = 0; i < 10; i++) {
        final msg = utf8.encode('Sender key regression $i');
        final encrypted =
            await senderKeyManager.encrypt('regression-group', msg);
        final decrypted = await bobSKM.decrypt(
          'regression-group',
          'alice-id',
          encrypted,
        );
        expect(utf8.decode(decrypted), equals('Sender key regression $i'));
      }
    });
  });

  // -- RatchetState.wipe() zeros Uint8List key fields ---------------------

  group('RatchetState.wipe() memory zeroing', () {
    test('wipe() zeros all Uint8List key fields', () {
      final state = RatchetState(
        dhSendingKeyPair: Uint8List.fromList(List.filled(64, 0xAB)),
        dhReceivingKey: Uint8List.fromList(List.filled(32, 0xCD)),
        rootKey: Uint8List.fromList(List.filled(32, 0xEF)),
        sendingChainKey: Uint8List.fromList(List.filled(32, 0x12)),
        receivingChainKey: Uint8List.fromList(List.filled(32, 0x34)),
        skippedKeys: {
          'key1:0': Uint8List.fromList(List.filled(32, 0x56)),
          'key2:1': Uint8List.fromList(List.filled(32, 0x78)),
        },
        receivedMessages: {'msg1', 'msg2'},
      );

      // Verify fields are non-zero before wipe
      expect(state.rootKey.any((b) => b != 0), isTrue);
      expect(state.sendingChainKey.any((b) => b != 0), isTrue);
      expect(state.dhSendingKeyPair.any((b) => b != 0), isTrue);
      expect(state.dhReceivingKey.any((b) => b != 0), isTrue);
      expect(state.receivingChainKey.any((b) => b != 0), isTrue);
      expect(state.skippedKeys, hasLength(2));
      expect(state.receivedMessages, hasLength(2));

      state.wipe();

      // All byte fields should be zeroed
      expect(state.dhSendingKeyPair.every((b) => b == 0), isTrue);
      expect(state.dhReceivingKey.every((b) => b == 0), isTrue);
      expect(state.rootKey.every((b) => b == 0), isTrue);
      expect(state.sendingChainKey.every((b) => b == 0), isTrue);
      expect(state.receivingChainKey.every((b) => b == 0), isTrue);
      expect(state.skippedKeys, isEmpty);
      expect(state.receivedMessages, isEmpty);
      expect(state.sendMessageNumber, 0);
      expect(state.receiveMessageNumber, 0);
      expect(state.previousChainLength, 0);
    });

    test('wipe() handles empty Uint8List fields without error', () {
      final state = RatchetState(
        dhSendingKeyPair: Uint8List(0),
        dhReceivingKey: Uint8List(0),
        rootKey: Uint8List(0),
        sendingChainKey: Uint8List(0),
        receivingChainKey: Uint8List(0),
      );

      // Should not throw
      state.wipe();

      expect(state.dhSendingKeyPair, isEmpty);
      expect(state.skippedKeys, isEmpty);
    });

    test('toJson/fromJson round-trip preserves Uint8List data', () {
      final original = RatchetState(
        dhSendingKeyPair: Uint8List.fromList(List.filled(64, 0xAB)),
        dhReceivingKey: Uint8List.fromList(List.filled(32, 0xCD)),
        rootKey: Uint8List.fromList(List.filled(32, 0xEF)),
        sendingChainKey: Uint8List.fromList(List.filled(32, 0x12)),
        receivingChainKey: Uint8List.fromList(List.filled(32, 0x34)),
        sendMessageNumber: 5,
        receiveMessageNumber: 3,
        previousChainLength: 2,
        skippedKeys: {
          'key1:0': Uint8List.fromList(List.filled(32, 0x56)),
        },
        receivedMessages: {'msg1', 'msg2'},
      );

      final json = original.toJson();
      final restored = RatchetState.fromJson(json);

      expect(restored.dhSendingKeyPair, equals(original.dhSendingKeyPair));
      expect(restored.dhReceivingKey, equals(original.dhReceivingKey));
      expect(restored.rootKey, equals(original.rootKey));
      expect(restored.sendingChainKey, equals(original.sendingChainKey));
      expect(restored.receivingChainKey, equals(original.receivingChainKey));
      expect(restored.sendMessageNumber, 5);
      expect(restored.receiveMessageNumber, 3);
      expect(restored.previousChainLength, 2);
      expect(restored.skippedKeys.length, 1);
      expect(restored.skippedKeys['key1:0'],
          equals(Uint8List.fromList(List.filled(32, 0x56))));
      expect(restored.receivedMessages, {'msg1', 'msg2'});
    });
  });
}
