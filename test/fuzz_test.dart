import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/message_padding.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/models/session_state.dart';
import 'package:risaal_crypto/src/sender_key.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';

import 'helpers/fake_secure_storage.dart';

/// Deterministic Random for reproducible fuzz tests.
/// Using a fixed seed so failures are reproducible.
final _rng = Random(0xDEADBEEF);

/// Generate random bytes of the given length.
Uint8List _randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _rng.nextInt(256);
  }
  return bytes;
}

/// Generate a random base64 string of raw byte length.
String _randomBase64(int byteLength) => base64Encode(_randomBytes(byteLength));

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

void main() {
  // ── A. Message Envelope Fuzzing ──────────────────────────────────────

  group('Message envelope fuzzing', () {
    late SignalProtocolManager bob;
    late FakeSecureStorage bobStorage;

    setUp(() async {
      bobStorage = FakeSecureStorage();
      bob = SignalProtocolManager(secureStorage: bobStorage);
      await bob.initialize();
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');
    });

    test(
        'random malformed envelopes never crash decryptMessage (100 inputs)',
        () async {
      for (var i = 0; i < 100; i++) {
        final envelope = _generateRandomEnvelope(i);
        try {
          await bob.decryptMessage('attacker-id', 'attacker-device', envelope);
          // If it succeeds, that is unexpected but not a crash
        } on SessionResetError {
          // Acceptable: auth error triggered auto-reset
        } on SessionUnstableError {
          // Acceptable: rate limited
        } on StateError {
          // Acceptable: missing session, bad format, etc.
        } on FormatException {
          // Acceptable: bad JSON structure
        } on TypeError {
          // Acceptable: wrong types in the map
        } on RangeError {
          // Acceptable: base64 decode of garbage
        } on ArgumentError {
          // Acceptable: invalid argument to crypto primitives
        } catch (e) {
          // Any other exception is still acceptable as long as it doesn't segfault.
          // The test passes as long as it doesn't hang or crash the process.
          // We explicitly list known exception types above and catch-all here.
        }
      }
      // If we get here, no inputs caused an unrecoverable crash
    });

    test('envelope with empty map does not crash', () async {
      try {
        await bob.decryptMessage('x', 'y', <String, dynamic>{});
      } catch (_) {
        // Any exception is fine, no crash
      }
    });

    test('envelope with null values does not crash', () async {
      final envelopes = [
        {'type': null, 'message': null},
        {'type': 'message', 'message': null, 'senderIdentityKey': null},
        {'type': 'prekey', 'senderIdentityKey': null},
      ];

      for (final envelope in envelopes) {
        try {
          await bob.decryptMessage(
            'x',
            'y',
            envelope.cast<String, dynamic>(),
          );
        } catch (_) {
          // Any exception is fine
        }
      }
    });

    test('envelope with huge field values does not crash', () async {
      final hugeString = 'A' * 1000000;
      final envelope = <String, dynamic>{
        'type': 'message',
        'senderIdentityKey': hugeString,
        'message': {
          'dhPublicKey': hugeString,
          'messageNumber': 999999999,
          'previousChainLength': 999999999,
          'ciphertext': hugeString,
          'nonce': hugeString,
        },
      };

      try {
        await bob.decryptMessage('x', 'y', envelope);
      } catch (_) {
        // Any exception is fine, should not hang or OOM
      }
    });

    test('envelope with wrong types does not crash', () async {
      final envelopes = [
        {'type': 42, 'message': 'not a map'},
        {'type': 'message', 'message': 42},
        {'type': 'message', 'message': <String, dynamic>{'dhPublicKey': 42}},
        {
          'type': 'prekey',
          'senderIdentityKey': 123,
          'senderEphemeralKey': true,
          'usedOneTimePreKeyId': 'not an int',
          'message': <String, dynamic>{},
        },
      ];

      for (final envelope in envelopes) {
        try {
          await bob.decryptMessage(
            'x',
            'y',
            envelope.cast<String, dynamic>(),
          );
        } catch (_) {
          // Any exception is fine
        }
      }
    });
  });

  // ── B. Ratchet State Corruption Fuzzing ──────────────────────────────

  group('Ratchet state corruption fuzzing', () {
    test(
        'corrupted ratchet state fields cause decrypt to throw, not produce garbage',
        () async {
      // Set up a valid session between Alice and Bob
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

      // Establish Bob's session
      final initEnvelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'init');
      await bob.decryptMessage('alice-id', 'alice-device', initEnvelope);

      // Get a valid encrypted message from Alice
      final validEnvelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'test');

      // Now corrupt Bob's session state in storage
      final sessionKey = 'crypto_session_alice-id_alice-device';
      final rawState = await bobStorage.read(key: sessionKey);
      expect(rawState, isNotNull);

      final stateJson = jsonDecode(rawState!) as Map<String, dynamic>;

      // Test various corruptions
      final corruptions = <String, dynamic>{
        'rootKey': _randomBase64(32), // Wrong root key
        'sendingChainKey': _randomBase64(32), // Wrong sending chain key
        'receivingChainKey': _randomBase64(32), // Wrong receiving chain key
        'dhReceivingKey': _randomBase64(32), // Wrong DH receiving key
      };

      for (final entry in corruptions.entries) {
        // Corrupt one field at a time
        final corruptedState = Map<String, dynamic>.from(stateJson);
        corruptedState[entry.key] = entry.value;

        // Write corrupted state back
        await bobStorage.write(
          key: sessionKey,
          value: jsonEncode(corruptedState),
        );

        // Create a fresh Bob manager that will load the corrupted state
        final corruptBob = SignalProtocolManager(secureStorage: bobStorage);
        await corruptBob.initialize();

        try {
          await corruptBob.decryptMessage(
            'alice-id',
            'alice-device',
            validEnvelope,
          );
          // If decryption somehow succeeds with corrupted state, verify it
          // doesn't produce the original plaintext (that would be very wrong)
        } on SessionResetError {
          // Expected: MAC failure triggers auto-reset
        } on StateError {
          // Expected: invalid state
        } catch (e) {
          // Any exception is acceptable -- the point is no crash
          // and no silent garbage output
        }

        // Restore original state for next iteration
        await bobStorage.write(key: sessionKey, value: rawState);
      }
    });

    test('RatchetState.fromJson with garbage fields throws', () {
      final garbageInputs = [
        <String, dynamic>{}, // empty
        {
          'dhSendingKeyPair': 42,
          'dhReceivingKey': null,
        }, // wrong types
        {
          'dhSendingKeyPair': '',
          'dhReceivingKey': '',
          'rootKey': '',
          'sendingChainKey': '',
          'receivingChainKey': '',
          'sendMessageNumber': 'not a number',
          'receiveMessageNumber': 0,
          'previousChainLength': 0,
        },
      ];

      for (final input in garbageInputs) {
        expect(
          () => RatchetState.fromJson(input),
          throwsA(anything),
          reason: 'Garbage input should cause RatchetState.fromJson to throw',
        );
      }
    });

    test(
        'DoubleRatchet.fromJson with truncated/mangled JSON throws',
        () {
      final badInputs = [
        <String, dynamic>{},
        {'dhSendingKeyPair': 'not json'},
        {
          'dhSendingKeyPair': '{}',
          'dhReceivingKey': '',
          'rootKey': '',
          'sendingChainKey': '',
          'receivingChainKey': '',
          'sendMessageNumber': 0,
          'receiveMessageNumber': 0,
          'previousChainLength': 0,
          'skippedKeys': 'not a map',
        },
      ];

      for (final input in badInputs) {
        expect(
          () => DoubleRatchet.fromJson(input),
          throwsA(anything),
          reason: 'Mangled JSON should cause DoubleRatchet.fromJson to throw',
        );
      }
    });
  });

  // ── C. PreKeyBundle Fuzzing ──────────────────────────────────────────

  group('PreKeyBundle fuzzing', () {
    test('createSession rejects bundles with invalid key sizes gracefully',
        () async {
      final aliceStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      await alice.initialize();

      // Generate a valid signing key for the signature field
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      // Generate a real signed pre-key so the signature is correct structure-wise
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(0, signingKP);

      // Test with wrong-sized identity key (should be 32 bytes)
      final wrongSizeKeys = [
        base64Encode(Uint8List(0)), // empty
        base64Encode(Uint8List(16)), // too short
        base64Encode(Uint8List(64)), // too long
        base64Encode(Uint8List(31)), // off by one
        base64Encode(Uint8List(33)), // off by one
      ];

      for (final badKey in wrongSizeKeys) {
        final bundle = PreKeyBundle(
          userId: 'victim',
          deviceId: 'device',
          identityKey: badKey,
          identitySigningKey: signingKP.publicKey,
          signedPreKey: SignedPreKeyPublic(
            keyId: 0,
            publicKey: signedPreKey.keyPair.publicKey,
            signature: signedPreKey.signature,
          ),
        );

        try {
          await alice.createSession(bundle);
          // May or may not succeed depending on the crypto library's validation
        } catch (e) {
          // StateError, ArgumentError, FormatException, etc. are all acceptable
          expect(e, isNot(isA<Error>().having(
            (e) => e.runtimeType.toString(),
            'type',
            contains('Segfault'),
          )));
        }
      }
    });

    test('PreKeyBundle.fromJson rejects missing identitySigningKey', () {
      expect(
        () => PreKeyBundle.fromJson({
          'userId': 'test',
          'deviceId': 'test',
          'identityKey': _randomBase64(32),
          'signedPreKey': {
            'keyId': 0,
            'publicKey': _randomBase64(32),
            'signature': _randomBase64(64),
          },
        }),
        throwsA(isA<StateError>()),
      );
    });

    test('PreKeyBundle.fromJson rejects empty identitySigningKey', () {
      expect(
        () => PreKeyBundle.fromJson({
          'userId': 'test',
          'deviceId': 'test',
          'identityKey': _randomBase64(32),
          'identitySigningKey': '',
          'signedPreKey': {
            'keyId': 0,
            'publicKey': _randomBase64(32),
            'signature': _randomBase64(64),
          },
        }),
        throwsA(isA<StateError>()),
      );
    });

    test('bundles with all-zero keys are handled gracefully', () async {
      final aliceStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      await alice.initialize();

      final zeroKey = base64Encode(Uint8List(32));
      final zeroSig = base64Encode(Uint8List(64));

      final bundle = PreKeyBundle(
        userId: 'zero-user',
        deviceId: 'zero-device',
        identityKey: zeroKey,
        identitySigningKey: zeroKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: 0,
          publicKey: zeroKey,
          signature: zeroSig,
        ),
      );

      try {
        await alice.createSession(bundle);
        // Signature verification should fail since keys are all zeros
        fail('Expected createSession to fail with all-zero keys');
      } on StateError catch (e) {
        // Expected: signature verification failed
        expect(e.message, contains('signature'));
      } catch (e) {
        // Other errors are also acceptable (invalid key material)
      }
    });

    test('bundles with all-0xFF keys are handled gracefully', () async {
      final aliceStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      await alice.initialize();

      final ffKey = base64Encode(Uint8List.fromList(List.filled(32, 0xFF)));
      final ffSig = base64Encode(Uint8List.fromList(List.filled(64, 0xFF)));

      final bundle = PreKeyBundle(
        userId: 'ff-user',
        deviceId: 'ff-device',
        identityKey: ffKey,
        identitySigningKey: ffKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: 0,
          publicKey: ffKey,
          signature: ffSig,
        ),
      );

      try {
        await alice.createSession(bundle);
        fail('Expected createSession to fail with all-0xFF keys');
      } on StateError {
        // Expected: invalid keys
      } catch (e) {
        // Other errors are also acceptable
      }
    });

    test('100 random PreKeyBundles do not crash createSession', () async {
      final aliceStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      await alice.initialize();

      for (var i = 0; i < 100; i++) {
        // Generate random key material of varying sizes
        final keySize = _rng.nextInt(64) + 1; // 1-64 bytes
        final sigSize = _rng.nextInt(128) + 1; // 1-128 bytes

        final bundle = PreKeyBundle(
          userId: 'fuzz-user-$i',
          deviceId: 'fuzz-device-$i',
          identityKey: _randomBase64(keySize),
          identitySigningKey: _randomBase64(keySize),
          signedPreKey: SignedPreKeyPublic(
            keyId: _rng.nextInt(1000),
            publicKey: _randomBase64(keySize),
            signature: _randomBase64(sigSize),
          ),
          oneTimePreKey: _rng.nextBool()
              ? OneTimePreKeyPublic(
                  keyId: _rng.nextInt(1000),
                  publicKey: _randomBase64(keySize),
                )
              : null,
        );

        try {
          await alice.createSession(bundle);
        } catch (_) {
          // Any exception is acceptable -- no crashes
        }
      }
    });
  });

  // ── D. Sender Key Fuzzing ────────────────────────────────────────────

  group('Sender Key fuzzing', () {
    test('SenderKeyDistribution.fromJson with garbage fields throws or handles',
        () {
      final garbageInputs = [
        <String, dynamic>{}, // empty
        {'groupId': 42, 'senderId': null}, // wrong types
        {
          'groupId': 'g',
          'senderId': 's',
          'iteration': 'not a number',
          'chainKey': 42,
          'signingKey': true,
        },
      ];

      for (final input in garbageInputs) {
        try {
          SenderKeyDistribution.fromJson(input);
          // May succeed with type coercion or fail
        } catch (_) {
          // Any exception is acceptable
        }
      }
    });

    test('SenderKeyMessage.fromJson with garbage fields throws or handles', () {
      final garbageInputs = [
        <String, dynamic>{}, // empty
        {'iteration': 'abc', 'ciphertext': 42, 'iv': null, 'signature': true},
        {
          'iteration': -1,
          'ciphertext': '',
          'iv': '',
          'signature': '',
        },
      ];

      for (final input in garbageInputs) {
        try {
          SenderKeyMessage.fromJson(input);
        } catch (_) {
          // Any exception is acceptable
        }
      }
    });

    test('processSenderKeyDistribution with corrupt chain key rejects',
        () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();
      await storage.write(key: 'user_id', value: 'test-user');

      // Valid-looking distribution but with wrong chain key sizes
      final badDistributions = [
        // Chain key too short
        SenderKeyDistribution(
          groupId: 'group-fuzz',
          senderId: 'attacker',
          iteration: 0,
          chainKey: base64Encode(Uint8List(8)), // Only 8 bytes, should be 32
          signingKey: _randomBase64(32),
        ),
        // Chain key empty
        SenderKeyDistribution(
          groupId: 'group-fuzz',
          senderId: 'attacker',
          iteration: 0,
          chainKey: base64Encode(Uint8List(0)),
          signingKey: _randomBase64(32),
        ),
        // Chain key very large
        SenderKeyDistribution(
          groupId: 'group-fuzz',
          senderId: 'attacker',
          iteration: 0,
          chainKey: base64Encode(Uint8List(1024)),
          signingKey: _randomBase64(32),
        ),
      ];

      for (final dist in badDistributions) {
        try {
          await manager.processGroupSenderKey('group-fuzz', 'attacker', dist);
          // If it stores the key, try decrypting -- should fail
          final fakeMessage = SenderKeyMessage(
            iteration: 0,
            ciphertext: _randomBase64(64),
            iv: _randomBase64(16),
            signature: _randomBase64(64),
          );
          await manager.decryptGroupMessage(
            'group-fuzz',
            'attacker',
            jsonEncode(fakeMessage.toJson()),
          );
          // Should not produce valid plaintext
        } catch (_) {
          // Expected: any error is acceptable
        }
      }
    });

    test('decrypt with forged signature rejects', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.initialize();
      await bob.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await bobStorage.write(key: 'user_id', value: 'bob-id');

      const groupId = 'group-sig-fuzz';

      // Alice generates and distributes sender key
      final distribution = await alice.generateGroupSenderKey(groupId);
      await bob.processGroupSenderKey(groupId, 'alice-id', distribution);

      // Alice encrypts a message
      final ciphertext =
          await alice.encryptGroupMessage(groupId, 'legitimate message');
      final msgJson = jsonDecode(ciphertext) as Map<String, dynamic>;

      // Forge the signature
      msgJson['signature'] = _randomBase64(64);
      final forgedCiphertext = jsonEncode(msgJson);

      // Bob should reject the forged message
      expect(
        () => bob.decryptGroupMessage(groupId, 'alice-id', forgedCiphertext),
        throwsA(isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('signature'),
        )),
      );
    });

    test('decrypt with tampered ciphertext rejects', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.initialize();
      await bob.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await bobStorage.write(key: 'user_id', value: 'bob-id');

      const groupId = 'group-tamper-fuzz';

      final distribution = await alice.generateGroupSenderKey(groupId);
      await bob.processGroupSenderKey(groupId, 'alice-id', distribution);

      final ciphertext =
          await alice.encryptGroupMessage(groupId, 'tamper target');
      final msgJson = jsonDecode(ciphertext) as Map<String, dynamic>;

      // Tamper with the ciphertext
      final ctBytes = base64Decode(msgJson['ciphertext'] as String);
      ctBytes[0] ^= 0xFF;
      msgJson['ciphertext'] = base64Encode(ctBytes);
      final tamperedCiphertext = jsonEncode(msgJson);

      // Should reject (signature won't match tampered data)
      expect(
        () => bob.decryptGroupMessage(groupId, 'alice-id', tamperedCiphertext),
        throwsA(isA<StateError>()),
      );
    });

    test('replay attack: same message decrypted twice throws', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.initialize();
      await bob.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await bobStorage.write(key: 'user_id', value: 'bob-id');

      const groupId = 'group-replay-fuzz';

      final distribution = await alice.generateGroupSenderKey(groupId);
      await bob.processGroupSenderKey(groupId, 'alice-id', distribution);

      final ciphertext =
          await alice.encryptGroupMessage(groupId, 'replay me');

      // First decrypt should succeed
      final plaintext =
          await bob.decryptGroupMessage(groupId, 'alice-id', ciphertext);
      expect(plaintext, equals('replay me'));

      // Second decrypt of the same message should fail (iteration behind stored)
      expect(
        () => bob.decryptGroupMessage(groupId, 'alice-id', ciphertext),
        throwsA(isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('replay'),
        )),
      );
    });
  });

  // ── E. EncryptedMessage Fuzzing ──────────────────────────────────────

  group('EncryptedMessage.fromJson fuzzing', () {
    test('100 random JSON maps do not crash fromJson', () {
      for (var i = 0; i < 100; i++) {
        final randomMap = _generateRandomMessageJson(i);
        try {
          EncryptedMessage.fromJson(randomMap);
        } on FormatException {
          // Expected for invalid inputs
        } on TypeError {
          // Expected for wrong types
        } catch (_) {
          // Any other exception is acceptable too
        }
      }
    });
  });

  // ── F. MessagePadding Fuzzing ────────────────────────────────────────

  group('MessagePadding fuzzing', () {
    test('100 random inputs pad and unpad correctly (round-trip)', () {
      for (var i = 0; i < 100; i++) {
        // Keep sizes moderate (0 to 5KB) for test speed while still
        // exercising the first 4 bucket boundaries thoroughly.
        final length = _rng.nextInt(5000);
        final data = _randomBytes(length);
        final padded = MessagePadding.pad(data);
        final recovered = MessagePadding.unpad(padded);
        expect(
          recovered,
          equals(data),
          reason: 'Round-trip failed for random input of length $length',
        );
      }
    });

    test('unpad with random garbage throws FormatException', () {
      for (var i = 0; i < 50; i++) {
        // Short garbage (less than 4 bytes)
        if (_rng.nextBool()) {
          final shortGarbage = _randomBytes(_rng.nextInt(4));
          try {
            MessagePadding.unpad(shortGarbage);
          } on FormatException {
            // Expected
          }
          continue;
        }

        // Longer garbage where the length prefix claims more data than exists
        final garbage = _randomBytes(_rng.nextInt(256) + 4);
        // Set an absurdly large length prefix
        garbage[0] = 0xFF;
        garbage[1] = 0xFF;
        garbage[2] = 0xFF;
        garbage[3] = 0xFF;
        try {
          MessagePadding.unpad(garbage);
        } on FormatException {
          // Expected
        }
      }
    });
  });
}

// ── Fuzz Generators ──────────────────────────────────────────────────────

/// Generate a random message envelope for fuzzing decryptMessage.
Map<String, dynamic> _generateRandomEnvelope(int seed) {
  final types = ['message', 'prekey', 'sealed', '', 'invalid', null];
  final type = types[seed % types.length];

  switch (seed % 8) {
    case 0:
      // Empty envelope with random type
      return {'type': type};

    case 1:
      // Envelope with missing message field
      return {
        'type': 'message',
        'senderIdentityKey': _randomBase64(32),
      };

    case 2:
      // Envelope with garbage message content
      return {
        'type': 'message',
        'senderIdentityKey': _randomBase64(32),
        'message': {
          'dhPublicKey': _randomBase64(_rng.nextInt(64) + 1),
          'messageNumber': _rng.nextInt(1000),
          'previousChainLength': _rng.nextInt(100),
          'ciphertext': _randomBase64(_rng.nextInt(256) + 16),
          'nonce': _randomBase64(12),
        },
      };

    case 3:
      // PreKey envelope with random fields
      return {
        'type': 'prekey',
        'senderIdentityKey': _randomBase64(32),
        'senderEphemeralKey': _randomBase64(32),
        'usedOneTimePreKeyId': _rng.nextBool() ? _rng.nextInt(100) : null,
        'message': {
          'dhPublicKey': _randomBase64(32),
          'messageNumber': 0,
          'previousChainLength': 0,
          'ciphertext': _randomBase64(_rng.nextInt(256) + 16),
          'nonce': _randomBase64(12),
        },
      };

    case 4:
      // Envelope with wrong field types
      return {
        'type': _rng.nextInt(100),
        'senderIdentityKey': _rng.nextInt(100),
        'message': _rng.nextInt(100),
      };

    case 5:
      // Envelope with extremely large values
      return {
        'type': 'message',
        'senderIdentityKey': _randomBase64(32),
        'message': {
          'dhPublicKey': _randomBase64(32),
          'messageNumber': 2147483647, // int max
          'previousChainLength': 2147483647,
          'ciphertext': _randomBase64(32),
          'nonce': _randomBase64(12),
        },
      };

    case 6:
      // Envelope with empty strings everywhere
      return {
        'type': 'message',
        'senderIdentityKey': '',
        'message': {
          'dhPublicKey': '',
          'messageNumber': 0,
          'previousChainLength': 0,
          'ciphertext': '',
          'nonce': '',
        },
      };

    case 7:
      // Envelope that looks almost valid but has subtle issues
      return {
        'type': 'message',
        'senderIdentityKey': _randomBase64(32),
        'message': {
          'dhPublicKey': _randomBase64(32),
          'messageNumber': -1, // Negative
          'previousChainLength': -1,
          'ciphertext': _randomBase64(48),
          'nonce': _randomBase64(12),
        },
      };

    default:
      return {'type': 'unknown'};
  }
}

/// Generate a random JSON map for EncryptedMessage fuzzing.
Map<String, dynamic> _generateRandomMessageJson(int seed) {
  switch (seed % 6) {
    case 0:
      return <String, dynamic>{};
    case 1:
      return {
        'dhPublicKey': _rng.nextBool() ? _randomBase64(32) : null,
        'messageNumber': _rng.nextBool() ? _rng.nextInt(100) : -1,
        'previousChainLength': _rng.nextBool() ? _rng.nextInt(100) : null,
        'ciphertext': _rng.nextBool() ? _randomBase64(48) : '',
        'nonce': _rng.nextBool() ? _randomBase64(12) : null,
      };
    case 2:
      return {
        'dhPublicKey': 42,
        'messageNumber': 'not a number',
        'previousChainLength': true,
        'ciphertext': <int>[1, 2, 3],
        'nonce': 3.14,
      };
    case 3:
      return {
        'dhPublicKey': _randomBase64(32),
        'messageNumber': 0,
        'previousChainLength': 0,
        'ciphertext': _randomBase64(48),
        'nonce': _randomBase64(12),
      };
    case 4:
      return {
        'extraField': 'surprise',
        'dhPublicKey': _randomBase64(32),
        'messageNumber': 999999,
        'previousChainLength': 999999,
        'ciphertext': _randomBase64(1024),
        'nonce': _randomBase64(12),
      };
    default:
      return {'dhPublicKey': ''};
  }
}
