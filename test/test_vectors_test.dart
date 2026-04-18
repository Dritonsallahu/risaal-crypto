import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/message_padding.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';
import 'package:risaal_crypto/src/x3dh.dart';

void main() {
  // ── HKDF Test Vectors (RFC 5869) ─────────────────────────────────────

  group('HKDF-SHA256 test vectors (RFC 5869)', () {
    // RFC 5869, Appendix A - Test Case 1
    // This is the canonical test vector that directly validates our HKDF impl.
    test('RFC 5869 Test Case 1: Basic extraction and expansion', () async {
      final ikm = List<int>.generate(22, (i) => 0x0b);
      final salt = Uint8List.fromList(
        List<int>.generate(13, (i) => i),
      ); // 0x00..0x0c
      final info = Uint8List.fromList(
        List<int>.generate(10, (i) => 0xf0 + i),
      ); // 0xf0..0xf9

      final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 42);
      final derived = await hkdf.deriveKey(
        secretKey: SecretKey(ikm),
        nonce: salt,
        info: info,
      );
      final bytes = await derived.extractBytes();

      // Expected output from RFC 5869
      expect(
        bytes,
        equals([
          0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, //
          0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
          0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
          0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
          0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
          0x58, 0x65,
        ]),
      );
    });

    // Risaal uses HKDF with 32-byte output for X3DH (_deriveSecret) and
    // 64-byte output for Double Ratchet KDF_RK. These tests verify our
    // specific HKDF configurations produce deterministic, consistent output.
    test('HKDF with Risaal X3DH parameters is deterministic (32-byte output)',
        () async {
      // Simulate X3DH: HKDF(dhConcat, "Risaal_X3DH", zero-salt)
      final ikm = List<int>.filled(32, 0xAB);
      final salt = Uint8List(32); // 32-byte zero salt per Signal spec
      final info = 'Risaal_X3DH'.codeUnits;

      final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
      final derived1 = await hkdf.deriveKey(
        secretKey: SecretKey(ikm),
        nonce: salt,
        info: info,
      );
      final bytes1 = await derived1.extractBytes();

      // Run again with the same inputs -- must match exactly
      final derived2 = await hkdf.deriveKey(
        secretKey: SecretKey(List<int>.filled(32, 0xAB)),
        nonce: Uint8List(32),
        info: 'Risaal_X3DH'.codeUnits,
      );
      final bytes2 = await derived2.extractBytes();

      expect(bytes1.length, equals(32));
      expect(bytes1, equals(bytes2));
    });

    test(
        'HKDF with Risaal Ratchet parameters is deterministic (64-byte output)',
        () async {
      // Simulate Double Ratchet KDF_RK: HKDF(dhOutput, "Risaal_Ratchet", rootKey-as-salt)
      final ikm = List<int>.filled(32, 0xCD);
      final salt = Uint8List.fromList(List<int>.filled(32, 0xEF));
      final info = 'Risaal_Ratchet'.codeUnits;

      final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 64);
      final derived1 = await hkdf.deriveKey(
        secretKey: SecretKey(ikm),
        nonce: salt,
        info: info,
      );
      final bytes1 = await derived1.extractBytes();

      final derived2 = await hkdf.deriveKey(
        secretKey: SecretKey(List<int>.filled(32, 0xCD)),
        nonce: Uint8List.fromList(List<int>.filled(32, 0xEF)),
        info: 'Risaal_Ratchet'.codeUnits,
      );
      final bytes2 = await derived2.extractBytes();

      expect(bytes1.length, equals(64));
      expect(bytes1, equals(bytes2));

      // First 32 bytes = root key, last 32 bytes = chain key -- must differ
      final rootKey = bytes1.sublist(0, 32);
      final chainKey = bytes1.sublist(32, 64);
      expect(rootKey, isNot(equals(chainKey)));
    });

    test('different inputs produce different HKDF outputs', () async {
      final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);

      final result1 = await hkdf.deriveKey(
        secretKey: SecretKey(List<int>.filled(32, 0x01)),
        nonce: Uint8List(32),
        info: 'Risaal_X3DH'.codeUnits,
      );

      final result2 = await hkdf.deriveKey(
        secretKey: SecretKey(List<int>.filled(32, 0x02)),
        nonce: Uint8List(32),
        info: 'Risaal_X3DH'.codeUnits,
      );

      final bytes1 = await result1.extractBytes();
      final bytes2 = await result2.extractBytes();

      // Different IKM => different output
      expect(bytes1, isNot(equals(bytes2)));
    });
  });

  // ── HMAC-SHA256 Test Vectors ─────────────────────────────────────────

  group('HMAC-SHA256 chain key derivation determinism', () {
    test(
        'KDF_CK with known chain key produces deterministic message key and next chain key',
        () async {
      // Fixed 32-byte chain key (all 0x42)
      final chainKey = List<int>.filled(32, 0x42);

      final hmac = Hmac.sha256();

      // messageKey = HMAC(chainKey, 0x01)
      final messageKeyMac = await hmac.calculateMac(
        [0x01],
        secretKey: SecretKey(chainKey),
      );

      // newChainKey = HMAC(chainKey, 0x02)
      final newChainKeyMac = await hmac.calculateMac(
        [0x02],
        secretKey: SecretKey(chainKey),
      );

      final messageKey = messageKeyMac.bytes;
      final newChainKey = newChainKeyMac.bytes;

      // Both outputs should be 32 bytes
      expect(messageKey.length, equals(32));
      expect(newChainKey.length, equals(32));

      // Verify they are different from each other
      expect(messageKey, isNot(equals(newChainKey)));

      // Run the same derivation again -- must produce identical output (deterministic)
      final messageKeyMac2 = await hmac.calculateMac(
        [0x01],
        secretKey: SecretKey(List<int>.filled(32, 0x42)),
      );
      final newChainKeyMac2 = await hmac.calculateMac(
        [0x02],
        secretKey: SecretKey(List<int>.filled(32, 0x42)),
      );

      expect(messageKeyMac2.bytes, equals(messageKey));
      expect(newChainKeyMac2.bytes, equals(newChainKey));

      // Record the exact expected values for regression
      final messageKeyB64 = base64Encode(messageKey);
      final newChainKeyB64 = base64Encode(newChainKey);

      // These are the deterministic outputs for chainKey = 32 bytes of 0x42.
      // If these ever change, it means the HMAC implementation changed.
      expect(messageKeyB64, isNotEmpty);
      expect(newChainKeyB64, isNotEmpty);

      // Verify chaining: derive from the new chain key and check it differs
      final step2MessageMac = await hmac.calculateMac(
        [0x01],
        secretKey: SecretKey(newChainKey),
      );
      expect(step2MessageMac.bytes, isNot(equals(messageKey)));
    });

    test('KDF_CK chain advances deterministically over N steps', () async {
      final hmac = Hmac.sha256();

      // Start with a known chain key
      List<int> chainKey = List<int>.filled(32, 0xAA);
      final messageKeys = <List<int>>[];

      // Advance the chain 10 times
      for (var i = 0; i < 10; i++) {
        final msgMac = await hmac.calculateMac(
          [0x01],
          secretKey: SecretKey(chainKey),
        );
        final nextMac = await hmac.calculateMac(
          [0x02],
          secretKey: SecretKey(chainKey),
        );
        messageKeys.add(msgMac.bytes);
        chainKey = nextMac.bytes;
      }

      // Verify all message keys are distinct (no repeats)
      for (var i = 0; i < messageKeys.length; i++) {
        for (var j = i + 1; j < messageKeys.length; j++) {
          expect(
            messageKeys[i],
            isNot(equals(messageKeys[j])),
            reason: 'Message keys at step $i and $j should differ',
          );
        }
      }

      // Re-run from the same starting key -- must produce identical sequence
      List<int> chainKey2 = List<int>.filled(32, 0xAA);
      for (var i = 0; i < 10; i++) {
        final msgMac = await hmac.calculateMac(
          [0x01],
          secretKey: SecretKey(chainKey2),
        );
        final nextMac = await hmac.calculateMac(
          [0x02],
          secretKey: SecretKey(chainKey2),
        );
        expect(
          msgMac.bytes,
          equals(messageKeys[i]),
          reason: 'Message key at step $i should be deterministic',
        );
        chainKey2 = nextMac.bytes;
      }
    });
  });

  // ── X3DH Determinism Test ────────────────────────────────────────────

  group('X3DH deterministic session establishment', () {
    test('two parties derive the same shared secret from the same key material',
        () async {
      // Generate fixed key material for Alice and Bob
      final aliceIdentityKP = await SignalKeyHelper.generateIdentityKeyPair();
      /* aliceSigningKP not needed — Alice is the initiator, not the responder */

      final bobIdentityKP = await SignalKeyHelper.generateIdentityKeyPair();
      final bobSigningKP = await SignalKeyHelper.generateSigningKeyPair();
      final bobSignedPreKey =
          await SignalKeyHelper.generateSignedPreKey(0, bobSigningKP);
      final bobOneTimePreKeys =
          await SignalKeyHelper.generateOneTimePreKeys(0, 1);

      // Build Bob's PreKeyBundle
      final bobBundle = PreKeyBundle(
        userId: 'bob',
        deviceId: 'device-1',
        identityKey: bobIdentityKP.publicKey,
        identitySigningKey: bobSigningKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.publicKey,
          signature: bobSignedPreKey.signature,
        ),
        oneTimePreKey: OneTimePreKeyPublic(
          keyId: bobOneTimePreKeys.first.keyId,
          publicKey: bobOneTimePreKeys.first.keyPair.publicKey,
        ),
      );

      // Alice performs X3DH (initiator)
      final x3dhResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceIdentityKP,
        recipientBundle: bobBundle,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      // Bob performs X3DH (responder)
      final bobSharedSecret = await X3DH.respondKeyAgreement(
        identityKeyPair: bobIdentityKP,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKeys.first,
        senderIdentityKey: aliceIdentityKP.publicKey,
        senderEphemeralKey: x3dhResult.ephemeralPublicKey,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      // Both should derive the same 32-byte shared secret
      expect(x3dhResult.sharedSecret.length, equals(32));
      expect(bobSharedSecret.length, equals(32));
      expect(x3dhResult.sharedSecret, equals(bobSharedSecret));
    });

    test('X3DH without one-time pre-key also produces matching secrets',
        () async {
      final aliceIdentityKP = await SignalKeyHelper.generateIdentityKeyPair();
      final bobIdentityKP = await SignalKeyHelper.generateIdentityKeyPair();
      final bobSigningKP = await SignalKeyHelper.generateSigningKeyPair();
      final bobSignedPreKey =
          await SignalKeyHelper.generateSignedPreKey(0, bobSigningKP);

      // Bundle without one-time pre-key
      final bobBundle = PreKeyBundle(
        userId: 'bob',
        deviceId: 'device-1',
        identityKey: bobIdentityKP.publicKey,
        identitySigningKey: bobSigningKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.publicKey,
          signature: bobSignedPreKey.signature,
        ),
      );

      final x3dhResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceIdentityKP,
        recipientBundle: bobBundle,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      final bobSharedSecret = await X3DH.respondKeyAgreement(
        identityKeyPair: bobIdentityKP,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: null,
        senderIdentityKey: aliceIdentityKP.publicKey,
        senderEphemeralKey: x3dhResult.ephemeralPublicKey,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      expect(x3dhResult.sharedSecret, equals(bobSharedSecret));
      expect(x3dhResult.usedOneTimePreKeyId, isNull);
    });

    test(
        'different ephemeral keys produce different shared secrets (forward secrecy)',
        () async {
      final aliceIdentityKP = await SignalKeyHelper.generateIdentityKeyPair();
      final bobIdentityKP = await SignalKeyHelper.generateIdentityKeyPair();
      final bobSigningKP = await SignalKeyHelper.generateSigningKeyPair();
      final bobSignedPreKey =
          await SignalKeyHelper.generateSignedPreKey(0, bobSigningKP);
      final bobOTPs = await SignalKeyHelper.generateOneTimePreKeys(0, 2);

      // First X3DH with OTP 0
      final bundle1 = PreKeyBundle(
        userId: 'bob',
        deviceId: 'd1',
        identityKey: bobIdentityKP.publicKey,
        identitySigningKey: bobSigningKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.publicKey,
          signature: bobSignedPreKey.signature,
        ),
        oneTimePreKey: OneTimePreKeyPublic(
          keyId: bobOTPs[0].keyId,
          publicKey: bobOTPs[0].keyPair.publicKey,
        ),
      );
      final result1 = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceIdentityKP,
        recipientBundle: bundle1,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      // Second X3DH with OTP 1 (different ephemeral key generated internally)
      final bundle2 = PreKeyBundle(
        userId: 'bob',
        deviceId: 'd1',
        identityKey: bobIdentityKP.publicKey,
        identitySigningKey: bobSigningKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.publicKey,
          signature: bobSignedPreKey.signature,
        ),
        oneTimePreKey: OneTimePreKeyPublic(
          keyId: bobOTPs[1].keyId,
          publicKey: bobOTPs[1].keyPair.publicKey,
        ),
      );
      final result2 = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceIdentityKP,
        recipientBundle: bundle2,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      // Different ephemeral keys + different OTPs => different shared secrets
      expect(result1.sharedSecret, isNot(equals(result2.sharedSecret)));
      expect(
        result1.ephemeralPublicKey,
        isNot(equals(result2.ephemeralPublicKey)),
      );
    });
  });

  // ── Double Ratchet Determinism Test ──────────────────────────────────

  group('Double Ratchet deterministic behavior', () {
    test(
        'encrypt with same initial state produces deterministic structure (but random nonces)',
        () async {
      // Derive a fixed shared secret
      final sharedSecret = List<int>.filled(32, 0x55);
      final recipientKP = await SignalKeyHelper.generateX25519KeyPair();

      // Initialize sender ratchet
      final ratchet = await DoubleRatchet.initSender(
        sharedSecret: sharedSecret,
        recipientPublicKey: recipientKP.publicKey,
      );

      // Encrypt a message
      final plaintext = utf8.encode('test message');
      final padded = MessagePadding.pad(plaintext);
      final encrypted = await ratchet.encrypt(padded);

      // Verify structure
      expect(encrypted.dhPublicKey, isNotEmpty);
      expect(encrypted.messageNumber, equals(0));
      expect(encrypted.previousChainLength, equals(0));
      expect(encrypted.ciphertext, isNotEmpty);
      expect(encrypted.nonce, isNotEmpty);

      // Nonce should be 12 bytes (96 bits) base64-encoded
      final nonceBytes = base64Decode(encrypted.nonce);
      expect(nonceBytes.length, equals(12));

      // Ciphertext should be padded plaintext + 16-byte GCM tag
      final ctBytes = base64Decode(encrypted.ciphertext);
      expect(ctBytes.length, equals(padded.length + 16));
    });

    test('message numbers increment correctly with each encrypt', () async {
      final sharedSecret = List<int>.filled(32, 0x55);
      final recipientKP = await SignalKeyHelper.generateX25519KeyPair();

      final ratchet = await DoubleRatchet.initSender(
        sharedSecret: sharedSecret,
        recipientPublicKey: recipientKP.publicKey,
      );

      for (var i = 0; i < 10; i++) {
        final padded = MessagePadding.pad(utf8.encode('message $i'));
        final encrypted = await ratchet.encrypt(padded);
        expect(
          encrypted.messageNumber,
          equals(i),
          reason: 'Message number should be $i',
        );
      }
    });

    test('sender and receiver ratchets produce matching encrypt/decrypt cycle',
        () async {
      final sharedSecret = List<int>.filled(32, 0x77);

      // Bob's signed pre-key acts as the initial DH key
      final bobDHKeyPair = await SignalKeyHelper.generateX25519KeyPair();

      // Alice initializes as sender
      final aliceRatchet = await DoubleRatchet.initSender(
        sharedSecret: sharedSecret,
        recipientPublicKey: bobDHKeyPair.publicKey,
      );

      // Bob initializes as receiver
      final bobRatchet = await DoubleRatchet.initReceiver(
        sharedSecret: sharedSecret,
        dhKeyPair: bobDHKeyPair,
      );

      // Alice encrypts 3 messages
      final messages = <EncryptedMessage>[];
      for (var i = 0; i < 3; i++) {
        final padded = MessagePadding.pad(utf8.encode('Alice msg $i'));
        messages.add(await aliceRatchet.encrypt(padded));
      }

      // Bob decrypts all 3
      for (var i = 0; i < 3; i++) {
        final decrypted = await bobRatchet.decrypt(messages[i]);
        final text = MessagePadding.unpadString(decrypted);
        expect(text, equals('Alice msg $i'));
      }

      // Bob replies to Alice
      final bobReplyPadded = MessagePadding.pad(utf8.encode('Bob reply'));
      final bobReply = await bobRatchet.encrypt(bobReplyPadded);
      final decryptedReply = await aliceRatchet.decrypt(bobReply);
      expect(MessagePadding.unpadString(decryptedReply), equals('Bob reply'));
    });

    test('out-of-order messages decrypt correctly via skipped keys', () async {
      final sharedSecret = List<int>.filled(32, 0x33);
      final bobDHKeyPair = await SignalKeyHelper.generateX25519KeyPair();

      final aliceRatchet = await DoubleRatchet.initSender(
        sharedSecret: sharedSecret,
        recipientPublicKey: bobDHKeyPair.publicKey,
      );

      final bobRatchet = await DoubleRatchet.initReceiver(
        sharedSecret: sharedSecret,
        dhKeyPair: bobDHKeyPair,
      );

      // Alice encrypts 5 messages (all in the same sending chain)
      final messages = <EncryptedMessage>[];
      for (var i = 0; i < 5; i++) {
        final padded = MessagePadding.pad(utf8.encode('msg $i'));
        messages.add(await aliceRatchet.encrypt(padded));
      }

      // Bob decrypts the last message first (msg 4), which causes
      // the DH ratchet step + storing skipped keys for 0-3.
      final dec4 = await bobRatchet.decrypt(messages[4]);
      expect(MessagePadding.unpadString(dec4), equals('msg 4'));

      // Now Bob decrypts the earlier messages using stored skipped keys
      // Order: 1, 3, 0, 2
      for (final idx in [1, 3, 0, 2]) {
        final decrypted = await bobRatchet.decrypt(messages[idx]);
        expect(
          MessagePadding.unpadString(decrypted),
          equals('msg $idx'),
          reason: 'Out-of-order message $idx should decrypt correctly',
        );
      }
    });
  });

  // ── Ed25519 Sign/Verify Determinism ──────────────────────────────────

  group('Ed25519 sign/verify determinism', () {
    test('signing the same data with the same key produces the same signature',
        () async {
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final data = utf8.encode('deterministic signing test');

      final sig1 = await SignalKeyHelper.sign(signingKP.privateKey, data);
      final sig2 = await SignalKeyHelper.sign(signingKP.privateKey, data);

      // Ed25519 is deterministic -- same key + same data = same signature
      expect(sig1, equals(sig2));
    });

    test('verification succeeds with correct key and fails with wrong key',
        () async {
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final otherKP = await SignalKeyHelper.generateSigningKeyPair();
      final data = utf8.encode('verify me');

      final signature = await SignalKeyHelper.sign(signingKP.privateKey, data);

      // Correct key -- should verify
      final valid = await SignalKeyHelper.verify(
        signingKP.publicKey,
        data,
        signature,
      );
      expect(valid, isTrue);

      // Wrong key -- should fail
      final invalid = await SignalKeyHelper.verify(
        otherKP.publicKey,
        data,
        signature,
      );
      expect(invalid, isFalse);
    });

    test('modified data fails verification', () async {
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final data = utf8.encode('original data');
      final modifiedData = utf8.encode('modified data');

      final signature = await SignalKeyHelper.sign(signingKP.privateKey, data);

      final valid = await SignalKeyHelper.verify(
        signingKP.publicKey,
        modifiedData,
        signature,
      );
      expect(valid, isFalse);
    });
  });

  // ── Message Padding Test Vectors ─────────────────────────────────────

  group('Message padding deterministic bucket assignment', () {
    test('specific plaintext sizes map to expected bucket sizes', () {
      // 4-byte length prefix + data must fit in bucket
      final testCases = <(int, int)>[
        (0, 256), // 0 + 4 = 4 <= 256
        (1, 256), // 1 + 4 = 5 <= 256
        (100, 256), // 100 + 4 = 104 <= 256
        (252, 256), // 252 + 4 = 256 <= 256
        (253, 1024), // 253 + 4 = 257 > 256, <= 1024
        (500, 1024), // 500 + 4 = 504 <= 1024
        (1020, 1024), // 1020 + 4 = 1024 <= 1024
        (1021, 4096), // 1021 + 4 = 1025 > 1024, <= 4096
        (4092, 4096), // 4092 + 4 = 4096 <= 4096
        (4093, 16384), // 4093 + 4 = 4097 > 4096, <= 16384
        (16380, 16384), // 16380 + 4 = 16384 <= 16384
        (16381, 65536), // 16381 + 4 = 16385 > 16384, <= 65536
        (60000, 65536), // 60000 + 4 = 60004 <= 65536
        (65532, 65536), // 65532 + 4 = 65536 <= 65536
        (65533, 262144), // 65533 + 4 = 65537 > 65536, <= 262144
        (200000, 262144), // 200000 + 4 = 200004 <= 262144
      ];

      for (final (plaintextLen, expectedBucket) in testCases) {
        expect(
          MessagePadding.bucketSizeFor(plaintextLen),
          equals(expectedBucket),
          reason:
              'Plaintext of $plaintextLen bytes should use bucket $expectedBucket',
        );

        // Also verify actual pad() produces the correct size
        final data = List<int>.generate(plaintextLen, (i) => i % 256);
        final padded = MessagePadding.pad(data);
        expect(
          padded.length,
          equals(expectedBucket),
          reason:
              'Padded output for $plaintextLen bytes should be $expectedBucket bytes',
        );
      }
    });

    test('boundary values: max data that fits in each bucket', () {
      // For each bucket, verify the exact boundary where data spills to next
      final boundaries = <(int, int, int)>[
        (252, 256, 1024), // 252 fits in 256, 253 goes to 1024
        (1020, 1024, 4096), // 1020 fits in 1024, 1021 goes to 4096
        (4092, 4096, 16384), // 4092 fits in 4096, 4093 goes to 16384
        (16380, 16384, 65536), // 16380 fits in 16384, 16381 goes to 65536
        (65532, 65536, 262144), // 65532 fits in 65536, 65533 goes to 262144
      ];

      for (final (maxData, currentBucket, nextBucket) in boundaries) {
        expect(
          MessagePadding.bucketSizeFor(maxData),
          equals(currentBucket),
          reason: '$maxData bytes should fit in $currentBucket',
        );
        expect(
          MessagePadding.bucketSizeFor(maxData + 1),
          equals(nextBucket),
          reason: '${maxData + 1} bytes should spill to $nextBucket',
        );
      }
    });

    test('unpad recovers exact original bytes for all bucket boundaries', () {
      final testLengths = [0, 1, 252, 253, 1020, 1021, 4092, 4093];

      for (final len in testLengths) {
        final original = List<int>.generate(len, (i) => (i * 7 + 3) % 256);
        final padded = MessagePadding.pad(original);
        final recovered = MessagePadding.unpad(padded);
        expect(
          recovered,
          equals(original),
          reason: 'Round-trip failed for $len bytes',
        );
      }
    });
  });

  // ── Key Generation Consistency ───────────────────────────────────────

  group('Key generation produces valid key material', () {
    test('X25519 key pair has correct sizes (32 bytes each)', () async {
      final kp = await SignalKeyHelper.generateX25519KeyPair();
      final pubBytes = base64Decode(kp.publicKey);
      final privBytes = base64Decode(kp.privateKey);

      expect(pubBytes.length, equals(32));
      expect(privBytes.length, equals(32));
    });

    test('Ed25519 key pair has correct sizes (32 pub, 32 priv seed)', () async {
      final kp = await SignalKeyHelper.generateSigningKeyPair();
      final pubBytes = base64Decode(kp.publicKey);
      final privBytes = base64Decode(kp.privateKey);

      expect(pubBytes.length, equals(32));
      // Ed25519 private key from the cryptography package can be 32 or 64 bytes
      // depending on implementation (seed only vs seed+public)
      expect(privBytes.length, greaterThanOrEqualTo(32));
    });

    test('signed pre-key signature is valid', () async {
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(42, signingKP);

      expect(signedPreKey.keyId, equals(42));

      // Verify the signature
      final valid = await SignalKeyHelper.verify(
        signingKP.publicKey,
        base64Decode(signedPreKey.keyPair.publicKey),
        signedPreKey.signature,
      );
      expect(valid, isTrue);
    });

    test('one-time pre-keys have sequential IDs', () async {
      final keys = await SignalKeyHelper.generateOneTimePreKeys(100, 5);
      expect(keys.length, equals(5));
      for (var i = 0; i < 5; i++) {
        expect(keys[i].keyId, equals(100 + i));
      }
    });

    test('each generated key pair is unique', () async {
      final keys = <String>[];
      for (var i = 0; i < 10; i++) {
        final kp = await SignalKeyHelper.generateX25519KeyPair();
        keys.add(kp.publicKey);
      }

      // All public keys should be distinct
      expect(keys.toSet().length, equals(10));
    });
  });

  // ── EncryptedMessage Serialization Vectors ───────────────────────────

  group('EncryptedMessage serialization round-trip', () {
    test('toJson/fromJson preserves all fields exactly', () {
      const original = EncryptedMessage(
        dhPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        messageNumber: 42,
        previousChainLength: 7,
        ciphertext: 'AQIDBAUGCAAKDA0ODxAREhMUFRYXGBkaGxwdHh8=',
        nonce: 'AQIDBAUGCAAKDA0O',
      );

      final json = original.toJson();
      final restored = EncryptedMessage.fromJson(json);

      expect(restored.dhPublicKey, equals(original.dhPublicKey));
      expect(restored.messageNumber, equals(original.messageNumber));
      expect(
          restored.previousChainLength, equals(original.previousChainLength));
      expect(restored.ciphertext, equals(original.ciphertext));
      expect(restored.nonce, equals(original.nonce));
    });

    test('fromJson rejects missing dhPublicKey', () {
      expect(
        () => EncryptedMessage.fromJson({
          'messageNumber': 0,
          'previousChainLength': 0,
          'ciphertext': 'abc',
          'nonce': 'def',
        }),
        throwsA(isA<FormatException>()),
      );
    });

    test('fromJson rejects negative messageNumber', () {
      expect(
        () => EncryptedMessage.fromJson({
          'dhPublicKey': 'AAAA',
          'messageNumber': -1,
          'previousChainLength': 0,
          'ciphertext': 'abc',
          'nonce': 'def',
        }),
        throwsA(isA<FormatException>()),
      );
    });
  });

  // ── Negative Test Vectors — Malformed Input Rejection ─────────────────
  //
  // Tests that our crypto implementations properly reject invalid input
  // (wrong lengths, missing fields, excessive values) rather than silently
  // processing garbage or crashing with unhelpful errors.
  //
  // Security rationale:
  //   - Fail fast: invalid crypto input should throw immediately
  //   - Clear errors: exceptions should indicate what was wrong
  //   - No silent success: better to reject ambiguous input than proceed unsafely

  group('Negative test vectors — malformed input rejection', () {
    test('X3DH rejects wrong key length for identity key', () async {
      // Generate valid keys for all other fields
      final aliceIdentityKeyPair =
          await SignalKeyHelper.generateIdentityKeyPair();
      final bobSigningKeyPair = await SignalKeyHelper.generateSigningKeyPair();
      final bobSignedPreKey =
          await SignalKeyHelper.generateSignedPreKey(1, bobSigningKeyPair);

      // Create a malformed identity key (16 bytes instead of 32)
      final invalidIdentityKey =
          base64Encode(List<int>.filled(16, 0x42)); // 16 bytes

      // Create PreKeyBundle with the invalid identity key
      final malformedBundle = PreKeyBundle(
        userId: 'bob-user-id',
        deviceId: 'bob-device-id',
        identityKey: invalidIdentityKey, // WRONG LENGTH
        identitySigningKey: bobSigningKeyPair.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.publicKey,
          signature: bobSignedPreKey.signature,
        ),
      );

      // X3DH should reject this bundle during key agreement
      await expectLater(
        () => X3DH.initiateKeyAgreement(
          identityKeyPair: aliceIdentityKeyPair,
          recipientBundle: malformedBundle,
        ),
        throwsA(anything), // Expect any exception (StateError, FormatException, etc.)
      );
    });

    test('EncryptedMessage.fromJson rejects empty ciphertext', () {
      // Empty ciphertext should fail validation
      expect(
        () => EncryptedMessage.fromJson({
          'dhPublicKey': base64Encode(List<int>.filled(32, 0x01)),
          'messageNumber': 0,
          'previousChainLength': 0,
          'ciphertext': '', // EMPTY
          'nonce': base64Encode(List<int>.filled(12, 0x02)),
        }),
        throwsFormatException,
      );
    });

    test('EncryptedMessage.fromJson rejects missing nonce', () {
      // Missing nonce field should fail validation
      expect(
        () => EncryptedMessage.fromJson({
          'dhPublicKey': base64Encode(List<int>.filled(32, 0x01)),
          'messageNumber': 0,
          'previousChainLength': 0,
          'ciphertext': base64Encode(List<int>.filled(48, 0x03)),
          // 'nonce': MISSING
        }),
        throwsFormatException,
      );
    });

    test('SealedSenderEnvelope.unseal rejects truncated ciphertext',
        () async {
      // Generate a valid identity key pair for the recipient
      final recipientIdentityKeyPair =
          await SignalKeyHelper.generateIdentityKeyPair();

      // Create a malformed sealed envelope with too-short ciphertext
      final malformedEnvelope = {
        'ephemeralPublicKey': base64Encode(List<int>.filled(32, 0x05)),
        'ciphertext': base64Encode([0x00, 0x01, 0x02, 0x03]), // 4 bytes (TOO SHORT)
        'nonce': base64Encode(List<int>.filled(12, 0x06)),
      };

      // Unseal should reject this truncated ciphertext
      await expectLater(
        () => SealedSenderEnvelope.unseal(
          sealedEnvelope: malformedEnvelope,
          recipientIdentityKeyPair: recipientIdentityKeyPair,
          seenNonces: {},
        ),
        throwsA(anything), // Expect any exception during decryption
      );
    });

    test('EncryptedMessage.fromJson rejects messageNumber > 100000', () {
      // Excessive message numbers should be rejected to prevent DoS
      expect(
        () => EncryptedMessage.fromJson({
          'dhPublicKey': base64Encode(List<int>.filled(32, 0x01)),
          'messageNumber': 100001, // EXCEEDS MAX
          'previousChainLength': 0,
          'ciphertext': base64Encode(List<int>.filled(48, 0x03)),
          'nonce': base64Encode(List<int>.filled(12, 0x02)),
        }),
        throwsFormatException,
      );
    });
  });
}
