import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// Establish a full bidirectional session between Alice and Bob.
///
/// Returns after both sides have an active session:
/// 1. Alice creates session from Bob's bundle (X3DH initiator).
/// 2. Alice encrypts a prekey message.
/// 3. Bob decrypts it (X3DH responder) -- this establishes Bob's session.
Future<
  ({
    SignalProtocolManager alice,
    FakeSecureStorage aliceStorage,
    SignalProtocolManager bob,
    FakeSecureStorage bobStorage,
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

  // Alice creates session from Bob's key bundle
  final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
  final bundle = acceptedBob.consumerBundle(
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

void main() {
  // ── Initialization ──────────────────────────────────────────────────

  group('SignalProtocolManager initialization', () {
    test(
      'initialize() generates all keys and returns true on first run',
      () async {
        final storage = FakeSecureStorage();
        final manager = SignalProtocolManager(secureStorage: storage);

        await manager.wipeForFreshRegistration();
        final isNew = await manager.initialize();

        expect(isNew, isTrue);
        // Identity key pair should now be persisted
        final identityRaw = await storage.read(key: 'crypto_identity_key_pair');
        expect(identityRaw, isNotNull);
        expect(identityRaw, isNotEmpty);
      },
    );

    test(
      'initialize() returns false after the exact bundle is acknowledged',
      () async {
        final storage = FakeSecureStorage();
        final manager = SignalProtocolManager(secureStorage: storage);

        await manager.wipeForFreshRegistration();
        final first = await manager.initialize();
        await CryptoTestFixtures.acceptInitialGeneration(manager);
        final second = await manager.initialize();

        expect(first, isTrue);
        expect(second, isFalse);
      },
    );

    test(
      'After initialize, getIdentityPublicKey() returns non-empty base64',
      () async {
        final storage = FakeSecureStorage();
        final manager = SignalProtocolManager(secureStorage: storage);
        await manager.wipeForFreshRegistration();
        await manager.initialize();

        final pubKey = await manager.getIdentityPublicKey();

        expect(pubKey, isNotEmpty);
        // Should be valid base64 that decodes to 32 bytes (X25519 public key)
        final bytes = base64Decode(pubKey);
        expect(bytes.length, 32);
      },
    );
  });

  // ── Key Bundle ──────────────────────────────────────────────────────

  group('SignalProtocolManager key bundle', () {
    test(
      'initial journal dispatch includes identity, signed pre-key and OPKs',
      () async {
        final (manager, _) =
            await CryptoTestFixtures.createInitializedManager();

        final accepted = await CryptoTestFixtures.acceptInitialGeneration(
          manager,
        );
        final bundle = accepted.publicMaterial;

        expect(bundle, containsPair('identityKey', isA<String>()));
        expect(bundle['identityKey'], isNotEmpty);

        expect(bundle, contains('signedPreKey'));
        final signedPreKey = bundle['signedPreKey'] as Map<String, dynamic>;
        expect(signedPreKey, containsPair('keyId', isA<int>()));
        expect(signedPreKey, containsPair('publicKey', isA<String>()));
        expect(signedPreKey, containsPair('signature', isA<String>()));

        expect(bundle, contains('oneTimePreKeys'));
        final otps = bundle['oneTimePreKeys'] as List<dynamic>;
        expect(otps, isNotEmpty);
        final firstOtp = otps.first as Map<String, dynamic>;
        expect(firstOtp, containsPair('keyId', isA<int>()));
        expect(firstOtp, containsPair('publicKey', isA<String>()));
      },
    );

    test('initial journal generation enforces the server OPK cap', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();

      final accepted = await CryptoTestFixtures.acceptInitialGeneration(
        manager,
        oneTimePreKeyCount: SignalProtocolManager.maxOneTimePreKeysPerBundle,
      );
      final bundle = accepted.publicMaterial;
      final otps = bundle['oneTimePreKeys'] as List<dynamic>;

      expect(
        otps.length,
        SignalProtocolManager.maxOneTimePreKeysPerBundle,
        reason:
            'Server rejects bundles larger than 100; the manager must trim.',
      );
    });

    test(
      'fresh epoch-2 bundle never exposes reserved one-time key id zero',
      () async {
        final (manager, _) =
            await CryptoTestFixtures.createInitializedManager();

        final accepted = await CryptoTestFixtures.acceptInitialGeneration(
          manager,
          oneTimePreKeyCount: 20,
        );
        final bundle = accepted.publicMaterial;
        final oneTimePreKeys = bundle['oneTimePreKeys'] as List<dynamic>;
        final ids = oneTimePreKeys
            .map((entry) => (entry as Map<String, dynamic>)['keyId'] as int)
            .toList();

        expect(ids, isNotEmpty);
        expect(ids.first, greaterThan(0));
        expect(ids.every((id) => id > 0), isTrue);
      },
    );

    test(
      'wipeForFreshRegistration authorizes a distinct fresh journal generation',
      () async {
        final (manager, _) =
            await CryptoTestFixtures.createInitializedManager();

        final prior = await CryptoTestFixtures.acceptInitialGeneration(
          manager,
          oneTimePreKeyCount: 20,
        );
        final priorBundle = prior.publicMaterial;
        final priorIdentity = priorBundle['identityKey'] as String;

        await manager.wipeForFreshRegistration();
        final isFreshInstall = await manager.initialize();
        expect(isFreshInstall, isTrue);

        final fresh = await CryptoTestFixtures.acceptInitialGeneration(
          manager,
          oneTimePreKeyCount: 20,
        );
        final freshBundle = fresh.publicMaterial;
        final freshOtps = freshBundle['oneTimePreKeys'] as List<dynamic>;

        expect(freshOtps, hasLength(20));
        expect(
          freshBundle['identityKey'],
          isNot(equals(priorIdentity)),
          reason: 'A new identity must be generated after a wipe.',
        );
      },
    );

    test('legacy generateKeyBundle API always fails closed', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);

      expect(
        () => manager.generateKeyBundle(),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });

  // ── Session Establishment ──────────────────────────────────────────

  group('SignalProtocolManager session establishment', () {
    test('createSession establishes a session from PreKeyBundle', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();

      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final bundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );

      // Should not throw
      await alice.createSession(bundle);

      // Session should exist on Alice's side
      final exists = await alice.hasSession('bob-id', 'bob-device');
      expect(exists, isTrue);
    });

    test('After createSession, hasSession returns true', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();

      // Before session creation
      expect(await alice.hasSession('bob-id', 'bob-device'), isFalse);

      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final bundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );
      await alice.createSession(bundle);

      // After session creation
      expect(await alice.hasSession('bob-id', 'bob-device'), isTrue);
    });

    test('After createSession, encryptMessage works', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();

      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final bundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
      );
      await alice.createSession(bundle);

      final envelope = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'Hello!',
      );

      expect(envelope, isA<Map<String, dynamic>>());
      expect(envelope['type'], equals('prekey'));
      expect(envelope, contains('message'));
      expect(envelope, contains('senderIdentityKey'));
      expect(envelope, contains('senderEphemeralKey'));
    });
  });

  // ── Message Exchange ────────────────────────────────────────────────

  group('SignalProtocolManager message exchange', () {
    test(
      'Full conversation flow: PreKey -> establish -> messages in both directions',
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

        // Get Bob's key bundle (simulating server fetch)
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
        );

        // Alice creates session from Bob's bundle (X3DH initiator)
        await alice.createSession(bundle);

        // Alice encrypts first message (should be PreKey type)
        final envelope1 = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'Hello Bob!',
        );
        expect(envelope1['type'], equals('prekey'));

        // Bob decrypts the PreKey message -> establishes Bob's session
        final plaintext1 = await bob.decryptMessage(
          'alice-id',
          'alice-device',
          envelope1,
        );
        expect(plaintext1, equals('Hello Bob!'));

        // Bob replies (should be normal message type since session is established)
        final envelope2 = await bob.encryptMessage(
          'alice-id',
          'alice-device',
          'Hi Alice!',
        );
        expect(envelope2['type'], equals('message'));

        // Alice decrypts Bob's reply
        final plaintext2 = await alice.decryptMessage(
          'bob-id',
          'bob-device',
          envelope2,
        );
        expect(plaintext2, equals('Hi Alice!'));
      },
    );

    test('Multiple messages in both directions', () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Alice -> Bob (several messages)
      for (var i = 0; i < 5; i++) {
        final envelope = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'Alice message $i',
        );
        final plain = await bob.decryptMessage(
          'alice-id',
          'alice-device',
          envelope,
        );
        expect(plain, equals('Alice message $i'));
      }

      // Bob -> Alice (several messages)
      for (var i = 0; i < 5; i++) {
        final envelope = await bob.encryptMessage(
          'alice-id',
          'alice-device',
          'Bob message $i',
        );
        final plain = await alice.decryptMessage(
          'bob-id',
          'bob-device',
          envelope,
        );
        expect(plain, equals('Bob message $i'));
      }

      // Interleaved: Alice, Bob, Alice, Bob
      for (var i = 0; i < 3; i++) {
        final e1 = await alice.encryptMessage(
          'bob-id',
          'bob-device',
          'Interleaved-A$i',
        );
        expect(
          await bob.decryptMessage('alice-id', 'alice-device', e1),
          'Interleaved-A$i',
        );

        final e2 = await bob.encryptMessage(
          'alice-id',
          'alice-device',
          'Interleaved-B$i',
        );
        expect(
          await alice.decryptMessage('bob-id', 'bob-device', e2),
          'Interleaved-B$i',
        );
      }
    });

    test('Message content preserved exactly (unicode, long text)', () async {
      final session = await _createFullSession();
      final alice = session.alice;
      final bob = session.bob;

      // Unicode: emoji, Arabic, CJK
      const unicode =
          'Hello! \u{1F512} \u0645\u0631\u062D\u0628\u0627 \u4F60\u597D';
      final e1 = await alice.encryptMessage('bob-id', 'bob-device', unicode);
      final p1 = await bob.decryptMessage('alice-id', 'alice-device', e1);
      expect(p1, equals(unicode));

      // Long text (2000+ characters)
      final longText = 'A' * 2500;
      final e2 = await alice.encryptMessage('bob-id', 'bob-device', longText);
      final p2 = await bob.decryptMessage('alice-id', 'alice-device', e2);
      expect(p2, equals(longText));

      // Empty-ish content (single character)
      const singleChar = 'X';
      final e3 = await alice.encryptMessage('bob-id', 'bob-device', singleChar);
      final p3 = await bob.decryptMessage('alice-id', 'alice-device', e3);
      expect(p3, equals(singleChar));

      // Newlines and special chars
      const special = 'Line1\nLine2\tTab\r\nWindows\x00null';
      final e4 = await alice.encryptMessage('bob-id', 'bob-device', special);
      final p4 = await bob.decryptMessage('alice-id', 'alice-device', e4);
      expect(p4, equals(special));
    });
  });

  // ── Sealed Sender ──────────────────────────────────────────────────

  group('SignalProtocolManager sealed sender', () {
    test(
      'encryptSealedSender -> decryptSealedSender round-trip recovers sender identity',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;
        final bob = session.bob;

        // Get Bob's identity public key for sealed sender
        final bobIdentityKey = await bob.getIdentityPublicKey();

        // Alice sends a sealed sender message
        final sealedEnvelope = await alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          bobIdentityKey,
          'Secret sealed message',
        );

        // Bob decrypts the sealed sender envelope
        final result = await bob.decryptSealedSender(sealedEnvelope);

        expect(result.senderId, equals('alice-id'));
        expect(result.senderDeviceId, equals('alice-device'));
        expect(result.plaintext, equals('Secret sealed message'));
      },
    );

    test(
      'Sealed sender message hides sender from envelope inspection',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;
        final bob = session.bob;

        final bobIdentityKey = await bob.getIdentityPublicKey();

        final sealedEnvelope = await alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          bobIdentityKey,
          'Hidden sender test',
        );

        // The sealed envelope should NOT contain sender identity in plaintext
        final envelopeJson = jsonEncode(sealedEnvelope);
        expect(envelopeJson, isNot(contains('alice-id')));
        expect(envelopeJson, isNot(contains('alice-device')));

        // It should only have ephemeral key, ciphertext, and nonce
        expect(sealedEnvelope, contains('ephemeralPublicKey'));
        expect(sealedEnvelope, contains('ciphertext'));
        expect(sealedEnvelope, contains('nonce'));
      },
    );
  });

  // ── Group Messaging ────────────────────────────────────────────────

  group('SignalProtocolManager group messaging', () {
    test(
      'Generate group sender key + distribute + encrypt + decrypt round-trip',
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
        await bobStorage.write(key: 'user_id', value: 'bob-id');

        const groupId = 'group-test-1';

        // Alice generates a sender key for the group
        final distribution = await alice.generateGroupSenderKey(groupId);
        expect(distribution.groupId, equals(groupId));
        expect(distribution.senderId, equals('alice-id'));
        expect(distribution.chainKey, isNotEmpty);
        expect(distribution.signingKey, isNotEmpty);

        // Bob processes Alice's sender key distribution
        await bob.processGroupSenderKey(groupId, 'alice-id', distribution);

        // Alice encrypts a group message
        final ciphertext = await alice.encryptGroupMessage(
          groupId,
          'Hello group!',
        );
        expect(ciphertext, isNotEmpty);

        // Bob decrypts Alice's group message
        final plaintext = await bob.decryptGroupMessage(
          groupId,
          'alice-id',
          ciphertext,
        );
        expect(plaintext, equals('Hello group!'));
      },
    );

    test('Multiple members exchange group messages', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final charlieStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      final charlie = SignalProtocolManager(secureStorage: charlieStorage);
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await charlie.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();
      await charlie.initialize();

      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await charlieStorage.write(key: 'user_id', value: 'charlie-id');

      const groupId = 'group-multi';

      // Each member generates their sender key
      final aliceDist = await alice.generateGroupSenderKey(groupId);
      final bobDist = await bob.generateGroupSenderKey(groupId);
      final charlieDist = await charlie.generateGroupSenderKey(groupId);

      // Distribute keys to all members
      await bob.processGroupSenderKey(groupId, 'alice-id', aliceDist);
      await charlie.processGroupSenderKey(groupId, 'alice-id', aliceDist);

      await alice.processGroupSenderKey(groupId, 'bob-id', bobDist);
      await charlie.processGroupSenderKey(groupId, 'bob-id', bobDist);

      await alice.processGroupSenderKey(groupId, 'charlie-id', charlieDist);
      await bob.processGroupSenderKey(groupId, 'charlie-id', charlieDist);

      // Alice sends a message -- Bob and Charlie decrypt it
      final aliceMsg = await alice.encryptGroupMessage(groupId, 'From Alice');
      expect(
        await bob.decryptGroupMessage(groupId, 'alice-id', aliceMsg),
        equals('From Alice'),
      );
      expect(
        await charlie.decryptGroupMessage(groupId, 'alice-id', aliceMsg),
        equals('From Alice'),
      );

      // Bob sends -- Alice and Charlie decrypt
      final bobMsg = await bob.encryptGroupMessage(groupId, 'From Bob');
      expect(
        await alice.decryptGroupMessage(groupId, 'bob-id', bobMsg),
        equals('From Bob'),
      );
      expect(
        await charlie.decryptGroupMessage(groupId, 'bob-id', bobMsg),
        equals('From Bob'),
      );

      // Charlie sends -- Alice and Bob decrypt
      final charlieMsg = await charlie.encryptGroupMessage(
        groupId,
        'From Charlie',
      );
      expect(
        await alice.decryptGroupMessage(groupId, 'charlie-id', charlieMsg),
        equals('From Charlie'),
      );
      expect(
        await bob.decryptGroupMessage(groupId, 'charlie-id', charlieMsg),
        equals('From Charlie'),
      );
    });
  });

  // ── Session Management ──────────────────────────────────────────────

  group('SignalProtocolManager session management', () {
    test('removeSession removes session, hasSession returns false', () async {
      final session = await _createFullSession();
      final alice = session.alice;

      // Session should exist
      expect(await alice.hasSession('bob-id', 'bob-device'), isTrue);

      // Remove it
      await alice.removeSession('bob-id', 'bob-device');

      // Session should be gone
      expect(await alice.hasSession('bob-id', 'bob-device'), isFalse);
    });

    test('removeAllSessionsForUser removes all device sessions', () async {
      // Create two sessions for the same user (different devices)
      final aliceStorage = FakeSecureStorage();
      final bobStorage1 = FakeSecureStorage();
      final bobStorage2 = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob1 = SignalProtocolManager(secureStorage: bobStorage1);
      final bob2 = SignalProtocolManager(secureStorage: bobStorage2);
      await alice.wipeForFreshRegistration();
      await bob1.wipeForFreshRegistration();
      await bob2.wipeForFreshRegistration();
      await alice.initialize();
      await bob1.initialize();
      await bob2.initialize();

      // Create session with Bob device-1
      final acceptedBob1 = await CryptoTestFixtures.acceptInitialGeneration(
        bob1,
      );
      await alice.createSession(
        acceptedBob1.consumerBundle(userId: 'bob-id', deviceId: 'bob-device-1'),
      );

      // Create session with Bob device-2. The identity key is a property of
      // the ACCOUNT, so Bob's second device presents the same one; a second
      // device claiming a different identity is a relay inventing a device id
      // and is refused (see the outbound continuity test below).
      await alice.createSession(
        acceptedBob1.consumerBundle(userId: 'bob-id', deviceId: 'bob-device-2'),
      );

      // Both sessions should exist
      expect(await alice.hasSession('bob-id', 'bob-device-1'), isTrue);
      expect(await alice.hasSession('bob-id', 'bob-device-2'), isTrue);

      // Remove all sessions for bob-id
      await alice.removeAllSessionsForUser('bob-id');

      // Both should be gone
      expect(await alice.hasSession('bob-id', 'bob-device-1'), isFalse);
      expect(await alice.hasSession('bob-id', 'bob-device-2'), isFalse);

      // ...but the trust anchors survive, so a later handshake still has
      // something to check an impostor against.
      expect(
        await alice.getSessionIdentityKey('bob-id', 'bob-device-1'),
        isNotNull,
      );
    });

    test(
      'a second device claiming a different identity key is refused',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final evilStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        final evil = SignalProtocolManager(secureStorage: evilStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await evil.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();
        await evil.initialize();

        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        await alice.createSession(
          acceptedBob.consumerBundle(userId: 'bob-id', deviceId: 'bob-d1'),
        );

        // The relay names a device id Alice has never seen and hands back its
        // own bundle for it. Nothing about the device id is authenticated, so
        // the only thing that can catch this is the contact-level pin.
        final acceptedEvil = await CryptoTestFixtures.acceptInitialGeneration(
          evil,
        );
        await expectLater(
          alice.createSession(
            acceptedEvil.consumerBundle(userId: 'bob-id', deviceId: 'relay-d9'),
          ),
          throwsA(isA<StateError>()),
        );

        expect(await alice.hasSession('bob-id', 'relay-d9'), isFalse);
        expect(
          await alice.getSessionIdentityKey('bob-id', 'relay-d9'),
          isNull,
          reason: 'a refused bundle must leave no pin behind',
        );
        expect(
          await alice.getSessionDevices('bob-id'),
          isNot(contains('relay-d9')),
        );
      },
    );
  });

  // ── Safety Numbers ──────────────────────────────────────────────────

  group('SignalProtocolManager safety numbers', () {
    test('getSafetyNumber returns 60-digit formatted string', () async {
      final (alice, _) = await CryptoTestFixtures.createInitializedManager();
      final (bob, _) = await CryptoTestFixtures.createInitializedManager();

      final bobKey = await bob.getIdentityPublicKey();

      final safetyNumber = await alice.getSafetyNumber(
        myUserId: 'alice-id',
        theirUserId: 'bob-id',
        theirIdentityKey: bobKey,
      );

      // Should be 60 digits + 11 spaces (12 groups of 5 digits)
      expect(safetyNumber.length, equals(71)); // 60 digits + 11 spaces
      final digitsOnly = safetyNumber.replaceAll(' ', '');
      expect(digitsOnly.length, equals(60));
      expect(RegExp(r'^\d{60}$').hasMatch(digitsOnly), isTrue);

      // Groups of 5 separated by spaces
      final groups = safetyNumber.split(' ');
      expect(groups.length, equals(12));
      for (final group in groups) {
        expect(group.length, equals(5));
        expect(RegExp(r'^\d{5}$').hasMatch(group), isTrue);
      }
    });

    test('getSafetyNumber is commutative (same for both parties)', () async {
      final (alice, _) = await CryptoTestFixtures.createInitializedManager();
      final (bob, _) = await CryptoTestFixtures.createInitializedManager();

      final aliceKey = await alice.getIdentityPublicKey();
      final bobKey = await bob.getIdentityPublicKey();

      final aliceSees = await alice.getSafetyNumber(
        myUserId: 'alice-id',
        theirUserId: 'bob-id',
        theirIdentityKey: bobKey,
      );

      final bobSees = await bob.getSafetyNumber(
        myUserId: 'bob-id',
        theirUserId: 'alice-id',
        theirIdentityKey: aliceKey,
      );

      expect(aliceSees, equals(bobSees));
    });
  });

  // ── Pre-key Replenishment ──────────────────────────────────────────

  group('SignalProtocolManager pre-key replenishment', () {
    test('full replacement generates the exact fresh OPK count', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();
      await CryptoTestFixtures.acceptInitialGeneration(manager);

      final replacement = await CryptoTestFixtures.acceptReplacementGeneration(
        manager,
        deviceId: 'device-1',
        oneTimePreKeyCount: 10,
      );
      final newKeys = replacement.publicMaterial['oneTimePreKeys'] as List;

      expect(newKeys.length, equals(10));
      for (final key in newKeys) {
        final publicKey = key as Map<String, dynamic>;
        expect(publicKey, containsPair('keyId', isA<int>()));
        expect(publicKey, containsPair('publicKey', isA<String>()));
        expect((publicKey['publicKey'] as String), isNotEmpty);
      }
    });

    test(
      'replacement OPK IDs are sequential, monotonic and disjoint',
      () async {
        final (manager, _) =
            await CryptoTestFixtures.createInitializedManager();
        final initial = await CryptoTestFixtures.acceptInitialGeneration(
          manager,
          oneTimePreKeyCount: 5,
        );

        final first = await CryptoTestFixtures.acceptReplacementGeneration(
          manager,
          deviceId: 'device-1',
          oneTimePreKeyCount: 5,
        );
        final second = await CryptoTestFixtures.acceptReplacementGeneration(
          manager,
          deviceId: 'device-1',
          oneTimePreKeyCount: 5,
        );
        List<int> ids(AcceptedTestGeneration generation) =>
            (generation.publicMaterial['oneTimePreKeys'] as List)
                .map((entry) => (entry as Map)['keyId'] as int)
                .toList(growable: false);
        final initialIds = ids(initial);
        final firstIds = ids(first);
        final secondIds = ids(second);

        expect(firstIds.first, greaterThan(initialIds.last));
        expect(secondIds.first, greaterThan(firstIds.last));
        expect(
          firstIds,
          List<int>.generate(5, (index) => firstIds.first + index),
        );
        expect(
          secondIds,
          List<int>.generate(5, (index) => secondIds.first + index),
        );
        expect(firstIds.toSet().intersection(secondIds.toSet()), isEmpty);
      },
    );
  });

  // ── Error Handling ──────────────────────────────────────────────────

  group('SignalProtocolManager error handling', () {
    test('encryptMessage without session throws StateError', () async {
      final (manager, _) = await CryptoTestFixtures.createInitializedManager();

      expect(
        () => manager.encryptMessage(
          'nonexistent-user',
          'nonexistent-device',
          'Hello',
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('decryptMessage with wrong session throws', () async {
      final session = await _createFullSession();
      final alice = session.alice;

      // Encrypt a message from Alice to Bob
      final envelope = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'Test',
      );

      // Try to decrypt with a completely different manager (no session)
      final (stranger, strangerStorage) =
          await CryptoTestFixtures.createInitializedManager();
      await strangerStorage.write(key: 'user_id', value: 'stranger-id');
      await strangerStorage.write(key: 'device_id', value: 'stranger-device');

      // A normal (non-prekey) message to a manager without the session
      // should throw since there's no session to decrypt with
      final normalEnvelope = {
        'type': 'message',
        'cryptoProtocolEpoch': RisaalCryptoProtocol.cryptoProtocolEpoch,
        'senderIdentityKey': envelope['senderIdentityKey'],
        'message': envelope['message'],
      };
      expect(
        () =>
            stranger.decryptMessage('alice-id', 'alice-device', normalEnvelope),
        throwsA(isA<StateError>()),
      );
    });
  });

  // ── Identity Key Persistence ────────────────────────────────────────

  group('SignalProtocolManager identity key persistence', () {
    test(
      'getSessionIdentityKey returns stored key after session creation',
      () async {
        final session = await _createFullSession();
        final alice = session.alice;

        final storedKey = await alice.getSessionIdentityKey(
          'bob-id',
          'bob-device',
        );
        expect(storedKey, isNotNull);

        // Should match Bob's actual identity key
        final bobKey = await session.bob.getIdentityPublicKey();
        expect(storedKey, equals(bobKey));
      },
    );
  });

  // ── Safety Number QR Payload ────────────────────────────────────────

  group('SignalProtocolManager QR payload', () {
    test(
      'getSafetyNumberQrPayload returns valid risaal-verify format',
      () async {
        final (alice, _) = await CryptoTestFixtures.createInitializedManager();
        final (bob, _) = await CryptoTestFixtures.createInitializedManager();

        final bobKey = await bob.getIdentityPublicKey();

        final qrPayload = await alice.getSafetyNumberQrPayload(
          myUserId: 'alice-id',
          theirUserId: 'bob-id',
          theirIdentityKey: bobKey,
        );

        expect(qrPayload, startsWith('risaal-verify:v0:'));
        final digits = qrPayload.substring('risaal-verify:v0:'.length);
        expect(digits.length, equals(60));
        expect(RegExp(r'^\d{60}$').hasMatch(digits), isTrue);
      },
    );
  });
}
