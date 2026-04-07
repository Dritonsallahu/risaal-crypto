import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/fake_secure_storage.dart';

void main() {
  // ── signedPreKeyAge ─────────────────────────────────────────────────

  group('signedPreKeyAge', () {
    test('returns 0 for freshly generated keys', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final age = await manager.signedPreKeyAge();

      // Freshly generated — age should be very small (< 1 second)
      expect(age, lessThan(1000));
    });

    test('returns 0 when no timestamp is stored (legacy keys)', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);

      // Manually write identity key to simulate legacy init without timestamp
      // (initialize() now writes the timestamp, so we test missing timestamp)
      await manager.initialize();

      // Delete the timestamp to simulate legacy
      await storage.delete(key: 'crypto_signed_prekey_created_at');

      final age = await manager.signedPreKeyAge();
      expect(age, equals(0));
    });
  });

  // ── rotateSignedPreKeyIfNeeded ──────────────────────────────────────

  group('rotateSignedPreKeyIfNeeded', () {
    test('does nothing when key is fresh', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Key was just created — rotation should not happen
      final result = await manager.rotateSignedPreKeyIfNeeded();

      expect(result, isNull, reason: 'Fresh key should not trigger rotation');
    });

    test('rotates when key age exceeds maxAge', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Simulate an old signed pre-key by setting a timestamp 8 days ago
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );

      final result = await manager.rotateSignedPreKeyIfNeeded();

      expect(result, isNotNull, reason: 'Old key should trigger rotation');
      expect(result, isA<Map<String, dynamic>>());
      expect(result!, contains('signedPreKey'));
      expect(result, contains('createdAt'));
    });

    test('rotates when key age exceeds custom maxAge', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Simulate a key created 2 hours ago
      final twoHoursAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(hours: 2).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: twoHoursAgo.toString(),
      );

      // Rotate with 1 hour maxAge — should trigger
      final result = await manager.rotateSignedPreKeyIfNeeded(
        maxAge: const Duration(hours: 1),
      );

      expect(result, isNotNull);
    });

    test('does not rotate when key age is within custom maxAge', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Key was just created, maxAge is 30 days — should NOT rotate
      final result = await manager.rotateSignedPreKeyIfNeeded(
        maxAge: const Duration(days: 30),
      );

      expect(result, isNull);
    });

    test('rotation increments signed pre-key keyId', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Get initial bundle to check keyId
      final initialBundle = await manager.generateKeyBundle();
      final initialKeyId = (initialBundle['signedPreKey']
          as Map<String, dynamic>)['keyId'] as int;

      // Force rotation
      final oldTimestamp = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: oldTimestamp.toString(),
      );

      final rotatedBundle = await manager.rotateSignedPreKeyIfNeeded();
      final newKeyId = (rotatedBundle!['signedPreKey']
          as Map<String, dynamic>)['keyId'] as int;

      expect(newKeyId, equals(initialKeyId + 1));
    });

    test('rotation updates the creation timestamp', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Force old timestamp
      final oldTimestamp = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: oldTimestamp.toString(),
      );

      await manager.rotateSignedPreKeyIfNeeded();

      // Timestamp should now be recent
      final age = await manager.signedPreKeyAge();
      expect(age, lessThan(1000));
    });
  });

  // ── 48h Overlap for Signed Pre-Key ─────────────────────────────────

  group('signed pre-key 48h overlap', () {
    test('rotation stores old key as previous with expiry', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Get initial key before rotation
      final initialBundle = await manager.generateKeyBundle();
      final initialKeyId = (initialBundle['signedPreKey']
          as Map<String, dynamic>)['keyId'] as int;

      // Force rotation
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );

      await manager.rotateSignedPreKeyIfNeeded();

      // Previous key should be stored
      final previousKey = await manager.getPreviousSignedPreKey();
      expect(previousKey, isNotNull);
      expect(previousKey!.keyId, equals(initialKeyId));
    });

    test('previous key is accessible within overlap window', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Force rotation to create a previous key
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );

      await manager.rotateSignedPreKeyIfNeeded();

      // Previous key should be retrievable (we're within 48h)
      final previous = await manager.getPreviousSignedPreKey();
      expect(previous, isNotNull);
    });

    test('previous key is null when overlap window has expired', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Force rotation
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );

      await manager.rotateSignedPreKeyIfNeeded();

      // Simulate expired overlap by setting expiry in the past
      final pastExpiry = DateTime.now().millisecondsSinceEpoch - 1000;
      await storage.write(
        key: 'crypto_previous_spk_expiry',
        value: pastExpiry.toString(),
      );

      final previous = await manager.getPreviousSignedPreKey();
      expect(previous, isNull);
    });

    test('expired previous key is cleaned up during rotation check',
        () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Force rotation to create a previous key
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );

      await manager.rotateSignedPreKeyIfNeeded();

      // Verify previous key exists
      expect(storage.store.containsKey('crypto_previous_signed_pre_key'), true);
      expect(storage.store.containsKey('crypto_previous_spk_expiry'), true);

      // Set overlap expiry to the past
      final pastExpiry = DateTime.now().millisecondsSinceEpoch - 1000;
      await storage.write(
        key: 'crypto_previous_spk_expiry',
        value: pastExpiry.toString(),
      );

      // Next rotation check cleans up the expired previous key
      await manager.rotateSignedPreKeyIfNeeded();

      // Previous key should be gone (cleanup ran first)
      expect(
        storage.store.containsKey('crypto_previous_signed_pre_key'),
        false,
      );
    });

    test('second rotation replaces previous key with current', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // First rotation
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );
      await manager.rotateSignedPreKeyIfNeeded();

      final firstPreviousKey = await manager.getPreviousSignedPreKey();
      final firstPreviousKeyId = firstPreviousKey!.keyId;

      // Second rotation
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );
      await manager.rotateSignedPreKeyIfNeeded();

      // Previous key should now be the key from the first rotation
      // (not the original key)
      final secondPreviousKey = await manager.getPreviousSignedPreKey();
      expect(secondPreviousKey, isNotNull);
      expect(secondPreviousKey!.keyId, equals(firstPreviousKeyId + 1));
    });
  });

  // ── 48h Overlap for Kyber Key ──────────────────────────────────────

  group('Kyber key 48h overlap', () {
    test('rotation stores old Kyber key as previous with expiry', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Verify Kyber key was generated during init
      expect(storage.store.containsKey('crypto_kyber_key_pair'), true);

      // Force rotation
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: eightDaysAgo.toString(),
      );

      final rotated = await manager.rotateKyberKeyIfNeeded();
      expect(rotated, isTrue);

      // Previous key should be stored
      final previousKyber = await manager.getPreviousKyberKeyPair();
      expect(previousKyber, isNotNull);
    });

    test('previous Kyber key is null when overlap expired', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Force rotation
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: eightDaysAgo.toString(),
      );

      await manager.rotateKyberKeyIfNeeded();

      // Simulate expired overlap
      final pastExpiry = DateTime.now().millisecondsSinceEpoch - 1000;
      await storage.write(
        key: 'crypto_previous_kyber_expiry',
        value: pastExpiry.toString(),
      );

      final previous = await manager.getPreviousKyberKeyPair();
      expect(previous, isNull);
    });

    test('expired previous Kyber key is cleaned up during rotation check',
        () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Force rotation
      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: eightDaysAgo.toString(),
      );
      await manager.rotateKyberKeyIfNeeded();

      expect(
        storage.store.containsKey('crypto_previous_kyber_key_pair'),
        true,
      );

      // Set expiry to past
      final pastExpiry = DateTime.now().millisecondsSinceEpoch - 1000;
      await storage.write(
        key: 'crypto_previous_kyber_expiry',
        value: pastExpiry.toString(),
      );

      // Next rotation check cleans up
      await manager.rotateKyberKeyIfNeeded();

      expect(
        storage.store.containsKey('crypto_previous_kyber_key_pair'),
        false,
      );
    });

    test('Kyber rotation does not happen when key is fresh', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final rotated = await manager.rotateKyberKeyIfNeeded();
      expect(rotated, isFalse);
    });
  });

  // ── Absolute Max Key Lifetime ──────────────────────────────────────

  group('absolute max key lifetime enforcement', () {
    test('SPK force-rotates when exceeding 30-day absolute max', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Set SPK timestamp to 31 days ago — within maxAge (default 7d) is
      // impossible, but absolute max (30d) should still trigger
      final thirtyOneDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: thirtyOneDaysAgo.toString(),
      );

      // Call with a maxAge longer than absolute max to test the hard cap
      // Key is 31 days old, maxAge is 60 days — normally it would NOT rotate.
      // But absolute max (30 days) forces rotation.
      final result = await manager.rotateSignedPreKeyIfNeeded(
        maxAge: const Duration(days: 60),
      );

      expect(result, isNotNull, reason: 'Absolute max should force rotation');
    });

    test('Kyber force-rotates when exceeding 30-day absolute max', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final thirtyOneDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: thirtyOneDaysAgo.toString(),
      );

      final rotated = await manager.rotateKyberKeyIfNeeded(
        maxAge: const Duration(days: 60),
      );

      expect(rotated, isTrue, reason: 'Absolute max should force rotation');
    });

    test('key at 29 days does not trigger absolute max', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final twentyNineDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 29).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: twentyNineDaysAgo.toString(),
      );

      // maxAge 60 days — 29 days is within both maxAge and absolute max
      final result = await manager.rotateSignedPreKeyIfNeeded(
        maxAge: const Duration(days: 60),
      );

      expect(result, isNull, reason: 'Key within absolute max should not rotate');
    });
  });

  // ── validateKeyFreshness ──────────────────────────────────────────

  group('validateKeyFreshness', () {
    test('returns true when all keys are fresh', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final fresh = await manager.validateKeyFreshness();
      expect(fresh, isTrue);
    });

    test('returns false when SPK exceeds absolute max lifetime', () async {
      final storage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final manager = SignalProtocolManager(
        secureStorage: storage,
        securityEventBus: eventBus,
      );
      await manager.initialize();

      // Set SPK to 31 days old
      final thirtyOneDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: thirtyOneDaysAgo.toString(),
      );

      // Track emitted events
      SecurityEvent? expiredEvent;
      eventBus.events.listen((event) {
        if (event.type == SecurityEventType.keyExpired) {
          expiredEvent = event;
        }
      });

      final fresh = await manager.validateKeyFreshness();

      expect(fresh, isFalse);
      expect(expiredEvent, isNotNull);
      expect(expiredEvent!.metadata?['keyType'], equals('signedPreKey'));
    });

    test('returns false when Kyber key exceeds absolute max lifetime',
        () async {
      final storage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final manager = SignalProtocolManager(
        secureStorage: storage,
        securityEventBus: eventBus,
      );
      await manager.initialize();

      // Set Kyber to 31 days old
      final thirtyOneDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: thirtyOneDaysAgo.toString(),
      );

      SecurityEvent? expiredEvent;
      eventBus.events.listen((event) {
        if (event.type == SecurityEventType.keyExpired &&
            event.metadata?['keyType'] == 'kyber') {
          expiredEvent = event;
        }
      });

      final fresh = await manager.validateKeyFreshness();

      expect(fresh, isFalse);
      expect(expiredEvent, isNotNull);
    });

    test('returns false when both keys exceed absolute max', () async {
      final storage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final manager = SignalProtocolManager(
        secureStorage: storage,
        securityEventBus: eventBus,
      );
      await manager.initialize();

      final old = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 31).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: old.toString(),
      );
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: old.toString(),
      );

      final expiredKeys = <String>[];
      eventBus.events.listen((event) {
        if (event.type == SecurityEventType.keyExpired) {
          expiredKeys.add(event.metadata?['keyType'] as String);
        }
      });

      final fresh = await manager.validateKeyFreshness();

      expect(fresh, isFalse);
      expect(expiredKeys, containsAll(['signedPreKey', 'kyber']));
    });

    test('cleans up expired overlap keys during validation', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Simulate an expired previous SPK
      await storage.write(
        key: 'crypto_previous_signed_pre_key',
        value: '{"keyId":0,"keyPair":{"publicKey":"a","privateKey":"b"},"signature":"c"}',
      );
      final pastExpiry = DateTime.now().millisecondsSinceEpoch - 1000;
      await storage.write(
        key: 'crypto_previous_spk_expiry',
        value: pastExpiry.toString(),
      );

      await manager.validateKeyFreshness();

      // Expired previous key should be cleaned up
      expect(
        storage.store.containsKey('crypto_previous_signed_pre_key'),
        false,
      );
    });
  });

  // ── oneTimePreKeyCount ──────────────────────────────────────────────

  group('oneTimePreKeyCount', () {
    test('returns correct count after initialization', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // initialize() generates 20 OTPs
      final count = await manager.oneTimePreKeyCount();
      expect(count, equals(20));
    });

    test('count increases after generateOneTimePreKeys', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      await manager.generateOneTimePreKeys(10);

      final count = await manager.oneTimePreKeyCount();
      expect(count, equals(30)); // 20 initial + 10 new
    });
  });

  // ── isPreKeyExhaustionNear ──────────────────────────────────────────

  group('isPreKeyExhaustionNear', () {
    test('returns false when keys are plentiful', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // 20 keys > default threshold of 10
      final exhausted = await manager.isPreKeyExhaustionNear();
      expect(exhausted, isFalse);
    });

    test('returns true when keys are at threshold', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // 20 keys — use threshold of 20 (at threshold)
      final exhausted = await manager.isPreKeyExhaustionNear(threshold: 20);
      expect(exhausted, isTrue);
    });

    test('returns true when keys are below threshold', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // 20 keys — use threshold of 25 (below threshold)
      final exhausted = await manager.isPreKeyExhaustionNear(threshold: 25);
      expect(exhausted, isTrue);
    });

    test('returns false when keys are above custom threshold', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // 20 keys — threshold of 5 (well above)
      final exhausted = await manager.isPreKeyExhaustionNear(threshold: 5);
      expect(exhausted, isFalse);
    });
  });

  // ── OTP Auto-Replenishment ──────────────────────────────────────────

  group('OTP auto-replenishment', () {
    test(
      'auto-generates 100 OTPs when pool drops below watermark during decryption',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final bobEventBus = SecurityEventBus();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(
          secureStorage: bobStorage,
          securityEventBus: bobEventBus,
        );
        await alice.initialize();
        await bob.initialize();

        await aliceStorage.write(key: 'user_id', value: 'alice-id');
        await aliceStorage.write(key: 'device_id', value: 'alice-device');
        await bobStorage.write(key: 'user_id', value: 'bob-id');
        await bobStorage.write(key: 'device_id', value: 'bob-device');

        // Track replenishment events
        SecurityEvent? replenishEvent;
        bobEventBus.events.listen((event) {
          if (event.type == SecurityEventType.preKeyReplenishmentNeeded) {
            replenishEvent = event;
          }
        });

        // Get Bob's bundle
        final bobBundle = await bob.generateKeyBundle();
        final signedPreKey =
            bobBundle['signedPreKey'] as Map<String, dynamic>;
        final oneTimePreKeys =
            bobBundle['oneTimePreKeys'] as List<dynamic>;
        final firstOtp = oneTimePreKeys.first as Map<String, dynamic>;

        final bundle = PreKeyBundle(
          userId: 'bob-id',
          deviceId: 'bob-device',
          identityKey: bobBundle['identityKey'] as String,
          identitySigningKey: bobBundle['identitySigningKey'] as String,
          signedPreKey: SignedPreKeyPublic(
            keyId: signedPreKey['keyId'] as int,
            publicKey: signedPreKey['publicKey'] as String,
            signature: signedPreKey['signature'] as String,
          ),
          oneTimePreKey: OneTimePreKeyPublic(
            keyId: firstOtp['keyId'] as int,
            publicKey: firstOtp['publicKey'] as String,
          ),
        );

        await alice.createSession(bundle);
        final envelope =
            await alice.encryptMessage('bob-id', 'bob-device', 'Hello!');

        // Bob had 20 OTPs, consumes 1 = 19 remaining (<= 25 watermark)
        // Auto-replenishment should generate 100 more
        await bob.decryptMessage('alice-id', 'alice-device', envelope);

        // Verify auto-replenishment happened
        expect(replenishEvent, isNotNull);
        expect(replenishEvent!.metadata['generated'], equals(100));
        expect(replenishEvent!.metadata['previousCount'], equals(19));
        expect(replenishEvent!.metadata['newTotal'], equals(119));

        // Verify the total OTP count
        final count = await bob.oneTimePreKeyCount();
        expect(count, equals(119)); // 20 - 1 + 100
      },
    );

    test('fires callback in addition to event bus', () async {
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

      int? callbackCount;
      bob.onPreKeyExhaustionWarning = (remaining) {
        callbackCount = remaining;
      };

      final bobBundle = await bob.generateKeyBundle();
      final signedPreKey =
          bobBundle['signedPreKey'] as Map<String, dynamic>;
      final oneTimePreKeys =
          bobBundle['oneTimePreKeys'] as List<dynamic>;
      final firstOtp = oneTimePreKeys.first as Map<String, dynamic>;

      final bundle = PreKeyBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
        identityKey: bobBundle['identityKey'] as String,
        identitySigningKey: bobBundle['identitySigningKey'] as String,
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey['keyId'] as int,
          publicKey: signedPreKey['publicKey'] as String,
          signature: signedPreKey['signature'] as String,
        ),
        oneTimePreKey: OneTimePreKeyPublic(
          keyId: firstOtp['keyId'] as int,
          publicKey: firstOtp['publicKey'] as String,
        ),
      );

      await alice.createSession(bundle);
      final envelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'Hello!');

      await bob.decryptMessage('alice-id', 'alice-device', envelope);

      // Callback fires with the count BEFORE replenishment
      expect(callbackCount, equals(19));
    });

    test('generateOneTimePreKeys increases the pool correctly', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final initialCount = await manager.oneTimePreKeyCount();
      expect(initialCount, equals(20));

      final newKeys = await manager.generateOneTimePreKeys(100);
      expect(newKeys.length, equals(100));

      final finalCount = await manager.oneTimePreKeyCount();
      expect(finalCount, equals(120));
    });

    test('new OTP keyIds continue from previous counter', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      // Generate 10 more OTPs
      final batch1 = await manager.generateOneTimePreKeys(10);
      final lastId1 = batch1.last['keyId'] as int;

      // Generate another 10
      final batch2 = await manager.generateOneTimePreKeys(10);
      final firstId2 = batch2.first['keyId'] as int;

      // IDs should be contiguous
      expect(firstId2, equals(lastId1 + 1));
    });
  });

  // ── onPreKeyExhaustionWarning callback (legacy) ────────────────────

  group('onPreKeyExhaustionWarning callback', () {
    test(
        'fires when OTP count drops below threshold during processPreKeyMessage',
        () async {
      // Set up Alice and Bob
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

      // Track exhaustion warnings on Bob
      int? warningCount;
      bob.onPreKeyExhaustionWarning = (remaining) {
        warningCount = remaining;
      };

      // Get Bob's bundle and create session
      final bobBundle = await bob.generateKeyBundle();
      final signedPreKey = bobBundle['signedPreKey'] as Map<String, dynamic>;
      final oneTimePreKeys = bobBundle['oneTimePreKeys'] as List<dynamic>;
      final firstOtp = oneTimePreKeys.first as Map<String, dynamic>;

      // Build a PreKeyBundle from the map
      final bundle = PreKeyBundle(
        userId: 'bob-id',
        deviceId: 'bob-device',
        identityKey: bobBundle['identityKey'] as String,
        identitySigningKey: bobBundle['identitySigningKey'] as String,
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey['keyId'] as int,
          publicKey: signedPreKey['publicKey'] as String,
          signature: signedPreKey['signature'] as String,
        ),
        oneTimePreKey: OneTimePreKeyPublic(
          keyId: firstOtp['keyId'] as int,
          publicKey: firstOtp['publicKey'] as String,
        ),
      );

      await alice.createSession(bundle);

      // Alice sends first message (prekey)
      final envelope =
          await alice.encryptMessage('bob-id', 'bob-device', 'Hello!');

      // Bob decrypts — this consumes an OTP and should check exhaustion
      await bob.decryptMessage('alice-id', 'alice-device', envelope);

      // Bob had 20 OTPs, consumed 1 = 19 remaining. Default threshold is 25.
      // 19 <= 25, so warning SHOULD fire
      expect(warningCount, equals(19));
    });
  });

  // ── generateKeyBundle includes createdAt ────────────────────────────

  group('generateKeyBundle createdAt', () {
    test('includes createdAt timestamp', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final bundle = await manager.generateKeyBundle();

      expect(bundle, contains('createdAt'));
      final createdAt = bundle['createdAt'] as int;
      // Should be a recent timestamp (within last second)
      final now = DateTime.now().millisecondsSinceEpoch;
      expect(createdAt, lessThanOrEqualTo(now));
      expect(createdAt, greaterThan(now - 5000)); // within 5 seconds
    });
  });

  // ── rotateKeysIfNeeded (convenience) ───────────────────────────────

  group('rotateKeysIfNeeded', () {
    test('returns null when all keys are fresh', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final result = await manager.rotateKeysIfNeeded();
      expect(result, isNull);
    });

    test('returns bundle when SPK rotation occurs', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_signed_prekey_created_at',
        value: eightDaysAgo.toString(),
      );

      final result = await manager.rotateKeysIfNeeded();
      expect(result, isNotNull);
      expect(result!, contains('signedPreKey'));
    });

    test('returns bundle when Kyber rotation occurs', () async {
      final storage = FakeSecureStorage();
      final manager = SignalProtocolManager(secureStorage: storage);
      await manager.initialize();

      final eightDaysAgo = DateTime.now().millisecondsSinceEpoch -
          const Duration(days: 8).inMilliseconds;
      await storage.write(
        key: 'crypto_kyber_created_at',
        value: eightDaysAgo.toString(),
      );

      final result = await manager.rotateKeysIfNeeded();
      expect(result, isNotNull);
    });
  });

  // ── Constants ──────────────────────────────────────────────────────

  group('key lifecycle constants', () {
    test('absoluteMaxKeyLifetime is 30 days', () {
      expect(
        SignalProtocolManager.absoluteMaxKeyLifetime,
        equals(const Duration(days: 30)),
      );
    });

    test('keyOverlapWindow is 48 hours', () {
      expect(
        SignalProtocolManager.keyOverlapWindow,
        equals(const Duration(hours: 48)),
      );
    });

    test('otpReplenishBatchSize is 100', () {
      expect(SignalProtocolManager.otpReplenishBatchSize, equals(100));
    });

    test('defaultOtpLowWatermark is 25', () {
      expect(SignalProtocolManager.defaultOtpLowWatermark, equals(25));
    });
  });
}
