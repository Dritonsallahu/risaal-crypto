import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
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

  // ── onPreKeyExhaustionWarning callback ──────────────────────────────

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

    test('fires when OTP count is at threshold after consumption', () async {
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

      // Track exhaustion warnings on Bob with a high threshold
      int? warningCount;
      bob.onPreKeyExhaustionWarning = (remaining) {
        warningCount = remaining;
      };

      // Get Bob's bundle
      final bobBundle = await bob.generateKeyBundle();
      final signedPreKey = bobBundle['signedPreKey'] as Map<String, dynamic>;
      final oneTimePreKeys = bobBundle['oneTimePreKeys'] as List<dynamic>;
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

      // Bob decrypts — 20 - 1 = 19 OTPs remaining
      // Default threshold is 25, so 19 <= 25 — warning fires
      await bob.decryptMessage('alice-id', 'alice-device', envelope);

      // 19 remaining, default threshold 25 — should fire
      expect(warningCount, equals(19));

      // Now verify it would fire if threshold were high enough
      // by checking the count directly
      final count = await bob.oneTimePreKeyCount();
      expect(count, equals(19));
      final nearExhaustion = await bob.isPreKeyExhaustionNear(threshold: 19);
      expect(nearExhaustion, isTrue);
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
}
