@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _sessionKey = 'crypto_e2_session_alice-id_alice-device';
const _identityKey = 'crypto_e2_session_ik_alice-id_alice-device';
const _pendingKey = 'crypto_e2_pending_prekey_alice-id_alice-device';
const _resetKey = 'crypto_e2_session_resets_alice-id_alice-device';

void main() {
  test('MessageAuthenticationError has a context-free diagnostic string', () {
    const error = MessageAuthenticationError();

    expect(
      error.toString(),
      'MessageAuthenticationError: Encrypted message authentication failed.',
    );
    expect(error.toString(), isNot(contains('alice-id')));
    expect(error.toString(), isNot(contains('ciphertext')));
    expect(error.toString(), isNot(contains('SecretBoxAuthenticationError')));
  });

  test(
    'normal-message MAC rejection preserves every session prerequisite',
    () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final events = <SecurityEvent>[];
      final subscription = eventBus.events.listen(events.add);
      addTearDown(subscription.cancel);
      addTearDown(eventBus.dispose);

      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(
        secureStorage: bobStorage,
        securityEventBus: eventBus,
      );
      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await aliceStorage.write(key: 'device_id', value: 'alice-device');
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');

      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      await alice.createSession(acceptedBob.consumerBundle());
      final firstContact = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'establish session',
      );
      expect(
        await bob.decryptMessage('alice-id', 'alice-device', firstContact),
        'establish session',
      );
      await Future<void>.delayed(Duration.zero);
      events.clear();

      var replenishmentCallbackCount = 0;
      bob.onPreKeyReplenishmentNeeded = () {
        replenishmentCallbackCount++;
      };

      const pendingSentinel = '{"sentinel":"must-survive"}';
      await bobStorage.write(key: _pendingKey, value: pendingSentinel);
      final cryptoStorage = CryptoStorage(secureStorage: bobStorage);
      await cryptoStorage.saveResetTimestamps(
        'alice-id',
        'alice-device',
        const [101, 202, 303],
      );

      final authenticOriginal = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'authentic original',
      );
      final nextValid = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'next valid',
      );
      expect(authenticOriginal['type'], 'message');
      expect(nextValid['type'], 'message');

      final tampered = Map<String, dynamic>.from(
        jsonDecode(jsonEncode(authenticOriginal)) as Map,
      );
      final inner = tampered['message'] as Map<String, dynamic>;
      final bytes = base64Decode(inner['ciphertext'] as String);
      bytes[0] ^= 0x80;
      inner['ciphertext'] = base64Encode(bytes);

      final before = Map<String, String>.from(bobStorage.store);
      final rawSessionBefore = before[_sessionKey];
      final rawIdentityBefore = before[_identityKey];
      final rawResetBefore = before[_resetKey];
      expect(rawSessionBefore, isNotNull);
      expect(rawIdentityBefore, isNotNull);

      await expectLater(
        bob.decryptMessage('alice-id', 'alice-device', tampered),
        throwsA(isA<MessageAuthenticationError>()),
      );
      await Future<void>.delayed(Duration.zero);

      // The auth rejection is a read-only state transition: every raw value is
      // byte-identical, including state not required for normal-message decrypt.
      expect(bobStorage.store, before);
      expect(bobStorage.store[_sessionKey], rawSessionBefore);
      expect(bobStorage.store[_identityKey], rawIdentityBefore);
      expect(bobStorage.store[_pendingKey], pendingSentinel);
      expect(bobStorage.store[_resetKey], rawResetBefore);
      expect(replenishmentCallbackCount, 0);

      final rejected = events.where(
        (event) =>
            event.type == SecurityEventType.messageAuthenticationRejected,
      );
      expect(rejected, hasLength(1));
      expect(rejected.single.sessionId, isEmpty);
      expect(rejected.single.metadata, const {'source': 'double_ratchet'});
      expect(rejected.single.toString(), isNot(contains('alice-id')));
      expect(rejected.single.toString(), isNot(contains('authentic original')));
      expect(
        events.where((event) => event.type == SecurityEventType.sessionReset),
        isEmpty,
      );
      expect(
        events.where(
          (event) => event.type == SecurityEventType.preKeyReplenishmentNeeded,
        ),
        isEmpty,
      );

      // Remove only the persisted copy after proving byte identity. Successful
      // decrypt now proves the in-memory cache was not evicted by the failure.
      await bobStorage.delete(key: _sessionKey);
      expect(
        await bob.decryptMessage('alice-id', 'alice-device', authenticOriginal),
        'authentic original',
      );
      expect(
        await bob.decryptMessage('alice-id', 'alice-device', nextValid),
        'next valid',
      );
      expect(bobStorage.store[_sessionKey], isNotNull);
      expect(bobStorage.store[_identityKey], rawIdentityBefore);
      expect(bobStorage.store[_pendingKey], pendingSentinel);
      expect(bobStorage.store[_resetKey], rawResetBefore);
      expect(replenishmentCallbackCount, 0);
    },
  );
}
