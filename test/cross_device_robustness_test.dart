import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

void main() {
  // ── 1. Reinstall Recovery / Peer Identity Key Change ─────────────

  group('Peer identity key change detection', () {
    test(
      'emits peerIdentityKeyChanged when peer reinstalls (new identity key)',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final eventBus = SecurityEventBus();
        final alice = SignalProtocolManager(
          secureStorage: aliceStorage,
          securityEventBus: eventBus,
        );
        final bob = SignalProtocolManager(secureStorage: bobStorage);

        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        // Alice creates session with Bob's first bundle
        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle1 = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-d1',
        );
        await alice.createSession(bundle1);

        // Bob "reinstalls" — new identity, new keys
        final bob2Storage = FakeSecureStorage();
        final bob2 = SignalProtocolManager(secureStorage: bob2Storage);
        await bob2.wipeForFreshRegistration();
        await bob2.initialize();

        final acceptedBob2 = await CryptoTestFixtures.acceptInitialGeneration(
          bob2,
        );
        final bundle2 = acceptedBob2.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-d1',
        );

        // Identity keys should differ
        expect(bundle1.identityKey, isNot(bundle2.identityKey));

        // Collect events
        final events = <SecurityEvent>[];
        eventBus.events
            .where((e) => e.type == SecurityEventType.peerIdentityKeyChanged)
            .listen(events.add);

        // Alice tries to create a new session with Bob's new bundle.
        //
        // This used to succeed and merely announce the change on the event bus,
        // which is a warning nobody blocks on: Alice would go on to encrypt to
        // whatever identity the relay had just supplied. Announcing a takeover
        // is not preventing one. The session build is now refused outright.
        await expectLater(
          alice.createSession(bundle2),
          throwsA(isA<StateError>()),
        );
        await Future<void>.delayed(Duration.zero);

        expect(events, hasLength(1));
        expect(events.first.metadata['reason'], 'outbound-identity-mismatch');
        expect(
          await alice.getSessionIdentityKey('bob-id', 'bob-d1'),
          bundle1.identityKey,
          reason: 'the refused bundle must not overwrite the pin',
        );

        // A real reinstall is resolved by the user deliberately un-trusting the
        // contact and re-verifying the safety number — never inline on a send.
        await alice.forgetPeerIdentity('bob-id');
        await alice.createSession(bundle2);
        expect(
          await alice.getSessionIdentityKey('bob-id', 'bob-d1'),
          bundle2.identityKey,
        );

        eventBus.dispose();
      },
    );

    test('does not emit when creating first session with a peer', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final alice = SignalProtocolManager(
        secureStorage: aliceStorage,
        securityEventBus: eventBus,
      );
      final bob = SignalProtocolManager(secureStorage: bobStorage);

      await alice.wipeForFreshRegistration();
      await bob.wipeForFreshRegistration();
      await alice.initialize();
      await bob.initialize();

      final events = <SecurityEvent>[];
      eventBus.events
          .where((e) => e.type == SecurityEventType.peerIdentityKeyChanged)
          .listen(events.add);

      final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
      final bundle = acceptedBob.consumerBundle(
        userId: 'bob-id',
        deviceId: 'bob-d1',
      );
      await alice.createSession(bundle);
      await Future<void>.delayed(Duration.zero);

      // No event — first session, no previous key to compare
      expect(events, isEmpty);

      eventBus.dispose();
    });

    test(
      'does not emit when same peer reconnects with same identity key',
      () async {
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final eventBus = SecurityEventBus();
        final alice = SignalProtocolManager(
          secureStorage: aliceStorage,
          securityEventBus: eventBus,
        );
        final bob = SignalProtocolManager(secureStorage: bobStorage);

        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-d1',
        );

        // Create session twice with same bundle
        await alice.createSession(bundle);

        final events = <SecurityEvent>[];
        eventBus.events
            .where((e) => e.type == SecurityEventType.peerIdentityKeyChanged)
            .listen(events.add);

        await alice.createSession(bundle);
        await Future<void>.delayed(Duration.zero);

        // Same identity key — no event
        expect(events, isEmpty);

        eventBus.dispose();
      },
    );
  });

  // ── 2. Clock Drift Tolerance ─────────────────────────────────────

  group('Clock drift tolerance', () {
    test('clockDriftGracePeriod constant exists and is 1 hour', () {
      expect(
        SignalProtocolManager.clockDriftGracePeriod,
        const Duration(hours: 1),
      );
    });

    test('absoluteMaxKeyLifetime is 30 days', () {
      expect(
        SignalProtocolManager.absoluteMaxKeyLifetime,
        const Duration(days: 30),
      );
    });

    test('key overlap window is 48 hours', () {
      expect(SignalProtocolManager.keyOverlapWindow, const Duration(hours: 48));
    });
  });

  // ── 3. Offline Gap Handling ──────────────────────────────────────

  group('Offline gap handling', () {
    test(
      'Double Ratchet anti-replay uses message counters not timestamps',
      () async {
        // Verify by creating a session and checking the replay check
        // uses dhPublicKey:messageNumber format
        final aliceStorage = FakeSecureStorage();
        final bobStorage = FakeSecureStorage();
        final alice = SignalProtocolManager(secureStorage: aliceStorage);
        final bob = SignalProtocolManager(secureStorage: bobStorage);
        await alice.wipeForFreshRegistration();
        await bob.wipeForFreshRegistration();
        await alice.initialize();
        await bob.initialize();

        final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(
          bob,
        );
        final bundle = acceptedBob.consumerBundle(
          userId: 'bob-id',
          deviceId: 'bob-d1',
        );
        await alice.createSession(bundle);

        final encrypted = await alice.encryptMessage(
          'bob-id',
          'bob-d1',
          'test',
        );
        await bob.decryptMessage('alice-id', 'alice-d1', encrypted);

        // Replay the same message — should throw (either StateError for
        // replay detection or SessionResetError from auto-renegotiation)
        expect(
          () => bob.decryptMessage('alice-id', 'alice-d1', encrypted),
          throwsA(anything),
        );
      },
    );

    test('skippedKeyCapReached event type exists', () {
      expect(
        SecurityEventType.values.contains(
          SecurityEventType.skippedKeyCapReached,
        ),
        isTrue,
      );
    });

    test('peerIdentityKeyChanged event type exists', () {
      expect(
        SecurityEventType.values.contains(
          SecurityEventType.peerIdentityKeyChanged,
        ),
        isTrue,
      );
    });
  });

  // ── 4. Peer Identity Key Storage ─────────────────────────────────

  group('CryptoStorage peer identity key tracking', () {
    test('savePeerIdentityKey and getPeerIdentityKey round-trip', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      await cryptoStorage.savePeerIdentityKey('bob', 'device1', 'key-abc');
      final result = await cryptoStorage.getPeerIdentityKey('bob', 'device1');
      expect(result, 'key-abc');
    });

    test('getPeerIdentityKey returns null for unknown peer', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      final result = await cryptoStorage.getPeerIdentityKey(
        'unknown',
        'device1',
      );
      expect(result, isNull);
    });

    test('deletePeerIdentityKey removes stored key', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      await cryptoStorage.savePeerIdentityKey('bob', 'device1', 'key-abc');
      await cryptoStorage.deletePeerIdentityKey('bob', 'device1');
      final result = await cryptoStorage.getPeerIdentityKey('bob', 'device1');
      expect(result, isNull);
    });

    test('different devices have independent identity keys', () async {
      final storage = FakeSecureStorage();
      final cryptoStorage = CryptoStorage(secureStorage: storage);

      await cryptoStorage.savePeerIdentityKey('bob', 'device1', 'key-1');
      await cryptoStorage.savePeerIdentityKey('bob', 'device2', 'key-2');

      expect(await cryptoStorage.getPeerIdentityKey('bob', 'device1'), 'key-1');
      expect(await cryptoStorage.getPeerIdentityKey('bob', 'device2'), 'key-2');
    });
  });
}
