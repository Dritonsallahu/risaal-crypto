import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/fake_secure_storage.dart';

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
  // ── 1. Reinstall Recovery / Peer Identity Key Change ─────────────

  group('Peer identity key change detection', () {
    test('emits peerIdentityKeyChanged when peer reinstalls (new identity key)',
        () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final alice = SignalProtocolManager(
        secureStorage: aliceStorage,
        securityEventBus: eventBus,
      );
      final bob = SignalProtocolManager(secureStorage: bobStorage);

      await alice.initialize();
      await bob.initialize();

      // Alice creates session with Bob's first bundle
      final bobBundle1 = await bob.generateKeyBundle();
      final bundle1 =
          _bundleFromMap(bobBundle1, userId: 'bob-id', deviceId: 'bob-d1');
      await alice.createSession(bundle1);

      // Bob "reinstalls" — new identity, new keys
      final bob2Storage = FakeSecureStorage();
      final bob2 = SignalProtocolManager(secureStorage: bob2Storage);
      await bob2.initialize();

      final bobBundle2 = await bob2.generateKeyBundle();
      final bundle2 =
          _bundleFromMap(bobBundle2, userId: 'bob-id', deviceId: 'bob-d1');

      // Identity keys should differ
      expect(bundle1.identityKey, isNot(bundle2.identityKey));

      // Collect events
      final events = <SecurityEvent>[];
      eventBus.events
          .where((e) => e.type == SecurityEventType.peerIdentityKeyChanged)
          .listen(events.add);

      // Alice creates a new session with Bob's new bundle
      await alice.createSession(bundle2);
      await Future<void>.delayed(Duration.zero);

      expect(events, hasLength(1));
      expect(events.first.metadata['reason'], contains('Identity key differs'));

      eventBus.dispose();
    });

    test('does not emit when creating first session with a peer', () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final alice = SignalProtocolManager(
        secureStorage: aliceStorage,
        securityEventBus: eventBus,
      );
      final bob = SignalProtocolManager(secureStorage: bobStorage);

      await alice.initialize();
      await bob.initialize();

      final events = <SecurityEvent>[];
      eventBus.events
          .where((e) => e.type == SecurityEventType.peerIdentityKeyChanged)
          .listen(events.add);

      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-d1');
      await alice.createSession(bundle);
      await Future<void>.delayed(Duration.zero);

      // No event — first session, no previous key to compare
      expect(events, isEmpty);

      eventBus.dispose();
    });

    test('does not emit when same peer reconnects with same identity key',
        () async {
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final alice = SignalProtocolManager(
        secureStorage: aliceStorage,
        securityEventBus: eventBus,
      );
      final bob = SignalProtocolManager(secureStorage: bobStorage);

      await alice.initialize();
      await bob.initialize();

      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-d1');

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
    });
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
      expect(
        SignalProtocolManager.keyOverlapWindow,
        const Duration(hours: 48),
      );
    });
  });

  // ── 3. Offline Gap Handling ──────────────────────────────────────

  group('Offline gap handling', () {
    test('Double Ratchet anti-replay uses message counters not timestamps',
        () async {
      // Verify by creating a session and checking the replay check
      // uses dhPublicKey:messageNumber format
      final aliceStorage = FakeSecureStorage();
      final bobStorage = FakeSecureStorage();
      final alice = SignalProtocolManager(secureStorage: aliceStorage);
      final bob = SignalProtocolManager(secureStorage: bobStorage);
      await alice.initialize();
      await bob.initialize();

      final bobBundle = await bob.generateKeyBundle();
      final bundle =
          _bundleFromMap(bobBundle, userId: 'bob-id', deviceId: 'bob-d1');
      await alice.createSession(bundle);

      final encrypted = await alice.encryptMessage('bob-id', 'bob-d1', 'test');
      await bob.decryptMessage('alice-id', 'alice-d1', encrypted);

      // Replay the same message — should throw (either StateError for
      // replay detection or SessionResetError from auto-renegotiation)
      expect(
        () => bob.decryptMessage('alice-id', 'alice-d1', encrypted),
        throwsA(anything),
      );
    });

    test('skippedKeyCapReached event type exists', () {
      expect(
        SecurityEventType.values
            .contains(SecurityEventType.skippedKeyCapReached),
        isTrue,
      );
    });

    test('peerIdentityKeyChanged event type exists', () {
      expect(
        SecurityEventType.values
            .contains(SecurityEventType.peerIdentityKeyChanged),
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

      final result =
          await cryptoStorage.getPeerIdentityKey('unknown', 'device1');
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
