@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

const _receiveJournalKey = 'crypto_e2_receive_commit_journal_v1';
const _bundleJournalKey = 'crypto_e2_bundle_replacement_journal_v1';
const _pendingPreKeyKey = 'crypto_e2_pending_prekey_alice-id_alice-device';

enum _FaultOperation { write, delete, read }

final class _InjectedStorageFailure implements Exception {
  final _FaultOperation operation;
  final String key;
  final bool afterCommit;

  const _InjectedStorageFailure({
    required this.operation,
    required this.key,
    required this.afterCommit,
  });

  @override
  String toString() =>
      'Injected ${operation.name} failure '
      '(${afterCommit ? 'after' : 'before'} commit)';
}

final class _FaultRule {
  final _FaultOperation operation;
  final String key;
  final bool afterCommit;
  int remaining;

  _FaultRule({
    required this.operation,
    required this.key,
    required this.afterCommit,
    required this.remaining,
  });
}

final class _FaultStorage extends FakeSecureStorage {
  _FaultRule? _fault;

  void failWrite(String key, {required bool afterCommit, int occurrence = 1}) {
    _fault = _FaultRule(
      operation: _FaultOperation.write,
      key: key,
      afterCommit: afterCommit,
      remaining: occurrence,
    );
  }

  /// P1-15: reads in the commit path were previously unfailable, so four
  /// post-authentication boundaries were untested — the journal durability
  /// re-read, the mutation re-read, the pre-state verification and the in-lock
  /// guard read. On iOS a locked device fails reads (`errSecInteractionNotAllowed`)
  /// at least as often as writes, and that is exactly when a push-woken
  /// background receive runs.
  void failRead(String key, {int occurrence = 1}) {
    _fault = _FaultRule(
      operation: _FaultOperation.read,
      key: key,
      afterCommit: false,
      remaining: occurrence,
    );
  }

  void failDelete(String key, {required bool afterCommit, int occurrence = 1}) {
    _fault = _FaultRule(
      operation: _FaultOperation.delete,
      key: key,
      afterCommit: afterCommit,
      remaining: occurrence,
    );
  }

  bool _hits(_FaultOperation operation, String key) {
    final fault = _fault;
    if (fault == null || fault.operation != operation || fault.key != key) {
      return false;
    }
    fault.remaining -= 1;
    if (fault.remaining > 0) return false;
    _fault = null;
    return true;
  }

  @override
  Future<String?> read({required String key}) async {
    if (_hits(_FaultOperation.read, key)) {
      throw const _InjectedStorageFailure(
        operation: _FaultOperation.read,
        key: 'redacted',
        afterCommit: false,
      );
    }
    return super.read(key: key);
  }

  @override
  Future<void> write({required String key, required String value}) async {
    final fault = _fault;
    if (_hits(_FaultOperation.write, key)) {
      if (fault!.afterCommit) {
        await super.write(key: key, value: value);
      }
      throw _InjectedStorageFailure(
        operation: _FaultOperation.write,
        key: key,
        afterCommit: fault.afterCommit,
      );
    }
    await super.write(key: key, value: value);
  }

  @override
  Future<void> delete({required String key}) async {
    final fault = _fault;
    if (_hits(_FaultOperation.delete, key)) {
      if (fault!.afterCommit) {
        await super.delete(key: key);
      }
      throw _InjectedStorageFailure(
        operation: _FaultOperation.delete,
        key: key,
        afterCommit: fault.afterCommit,
      );
    }
    await super.delete(key: key);
  }
}

final class _Pair {
  final SignalProtocolManager alice;
  final FakeSecureStorage aliceStorage;
  final SignalProtocolManager bob;
  final _FaultStorage bobStorage;

  const _Pair({
    required this.alice,
    required this.aliceStorage,
    required this.bob,
    required this.bobStorage,
  });
}

final class _PreparedBase {
  final _Pair pair;
  final Map<String, dynamic> envelope;
  final PreparedReceive prepared;
  final Map<String, String> preState;
  final Map<String, String> preparedSnapshot;
  final String plaintext;
  final String deliveryId;

  const _PreparedBase({
    required this.pair,
    required this.envelope,
    required this.prepared,
    required this.preState,
    required this.preparedSnapshot,
    required this.plaintext,
    required this.deliveryId,
  });
}

Future<_Pair> _freshPair({bool simultaneousFirstContact = false}) async {
  final aliceStorage = FakeSecureStorage();
  final bobStorage = _FaultStorage();
  final aliceResult = await CryptoTestFixtures.createInitializedManager(
    storage: aliceStorage,
  );
  final bobResult = await CryptoTestFixtures.createInitializedManager(
    storage: bobStorage,
  );
  final alice = aliceResult.$1;
  final bob = bobResult.$1;

  await aliceStorage.write(key: 'user_id', value: 'alice-id');
  await aliceStorage.write(key: 'device_id', value: 'alice-device');
  await bobStorage.write(key: 'user_id', value: 'bob-id');
  await bobStorage.write(key: 'device_id', value: 'bob-device');

  final acceptedBob = await CryptoTestFixtures.acceptInitialGeneration(bob);
  AcceptedTestGeneration? acceptedAlice;
  if (simultaneousFirstContact) {
    acceptedAlice = await CryptoTestFixtures.acceptInitialGeneration(alice);
  }
  await alice.createSession(
    acceptedBob.consumerBundle(userId: 'bob-id', deviceId: 'bob-device'),
  );
  if (acceptedAlice != null) {
    await bob.createSession(
      acceptedAlice.consumerBundle(
        userId: 'alice-id',
        deviceId: 'alice-device',
      ),
    );
  }
  return _Pair(
    alice: alice,
    aliceStorage: aliceStorage,
    bob: bob,
    bobStorage: bobStorage,
  );
}

Future<_PreparedBase> _preparedBase({
  bool simultaneousFirstContact = false,
  String deliveryId = 'fault-delivery-prekey-1',
  String plaintext = 'fault-matrix-private-plaintext',
}) async {
  final pair = await _freshPair(
    simultaneousFirstContact: simultaneousFirstContact,
  );
  final envelope = await pair.alice.encryptMessage(
    'bob-id',
    'bob-device',
    plaintext,
  );
  final preState = _withoutReceiveWal(pair.bobStorage.store);
  final prepared = await pair.bob.prepareReceive(
    deliveryId: deliveryId,
    senderId: 'alice-id',
    senderDeviceId: 'alice-device',
    envelope: envelope,
  );
  return _PreparedBase(
    pair: pair,
    envelope: envelope,
    prepared: prepared,
    preState: preState,
    preparedSnapshot: pair.bobStorage.store,
    plaintext: plaintext,
    deliveryId: deliveryId,
  );
}

Future<_PreparedBase> _preparedNormalBase() async {
  final pair = await _freshPair();
  final firstEnvelope = await pair.alice.encryptMessage(
    'bob-id',
    'bob-device',
    'establish before normal fault',
  );
  final first = await pair.bob.prepareReceive(
    deliveryId: 'establish-before-normal-fault',
    senderId: 'alice-id',
    senderDeviceId: 'alice-device',
    envelope: firstEnvelope,
  );
  await pair.bob.acknowledgeReceive(first.receipt);

  const deliveryId = 'normal-mutation-boundary-delivery';
  const plaintext = 'normal-mutation-boundary-private-plaintext';
  final envelope = await pair.alice.encryptMessage(
    'bob-id',
    'bob-device',
    plaintext,
  );
  final preState = _withoutReceiveWal(pair.bobStorage.store);
  final prepared = await pair.bob.prepareReceive(
    deliveryId: deliveryId,
    senderId: 'alice-id',
    senderDeviceId: 'alice-device',
    envelope: envelope,
  );
  return _PreparedBase(
    pair: pair,
    envelope: envelope,
    prepared: prepared,
    preState: preState,
    preparedSnapshot: pair.bobStorage.store,
    plaintext: plaintext,
    deliveryId: deliveryId,
  );
}

/// P1-12: the sealed-PreKey shape had no fault coverage at all, yet it is the
/// default first-contact path and the one shape where the key-bundle journal,
/// the pending-prekey delete and the sealed nonce must all land atomically.
/// A relay that interrupts it either strands a consumed one-time prekey
/// (message lost forever) or resurrects the replay nonce.
Future<_PreparedBase> _preparedSealedPreKeyBase() async {
  final pair = await _freshPair();

  const deliveryId = 'sealed-prekey-mutation-boundary-delivery';
  const plaintext = 'sealed-prekey-boundary-private-plaintext';
  // No prior session: this really is first contact, so the envelope carries the
  // full routed PreKey handshake.
  final envelope = await pair.alice.encryptSealedSender(
    'bob-id',
    'bob-device',
    await pair.bob.getIdentityPublicKey(),
    plaintext,
  );
  final preState = _withoutReceiveWal(pair.bobStorage.store);
  final prepared = await pair.bob.prepareSealedReceive(
    deliveryId: deliveryId,
    sealedEnvelope: envelope,
  );
  expect(prepared.receipt.kind, ReceiveEnvelopeKind.sealedPreKey);
  return _PreparedBase(
    pair: pair,
    envelope: envelope,
    prepared: prepared,
    preState: preState,
    preparedSnapshot: pair.bobStorage.store,
    plaintext: plaintext,
    deliveryId: deliveryId,
  );
}

Future<_PreparedBase> _preparedSealedNormalBase() async {
  final pair = await _freshPair();
  final firstEnvelope = await pair.alice.encryptMessage(
    'bob-id',
    'bob-device',
    'establish before sealed fault',
  );
  final first = await pair.bob.prepareReceive(
    deliveryId: 'establish-before-sealed-fault',
    senderId: 'alice-id',
    senderDeviceId: 'alice-device',
    envelope: firstEnvelope,
  );
  await pair.bob.acknowledgeReceive(first.receipt);

  const deliveryId = 'sealed-mutation-boundary-delivery';
  const plaintext = 'sealed-mutation-boundary-private-plaintext';
  final envelope = await pair.alice.encryptSealedSender(
    'bob-id',
    'bob-device',
    await pair.bob.getIdentityPublicKey(),
    plaintext,
  );
  final preState = _withoutReceiveWal(pair.bobStorage.store);
  final prepared = await pair.bob.prepareSealedReceive(
    deliveryId: deliveryId,
    sealedEnvelope: envelope,
  );
  return _PreparedBase(
    pair: pair,
    envelope: envelope,
    prepared: prepared,
    preState: preState,
    preparedSnapshot: pair.bobStorage.store,
    plaintext: plaintext,
    deliveryId: deliveryId,
  );
}

Map<String, String> _withoutReceiveWal(Map<String, String> source) =>
    Map<String, String>.fromEntries(
      source.entries.where((entry) => entry.key != _receiveJournalKey),
    );

Future<_FaultStorage> _cloneStorage(Map<String, String> snapshot) async {
  final clone = _FaultStorage();
  for (final entry in snapshot.entries) {
    await clone.write(key: entry.key, value: entry.value);
  }
  return clone;
}

List<Map<String, dynamic>> _pendingMutations(Map<String, String> snapshot) {
  final raw = snapshot[_receiveJournalKey];
  if (raw == null) throw StateError('Prepared receive journal is missing');
  final decoded = Map<String, dynamic>.from(jsonDecode(raw) as Map);
  final pending = Map<String, dynamic>.from(decoded['pending'] as Map);
  return (pending['mutations'] as List)
      .map((value) => Map<String, dynamic>.from(value as Map))
      .toList(growable: false);
}

Future<ReceiveCommitRecoveryRequired> _expectRecoveryRequired(
  SignalProtocolManager manager,
) async {
  try {
    await manager.initialize();
  } on ReceiveCommitRecoveryRequired catch (error) {
    return error;
  }
  throw StateError('Expected receive recovery gate');
}

Future<SignalProtocolManager> _initializeAfterHostDurable(
  _FaultStorage storage,
) async {
  final manager = SignalProtocolManager(secureStorage: storage);
  try {
    await manager.initialize();
  } on ReceiveCommitRecoveryRequired catch (recovery) {
    await manager.acknowledgeReceive(recovery.receipt);
    await manager.initialize();
  }
  return manager;
}

void _expectWalPrivacy(
  _FaultStorage storage, {
  required String plaintext,
  required String deliveryId,
}) {
  final raw = storage.store[_receiveJournalKey] ?? '';
  expect(raw, isNot(contains(plaintext)));
  expect(raw, isNot(contains(deliveryId)));
}

void main() {
  group('receive WAL preparation and rollback recovery', () {
    test(
      'fail-before and commit-then-throw WAL prepare preserve exact pre-state',
      () async {
        for (final afterCommit in <bool>[false, true]) {
          final pair = await _freshPair();
          final deliveryId =
              'prepare-fault-${afterCommit ? 'after' : 'before'}';
          const plaintext = 'prepare-fault-private-plaintext';
          final envelope = await pair.alice.encryptMessage(
            'bob-id',
            'bob-device',
            plaintext,
          );
          final preState = _withoutReceiveWal(pair.bobStorage.store);
          pair.bobStorage.failWrite(
            _receiveJournalKey,
            afterCommit: afterCommit,
          );

          await expectLater(
            pair.bob.prepareReceive(
              deliveryId: deliveryId,
              senderId: 'alice-id',
              senderDeviceId: 'alice-device',
              envelope: envelope,
            ),
            throwsA(isA<_InjectedStorageFailure>()),
          );
          expect(_withoutReceiveWal(pair.bobStorage.store), preState);
          _expectWalPrivacy(
            pair.bobStorage,
            plaintext: plaintext,
            deliveryId: deliveryId,
          );

          final restarted = SignalProtocolManager(
            secureStorage: pair.bobStorage,
          );
          if (afterCommit) {
            final recovery = await _expectRecoveryRequired(restarted);
            await restarted.abortPreparedReceive(recovery.receipt);
            await restarted.initialize();
          } else {
            await restarted.initialize();
          }
          expect(_withoutReceiveWal(pair.bobStorage.store), preState);

          final retried = await restarted.prepareReceive(
            deliveryId: deliveryId,
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            envelope: envelope,
          );
          expect(retried.plaintext, plaintext);
          await restarted.acknowledgeReceive(retried.receipt);
        }
      },
    );

    test(
      'interrupted abort is idempotent for fail-before and commit-then-throw',
      () async {
        final base = await _preparedBase(
          deliveryId: 'rollback-interruption-delivery',
          plaintext: 'rollback-interruption-private-plaintext',
        );

        for (final afterCommit in <bool>[false, true]) {
          final storage = await _cloneStorage(base.preparedSnapshot);
          final firstRestart = SignalProtocolManager(secureStorage: storage);
          final recovery = await _expectRecoveryRequired(firstRestart);
          storage.failWrite(_receiveJournalKey, afterCommit: afterCommit);
          await expectLater(
            firstRestart.abortPreparedReceive(recovery.receipt),
            throwsA(isA<_InjectedStorageFailure>()),
          );

          final secondRestart = SignalProtocolManager(secureStorage: storage);
          if (afterCommit) {
            await secondRestart.initialize();
            await secondRestart.abortPreparedReceive(recovery.receipt);
          } else {
            final repeatedRecovery = await _expectRecoveryRequired(
              secondRestart,
            );
            expect(
              repeatedRecovery.receipt.matchesExact(recovery.receipt),
              isTrue,
            );
            await secondRestart.abortPreparedReceive(repeatedRecovery.receipt);
            await secondRestart.initialize();
          }
          expect(_withoutReceiveWal(storage.store), base.preState);

          final retried = await secondRestart.prepareReceive(
            deliveryId: base.deliveryId,
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            envelope: base.envelope,
          );
          expect(retried.plaintext, base.plaintext);
          await secondRestart.acknowledgeReceive(retried.receipt);
        }
      },
    );
  });

  group('receive ACK crash recovery', () {
    test(
      'pending host receipt blocks every eager session writer on the shared lane',
      () async {
        final base = await _preparedBase(
          simultaneousFirstContact: true,
          deliveryId: 'shared-session-lane-delivery',
          plaintext: 'shared-session-lane-private-plaintext',
        );
        final exactPreparedState = base.pair.bobStorage.store;

        await expectLater(
          base.pair.bob.encryptMessage(
            'alice-id',
            'alice-device',
            'must not advance outgoing session',
          ),
          throwsA(isA<StateError>()),
        );
        await expectLater(
          base.pair.bob.decryptMessage(
            'alice-id',
            'alice-device',
            base.envelope,
          ),
          throwsA(isA<StateError>()),
        );
        await expectLater(
          base.pair.bob.removeSession('alice-id', 'alice-device'),
          throwsA(isA<StateError>()),
        );
        expect(base.pair.bobStorage.store, exactPreparedState);

        await base.pair.bob.acknowledgeReceive(base.prepared.receipt);
      },
    );

    test(
      'commit decision and completion WAL writes recover on both failure timings',
      () async {
        final base = await _preparedBase(
          deliveryId: 'ack-wal-boundary-delivery',
          plaintext: 'ack-wal-boundary-private-plaintext',
        );
        SignalProtocolManager? lastRecovered;

        for (final occurrence in <int>[1, 2]) {
          for (final afterCommit in <bool>[false, true]) {
            final storage = await _cloneStorage(base.preparedSnapshot);
            storage.failWrite(
              _receiveJournalKey,
              afterCommit: afterCommit,
              occurrence: occurrence,
            );
            final acknowledging = SignalProtocolManager(secureStorage: storage);
            await expectLater(
              acknowledging.acknowledgeReceive(base.prepared.receipt),
              throwsA(isA<_InjectedStorageFailure>()),
            );

            final recovered = await _initializeAfterHostDurable(storage);
            final redelivery = await recovered.prepareReceive(
              deliveryId: base.deliveryId,
              senderId: 'alice-id',
              senderDeviceId: 'alice-device',
              envelope: base.envelope,
            );
            expect(redelivery.alreadyAcknowledged, isTrue);
            expect(redelivery.plaintext, isNull);
            _expectWalPrivacy(
              storage,
              plaintext: base.plaintext,
              deliveryId: base.deliveryId,
            );
            lastRecovered = recovered;
          }
        }

        final nextEnvelope = await base.pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'next valid after WAL recovery',
        );
        final next = await lastRecovered!.prepareReceive(
          deliveryId: 'next-after-ack-wal-recovery',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: nextEnvelope,
        );
        expect(next.plaintext, 'next valid after WAL recovery');
        await lastRecovered.acknowledgeReceive(next.receipt);
      },
    );

    test(
      'every PreKey mutation recovers from fail-before and commit-then-throw',
      () async {
        final base = await _preparedBase(
          simultaneousFirstContact: true,
          deliveryId: 'mutation-boundary-delivery',
          plaintext: 'mutation-boundary-private-plaintext',
        );
        final mutations = _pendingMutations(base.preparedSnapshot);
        final mutationKeys = mutations
            .map((mutation) => mutation['key'])
            .toSet();
        expect(mutationKeys, contains(_bundleJournalKey));
        expect(mutationKeys, contains(_pendingPreKeyKey));
        SignalProtocolManager? lastRecovered;

        for (final mutation in mutations) {
          final key = mutation['key'] as String;
          final afterValue = mutation['afterValue'] as String?;
          for (final afterCommit in <bool>[false, true]) {
            final storage = await _cloneStorage(base.preparedSnapshot);
            if (afterValue == null) {
              storage.failDelete(key, afterCommit: afterCommit);
            } else {
              storage.failWrite(key, afterCommit: afterCommit);
            }
            final acknowledging = SignalProtocolManager(secureStorage: storage);
            await expectLater(
              acknowledging.acknowledgeReceive(base.prepared.receipt),
              throwsA(isA<_InjectedStorageFailure>()),
            );

            final recovered = SignalProtocolManager(secureStorage: storage);
            await recovered.initialize();
            for (final planned in mutations) {
              expect(
                await storage.read(key: planned['key'] as String),
                planned['afterValue'],
                reason:
                    'recovery after ${afterCommit ? 'commit-then-throw' : 'fail-before'} '
                    'at $key must apply every after-image',
              );
            }
            final redelivery = await recovered.prepareReceive(
              deliveryId: base.deliveryId,
              senderId: 'alice-id',
              senderDeviceId: 'alice-device',
              envelope: base.envelope,
            );
            expect(redelivery.alreadyAcknowledged, isTrue);
            _expectWalPrivacy(
              storage,
              plaintext: base.plaintext,
              deliveryId: base.deliveryId,
            );
            lastRecovered = recovered;
          }
        }

        final nextEnvelope = await base.pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'next valid after every mutation boundary',
        );
        final next = await lastRecovered!.prepareReceive(
          deliveryId: 'next-after-mutation-boundaries',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: nextEnvelope,
        );
        expect(next.plaintext, 'next valid after every mutation boundary');
        await lastRecovered.acknowledgeReceive(next.receipt);
      },
    );

    test(
      'normal session mutation recovers on both ambiguous failure timings',
      () async {
        final base = await _preparedNormalBase();
        final mutations = _pendingMutations(base.preparedSnapshot);
        expect(mutations, hasLength(1));
        final mutation = mutations.single;
        final key = mutation['key'] as String;
        final afterValue = mutation['afterValue'] as String;
        SignalProtocolManager? lastRecovered;

        for (final afterCommit in <bool>[false, true]) {
          final storage = await _cloneStorage(base.preparedSnapshot);
          storage.failWrite(key, afterCommit: afterCommit);
          final acknowledging = SignalProtocolManager(secureStorage: storage);
          await expectLater(
            acknowledging.acknowledgeReceive(base.prepared.receipt),
            throwsA(isA<_InjectedStorageFailure>()),
          );
          final recovered = SignalProtocolManager(secureStorage: storage);
          await recovered.initialize();
          expect(await storage.read(key: key), afterValue);
          final redelivery = await recovered.prepareReceive(
            deliveryId: base.deliveryId,
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            envelope: base.envelope,
          );
          expect(redelivery.alreadyAcknowledged, isTrue);
          _expectWalPrivacy(
            storage,
            plaintext: base.plaintext,
            deliveryId: base.deliveryId,
          );
          lastRecovered = recovered;
        }

        final nextEnvelope = await base.pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'normal next valid after recovery',
        );
        final next = await lastRecovered!.prepareReceive(
          deliveryId: 'normal-next-valid-after-recovery',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: nextEnvelope,
        );
        expect(next.plaintext, 'normal next valid after recovery');
        await lastRecovered.acknowledgeReceive(next.receipt);
      },
    );

    test(
      'sealed session and nonce mutations each recover on both failure timings',
      () async {
        final base = await _preparedSealedNormalBase();
        final mutations = _pendingMutations(base.preparedSnapshot);
        expect(mutations, hasLength(2));
        expect(
          mutations.map((mutation) => mutation['key']),
          contains('crypto_e2_seen_nonces'),
        );
        SignalProtocolManager? lastRecovered;

        for (final mutation in mutations) {
          final key = mutation['key'] as String;
          final afterValue = mutation['afterValue'] as String;
          for (final afterCommit in <bool>[false, true]) {
            final storage = await _cloneStorage(base.preparedSnapshot);
            storage.failWrite(key, afterCommit: afterCommit);
            final acknowledging = SignalProtocolManager(secureStorage: storage);
            await expectLater(
              acknowledging.acknowledgeReceive(base.prepared.receipt),
              throwsA(isA<_InjectedStorageFailure>()),
            );
            final recovered = SignalProtocolManager(secureStorage: storage);
            await recovered.initialize();
            expect(await storage.read(key: key), afterValue);
            final redelivery = await recovered.prepareSealedReceive(
              deliveryId: base.deliveryId,
              sealedEnvelope: base.envelope,
            );
            expect(redelivery.alreadyAcknowledged, isTrue);
            _expectWalPrivacy(
              storage,
              plaintext: base.plaintext,
              deliveryId: base.deliveryId,
            );
            lastRecovered = recovered;
          }
        }

        final nextEnvelope = await base.pair.alice.encryptSealedSender(
          'bob-id',
          'bob-device',
          await lastRecovered!.getIdentityPublicKey(),
          'sealed next valid after recovery',
        );
        final next = await lastRecovered.prepareSealedReceive(
          deliveryId: 'sealed-next-valid-after-recovery',
          sealedEnvelope: nextEnvelope,
        );
        expect(next.plaintext, 'sealed next valid after recovery');
        await lastRecovered.acknowledgeReceive(next.receipt);
      },
    );
  });
  group('P1-15 read boundaries in the commit path are fault-tolerant', () {
    test('a read failure at acknowledge leaves the pre-state intact and the '
        'delivery still recoverable', () async {
      final pair = await _freshPair();
      final envelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'read-fault delivery',
      );

      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'p1-15-read-fault',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: envelope,
      );
      final beforeAck = Map<String, String>.from(pair.bobStorage.store);

      // Fail the journal READ that acknowledge performs first. On a locked iOS
      // device this is an ordinary occurrence, not an exotic fault.
      pair.bobStorage.failRead(_receiveJournalKey);
      await expectLater(
        pair.bob.acknowledgeReceive(prepared.receipt),
        throwsA(isA<_InjectedStorageFailure>()),
      );

      // Nothing may have been published by a failed read.
      expect(
        pair.bobStorage.store,
        beforeAck,
        reason: 'a failed read must not mutate durable state',
      );

      // And the delivery is still completable once storage recovers.
      final durable = await pair.bob.acknowledgeReceive(prepared.receipt);
      expect(durable.matchesExact(prepared.receipt), isTrue);
      expect(
        pair.bobStorage.store[_receiveJournalKey],
        isNot(beforeAck[_receiveJournalKey]),
        reason: 'the commit must have advanced after recovery',
      );
    });

    test(
      'a read failure during prepare leaves no pending commit behind',
      () async {
        final pair = await _freshPair();
        final envelope = await pair.alice.encryptMessage(
          'bob-id',
          'bob-device',
          'read-fault prepare',
        );
        final before = Map<String, String>.from(pair.bobStorage.store);

        pair.bobStorage.failRead(_receiveJournalKey);
        await expectLater(
          pair.bob.prepareReceive(
            deliveryId: 'p1-15-prepare-read-fault',
            senderId: 'alice-id',
            senderDeviceId: 'alice-device',
            envelope: envelope,
          ),
          throwsA(isA<_InjectedStorageFailure>()),
        );
        expect(pair.bobStorage.store, before);

        // The peer simply redelivers; nothing is stuck.
        final retried = await pair.bob.prepareReceive(
          deliveryId: 'p1-15-prepare-read-fault',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: envelope,
        );
        expect(retried.plaintext, 'read-fault prepare');
        await pair.bob.acknowledgeReceive(retried.receipt);
      },
    );
  });
  group('P1-12/P1-13 sealed PreKey is the first-contact path and must be '
      'fault-covered', () {
    test('every sealed-PreKey mutation recovers from fail-before and '
        'commit-then-throw, with byte-identical pre-state until ACK', () async {
      final base = await _preparedSealedPreKeyBase();
      final mutations = _pendingMutations(base.preparedSnapshot);
      expect(
        mutations.length,
        greaterThan(2),
        reason:
            'sealed PreKey must commit the session, the identity pin, the '
            'bundle journal and the sealed nonce together',
      );

      // P1-13: the pre-state was captured on every lane but only ever asserted
      // on direct-PreKey. Assert it here, whole-map, before any ACK.
      expect(
        _withoutReceiveWal(base.pair.bobStorage.store),
        base.preState,
        reason: 'a prepared receive must publish nothing',
      );

      for (final mutation in mutations) {
        final key = mutation['key'] as String;
        final afterValue = mutation['afterValue'] as String?;
        for (final afterCommit in const <bool>[false, true]) {
          final scenario = await _preparedSealedPreKeyBase();
          if (afterValue == null) {
            scenario.pair.bobStorage.failDelete(key, afterCommit: afterCommit);
          } else {
            scenario.pair.bobStorage.failWrite(key, afterCommit: afterCommit);
          }
          await expectLater(
            scenario.pair.bob.acknowledgeReceive(scenario.prepared.receipt),
            throwsA(isA<_InjectedStorageFailure>()),
            reason: 'injected $key afterCommit=$afterCommit',
          );

          // Recovery must converge to exactly one completed receipt.
          final durable = await scenario.pair.bob.acknowledgeReceive(
            scenario.prepared.receipt,
          );
          expect(
            durable.matchesExact(scenario.prepared.receipt),
            isTrue,
            reason: 'converged receipt differs for $key/$afterCommit',
          );

          // And the delivery is genuinely applied, not merely marked done.
          expect(
            await scenario.pair.bob.hasSession('alice-id', 'alice-device'),
            isTrue,
            reason: 'session missing after recovery for $key/$afterCommit',
          );

          // A redelivery is idempotent, never a second ratchet advance.
          final replay = await scenario.pair.bob.prepareSealedReceive(
            deliveryId: scenario.deliveryId,
            sealedEnvelope: scenario.envelope,
          );
          expect(replay.alreadyAcknowledged, isTrue);
        }
      }
    });
  });
  group('P1 coverage: cross-sender interleaving, roll-forward faults, sealed '
      'abort', () {
    test('two senders interleave: one pending receive never corrupts the '
        'other sender\'s session', () async {
      final pair = await _freshPair();
      final (carol, _) = await CryptoTestFixtures.createInitializedManager();
      final bobAccepted = await CryptoTestFixtures.acceptReplacementGeneration(
        pair.bob,
        deviceId: 'bob-device',
      );
      await carol.createSession(bobAccepted.consumerBundle());

      final fromAlice = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'alice one',
      );
      final fromCarol = await carol.encryptMessage(
        'bob-id',
        'bob-device',
        'carol one',
      );

      // Alice's delivery is prepared and left pending.
      final alicePending = await pair.bob.prepareReceive(
        deliveryId: 'interleave-alice',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: fromAlice,
      );
      expect(alicePending.plaintext, 'alice one');

      // A different sender's delivery must not be able to start while another
      // is pending — the WAL is single-writer by design — but it must succeed
      // immediately afterwards, with its own plaintext, uncorrupted.
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'interleave-carol',
          senderId: 'carol-id',
          senderDeviceId: 'carol-device',
          envelope: fromCarol,
        ),
        throwsA(isA<StateError>()),
      );

      await pair.bob.acknowledgeReceive(alicePending.receipt);

      final carolPrepared = await pair.bob.prepareReceive(
        deliveryId: 'interleave-carol',
        senderId: 'carol-id',
        senderDeviceId: 'carol-device',
        envelope: fromCarol,
      );
      expect(carolPrepared.plaintext, 'carol one');
      await pair.bob.acknowledgeReceive(carolPrepared.receipt);

      // Both sessions are independently live afterwards.
      expect(await pair.bob.hasSession('alice-id', 'alice-device'), isTrue);
      expect(await pair.bob.hasSession('carol-id', 'carol-device'), isTrue);
    });

    test('a fault during roll-forward recovery still converges', () async {
      final base = await _preparedBase(
        deliveryId: 'roll-forward-fault-delivery',
        plaintext: 'roll-forward-private-plaintext',
      );

      // Drive the commit to `commitDecided`, then fail the completion write so
      // recovery has real roll-forward work left to do.
      base.pair.bobStorage.failWrite(
        _receiveJournalKey,
        afterCommit: false,
        occurrence: 2,
      );
      await expectLater(
        base.pair.bob.acknowledgeReceive(base.prepared.receipt),
        throwsA(isA<_InjectedStorageFailure>()),
      );

      // Now fail again during the recovery attempt itself.
      base.pair.bobStorage.failWrite(_receiveJournalKey, afterCommit: true);
      await expectLater(
        base.pair.bob.acknowledgeReceive(base.prepared.receipt),
        throwsA(isA<_InjectedStorageFailure>()),
      );

      // Third attempt, storage healthy: it must converge to exactly one
      // completed receipt rather than double-applying or wedging.
      final durable = await base.pair.bob.acknowledgeReceive(
        base.prepared.receipt,
      );
      expect(durable.matchesExact(base.prepared.receipt), isTrue);
      expect(
        await base.pair.bob.hasSession('alice-id', 'alice-device'),
        isTrue,
      );
    });

    test('aborting a sealed prepare rolls back the nonce so the peer can '
        'redeliver', () async {
      final base = await _preparedSealedPreKeyBase();
      final preState = base.preState;

      await base.pair.bob.abortPreparedReceive(base.prepared.receipt);
      expect(
        _withoutReceiveWal(base.pair.bobStorage.store),
        preState,
        reason:
            'an aborted sealed prepare must leave no trace, including no '
            'consumed replay nonce — otherwise the redelivery is refused and '
            'the message is lost for good',
      );

      // The peer redelivers the identical envelope and it must work.
      final retried = await base.pair.bob.prepareSealedReceive(
        deliveryId: base.deliveryId,
        sealedEnvelope: base.envelope,
      );
      expect(retried.plaintext, base.plaintext);
      await base.pair.bob.acknowledgeReceive(retried.receipt);
    });
  });
}
