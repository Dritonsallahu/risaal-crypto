import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/session_errors.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// R4-PKG-SESSION-PIN-CHECK: a session records the remote identity it was
/// created with, and no encrypt/decrypt may use it once that identity
/// disagrees with the enforced pin (`session_ik`).
class _CrashableStorage extends FakeSecureStorage {
  bool failDeletes = false;
  String? failWriteKey;

  @override
  Future<void> delete({required String key}) async {
    if (failDeletes) throw StateError('simulated crash during cleanup');
    await super.delete(key: key);
  }

  @override
  Future<void> write({required String key, required String value}) async {
    if (key == failWriteKey) throw StateError('simulated crash on write');
    await super.write(key: key, value: value);
  }
}

const _sessionKey = 'crypto_e2_session_bob-id_bob-d1';
const _pinKey = 'crypto_e2_session_ik_bob-id_bob-d1';

class _F {
  _F(this.alice, this.store, this.bob1, this.bob1Store, this.bob2, this.k1);
  final SignalProtocolManager alice;
  final _CrashableStorage store;
  final SignalProtocolManager bob1;
  final FakeSecureStorage bob1Store;
  final SignalProtocolManager bob2;
  final String k1;
  late PreKeyBundle bob2Bundle;
  late String k2;
  late String aliceIk;
}

Future<(SignalProtocolManager, FakeSecureStorage)> _peer(
  String userId,
  String deviceId, [
  FakeSecureStorage? storage,
]) async {
  final s = storage ?? FakeSecureStorage();
  final manager = SignalProtocolManager(secureStorage: s);
  await manager.wipeForFreshRegistration();
  await manager.initialize();
  await s.write(key: 'user_id', value: userId);
  await s.write(key: 'device_id', value: deviceId);
  return (manager, s);
}

/// Alice and bob-id/bob-d1 (identity K1) with a live session both ways; bob2
/// holds K2 for the same user/device (the key a user would verify).
Future<_F> _setUp() async {
  final store = _CrashableStorage();
  final (alice, _) = await _peer('alice-id', 'alice-device', store);
  final (bob1, bob1Store) = await _peer('bob-id', 'bob-d1');
  final bundle = (await CryptoTestFixtures.acceptInitialGeneration(
    bob1,
  )).consumerBundle(userId: 'bob-id', deviceId: 'bob-d1');
  await alice.createSession(bundle);
  final first = await alice.encryptMessage('bob-id', 'bob-d1', 'hello');
  expect(await bob1.decryptMessage('alice-id', 'alice-device', first), 'hello');
  final reply = await bob1.encryptMessage('alice-id', 'alice-device', 'hi');
  expect(await alice.decryptMessage('bob-id', 'bob-d1', reply), 'hi');
  final (bob2, _) = await _peer('bob-id', 'bob-d1');
  final f = _F(alice, store, bob1, bob1Store, bob2, bundle.identityKey);
  f.bob2Bundle = (await CryptoTestFixtures.acceptInitialGeneration(
    bob2,
  )).consumerBundle(userId: 'bob-id', deviceId: 'bob-d1');
  f.k2 = f.bob2Bundle.identityKey;
  f.aliceIk = await alice.getIdentityPublicKey();
  expect(f.k2, isNot(f.k1));
  return f;
}

Map<String, dynamic> _stored(FakeSecureStorage s, String key) =>
    jsonDecode(s.store[key]!) as Map<String, dynamic>;

/// Rewrite the stored session record (e.g. drop the field = legacy record).
Future<void> _editSession(
  _CrashableStorage s,
  void Function(Map<String, dynamic>) edit,
) async {
  final json = _stored(s, _sessionKey);
  edit(json);
  await s.write(key: _sessionKey, value: jsonEncode(json));
}

Future<SignalProtocolManager> _restart(_CrashableStorage s) async {
  final m = SignalProtocolManager(secureStorage: s);
  await m.initialize();
  return m;
}

final _mismatch = throwsA(
  isA<SessionIdentityMismatchError>()
      .having((e) => e.peerId, 'peerId', 'bob-id')
      .having((e) => e.deviceId, 'deviceId', 'bob-d1'),
);

/// Every outbound and inbound use of the bob-id/bob-d1 session is refused
/// with the typed error and leaves the stored ratchet byte-identical.
Future<void> _expectRefusedEverywhere(
  _F f,
  SignalProtocolManager m, {
  required String tag,
}) async {
  final before = f.store.store[_sessionKey];
  final normal = await f.bob1.encryptMessage('alice-id', 'alice-device', tag);
  expect(normal['type'], 'message');
  await expectLater(m.encryptMessage('bob-id', 'bob-d1', 'x'), _mismatch);
  await expectLater(m.decryptMessage('bob-id', 'bob-d1', normal), _mismatch);
  await expectLater(
    m.decryptNormalBatch('bob-id', 'bob-d1', [normal], useIsolate: false),
    _mismatch,
  );
  await expectLater(
    m.prepareReceive(
      deliveryId: 'normal-$tag',
      senderId: 'bob-id',
      senderDeviceId: 'bob-d1',
      envelope: normal,
    ),
    _mismatch,
  );
  // Host-keyed sealed sends with the OLD key K1.
  await expectLater(
    m.encryptSealedSender('bob-id', 'bob-d1', f.k1, 'x'),
    _mismatch,
  );
  await expectLater(
    m.prepareSealedSend(
      deliveryId: 'send-$tag',
      recipientId: 'bob-id',
      recipientDeviceId: 'bob-d1',
      recipientIdentityPublicKey: f.k1,
      plaintext: 'x',
    ),
    _mismatch,
  );
  expect(f.store.store[_sessionKey], before, reason: 'ratchet untouched');
}

void main() {
  test(
    'a new session records the remote identity and survives a reload',
    () async {
      final f = await _setUp();
      // Send side (createSession) and receive side (legacy PreKey responder).
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k1);
      expect(
        _stored(
          f.bob1Store,
          'crypto_e2_session_alice-id_alice-device',
        )['remoteIdentityKey'],
        f.aliceIk,
      );
      // Receive side, WAL lane: a prepared + acknowledged PreKey from carol.
      final aliceGen = await CryptoTestFixtures.acceptInitialGeneration(
        f.alice,
      );
      final aliceBundle = aliceGen.consumerBundle(
        userId: 'alice-id',
        deviceId: 'alice-device',
      );
      final (carol, _) = await _peer('carol-id', 'carol-d1');
      await carol.createSession(aliceBundle);
      final pre = await carol.encryptMessage('alice-id', 'alice-device', 'c');
      final prepared = await f.alice.prepareReceive(
        deliveryId: 'carol-1',
        senderId: 'carol-id',
        senderDeviceId: 'carol-d1',
        envelope: pre,
      );
      expect(prepared.plaintext, 'c');
      await f.alice.acknowledgeReceive(prepared.receipt);
      expect(
        _stored(
          f.store,
          'crypto_e2_session_carol-id_carol-d1',
        )['remoteIdentityKey'],
        await carol.getIdentityPublicKey(),
      );
      // Legacy responder lane, inspected before any later load.
      final (erin, _) = await _peer('erin-id', 'erin-d1');
      await erin.createSession(
        aliceGen.consumerBundle(
          userId: 'alice-id',
          deviceId: 'alice-device',
          oneTimePreKeyIndex: 1,
        ),
      );
      final erinPre = await erin.encryptMessage(
        'alice-id',
        'alice-device',
        'e',
      );
      expect(await f.alice.decryptMessage('erin-id', 'erin-d1', erinPre), 'e');
      expect(
        _stored(
          f.store,
          'crypto_e2_session_erin-id_erin-d1',
        )['remoteIdentityKey'],
        await erin.getIdentityPublicKey(),
      );
      // Recorded at creation, before any load could stamp it.
      final (dave, _) = await _peer('dave-id', 'dave-d1');
      final daveBundle = (await CryptoTestFixtures.acceptInitialGeneration(
        dave,
      )).consumerBundle(userId: 'dave-id', deviceId: 'dave-d1');
      await f.alice.createSession(daveBundle);
      expect(
        _stored(
          f.store,
          'crypto_e2_session_dave-id_dave-d1',
        )['remoteIdentityKey'],
        daveBundle.identityKey,
      );

      final restarted = await _restart(f.store);
      final env = await restarted.encryptMessage('bob-id', 'bob-d1', 'again');
      expect(
        await f.bob1.decryptMessage('alice-id', 'alice-device', env),
        'again',
      );
      final back = await f.bob1.encryptMessage('alice-id', 'alice-device', 'b');
      expect(await restarted.decryptMessage('bob-id', 'bob-d1', back), 'b');
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k1);
    },
  );

  test(
    'pin changed under a live session: every path refuses, ratchet unchanged',
    () async {
      final f = await _setUp();
      await f.store.write(key: _pinKey, value: f.k2); // simulated drift
      await _expectRefusedEverywhere(f, f.alice, tag: 'live');
      // Sealed receive is refused too (outer K1 vs pin K2 — pre-existing check).
      final sealed = await f.bob1.encryptSealedSender(
        'alice-id',
        'alice-device',
        f.aliceIk,
        's',
      );
      await expectLater(
        f.alice.decryptSealedSender(sealed),
        throwsA(isA<StateError>()),
      );
      // The error never carries key material.
      try {
        await f.alice.encryptMessage('bob-id', 'bob-d1', 'x');
      } on SessionIdentityMismatchError catch (e) {
        expect(e.message, isNot(contains(f.k1)));
        expect(e.message, isNot(contains(f.k2)));
      }

      // Undo the drift: the untouched session works again, from the same step.
      await f.store.write(key: _pinKey, value: f.k1);
      final env = await f.alice.encryptMessage('bob-id', 'bob-d1', 'ok');
      expect(
        await f.bob1.decryptMessage('alice-id', 'alice-device', env),
        'ok',
      );
    },
  );

  test(
    'sealed inner path refuses a session whose record disagrees with the pin',
    () async {
      final f = await _setUp();
      await _editSession(f.store, (j) => j['remoteIdentityKey'] = f.k2);
      final m = await _restart(f.store);
      final before = f.store.store[_sessionKey];
      final sealed = await f.bob1.encryptSealedSender(
        'alice-id',
        'alice-device',
        f.aliceIk,
        's',
      );
      await expectLater(m.decryptSealedSender(sealed), _mismatch);
      await expectLater(
        m.prepareSealedReceive(deliveryId: 'sealed-1', sealedEnvelope: sealed),
        _mismatch,
      );
      expect(f.store.store[_sessionKey], before);
    },
  );

  test(
    'interrupted accept: old session refused on every path; retry completes',
    () async {
      final f = await _setUp();
      f.store.failDeletes = true;
      await expectLater(
        f.alice.acceptVerifiedPeerIdentity(
          userId: 'bob-id',
          deviceId: 'bob-d1',
          identityKey: f.k2,
        ),
        throwsA(isA<StateError>()),
      );
      f.store.failDeletes = false;
      expect(f.store.store[_pinKey], f.k2);
      expect(f.store.store.containsKey(_sessionKey), isTrue);

      await _expectRefusedEverywhere(f, f.alice, tag: 'live');
      final restarted = await _restart(f.store);
      await _expectRefusedEverywhere(f, restarted, tag: 'restarted');

      await restarted.acceptVerifiedPeerIdentity(
        userId: 'bob-id',
        deviceId: 'bob-d1',
        identityKey: f.k2,
      );
      expect(await restarted.hasSession('bob-id', 'bob-d1'), isFalse);
      await restarted.createSession(f.bob2Bundle);
      final env = await restarted.encryptMessage('bob-id', 'bob-d1', 'to K2');
      expect(
        await f.bob2.decryptMessage('alice-id', 'alice-device', env),
        'to K2',
      );
      final back = await f.bob2.encryptMessage(
        'alice-id',
        'alice-device',
        'k2',
      );
      expect(await restarted.decryptMessage('bob-id', 'bob-d1', back), 'k2');
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k2);
    },
  );

  test(
    'legacy session: stamped with the current pin on first load; later interrupted accept still detected',
    () async {
      final f = await _setUp();
      void strip(Map<String, dynamic> j) => j.remove('remoteIdentityKey');

      // Direct lane: first load stamps and persists K1; the session keeps working.
      await _editSession(f.store, strip);
      expect(
        _stored(f.store, _sessionKey).containsKey('remoteIdentityKey'),
        isFalse,
      );
      var m = await _restart(f.store);
      final env = await m.encryptMessage('bob-id', 'bob-d1', 'legacy');
      expect(
        await f.bob1.decryptMessage('alice-id', 'alice-device', env),
        'legacy',
      );
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k1);

      // The first-load stamp is persisted even when the operation then fails.
      await _editSession(f.store, strip);
      m = await _restart(f.store);
      final tampered =
          jsonDecode(
                jsonEncode(
                  await f.bob1.encryptMessage('alice-id', 'alice-device', 't'),
                ),
              )
              as Map<String, dynamic>;
      final inner = tampered['message'] as Map<String, dynamic>;
      final bytes = base64Decode(inner['ciphertext'] as String);
      bytes[0] ^= 0x80;
      inner['ciphertext'] = base64Encode(bytes);
      await expectLater(
        m.decryptMessage('bob-id', 'bob-d1', tampered),
        throwsA(isA<MessageAuthenticationError>()),
      );
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k1);

      // WAL lane: the stamp travels with the committed candidate.
      await _editSession(f.store, strip);
      m = await _restart(f.store);
      final normal = await f.bob1.encryptMessage(
        'alice-id',
        'alice-device',
        'w',
      );
      final prepared = await m.prepareReceive(
        deliveryId: 'legacy-1',
        senderId: 'bob-id',
        senderDeviceId: 'bob-d1',
        envelope: normal,
      );
      expect(prepared.plaintext, 'w');
      await m.acknowledgeReceive(prepared.receipt);
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k1);

      // A legacy record at the moment of an interrupted accept is stamped with
      // the OLD pin first, so the new pin can never bless it.
      await _editSession(f.store, strip);
      m = await _restart(f.store);
      f.store.failDeletes = true;
      await expectLater(
        m.acceptVerifiedPeerIdentity(
          userId: 'bob-id',
          deviceId: 'bob-d1',
          identityKey: f.k2,
        ),
        throwsA(isA<StateError>()),
      );
      f.store.failDeletes = false;
      expect(f.store.store[_pinKey], f.k2);
      expect(_stored(f.store, _sessionKey)['remoteIdentityKey'], f.k1);
      await _expectRefusedEverywhere(f, await _restart(f.store), tag: 'legacy');
    },
  );

  test(
    'legacy session without any pin is removed before the new pin is written',
    () async {
      final f = await _setUp();
      await _editSession(f.store, (j) => j.remove('remoteIdentityKey'));
      await f.store.delete(key: _pinKey);
      final m = await _restart(f.store);
      f.store.failWriteKey = _pinKey; // crash exactly at the pin write
      await expectLater(
        m.acceptVerifiedPeerIdentity(
          userId: 'bob-id',
          deviceId: 'bob-d1',
          identityKey: f.k2,
        ),
        throwsA(isA<StateError>()),
      );
      f.store.failWriteKey = null;
      expect(f.store.store.containsKey(_sessionKey), isFalse);
      await expectLater(
        (await _restart(f.store)).encryptMessage('bob-id', 'bob-d1', 'x'),
        throwsA(isA<NoSessionError>()),
      );
    },
  );
}
