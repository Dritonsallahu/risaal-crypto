import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// R5-N1 Part P: calls ask the same trust question messaging enforces on
/// every outbound session and inbound handshake, without writing anything.
void main() {
  const timeout = Timeout(Duration(seconds: 60));

  Future<SignalProtocolManager> device(
    FakeSecureStorage storage,
    String userId,
    String deviceId,
  ) async {
    final manager = SignalProtocolManager(secureStorage: storage);
    await manager.wipeForFreshRegistration();
    await manager.initialize();
    await storage.write(key: 'user_id', value: userId);
    await storage.write(key: 'device_id', value: deviceId);
    return manager;
  }

  late FakeSecureStorage aliceStorage;
  late SignalProtocolManager alice;
  late String k1;
  late String k2;

  setUp(() async {
    aliceStorage = FakeSecureStorage();
    alice = await device(aliceStorage, 'alice-id', 'alice-device');

    // Bob's identity K1 on two devices, both pinned on Alice's phone.
    final bob1 = await device(FakeSecureStorage(), 'bob-id', 'bob-d1');
    final bob1Gen = await CryptoTestFixtures.acceptInitialGeneration(bob1);
    final d1 = bob1Gen.consumerBundle(userId: 'bob-id', deviceId: 'bob-d1');
    await alice.createSession(d1);
    await alice.createSession(
      bob1Gen.consumerBundle(userId: 'bob-id', deviceId: 'bob-d2'),
    );
    k1 = d1.identityKey;

    // Another identity, K2, that Alice never pinned.
    final other = await device(FakeSecureStorage(), 'bob-id', 'bob-d1');
    k2 = (await CryptoTestFixtures.acceptInitialGeneration(
      other,
    )).consumerBundle(userId: 'bob-id', deviceId: 'bob-d1').identityKey;
    expect(k2, isNot(k1));
  });

  Future<PeerIdentityPinStatus> status(
    String identityKey, {
    String userId = 'bob-id',
    String? deviceId,
  }) => alice.peerIdentityPinStatus(
    userId: userId,
    identityKey: identityKey,
    deviceId: deviceId,
  );

  test('the device pin decides when the device has one', () async {
    expect(
      await status(k1, deviceId: 'bob-d1'),
      PeerIdentityPinStatus.matchesPin,
    );
    expect(
      await status(k2, deviceId: 'bob-d1'),
      PeerIdentityPinStatus.contradictsPin,
    );
  }, timeout: timeout);

  test(
    'a device without a pin is judged by the contact\'s other pins',
    () async {
      expect(
        await status(k1, deviceId: 'bob-d3'),
        PeerIdentityPinStatus.matchesPin,
      );
      expect(
        await status(k2, deviceId: 'bob-d3'),
        PeerIdentityPinStatus.contradictsPin,
      );
    },
    timeout: timeout,
  );

  test('without a device id the contact\'s pins decide', () async {
    expect(await status(k1), PeerIdentityPinStatus.matchesPin);
    expect(await status(k2), PeerIdentityPinStatus.contradictsPin);
  }, timeout: timeout);

  test(
    'a contact with no pin at all is noPin, with or without a device',
    () async {
      expect(await status(k1, userId: 'carol-id'), PeerIdentityPinStatus.noPin);
      expect(
        await status(k1, userId: 'carol-id', deviceId: 'carol-d1'),
        PeerIdentityPinStatus.noPin,
      );
    },
    timeout: timeout,
  );

  test('after the user verifies K2, only K2 matches', () async {
    await alice.acceptVerifiedPeerIdentity(
      userId: 'bob-id',
      deviceId: 'bob-d1',
      identityKey: k2,
    );
    expect(
      await status(k2, deviceId: 'bob-d1'),
      PeerIdentityPinStatus.matchesPin,
    );
    expect(
      await status(k1, deviceId: 'bob-d1'),
      PeerIdentityPinStatus.contradictsPin,
    );
    expect(await status(k1), PeerIdentityPinStatus.contradictsPin);
    expect(
      await status(k1, deviceId: 'bob-d2'),
      PeerIdentityPinStatus.contradictsPin,
    );
  }, timeout: timeout);

  test('after "Reset encryption" the contact is noPin again', () async {
    await alice.forgetPeerIdentity('bob-id');
    expect(await status(k1), PeerIdentityPinStatus.noPin);
    expect(await status(k1, deviceId: 'bob-d1'), PeerIdentityPinStatus.noPin);
  }, timeout: timeout);

  test('it is a pure query: nothing in storage changes', () async {
    final before = Map<String, String>.of(aliceStorage.store);
    await status(k1, deviceId: 'bob-d1');
    await status(k2, deviceId: 'bob-d3');
    await status(k1, userId: 'carol-id', deviceId: 'carol-d1');
    expect(aliceStorage.store, before);
  }, timeout: timeout);

  test('it answers while a message from the contact awaits host '
      'acknowledgement (R5-N1-FIX-R1)', () async {
    final pair = await CryptoTestFixtures.createPairedManagers();
    // A first message, fully acknowledged, gives Bob his pin for Alice.
    final first = await pair.bob.prepareReceive(
      deliveryId: 'delivery-r5-n1-fix-r1-first',
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'first',
      ),
    );
    await pair.bob.acknowledgeReceive(first.receipt);
    // The second stays pending while the call is checked.
    final envelope = await pair.alice.encryptMessage(
      'bob-id',
      'bob-device',
      'pending while a call is checked',
    );
    final prepared = await pair.bob.prepareReceive(
      deliveryId: 'delivery-r5-n1-fix-r1',
      senderId: 'alice-id',
      senderDeviceId: 'alice-device',
      envelope: envelope,
    );
    expect(prepared.requiresHostPersistence, isTrue);

    final aliceKey = await pair.alice.getIdentityPublicKey();
    expect(
      await pair.bob.peerIdentityPinStatus(
        userId: 'alice-id',
        identityKey: aliceKey,
        deviceId: 'alice-device',
      ),
      PeerIdentityPinStatus.matchesPin,
    );
  }, timeout: timeout);

  test('a malformed id throws instead of answering', () async {
    await expectLater(
      status(k1, userId: 'ik'),
      throwsA(isA<FormatException>()),
    );
    await expectLater(
      status(k1, deviceId: 'a b'),
      throwsA(isA<FormatException>()),
    );
  }, timeout: timeout);
}
