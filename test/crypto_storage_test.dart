import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/models/session_state.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'helpers/fake_secure_storage.dart';

void main() {
  late FakeSecureStorage fakeStorage;
  late CryptoStorage cryptoStorage;

  setUp(() {
    fakeStorage = FakeSecureStorage();
    cryptoStorage = CryptoStorage(secureStorage: fakeStorage);
  });

  tearDown(() {
    fakeStorage.reset();
  });

  /// Helper to create a test RatchetState
  Future<RatchetState> createTestRatchetState() async {
    final kp = await SignalKeyHelper.generateX25519KeyPair();
    final ratchet = await DoubleRatchet.initSender(
      sharedSecret: List.generate(32, (i) => i + 1),
      recipientPublicKey: kp.publicKey,
    );
    return ratchet.state;
  }

  group('CryptoStorage identity keys', () {
    test('Save and load identity key pair round-trip', () async {
      final keyPair = await SignalKeyHelper.generateX25519KeyPair();

      await cryptoStorage.saveIdentityKeyPair(keyPair);
      final loaded = await cryptoStorage.getIdentityKeyPair();

      expect(loaded, isNotNull);
      expect(loaded!.publicKey, keyPair.publicKey);
      expect(loaded.privateKey, keyPair.privateKey);
    });

    test('getIdentityKeyPair returns null when not saved', () async {
      final loaded = await cryptoStorage.getIdentityKeyPair();
      expect(loaded, isNull);
    });

    test('Overwrite preserves latest value', () async {
      final keyPair1 = await SignalKeyHelper.generateX25519KeyPair();
      final keyPair2 = await SignalKeyHelper.generateX25519KeyPair();

      await cryptoStorage.saveIdentityKeyPair(keyPair1);
      await cryptoStorage.saveIdentityKeyPair(keyPair2);

      final loaded = await cryptoStorage.getIdentityKeyPair();
      expect(loaded!.publicKey, keyPair2.publicKey);
      expect(loaded.privateKey, keyPair2.privateKey);
    });
  });

  group('CryptoStorage signing keys', () {
    test('Save and load signing key pair round-trip', () async {
      final keyPair = await SignalKeyHelper.generateSigningKeyPair();

      await cryptoStorage.saveSigningKeyPair(keyPair);
      final loaded = await cryptoStorage.getSigningKeyPair();

      expect(loaded, isNotNull);
      expect(loaded!.publicKey, keyPair.publicKey);
      expect(loaded.privateKey, keyPair.privateKey);
    });

    test('getSigningKeyPair returns null when not saved', () async {
      final loaded = await cryptoStorage.getSigningKeyPair();
      expect(loaded, isNull);
    });
  });

  group('CryptoStorage signed pre-key', () {
    test('Save and load signed pre-key round-trip', () async {
      final keyPair = await SignalKeyHelper.generateX25519KeyPair();
      final signingKeyPair = await SignalKeyHelper.generateSigningKeyPair();
      final publicKeyBytes = base64.decode(keyPair.publicKey);
      final signature = await SignalKeyHelper.sign(
        signingKeyPair.privateKey,
        publicKeyBytes,
      );

      final signedPreKey = SignedPreKey(
        keyId: 42,
        keyPair: keyPair,
        signature: signature,
        createdAt: DateTime(2026, 4, 6),
      );

      await cryptoStorage.saveSignedPreKey(signedPreKey);
      final loaded = await cryptoStorage.getSignedPreKey();

      expect(loaded, isNotNull);
      expect(loaded!.keyId, 42);
      expect(loaded.keyPair.publicKey, keyPair.publicKey);
      expect(loaded.keyPair.privateKey, keyPair.privateKey);
      expect(loaded.signature, signature);
      expect(loaded.createdAt, DateTime(2026, 4, 6));
    });

    test('getSignedPreKey returns null when not saved', () async {
      final loaded = await cryptoStorage.getSignedPreKey();
      expect(loaded, isNull);
    });
  });

  group('CryptoStorage one-time pre-keys', () {
    test('Save and load list of OTPs round-trip', () async {
      final kp1 = await SignalKeyHelper.generateX25519KeyPair();
      final kp2 = await SignalKeyHelper.generateX25519KeyPair();

      final otps = [
        OneTimePreKey(keyId: 1, keyPair: kp1),
        OneTimePreKey(keyId: 2, keyPair: kp2),
      ];

      await cryptoStorage.saveOneTimePreKeys(otps);
      final loaded = await cryptoStorage.getOneTimePreKeys();

      expect(loaded.length, 2);
      expect(loaded[0].keyId, 1);
      expect(loaded[0].keyPair.publicKey, kp1.publicKey);
      expect(loaded[1].keyId, 2);
      expect(loaded[1].keyPair.publicKey, kp2.publicKey);
    });

    test('getOneTimePreKeys returns empty list when not saved', () async {
      final loaded = await cryptoStorage.getOneTimePreKeys();
      expect(loaded, isEmpty);
    });

    test('removeOneTimePreKey removes specific key by ID', () async {
      final kp1 = await SignalKeyHelper.generateX25519KeyPair();
      final kp2 = await SignalKeyHelper.generateX25519KeyPair();
      final kp3 = await SignalKeyHelper.generateX25519KeyPair();

      final otps = [
        OneTimePreKey(keyId: 1, keyPair: kp1),
        OneTimePreKey(keyId: 2, keyPair: kp2),
        OneTimePreKey(keyId: 3, keyPair: kp3),
      ];

      await cryptoStorage.saveOneTimePreKeys(otps);
      await cryptoStorage.removeOneTimePreKey(2);

      final loaded = await cryptoStorage.getOneTimePreKeys();
      expect(loaded.length, 2);
      expect(loaded.map((k) => k.keyId), [1, 3]);
    });

    test('removeOneTimePreKey preserves other keys', () async {
      final kp1 = await SignalKeyHelper.generateX25519KeyPair();
      final kp2 = await SignalKeyHelper.generateX25519KeyPair();

      final otps = [
        OneTimePreKey(keyId: 10, keyPair: kp1),
        OneTimePreKey(keyId: 20, keyPair: kp2),
      ];

      await cryptoStorage.saveOneTimePreKeys(otps);
      await cryptoStorage.removeOneTimePreKey(10);

      final loaded = await cryptoStorage.getOneTimePreKeys();
      expect(loaded.length, 1);
      expect(loaded[0].keyId, 20);
      expect(loaded[0].keyPair.publicKey, kp2.publicKey);
    });
  });

  group('CryptoStorage Kyber keys', () {
    test('Save and load KyberKeyPair round-trip', () async {
      final kyberPair = KyberKeyPair(
        publicKey: 'kyber-public-base64',
        privateKey: 'kyber-private-base64',
      );

      await cryptoStorage.saveKyberKeyPair(kyberPair);
      final loaded = await cryptoStorage.getKyberKeyPair();

      expect(loaded, isNotNull);
      expect(loaded!.publicKey, 'kyber-public-base64');
      expect(loaded.privateKey, 'kyber-private-base64');
    });

    test('getKyberKeyPair returns null when not saved', () async {
      final loaded = await cryptoStorage.getKyberKeyPair();
      expect(loaded, isNull);
    });
  });

  group('CryptoStorage sessions', () {
    test('Save and load RatchetState round-trip', () async {
      final state = await createTestRatchetState();

      await cryptoStorage.saveSession('user123', 'device456', state);
      final loaded = await cryptoStorage.getSession('user123', 'device456');

      expect(loaded, isNotNull);
      expect(loaded!.dhSendingKeyPair, state.dhSendingKeyPair);
      expect(loaded.dhReceivingKey, state.dhReceivingKey);
      expect(loaded.rootKey, state.rootKey);
      expect(loaded.sendingChainKey, state.sendingChainKey);
      expect(loaded.receivingChainKey, state.receivingChainKey);
    });

    test('Different (recipientId, deviceId) pairs stored independently',
        () async {
      final state1 = await createTestRatchetState();
      final state2 = await createTestRatchetState();

      await cryptoStorage.saveSession('user1', 'device1', state1);
      await cryptoStorage.saveSession('user2', 'device2', state2);

      final loaded1 = await cryptoStorage.getSession('user1', 'device1');
      final loaded2 = await cryptoStorage.getSession('user2', 'device2');

      expect(loaded1!.rootKey, state1.rootKey);
      expect(loaded2!.rootKey, state2.rootKey);
      expect(loaded1.rootKey, isNot(loaded2.rootKey));
    });

    test('deleteSession removes specific session', () async {
      final state = await createTestRatchetState();

      await cryptoStorage.saveSession('user123', 'device456', state);
      await cryptoStorage.deleteSession('user123', 'device456');

      final loaded = await cryptoStorage.getSession('user123', 'device456');
      expect(loaded, isNull);
    });

    test('getSession returns null for non-existent', () async {
      final loaded = await cryptoStorage.getSession('nonexistent', 'none');
      expect(loaded, isNull);
    });
  });

  group('CryptoStorage session identity keys', () {
    test('Save and load session identity key', () async {
      await cryptoStorage.saveSessionIdentityKey(
        'user123',
        'device456',
        'identity-key-base64',
      );

      final loaded = await cryptoStorage.getSessionIdentityKey(
        'user123',
        'device456',
      );

      expect(loaded, 'identity-key-base64');
    });

    test('deleteSessionIdentityKey removes it', () async {
      await cryptoStorage.saveSessionIdentityKey(
        'user123',
        'device456',
        'identity-key-base64',
      );

      await cryptoStorage.deleteSessionIdentityKey('user123', 'device456');

      final loaded = await cryptoStorage.getSessionIdentityKey(
        'user123',
        'device456',
      );
      expect(loaded, isNull);
    });
  });

  group('CryptoStorage session device tracking', () {
    test('trackSessionDevice adds device to list', () async {
      await cryptoStorage.trackSessionDevice('user123', 'device1');
      await cryptoStorage.trackSessionDevice('user123', 'device2');

      // Verify by reading raw storage
      final devices = await fakeStorage.read(
        key: 'crypto_session_devices_user123',
      );
      expect(devices, contains('device1'));
      expect(devices, contains('device2'));
    });

    test('trackSessionDevice is idempotent', () async {
      await cryptoStorage.trackSessionDevice('user123', 'device1');
      await cryptoStorage.trackSessionDevice('user123', 'device1');

      final devices = await fakeStorage.read(
        key: 'crypto_session_devices_user123',
      );
      expect(devices, 'device1');
    });

    test('deleteAllSessionsForUser removes all tracked sessions and keys',
        () async {
      final state1 = await createTestRatchetState();
      final state2 = await createTestRatchetState();

      // Create sessions for two devices
      await cryptoStorage.trackSessionDevice('user123', 'device1');
      await cryptoStorage.trackSessionDevice('user123', 'device2');
      await cryptoStorage.saveSession('user123', 'device1', state1);
      await cryptoStorage.saveSession('user123', 'device2', state2);
      await cryptoStorage.saveSessionIdentityKey(
        'user123',
        'device1',
        'ik1',
      );
      await cryptoStorage.saveSessionIdentityKey(
        'user123',
        'device2',
        'ik2',
      );
      await cryptoStorage.savePendingPreKeyInfo(
        'user123',
        'device1',
        'ephemeral1',
        42,
      );

      // Delete all
      await cryptoStorage.deleteAllSessionsForUser('user123');

      // Verify all are gone
      expect(await cryptoStorage.getSession('user123', 'device1'), isNull);
      expect(await cryptoStorage.getSession('user123', 'device2'), isNull);
      expect(
        await cryptoStorage.getSessionIdentityKey('user123', 'device1'),
        isNull,
      );
      expect(
        await cryptoStorage.getSessionIdentityKey('user123', 'device2'),
        isNull,
      );
      expect(
        await cryptoStorage.getPendingPreKeyInfo('user123', 'device1'),
        isNull,
      );
      expect(
        await fakeStorage.read(key: 'crypto_session_devices_user123'),
        isNull,
      );
    });
  });

  group('CryptoStorage pending prekey info', () {
    test('Save and load pending prekey info round-trip', () async {
      await cryptoStorage.savePendingPreKeyInfo(
        'user123',
        'device456',
        'ephemeral-pub-key',
        42,
      );

      final loaded = await cryptoStorage.getPendingPreKeyInfo(
        'user123',
        'device456',
      );

      expect(loaded, isNotNull);
      expect(loaded!['ephemeralPublicKey'], 'ephemeral-pub-key');
      expect(loaded['usedOneTimePreKeyId'], 42);
      expect(loaded.containsKey('kyberCiphertext'), false);
    });

    test('Optional kyberCiphertext included when provided', () async {
      await cryptoStorage.savePendingPreKeyInfo(
        'user123',
        'device456',
        'ephemeral-pub-key',
        42,
        kyberCiphertext: 'kyber-ct-base64',
      );

      final loaded = await cryptoStorage.getPendingPreKeyInfo(
        'user123',
        'device456',
      );

      expect(loaded!['kyberCiphertext'], 'kyber-ct-base64');
    });

    test('clearPendingPreKeyInfo removes it', () async {
      await cryptoStorage.savePendingPreKeyInfo(
        'user123',
        'device456',
        'ephemeral-pub-key',
        42,
      );

      await cryptoStorage.clearPendingPreKeyInfo('user123', 'device456');

      final loaded = await cryptoStorage.getPendingPreKeyInfo(
        'user123',
        'device456',
      );
      expect(loaded, isNull);
    });
  });

  group('CryptoStorage pre-key counter', () {
    test('getNextPreKeyId returns 0 by default', () async {
      final id = await cryptoStorage.getNextPreKeyId();
      expect(id, 0);
    });

    test('setNextPreKeyId persists value', () async {
      await cryptoStorage.setNextPreKeyId(999);
      final loaded = await cryptoStorage.getNextPreKeyId();
      expect(loaded, 999);
    });
  });

  group('CryptoStorage sender keys', () {
    test('Save and load sender key state round-trip', () async {
      final stateJson = {
        'chainKey': 'chain-key-base64',
        'messageNumber': 5,
      };

      await cryptoStorage.saveSenderKeyRaw('group123', 'sender456', stateJson);
      final loaded = await cryptoStorage.getSenderKeyRaw(
        'group123',
        'sender456',
      );

      expect(loaded, isNotNull);
      expect(loaded!['chainKey'], 'chain-key-base64');
      expect(loaded['messageNumber'], 5);
    });

    test('deleteSenderKey removes specific key', () async {
      final stateJson = {'chainKey': 'test'};

      await cryptoStorage.saveSenderKeyRaw('group123', 'sender456', stateJson);
      await cryptoStorage.deleteSenderKey('group123', 'sender456');

      final loaded = await cryptoStorage.getSenderKeyRaw(
        'group123',
        'sender456',
      );
      expect(loaded, isNull);
    });

    test('deleteSenderKeysForGroup removes all member keys', () async {
      final state1 = {'chainKey': 'key1'};
      final state2 = {'chainKey': 'key2'};
      final state3 = {'chainKey': 'key3'};

      await cryptoStorage.saveSenderKeyRaw('group123', 'member1', state1);
      await cryptoStorage.saveSenderKeyRaw('group123', 'member2', state2);
      await cryptoStorage.saveSenderKeyRaw('group123', 'member3', state3);

      await cryptoStorage.deleteSenderKeysForGroup(
        'group123',
        ['member1', 'member2', 'member3'],
      );

      expect(
        await cryptoStorage.getSenderKeyRaw('group123', 'member1'),
        isNull,
      );
      expect(
        await cryptoStorage.getSenderKeyRaw('group123', 'member2'),
        isNull,
      );
      expect(
        await cryptoStorage.getSenderKeyRaw('group123', 'member3'),
        isNull,
      );
    });
  });

  group('CryptoStorage reset timestamps', () {
    test('loadResetTimestamps returns empty list by default', () async {
      final timestamps = await cryptoStorage.loadResetTimestamps(
        'user123',
        'device456',
      );
      expect(timestamps, isEmpty);
    });

    test('saveResetTimestamps persists list', () async {
      final timestamps = [1000, 2000, 3000];

      await cryptoStorage.saveResetTimestamps(
        'user123',
        'device456',
        timestamps,
      );

      final loaded = await cryptoStorage.loadResetTimestamps(
        'user123',
        'device456',
      );
      expect(loaded, [1000, 2000, 3000]);
    });

    test('saveResetTimestamps trims to last 10 entries', () async {
      final timestamps = List.generate(15, (i) => (i + 1) * 1000);

      await cryptoStorage.saveResetTimestamps(
        'user123',
        'device456',
        timestamps,
      );

      final loaded = await cryptoStorage.loadResetTimestamps(
        'user123',
        'device456',
      );
      expect(loaded.length, 10);
      expect(loaded.first, 6000); // Should keep last 10
      expect(loaded.last, 15000);
    });

    test('clearResetTimestamps removes all', () async {
      final timestamps = [1000, 2000, 3000];

      await cryptoStorage.saveResetTimestamps(
        'user123',
        'device456',
        timestamps,
      );

      await cryptoStorage.clearResetTimestamps('user123', 'device456');

      final loaded = await cryptoStorage.loadResetTimestamps(
        'user123',
        'device456',
      );
      expect(loaded, isEmpty);
    });
  });

  group('CryptoStorage wipeAll', () {
    test('wipeAll clears ALL stored data', () async {
      // Save various data types
      final identityKP = await SignalKeyHelper.generateX25519KeyPair();
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final state = await createTestRatchetState();

      await cryptoStorage.saveIdentityKeyPair(identityKP);
      await cryptoStorage.saveSigningKeyPair(signingKP);
      await cryptoStorage.saveSession('user123', 'device456', state);
      await cryptoStorage.saveSessionIdentityKey(
        'user123',
        'device456',
        'ik',
      );
      await cryptoStorage.setNextPreKeyId(100);
      await cryptoStorage.saveSenderKeyRaw(
        'group1',
        'sender1',
        {'key': 'value'},
      );
      await cryptoStorage.saveResetTimestamps(
        'user123',
        'device456',
        [1000, 2000],
      );

      // Wipe all
      await cryptoStorage.wipeAll();

      // Verify everything is gone
      expect(await cryptoStorage.getIdentityKeyPair(), isNull);
      expect(await cryptoStorage.getSigningKeyPair(), isNull);
      expect(await cryptoStorage.getSession('user123', 'device456'), isNull);
      expect(
        await cryptoStorage.getSessionIdentityKey('user123', 'device456'),
        isNull,
      );
      expect(await cryptoStorage.getNextPreKeyId(), 0);
      expect(
        await cryptoStorage.getSenderKeyRaw('group1', 'sender1'),
        isNull,
      );
      expect(
        await cryptoStorage.loadResetTimestamps('user123', 'device456'),
        isEmpty,
      );
    });
  });
}
