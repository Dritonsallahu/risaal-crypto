import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_storage.dart';
import 'package:risaal_crypto/src/sender_key.dart';

import 'helpers/fake_secure_storage.dart';

Future<(SenderKeyManager manager, FakeSecureStorage storage)> _createManager(
  String userId,
) async {
  final storage = FakeSecureStorage();
  await storage.write(key: 'user_id', value: userId);
  final cryptoStorage = CryptoStorage(secureStorage: storage);
  final manager = SenderKeyManager(cryptoStorage: cryptoStorage);
  return (manager, storage);
}

void main() {
  group('SenderKey epoch — types', () {
    test('SenderKeyState exposes epoch defaulting to 0', () {
      final state = SenderKeyState(
        groupId: 'g',
        senderId: 's',
        iteration: 0,
        chainKey: List<int>.filled(32, 0),
        signingPublicKey: 'pub',
      );
      expect(state.epoch, 0);
    });

    test('SenderKeyDistribution exposes epoch defaulting to 0', () {
      const dist = SenderKeyDistribution(
        groupId: 'g',
        senderId: 's',
        iteration: 0,
        chainKey: 'AAAA',
        signingKey: 'pub',
      );
      expect(dist.epoch, 0);
    });

    test('SenderKeyState JSON round-trip preserves epoch', () {
      final original = SenderKeyState(
        groupId: 'g',
        senderId: 's',
        iteration: 5,
        epoch: 3,
        chainKey: List<int>.filled(32, 7),
        signingPublicKey: 'pub',
      );
      final restored = SenderKeyState.fromJson(original.toJson());
      expect(restored.epoch, 3);
    });

    test('SenderKeyDistribution JSON round-trip preserves epoch', () {
      const original = SenderKeyDistribution(
        groupId: 'g',
        senderId: 's',
        iteration: 0,
        epoch: 2,
        chainKey: 'AAAA',
        signingKey: 'pub',
      );
      final restored = SenderKeyDistribution.fromJson(original.toJson());
      expect(restored.epoch, 2);
    });

    test('SenderKeyState.fromJson without epoch defaults to 0 (legacy state)',
        () {
      final json = {
        'groupId': 'g',
        'senderId': 's',
        'iteration': 0,
        'chainKey': base64Encode(List<int>.filled(32, 0)),
        'signingPublicKey': 'pub',
      };
      final state = SenderKeyState.fromJson(json);
      expect(state.epoch, 0);
    });
  });

  group('SenderKey epoch — generation', () {
    test('first generateSenderKey returns epoch 0', () async {
      final (manager, _) = await _createManager('alice');
      final dist = await manager.generateSenderKey('group');
      expect(dist.epoch, 0);
    });

    test('subsequent generateSenderKey on same group bumps epoch', () async {
      final (manager, _) = await _createManager('alice');
      final dist0 = await manager.generateSenderKey('group');
      final dist1 = await manager.generateSenderKey('group');
      final dist2 = await manager.generateSenderKey('group');

      expect(dist0.epoch, 0);
      expect(dist1.epoch, 1);
      expect(dist2.epoch, 2);
    });

    test('regeneration produces fresh chainKey and signing key', () async {
      final (manager, _) = await _createManager('alice');
      final dist0 = await manager.generateSenderKey('group');
      final dist1 = await manager.generateSenderKey('group');

      expect(dist1.chainKey, isNot(equals(dist0.chainKey)));
      expect(dist1.signingKey, isNot(equals(dist0.signingKey)));
    });
  });

  group('SenderKey epoch — distribution acceptance', () {
    test('processSenderKeyDistribution accepts equal or newer epoch',
        () async {
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');

      final skdm0 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm0);

      final skdm1 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm1);
      // Survives without throwing — no assertion needed.
    });

    test('processSenderKeyDistribution rejects stale epoch (replay)', () async {
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');

      final skdm0 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm0);

      final skdm1 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm1);

      // Replay attempt: send the old skdm0 again. Bob's stored state is at
      // epoch 1; receiving an epoch 0 SKDM must be rejected.
      expect(
        () => bob.processSenderKeyDistribution('group', 'alice', skdm0),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Stale Sender Key distribution'),
          ),
        ),
      );
    });
  });

  group('SenderKey epoch — wire compatibility', () {
    // Sentinel: encrypt/decrypt round-trip at epoch=0 must keep working
    // through the upcoming wire-format migration (v2 → v3). If this breaks,
    // it means the migration accidentally regressed the basic happy path.
    test('encrypt/decrypt round-trip works at epoch=0', () async {
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');

      final skdm = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm);

      final msg = await alice.encrypt('group', utf8.encode('hello'));
      final pt = await bob.decrypt('group', 'alice', msg);
      expect(utf8.decode(pt), 'hello');
    });
  });

  group('SenderKey epoch — wire format v3', () {
    test('encrypt embeds current epoch into ciphertext (v3)', () async {
      final (alice, _) = await _createManager('alice');
      await alice.generateSenderKey('group');
      // Bump alice to epoch=1
      await alice.generateSenderKey('group');

      final msg = await alice.encrypt('group', utf8.encode('x'));
      final blob = base64Decode(msg.ciphertext);

      // v3 layout: [0x03, epoch(4 LE), nonce(12), ct(N), mac(16)]
      expect(blob[0], 0x03);
      // Epoch bytes 1..5 little-endian == 1
      final epoch = blob[1] | (blob[2] << 8) | (blob[3] << 16) | (blob[4] << 24);
      expect(epoch, 1);
    });

    test('v3 encrypt → v3 decrypt round-trips at the same epoch', () async {
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');

      // Bump both to epoch=1
      await alice.generateSenderKey('group');
      final skdm1 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm1);

      final msg = await alice.encrypt('group', utf8.encode('synced'));
      final pt = await bob.decrypt('group', 'alice', msg);
      expect(utf8.decode(pt), 'synced');
    });

    test('decrypt rejects message whose embedded epoch differs from stored',
        () async {
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');

      // Bob receives epoch 0 from alice, then alice rotates to epoch 1.
      // Bob NEVER receives the epoch-1 SKDM (simulating a removed member).
      final skdm0 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm0);
      await alice.generateSenderKey('group'); // alice now at epoch=1

      final msgEpoch1 = await alice.encrypt('group', utf8.encode('after'));

      expect(
        () => bob.decrypt('group', 'alice', msgEpoch1),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            anyOf(
              contains('epoch'),
              contains('Sender Key'),
            ),
          ),
        ),
      );
    });
  });

  group('SenderKey epoch — security property (headline)', () {
    test(
        'removed member cannot decrypt post-rotation messages '
        '(forward secrecy on member removal)', () async {
      // Alice, Bob, Carol are in the group.
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');
      final (carol, _) = await _createManager('carol');

      // Alice generates and distributes her sender key to both.
      final skdm0 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm0);
      await carol.processSenderKeyDistribution('group', 'alice', skdm0);

      // Pre-removal message: both can decrypt.
      final pre =
          await alice.encrypt('group', utf8.encode('hello pre-removal'));
      expect(utf8.decode(await bob.decrypt('group', 'alice', pre)),
          'hello pre-removal');
      expect(utf8.decode(await carol.decrypt('group', 'alice', pre)),
          'hello pre-removal');

      // Carol is removed → Alice rotates her sender key. ONLY Bob receives
      // the new SKDM (the server stops delivering to Carol).
      final skdm1 = await alice.generateSenderKey('group');
      expect(skdm1.epoch, 1);
      await bob.processSenderKeyDistribution('group', 'alice', skdm1);
      // Carol's state is still pinned at epoch=0.

      // Alice sends a new message at epoch=1.
      final post =
          await alice.encrypt('group', utf8.encode('hello post-removal'));

      // Bob decrypts.
      expect(utf8.decode(await bob.decrypt('group', 'alice', post)),
          'hello post-removal');

      // Carol — even retaining her old chainKey — cannot decrypt.
      expect(
        () => carol.decrypt('group', 'alice', post),
        throwsA(isA<StateError>()),
      );
    });

    test('continued rotation: 3 epochs, removed member stays at epoch 0',
        () async {
      final (alice, _) = await _createManager('alice');
      final (bob, _) = await _createManager('bob');
      final (eve, _) = await _createManager('eve');

      final skdm0 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm0);
      await eve.processSenderKeyDistribution('group', 'alice', skdm0);

      // Eve removed.
      final skdm1 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm1);

      // Another rotation (e.g. another member removed).
      final skdm2 = await alice.generateSenderKey('group');
      await bob.processSenderKeyDistribution('group', 'alice', skdm2);

      final msg = await alice.encrypt('group', utf8.encode('current'));

      expect(utf8.decode(await bob.decrypt('group', 'alice', msg)), 'current');
      expect(
        () => eve.decrypt('group', 'alice', msg),
        throwsA(isA<StateError>()),
      );
    });
  });
}
