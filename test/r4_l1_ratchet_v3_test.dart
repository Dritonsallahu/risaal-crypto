import 'dart:convert';

import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/message_padding.dart';
import 'package:risaal_crypto/src/models/session_state.dart';
import 'package:risaal_crypto/src/ratchet_batch_decrypt.dart';

import 'helpers/r4_l1_contract.dart';

/// R4-L1 Part A at the Double Ratchet layer (contract §5 A): a receiver
/// accepts the identity-bound wire version 3, binds both identity keys into
/// the AEAD, and never goes back to v2 on a session that has received v3.
class _Session {
  _Session(this.alice, this.bob, this.aliceIk, this.bobIk);

  final DoubleRatchet alice;
  final DoubleRatchet bob;
  final String aliceIk;
  final String bobIk;
}

Future<_Session> _session() async {
  final bobPreKey = await SignalKeyHelper.generateX25519KeyPair();
  final secret = List<int>.generate(32, (i) => i + 7);
  final alice = await DoubleRatchet.initSender(
    sharedSecret: secret,
    recipientPublicKey: bobPreKey.publicKey,
  );
  final bob = await DoubleRatchet.initReceiver(
    sharedSecret: secret,
    dhKeyPair: bobPreKey,
  );
  final aliceIk = (await SignalKeyHelper.generateX25519KeyPair()).publicKey;
  final bobIk = (await SignalKeyHelper.generateX25519KeyPair()).publicKey;
  alice.state.remoteIdentityKey = bobIk;
  bob.state.remoteIdentityKey = aliceIk;
  return _Session(alice, bob, aliceIk, bobIk);
}

/// A v3 envelope built by the contract encoder, not by the implementation.
Future<EncryptedMessage> _helperV3(
  _Session s,
  String text, {
  String? identityA,
  String? identityB,
}) => R4L1Contract.encryptNext(
  s.alice.state,
  MessagePadding.padString(text),
  version: 3,
  aad: (dh, n, pn) => R4L1Contract.aadV3(
    version: 3,
    dhPublicKey: dh,
    messageNumber: n,
    previousChainLength: pn,
    identityA: identityA ?? s.aliceIk,
    identityB: identityB ?? s.bobIk,
  ),
);

Future<EncryptedMessage> _helperV2(_Session s, String text) =>
    R4L1Contract.encryptNext(
      s.alice.state,
      MessagePadding.padString(text),
      version: 2,
      aad: (dh, n, pn) => R4L1Contract.aadV2(
        version: 2,
        dhPublicKey: dh,
        messageNumber: n,
        previousChainLength: pn,
      ),
    );

Future<String> _bobDecrypt(_Session s, EncryptedMessage m) async =>
    MessagePadding.unpadString(
      await s.bob.decrypt(m, localIdentityKey: s.bobIk),
    );

void main() {
  group('R4-L1 Part A: v3 receive', () {
    test('a v3 envelope made by the contract helper decrypts and marks the '
        'peer as speaking v3', () async {
      final s = await _session();
      expect(s.bob.state.peerSpeaksV3, isFalse);
      final m = await _helperV3(s, 'bound hello');
      expect(m.toJson()['version'], 3);

      expect(await _bobDecrypt(s, m), 'bound hello');
      expect(s.bob.state.peerSpeaksV3, isTrue);
      // Persisted with the session.
      final reloaded = RatchetState.fromJson(s.bob.toJson());
      expect(reloaded.peerSpeaksV3, isTrue);
    });

    test('a v3 envelope whose AD names a different identity fails '
        'authentication and leaves the session unchanged', () async {
      final s = await _session();
      final stranger =
          (await SignalKeyHelper.generateX25519KeyPair()).publicKey;

      for (final (name, a, b) in <(String, String, String)>[
        ('sender identity swapped', stranger, s.bobIk),
        ('recipient identity swapped', s.aliceIk, stranger),
      ]) {
        final before = jsonEncode(s.bob.toJson());
        final m = await _helperV3(s, 'misbound', identityA: a, identityB: b);
        await expectLater(
          s.bob.decrypt(m, localIdentityKey: s.bobIk),
          throwsA(isA<SecretBoxAuthenticationError>()),
          reason: name,
        );
        expect(jsonEncode(s.bob.toJson()), before, reason: name);
      }

      // The receiver's own view of the identities is bound too: a receiver
      // that believes it is someone else cannot open a genuine message.
      final genuine = await _helperV3(s, 'genuine');
      final before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(genuine, localIdentityKey: stranger),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);
      expect(await _bobDecrypt(s, genuine), 'genuine');
    });

    test('v3 and v2 header bytes are not interchangeable', () async {
      final s = await _session();

      // v2 AAD bytes, labelled v3.
      final v2AsV3 = await R4L1Contract.encryptNext(
        s.alice.state,
        MessagePadding.padString('v2 bytes, v3 label'),
        version: 3,
        aad: (dh, n, pn) => R4L1Contract.aadV2(
          version: 3,
          dhPublicKey: dh,
          messageNumber: n,
          previousChainLength: pn,
        ),
      );
      var before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(v2AsV3, localIdentityKey: s.bobIk),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);

      // v3 AAD bytes, labelled v2.
      final v3AsV2 = await R4L1Contract.encryptNext(
        s.alice.state,
        MessagePadding.padString('v3 bytes, v2 label'),
        version: 2,
        aad: (dh, n, pn) => R4L1Contract.aadV3(
          version: 2,
          dhPublicKey: dh,
          messageNumber: n,
          previousChainLength: pn,
          identityA: s.aliceIk,
          identityB: s.bobIk,
        ),
      );
      before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(v3AsV2, localIdentityKey: s.bobIk),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);

      // A genuine v2 envelope relabelled v3 also fails.
      final relabelled = EncryptedMessage.fromJson(
        (await _helperV2(s, 'relabel')).toJson()..['version'] = 3,
      );
      before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(relabelled, localIdentityKey: s.bobIk),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);
    });

    test('after one v3 message a v2 message on the same session is refused '
        'and the session is unchanged (L1-I1)', () async {
      final s = await _session();
      expect(await _bobDecrypt(s, await _helperV3(s, 'first v3')), 'first v3');
      expect(s.bob.state.peerSpeaksV3, isTrue);

      final downgrade = await _helperV2(s, 'late v2');
      final before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(downgrade, localIdentityKey: s.bobIk),
        throwsA(isA<FormatException>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);

      // The same refusal holds on a reloaded session.
      final reloaded = DoubleRatchet.fromJson(s.bob.toJson());
      await expectLater(
        reloaded.decrypt(downgrade, localIdentityKey: s.bobIk),
        throwsA(isA<FormatException>()),
      );
      expect(jsonEncode(reloaded.toJson()), before);
    });

    test('a v2 session still accepts v2 before any v3 arrives', () async {
      final s = await _session();
      expect(await _bobDecrypt(s, await _helperV2(s, 'plain v2')), 'plain v2');
      expect(s.bob.state.peerSpeaksV3, isFalse);
      expect(s.bob.toJson().containsKey('peerSpeaksV3'), isFalse);
      expect(await _bobDecrypt(s, await _helperV3(s, 'then v3')), 'then v3');
      expect(s.bob.state.peerSpeaksV3, isTrue);
    });

    test('a v3 message without both identity keys is refused before any '
        'state change (L1-I2)', () async {
      final s = await _session();
      final m = await _helperV3(s, 'needs identities');

      var before = jsonEncode(s.bob.toJson());
      await expectLater(s.bob.decrypt(m), throwsA(isA<FormatException>()));
      expect(jsonEncode(s.bob.toJson()), before);

      s.bob.state.remoteIdentityKey = null;
      before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(m, localIdentityKey: s.bobIk),
        throwsA(isA<FormatException>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);

      s.bob.state.remoteIdentityKey = s.aliceIk;
      expect(await _bobDecrypt(s, m), 'needs identities');
    });

    test('a v3 message from the skipped-key store is bound too', () async {
      final s = await _session();
      final first = await _helperV3(s, 'one');
      final second = await _helperV3(s, 'two');
      expect(await _bobDecrypt(s, second), 'two');
      expect(s.bob.state.skippedKeys, hasLength(1));

      final stranger =
          (await SignalKeyHelper.generateX25519KeyPair()).publicKey;
      final before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(first, localIdentityKey: stranger),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);
      expect(await _bobDecrypt(s, first), 'one');
    });

    test('ratchet state round-trips both flags; absent means false', () {
      final state = RatchetState(
        dhSendingKeyPair: utf8.encode('{}'),
        dhReceivingKey: utf8.encode(''),
        rootKey: utf8.encode('r'),
        sendingChainKey: utf8.encode(''),
        receivingChainKey: utf8.encode(''),
      );
      final legacy = state.toJson();
      expect(legacy.containsKey('peerSpeaksV3'), isFalse);
      expect(legacy.containsKey('sendV3'), isFalse);
      expect(RatchetState.fromJson(legacy).peerSpeaksV3, isFalse);
      expect(RatchetState.fromJson(legacy).sendV3, isFalse);

      state
        ..peerSpeaksV3 = true
        ..sendV3 = true;
      final both = RatchetState.fromJson(state.toJson());
      expect(both.peerSpeaksV3, isTrue);
      expect(both.sendV3, isTrue);

      for (final field in const ['peerSpeaksV3', 'sendV3']) {
        expect(
          () => RatchetState.fromJson({...legacy, field: 'true'}),
          throwsFormatException,
          reason: field,
        );
      }
    });

    test('the batch decrypter handles v3 like v2 and keeps L1-I1', () async {
      final s = await _session();
      final v3 = await _helperV3(s, 'batch v3');
      final lateV2 = await _helperV2(s, 'batch late v2');
      final before = s.bob.toJson();

      final result = await ratchetBatchDecrypt(
        RatchetBatchRequest(
          stateJson: before,
          messages: [v3.toJson(), lateV2.toJson()],
          localIdentityKey: s.bobIk,
        ),
      );
      expect(result.plaintexts, ['batch v3']);
      expect(result.failedIndex, 1);
      expect(RatchetState.fromJson(result.finalStateJson).peerSpeaksV3, isTrue);
    });
  });

  group('R4-L1 low-level v3 send', () {
    test('encrypt(version: 3) matches the contract encoding and sticks to '
        'v3 afterwards', () async {
      final s = await _session();
      final chainKey = List<int>.from(s.alice.state.sendingChainKey);
      final m = await s.alice.encrypt(
        MessagePadding.padString('real v3'),
        version: 3,
        localIdentityKey: s.aliceIk,
      );
      expect(m.version, 3);
      expect(s.alice.state.sendV3, isTrue);

      final opened = await R4L1Contract.decryptWithChainKey(
        chainKey,
        m,
        R4L1Contract.aadV3(
          version: 3,
          dhPublicKey: m.dhPublicKey,
          messageNumber: m.messageNumber,
          previousChainLength: m.previousChainLength,
          identityA: s.bobIk,
          identityB: s.aliceIk,
        ),
      );
      expect(MessagePadding.unpadString(opened), 'real v3');
      expect(await _bobDecrypt(s, m), 'real v3');

      // Never downgrade the send side: the peer now refuses v2 from us.
      final before = jsonEncode(s.alice.toJson());
      await expectLater(
        s.alice.encrypt(MessagePadding.padString('v2 again')),
        throwsA(isA<StateError>()),
      );
      expect(jsonEncode(s.alice.toJson()), before);
    });

    test('encrypt(version: 3) without both identity keys is refused before '
        'any state change', () async {
      final s = await _session();
      var before = jsonEncode(s.alice.toJson());
      await expectLater(
        s.alice.encrypt(MessagePadding.padString('x'), version: 3),
        throwsA(isA<StateError>()),
      );
      expect(jsonEncode(s.alice.toJson()), before);

      s.alice.state.remoteIdentityKey = null;
      before = jsonEncode(s.alice.toJson());
      await expectLater(
        s.alice.encrypt(
          MessagePadding.padString('x'),
          version: 3,
          localIdentityKey: s.aliceIk,
        ),
        throwsA(isA<StateError>()),
      );
      expect(jsonEncode(s.alice.toJson()), before);
    });

    test('v1 and unknown versions stay refused', () async {
      final s = await _session();
      for (final version in const [1, 4]) {
        final before = jsonEncode(s.alice.toJson());
        await expectLater(
          s.alice.encrypt(
            MessagePadding.padString('x'),
            version: version,
            localIdentityKey: s.aliceIk,
          ),
          throwsA(isA<FormatException>()),
        );
        expect(jsonEncode(s.alice.toJson()), before);
      }
      final future = EncryptedMessage.fromJson(
        (await _helperV3(s, 'f')).toJson()..['version'] = 4,
      );
      final before = jsonEncode(s.bob.toJson());
      await expectLater(
        s.bob.decrypt(future, localIdentityKey: s.bobIk),
        throwsA(isA<FormatException>()),
      );
      expect(jsonEncode(s.bob.toJson()), before);
    });
  });
}
