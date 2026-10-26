import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart'
    show SecretBoxAuthenticationError;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/message_padding.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/x3dh.dart';

/// R4-L1 fixed vectors (contract L1-I5). The vectors were generated from
/// primitives and the contract layout, not from the implementation, and their
/// byte layouts were re-derived independently in Python. Any change to the
/// transcript-2 or v3 AAD encoding breaks these tests.
final Map<String, dynamic> _vectors =
    jsonDecode(
          File(
            'test/vectors/r4_l1_identity_binding_v1.json',
          ).readAsStringSync(),
        )
        as Map<String, dynamic>;

Map<String, dynamic> _section(String name) =>
    Map<String, dynamic>.from(_vectors[name] as Map);

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  test('PQXDH transcript 1 is unchanged and transcript 2 matches', () {
    final t = _section('transcript');
    final routing = PreKeyHandshakeRouting.fromEnvelopeJson(
      Map<String, dynamic>.from(t['routing'] as Map),
    );
    expect(_hex(routing.canonicalTranscript()), t['transcriptV1Hex']);
    final bound = routing
        .withTranscriptVersion(2)
        .bindIdentityKeys(
          initiatorIdentityKey: t['initiatorIdentityKey'] as String,
          responderIdentityKey: t['responderIdentityKey'] as String,
        );
    expect(_hex(bound.canonicalTranscript()), t['transcriptV2Hex']);
  });

  test('the PQXDH responder derives the vector root keys', () async {
    final p = _section('pqxdhResponder');
    final routing = PreKeyHandshakeRouting.fromEnvelopeJson(
      Map<String, dynamic>.from(p['routing'] as Map),
    );
    Future<List<int>> respond(PreKeyHandshakeRouting r) =>
        X3DH.respondKeyAgreement(
          identityKeyPair: KeyPair.fromJson(
            Map<String, dynamic>.from(p['identityKeyPair'] as Map),
          ),
          signedPreKey: SignedPreKey.fromJson(
            Map<String, dynamic>.from(p['signedPreKey'] as Map),
          ),
          oneTimePreKey: OneTimePreKey.fromJson(
            Map<String, dynamic>.from(p['oneTimePreKey'] as Map),
          ),
          senderIdentityKey: p['senderIdentityKey'] as String,
          senderEphemeralKey: p['senderEphemeralKey'] as String,
          kyberKeyPair: KyberKeyPair.fromJson(
            Map<String, dynamic>.from(p['kyberKeyPair'] as Map),
          ),
          kyberCiphertext: p['kyberCiphertext'] as String,
          routing: r,
        );
    expect(_hex(await respond(routing)), p['sharedSecretTranscriptV1Hex']);
    expect(
      _hex(await respond(routing.withTranscriptVersion(2))),
      p['sharedSecretTranscriptV2Hex'],
    );
  });

  test('the identity AD and both AAD layouts match', () {
    final a = _section('aad');
    final ikA = a['identityKeyA'] as String;
    final ikB = a['identityKeyB'] as String;
    final ad = DoubleRatchet.identityAssociatedData(
      localIdentityKey: ikA,
      remoteIdentityKey: ikB,
    );
    expect(_hex(ad), a['identityAdHex']);
    // Either side builds the same AD.
    expect(
      _hex(
        DoubleRatchet.identityAssociatedData(
          localIdentityKey: ikB,
          remoteIdentityKey: ikA,
        ),
      ),
      a['identityAdHex'],
    );
    expect(
      _hex(
        DoubleRatchet.canonicalHeaderAad(
          version: 3,
          dhPublicKey: a['dhPublicKey'] as String,
          messageNumber: a['messageNumber'] as int,
          previousChainLength: a['previousChainLength'] as int,
          identityAd: ad,
        ),
      ),
      a['aadV3Hex'],
    );
    // Flag-off output pin: the v2 AAD is byte-identical to PR-SEC-004.
    expect(
      _hex(
        DoubleRatchet.canonicalHeaderAad(
          version: 2,
          dhPublicKey: a['dhPublicKey'] as String,
          messageNumber: a['messageNumber'] as int,
          previousChainLength: a['previousChainLength'] as int,
        ),
      ),
      a['aadV2Hex'],
    );
  });

  test('the golden v3 message decrypts; relabelled v2 does not', () async {
    final r = _section('ratchetV3');
    final state = Map<String, dynamic>.from(r['receiverState'] as Map);
    final message = Map<String, dynamic>.from(r['message'] as Map);
    final local = r['localIdentityKey'] as String;

    final bob = DoubleRatchet.fromJson(state);
    final plain = await bob.decrypt(
      EncryptedMessage.fromJson(message),
      localIdentityKey: local,
    );
    expect(MessagePadding.unpadString(plain), r['plaintext']);
    expect(bob.state.peerSpeaksV3, isTrue);

    final fresh = DoubleRatchet.fromJson(state);
    await expectLater(
      fresh.decrypt(
        EncryptedMessage.fromJson({...message, 'version': 2}),
        localIdentityKey: local,
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
  });
}
