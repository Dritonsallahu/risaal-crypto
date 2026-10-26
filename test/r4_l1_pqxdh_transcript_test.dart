import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/x3dh.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/r4_l1_contract.dart';

/// R4-L1 Part A at the PQXDH layer (contract §3, §5 A): transcript 2 appends
/// both identity keys under its own domain, the responder accepts it, and the
/// version cannot be moved without changing the root key.
const _route = OpkGenerationRouting(
  bundleRevision: 4294967303,
  opkGeneration: 4294967301,
  opkSetDigest:
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
);
const _routing = PreKeyHandshakeRouting(
  opkRoute: _route,
  recipientSignedPreKeyId: 17,
  usedOneTimePreKeyId: 23,
  kemMetadata: MlKemEnvelopeMetadata.current(recipientKeyId: 19),
);

class _Bob {
  _Bob(this.bundle, this.identity, this.signedPreKey, this.otpk, this.kyber);

  final PreKeyBundle bundle;
  final KeyPair identity;
  final SignedPreKey signedPreKey;
  final OneTimePreKey otpk;
  final KyberKeyPair kyber;

  Future<List<int>> respond({
    required KeyPair alice,
    required X3DHResult result,
    required PreKeyHandshakeRouting routing,
  }) => X3DH.respondKeyAgreement(
    identityKeyPair: identity,
    signedPreKey: signedPreKey,
    oneTimePreKey: otpk,
    senderIdentityKey: alice.publicKey,
    senderEphemeralKey: result.ephemeralPublicKey,
    kyberKeyPair: kyber,
    kyberCiphertext: result.kyberCiphertext!,
    routing: routing,
  );
}

Future<_Bob> _bob() async {
  final identity = await SignalKeyHelper.generateX25519KeyPair();
  final signing = await SignalKeyHelper.generateSigningKeyPair();
  final signedPreKey = await SignalKeyHelper.generateSignedPreKey(1, signing);
  final otpk = (await SignalKeyHelper.generateOneTimePreKeys(1, 1)).single;
  final kyber = SignalKeyHelper.generateKyberKeyPair();
  final bundle = await CryptoTestFixtures.buildBundle(
    userId: 'bob-id',
    deviceId: 'bob-device',
    identityKP: identity,
    signingKP: signing,
    signedPreKey: signedPreKey,
    oneTimePreKeys: [otpk],
    kyberKP: kyber,
  );
  return _Bob(bundle, identity, signedPreKey, otpk, kyber);
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('R4-L1 transcript 2', () {
    test('the responder derives the initiator root key for transcript 2, '
        'and a different one under transcript 1', () async {
      final alice = await SignalKeyHelper.generateX25519KeyPair();
      final bob = await _bob();

      final initiated = await X3DH.initiateKeyAgreement(
        identityKeyPair: alice,
        recipientBundle: bob.bundle,
        transcriptVersion: 2,
      );
      expect(initiated.routing.transcriptVersion, 2);

      final responderV2 = await bob.respond(
        alice: alice,
        result: initiated,
        routing: initiated.routing,
      );
      expect(responderV2, initiated.sharedSecret);

      final responderV1 = await bob.respond(
        alice: alice,
        result: initiated,
        routing: initiated.routing.withTranscriptVersion(1),
      );
      expect(responderV1, isNot(initiated.sharedSecret));

      // A transcript-1 handshake still agrees with itself (Part A keeps it).
      final legacy = await X3DH.initiateKeyAgreement(
        identityKeyPair: alice,
        recipientBundle: bob.bundle,
      );
      expect(legacy.routing.transcriptVersion, 1);
      expect(
        await bob.respond(
          alice: alice,
          result: legacy,
          routing: legacy.routing,
        ),
        legacy.sharedSecret,
      );
    });

    test('transcript 2 binds which identity is the initiator', () async {
      final alice = await SignalKeyHelper.generateX25519KeyPair();
      final bob = await _bob();
      final initiated = await X3DH.initiateKeyAgreement(
        identityKeyPair: alice,
        recipientBundle: bob.bundle,
        transcriptVersion: 2,
      );
      final bound = initiated.routing.bindIdentityKeys(
        initiatorIdentityKey: alice.publicKey,
        responderIdentityKey: bob.identity.publicKey,
      );
      final swapped = initiated.routing.bindIdentityKeys(
        initiatorIdentityKey: bob.identity.publicKey,
        responderIdentityKey: alice.publicKey,
      );
      expect(bound.canonicalTranscript(), isNot(swapped.canonicalTranscript()));
    });

    test('transcript 2 is the v1 fields under the v2 domain plus both raw '
        'identity keys', () async {
      final ikA = (await SignalKeyHelper.generateX25519KeyPair()).publicKey;
      final ikB = (await SignalKeyHelper.generateX25519KeyPair()).publicKey;
      final v1 = _routing.canonicalTranscript();
      final v2 = _routing
          .withTranscriptVersion(2)
          .bindIdentityKeys(
            initiatorIdentityKey: ikA,
            responderIdentityKey: ikB,
          )
          .canonicalTranscript();

      final v1Domain = R4L1Contract.lengthPrefixed(
        utf8.encode(R4L1Contract.transcriptDomainV1),
      );
      final v2Domain = R4L1Contract.lengthPrefixed(
        utf8.encode(R4L1Contract.transcriptDomainV2),
      );
      final v1Fields = v1.sublist(v1Domain.length);
      expect(_hex(v1.sublist(0, v1Domain.length)), _hex(v1Domain));
      expect(
        _hex(v2),
        _hex(<int>[
          ...v2Domain,
          ...v1Fields,
          ...R4L1Contract.lengthPrefixed(base64Decode(ikA)),
          ...R4L1Contract.lengthPrefixed(base64Decode(ikB)),
        ]),
      );
      // Binding identities never changes transcript 1.
      expect(
        _routing
            .bindIdentityKeys(
              initiatorIdentityKey: ikA,
              responderIdentityKey: ikB,
            )
            .canonicalTranscript(),
        v1,
      );
    });

    test('transcript 2 without both identity keys fails closed', () async {
      final ik = (await SignalKeyHelper.generateX25519KeyPair()).publicKey;
      final v2 = _routing.withTranscriptVersion(2);
      expect(v2.canonicalTranscript, throwsFormatException);
      expect(
        v2
            .bindIdentityKeys(
              initiatorIdentityKey: ik,
              responderIdentityKey: base64Encode(List<int>.filled(31, 1)),
            )
            .canonicalTranscript,
        throwsFormatException,
      );
    });

    test('the envelope carries transcriptVersion only for transcript 2', () {
      expect(_routing.toEnvelopeJson().containsKey('transcriptVersion'), false);
      expect(
        _routing.toSealedProjectionJson().containsKey('transcriptVersion'),
        isFalse,
      );
      final v2 = _routing.withTranscriptVersion(2);
      expect(v2.toEnvelopeJson()['transcriptVersion'], 2);
      // The sealed outer projection never exposes it to the relay.
      expect(
        v2.toSealedProjectionJson().containsKey('transcriptVersion'),
        isFalse,
      );

      final parsedV1 = PreKeyHandshakeRouting.fromEnvelopeJson(
        _routing.toEnvelopeJson(),
      );
      expect(parsedV1.transcriptVersion, 1);
      expect(parsedV1, _routing);
      final parsedV2 = PreKeyHandshakeRouting.fromEnvelopeJson(
        v2.toEnvelopeJson(),
      );
      expect(parsedV2.transcriptVersion, 2);
      expect(parsedV2, v2);
      expect(parsedV2, isNot(_routing));

      for (final bad in <Object?>[1, 0, 3, '2', null, 2.0]) {
        expect(
          () => PreKeyHandshakeRouting.fromEnvelopeJson(<String, dynamic>{
            ..._routing.toEnvelopeJson(),
            'transcriptVersion': bad,
          }),
          throwsFormatException,
          reason: 'transcriptVersion=$bad',
        );
      }
      expect(
        () => _routing.withTranscriptVersion(3).canonicalTranscript(),
        throwsFormatException,
      );
    });
  });
}
