import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/x3dh.dart';

import 'helpers/crypto_test_fixtures.dart';

/// External report F5 (2026-10-22): no X25519 call site rejected the
/// all-zero output RFC 7748 §6.1 requires rejecting, so a low-order public
/// key forced a DH term to a public constant.

// u = 0 and u = 1 are low-order points on Curve25519: X25519 with either
// yields 32 zero bytes for every private scalar.
final _lowOrderPoints = <String, String>{
  'u=0': base64Encode(List<int>.filled(32, 0)),
  'u=1': base64Encode(<int>[1, ...List<int>.filled(31, 0)]),
};

Future<PreKeyBundle> _bundle({String? identityKey}) async {
  final identityKP = await SignalKeyHelper.generateX25519KeyPair();
  final signingKP = await SignalKeyHelper.generateSigningKeyPair();
  final signedPreKey = await SignalKeyHelper.generateSignedPreKey(1, signingKP);
  final kyberKP = SignalKeyHelper.generateKyberKeyPair();
  final kyberSignature = await SignalKeyHelper.sign(
    signingKP.privateKey,
    RisaalCryptoProtocol.kyberPreKeySignatureTranscript(
      keyId: kyberKP.keyId!,
      publicKey: kyberKP.publicKey,
    ),
  );
  return PreKeyBundle(
    opkRoute: testOpkRoute,
    userId: 'bob-123',
    deviceId: 'device-1',
    identityKey: identityKey ?? identityKP.publicKey,
    identitySigningKey: signingKP.publicKey,
    signedPreKey: SignedPreKeyPublic(
      keyId: signedPreKey.keyId,
      publicKey: signedPreKey.keyPair.publicKey,
      signature: signedPreKey.signature,
    ),
    kyberPreKey: KyberPreKeyPublic(
      keyId: kyberKP.keyId!,
      publicKey: kyberKP.publicKey,
      cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
      kemSuite: RisaalCryptoProtocol.kemSuite,
      kemStandard: RisaalCryptoProtocol.kemStandard,
      kemWireVersion: RisaalCryptoProtocol.kemWireVersion,
      signature: kyberSignature,
    ),
  );
}

void main() {
  test('requireContributoryX25519 rejects only the all-zero output', () {
    expect(
      () => SignalKeyHelper.requireContributoryX25519(List<int>.filled(32, 0)),
      throwsArgumentError,
    );
    SignalKeyHelper.requireContributoryX25519(<int>[
      ...List<int>.filled(31, 0),
      1,
    ]);
  });

  for (final entry in _lowOrderPoints.entries) {
    test('X3DH refuses a bundle whose identity key is low-order '
        '(${entry.key})', () async {
      final alice = await SignalKeyHelper.generateX25519KeyPair();
      final bundle = await _bundle(identityKey: entry.value);
      await expectLater(
        X3DH.initiateKeyAgreement(
          identityKeyPair: alice,
          recipientBundle: bundle,
        ),
        throwsArgumentError,
      );
    });
  }

  test('X3DH with an honest bundle still agrees', () async {
    final alice = await SignalKeyHelper.generateX25519KeyPair();
    final result = await X3DH.initiateKeyAgreement(
      identityKeyPair: alice,
      recipientBundle: await _bundle(),
    );
    expect(result.sharedSecret, isNotEmpty);
  });
}
