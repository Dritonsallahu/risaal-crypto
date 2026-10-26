import 'package:crypto/crypto.dart' as crypto;
import 'package:risaal_crypto/src/crypto_protocol.dart';
import 'package:test/test.dart';

void main() {
  test('Dart2JS-safe OPK route transcript matches the >u32 golden', () {
    const routing = PreKeyHandshakeRouting(
      opkRoute: OpkGenerationRouting(
        bundleRevision: 4294967303,
        opkGeneration: 4294967301,
        opkSetDigest:
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      ),
      recipientSignedPreKeyId: 17,
      usedOneTimePreKeyId: 23,
      kemMetadata: MlKemEnvelopeMetadata.current(recipientKeyId: 19),
    );

    final transcript = routing.canonicalTranscript();
    expect(
      transcript.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
      '0000001952495341414c5f50515844485f4f504b5f524f5554455f7631'
      '0000000200000001000000070000000100000005000000200123456789abcdef'
      '0123456789abcdef0123456789abcdef0123456789abcdef000000110100000017'
      '00000013000000010000000a4d4c2d4b454d2d3736380000000746495053323033',
    );
    expect(
      crypto.sha256.convert(transcript).toString(),
      '371849dbf3895d18a3944cab5188f2a4805b83b40be3ca275399b9543042d182',
    );

    const maxSafeRouting = PreKeyHandshakeRouting(
      opkRoute: OpkGenerationRouting(
        bundleRevision: RisaalCryptoProtocol.maxServerSafeInt,
        opkGeneration: RisaalCryptoProtocol.maxServerSafeInt,
        opkSetDigest:
            '0000000000000000000000000000000000000000000000000000000000000000',
      ),
      recipientSignedPreKeyId: 1,
      usedOneTimePreKeyId: null,
      kemMetadata: MlKemEnvelopeMetadata.current(recipientKeyId: 1),
    );
    final maxHex = maxSafeRouting
        .canonicalTranscript()
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
    expect(
      maxHex.substring(33 * 2, 49 * 2),
      '001fffffffffffff001fffffffffffff',
    );
  });
}
