@Retry(0)
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Ed25519;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/sealed_sender_errors.dart';
import 'package:risaal_crypto/src/sender_certificate.dart';

/// Shared Sender Certificate v1 vector (contract §6, as amended by v2: no
/// sender binding, so no `senderSignature` and no `wrong-recipient` case;
/// certificate bytes and server signatures are unchanged). A VERBATIM copy of
/// `risaal-server/test/fixtures/sender-certificate-v1.json`. The normal run
/// re-derives every value from the seeds and compares byte-for-byte; it only
/// writes the file when RISAAL_REGEN_FIXTURES=1.
const _fixturePath = 'test/fixtures/sender_certificate/v1_vectors.json';

const _serverSeedHex =
    '0101010101010101010101010101010101010101010101010101010101010101';
const _senderSeedHex =
    '0202020202020202020202020202020202020202020202020202020202020202';
const _keyId = 'test-key-1';
const _senderId = '507f1f77bcf86cd799439011';
const _senderDeviceId = 'device-1';
const _issuedAt = 1760000000000;
const _expiresAt = 1760086400000;
const _timestamp = 1760000500000;

Uint8List _hex(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

String _b64Fill(int byte) => base64Encode(List<int>.filled(32, byte));

Future<String> _ed25519PublicFromSeed(Uint8List seed) async {
  final kp = await Ed25519().newKeyPairFromSeed(seed);
  final pub = await kp.extractPublicKey();
  return base64Encode(pub.bytes);
}

Uint8List _bytes(Map<String, Object?> object) =>
    Uint8List.fromList(utf8.encode(jsonEncode(object)));

Map<String, Object?> _certObject({
  Object? v = 1,
  Object? keyId = _keyId,
  Object? senderId = _senderId,
  Object? senderDeviceId = _senderDeviceId,
  Object? senderIdentityKey,
  Object? senderSigningKey,
  Object? issuedAt = _issuedAt,
  Object? expiresAt = _expiresAt,
}) => {
  'expiresAt': expiresAt,
  'issuedAt': issuedAt,
  'keyId': keyId,
  'senderDeviceId': senderDeviceId,
  'senderId': senderId,
  'senderIdentityKey': senderIdentityKey ?? _b64Fill(5),
  'senderSigningKey': senderSigningKey ?? _b64Fill(7),
  'v': v,
};

Matcher _failsWith(SenderCertificateFailure reason) => throwsA(
  isA<SealedSenderCertificateError>().having((e) => e.reason, 'reason', reason),
);

/// Re-derives the whole fixture from the contract §6 inputs.
Future<Map<String, Object?>> _deriveVectors() async {
  final serverPriv = base64Encode(_hex(_serverSeedHex));
  final serverPub = await _ed25519PublicFromSeed(_hex(_serverSeedHex));
  final senderPub = await _ed25519PublicFromSeed(_hex(_senderSeedHex));

  Future<IssuedSenderCertificate> issue({
    String keyId = _keyId,
    String deviceId = _senderDeviceId,
    int issuedAt = _issuedAt,
    int expiresAt = _expiresAt,
  }) => SenderCertificateVerifier.issueForTesting(
    serverSigningPrivateKey: serverPriv,
    keyId: keyId,
    senderId: _senderId,
    senderDeviceId: deviceId,
    senderIdentityKey: _b64Fill(5),
    senderSigningKey: senderPub,
    issuedAt: issuedAt,
    expiresAt: expiresAt,
  );

  final valid = await issue();
  final tampered = await issue(deviceId: 'device-2');
  final unknown = await issue(keyId: 'test-key-9');
  final expired = await issue(
    issuedAt: 1700000000000,
    expiresAt: 1700086400000,
  );

  return {
    'version': 1,
    'domains': {'serverSignature': SenderCertificateDomains.serverSignature},
    'seeds': {
      'serverSigningSeedHex': _serverSeedHex,
      'senderSigningSeedHex': _senderSeedHex,
    },
    'serverSigningKey': {'keyId': _keyId, 'publicKey': serverPub},
    'timestamp': _timestamp,
    'valid': {
      'certificateObject': jsonDecode(utf8.decode(valid.certificateBytes)),
      'certificate': base64Encode(valid.certificateBytes),
      'serverSignature': valid.serverSignature,
    },
    'negative': [
      {
        'name': 'tampered-device-id',
        'reason': 'badServerSignature',
        'certificate': base64Encode(tampered.certificateBytes),
        'serverSignature': valid.serverSignature,
      },
      {
        'name': 'unknown-key-id',
        'reason': 'unknownKeyId',
        'certificate': base64Encode(unknown.certificateBytes),
        'serverSignature': unknown.serverSignature,
      },
      {
        'name': 'expired',
        'reason': 'expired',
        'certificate': base64Encode(expired.certificateBytes),
        'serverSignature': expired.serverSignature,
      },
    ],
  };
}

String _encodeFixture(Map<String, Object?> vectors) =>
    '${const JsonEncoder.withIndent('  ').convert(vectors)}\n';

void main() {
  late Map<String, dynamic> fixture;
  late String fixtureText;
  late Map<String, String> trusted;

  setUpAll(() async {
    if (Platform.environment['RISAAL_REGEN_FIXTURES'] == '1') {
      File(
        _fixturePath,
      ).writeAsStringSync(_encodeFixture(await _deriveVectors()));
    }
    fixtureText = File(_fixturePath).readAsStringSync();
    fixture = jsonDecode(fixtureText) as Map<String, dynamic>;
    final serverKey = fixture['serverSigningKey'] as Map<String, dynamic>;
    trusted = {serverKey['keyId'] as String: serverKey['publicKey'] as String};
  });

  IssuedSenderCertificate validIssued() {
    final valid = fixture['valid'] as Map<String, dynamic>;
    return IssuedSenderCertificate.fromIssuedJson({
      'certificate': valid['certificate'],
      'serverSignature': valid['serverSignature'],
    });
  }

  group('shared v1 vector', () {
    test('re-derived from the seeds byte-for-byte (whole file)', () async {
      final derived = await _deriveVectors();
      expect(_encodeFixture(derived), fixtureText);
    });

    test('issueForTesting reproduces the server signature', () async {
      final senderPub = await _ed25519PublicFromSeed(_hex(_senderSeedHex));
      final issued = await SenderCertificateVerifier.issueForTesting(
        serverSigningPrivateKey: base64Encode(_hex(_serverSeedHex)),
        keyId: _keyId,
        senderId: _senderId,
        senderDeviceId: _senderDeviceId,
        senderIdentityKey: _b64Fill(5),
        senderSigningKey: senderPub,
        issuedAt: _issuedAt,
        expiresAt: _expiresAt,
      );
      final valid = fixture['valid'] as Map<String, dynamic>;
      expect(base64Encode(issued.certificateBytes), valid['certificate']);
      expect(issued.serverSignature, valid['serverSignature']);
    });

    test('valid vector passes every envelope check', () async {
      final valid = fixture['valid'] as Map<String, dynamic>;
      final cert = await SenderCertificateVerifier.verifyForEnvelope(
        issued: validIssued(),
        trustedServerSigningKeys: trusted,
        senderId: _senderId,
        senderDeviceId: _senderDeviceId,
        senderIdentityKey: _b64Fill(5),
        sealedTimestamp: fixture['timestamp'] as int,
      );
      expect(cert.keyId, _keyId);
      expect(cert.senderId, _senderId);
      expect(
        cert.senderSigningKey,
        (valid['certificateObject']
            as Map<String, dynamic>)['senderSigningKey'],
      );
    });

    test('every negative vector fails with its declared reason', () async {
      final negatives = fixture['negative'] as List<dynamic>;
      expect(negatives.map((v) => (v as Map<String, dynamic>)['name']), [
        'tampered-device-id',
        'unknown-key-id',
        'expired',
      ]);
      for (final raw in negatives) {
        final vector = raw as Map<String, dynamic>;
        final reason = SenderCertificateFailure.values.byName(
          vector['reason'] as String,
        );
        await expectLater(
          SenderCertificateVerifier.verifyForEnvelope(
            issued: IssuedSenderCertificate.fromIssuedJson({
              'certificate': vector['certificate'],
              'serverSignature': vector['serverSignature'],
            }),
            trustedServerSigningKeys: trusted,
            senderId: _senderId,
            senderDeviceId: _senderDeviceId,
            senderIdentityKey: _b64Fill(5),
            sealedTimestamp: fixture['timestamp'] as int,
          ),
          _failsWith(reason),
          reason: vector['name'] as String,
        );
      }
    });
  });

  group('SenderCertificate.parse', () {
    test('accepts the valid fixture vector and keeps the exact bytes', () {
      final issued = validIssued();
      final cert = SenderCertificate.parse(issued.certificateBytes);
      expect(cert.bytes, issued.certificateBytes);
      expect(cert.issuedAt, _issuedAt);
      expect(cert.expiresAt, _expiresAt);
      expect(cert.senderDeviceId, _senderDeviceId);
      expect(cert.senderIdentityKey, _b64Fill(5));
      expect(cert.coversSealedTimestamp(_timestamp), isTrue);
      expect(cert.usableAt(_timestamp), isTrue);
      expect(cert.usableAt(_expiresAt), isFalse);
    });

    test('rejects v != 1', () {
      expect(
        () => SenderCertificate.parse(_bytes(_certObject(v: 2))),
        _failsWith(SenderCertificateFailure.malformed),
      );
      expect(
        () => SenderCertificate.parse(_bytes(_certObject(v: '1'))),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('rejects a missing field', () {
      final object = _certObject()..remove('senderDeviceId');
      expect(
        () => SenderCertificate.parse(_bytes(object)),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('rejects an extra field', () {
      final object = _certObject()..['extra'] = 'x';
      expect(
        () => SenderCertificate.parse(_bytes(object)),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('rejects a 31-byte key and non-canonical base64', () {
      expect(
        () => SenderCertificate.parse(
          _bytes(
            _certObject(
              senderSigningKey: base64Encode(List<int>.filled(31, 7)),
            ),
          ),
        ),
        _failsWith(SenderCertificateFailure.malformed),
      );
      final urlSafe = base64Url.encode(List<int>.filled(32, 0xfb));
      expect(urlSafe, contains('-'));
      expect(
        () => SenderCertificate.parse(
          _bytes(_certObject(senderIdentityKey: urlSafe)),
        ),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('rejects expiresAt <= issuedAt', () {
      expect(
        () =>
            SenderCertificate.parse(_bytes(_certObject(expiresAt: _issuedAt))),
        _failsWith(SenderCertificateFailure.malformed),
      );
      expect(
        () => SenderCertificate.parse(
          _bytes(_certObject(expiresAt: _issuedAt - 1)),
        ),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('rejects validity > 30 days', () {
      const thirtyDays = 30 * 24 * 60 * 60 * 1000;
      expect(
        SenderCertificate.parse(
          _bytes(_certObject(expiresAt: _issuedAt + thirtyDays)),
        ).expiresAt,
        _issuedAt + thirtyDays,
      );
      expect(
        () => SenderCertificate.parse(
          _bytes(_certObject(expiresAt: _issuedAt + thirtyDays + 1)),
        ),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('rejects bad keyId, non-int timestamps, non-JSON and non-UTF-8', () {
      for (final keyId in ['', 'a' * 65, 'bad key', 'k/1']) {
        expect(
          () => SenderCertificate.parse(_bytes(_certObject(keyId: keyId))),
          _failsWith(SenderCertificateFailure.malformed),
          reason: 'keyId "$keyId"',
        );
      }
      expect(
        () => SenderCertificate.parse(
          _bytes(_certObject(issuedAt: 1760000000000.0)),
        ),
        _failsWith(SenderCertificateFailure.malformed),
      );
      expect(
        () => SenderCertificate.parse(_bytes(_certObject(senderId: ''))),
        _failsWith(SenderCertificateFailure.malformed),
      );
      expect(
        () => SenderCertificate.parse(Uint8List.fromList(utf8.encode('[1]'))),
        _failsWith(SenderCertificateFailure.malformed),
      );
      expect(
        () => SenderCertificate.parse(Uint8List.fromList([0x7b, 0xff, 0x7d])),
        _failsWith(SenderCertificateFailure.malformed),
      );
    });

    test('error message carries no ids or keys', () {
      try {
        SenderCertificate.parse(_bytes(_certObject(v: 9)));
        fail('expected rejection');
      } on SealedSenderCertificateError catch (e) {
        expect(e.toString(), isNot(contains(_senderId)));
        expect(e.toString(), isNot(contains(_b64Fill(5))));
        expect(e.toString(), contains('malformed'));
      }
    });
  });

  group('IssuedSenderCertificate', () {
    test('fromIssuedJson ignores unknown keys and round-trips', () {
      final valid = fixture['valid'] as Map<String, dynamic>;
      final issued = IssuedSenderCertificate.fromIssuedJson({
        'certificate': valid['certificate'],
        'serverSignature': valid['serverSignature'],
        'keyId': _keyId,
        'algorithm': 'Ed25519',
        'expiresAt': _expiresAt,
      });
      expect(issued.toIssuedJson(), {
        'certificate': valid['certificate'],
        'serverSignature': valid['serverSignature'],
      });
    });

    test('fromIssuedJson rejects missing or non-canonical fields', () {
      final valid = fixture['valid'] as Map<String, dynamic>;
      for (final json in <Map<String, dynamic>>[
        {'certificate': valid['certificate']},
        {'serverSignature': valid['serverSignature']},
        {'certificate': 42, 'serverSignature': valid['serverSignature']},
        {
          'certificate': (valid['certificate'] as String).replaceAll('=', ''),
          'serverSignature': valid['serverSignature'],
        },
        {
          'certificate': valid['certificate'],
          'serverSignature': base64Encode(List<int>.filled(63, 1)),
        },
      ]) {
        expect(
          () => IssuedSenderCertificate.fromIssuedJson(json),
          _failsWith(SenderCertificateFailure.malformed),
        );
      }
    });
  });

  group('SenderCertificateVerifier', () {
    test('verifyIssued returns the certificate for the vector', () async {
      final cert = await SenderCertificateVerifier.verifyIssued(
        issued: validIssued(),
        trustedServerSigningKeys: trusted,
      );
      expect(cert.keyId, _keyId);
    });

    test('verifyIssued: unknownKeyId when the map lacks the key', () async {
      await expectLater(
        SenderCertificateVerifier.verifyIssued(
          issued: validIssued(),
          trustedServerSigningKeys: {'other-key': trusted.values.single},
        ),
        _failsWith(SenderCertificateFailure.unknownKeyId),
      );
    });

    test(
      'verifyIssued: badServerSignature for a flipped certificate byte',
      () async {
        final issued = validIssued();
        final bytes = Uint8List.fromList(issued.certificateBytes);
        // Flip a byte inside the senderDeviceId value so the JSON stays valid:
        // "device-1" -> "device-3".
        final text = utf8.decode(bytes);
        final at = text.indexOf('device-1') + 'device-'.length;
        bytes[at] ^= 0x02;
        expect(utf8.decode(bytes), contains('device-3'));
        await expectLater(
          SenderCertificateVerifier.verifyIssued(
            issued: IssuedSenderCertificate(
              certificateBytes: bytes,
              serverSignature: issued.serverSignature,
            ),
            trustedServerSigningKeys: trusted,
          ),
          _failsWith(SenderCertificateFailure.badServerSignature),
        );
      },
    );

    test('verifyIssued: a malformed pinned key fails closed', () async {
      await expectLater(
        SenderCertificateVerifier.verifyIssued(
          issued: validIssued(),
          trustedServerSigningKeys: {_keyId: 'not-base64'},
        ),
        _failsWith(SenderCertificateFailure.unknownKeyId),
      );
    });

    test('verifyForEnvelope: identity mismatch and time window', () async {
      Future<SenderCertificate> run({
        String senderId = _senderId,
        String senderDeviceId = _senderDeviceId,
        String? senderIdentityKey,
        int sealedTimestamp = _timestamp,
      }) => SenderCertificateVerifier.verifyForEnvelope(
        issued: validIssued(),
        trustedServerSigningKeys: trusted,
        senderId: senderId,
        senderDeviceId: senderDeviceId,
        senderIdentityKey: senderIdentityKey ?? _b64Fill(5),
        sealedTimestamp: sealedTimestamp,
      );

      await expectLater(
        run(senderId: '507f1f77bcf86cd799439012'),
        _failsWith(SenderCertificateFailure.identityMismatch),
      );
      await expectLater(
        run(senderDeviceId: 'device-2'),
        _failsWith(SenderCertificateFailure.identityMismatch),
      );
      await expectLater(
        run(senderIdentityKey: _b64Fill(9)),
        _failsWith(SenderCertificateFailure.identityMismatch),
      );
      const skew = 5 * 60 * 1000;
      expect(await run(sealedTimestamp: _issuedAt - skew), isNotNull);
      expect(await run(sealedTimestamp: _expiresAt + skew), isNotNull);
      await expectLater(
        run(sealedTimestamp: _issuedAt - skew - 1),
        _failsWith(SenderCertificateFailure.notYetValid),
      );
      await expectLater(
        run(sealedTimestamp: _expiresAt + skew + 1),
        _failsWith(SenderCertificateFailure.expired),
      );
    });
  });
}
