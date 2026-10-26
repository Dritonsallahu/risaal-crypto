@Retry(0)
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' show Ed25519;
import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';

/// Shared GroupRoster v1 vector (R4-H10). A byte-identical copy lives at
/// `risaal-server/test/fixtures/group-roster-v1.json` and is checked by
/// `group-roster.vector.spec.ts` against the Node parser. The normal run
/// re-derives every value from the seeds and compares byte-for-byte; it only
/// writes the file when RISAAL_REGEN_FIXTURES=1.
const _fixturePath = 'test/fixtures/group_roster/v1_vectors.json';

const _groupId = '0f8fad5b-d9cb-469f-a165-70867728950e';
const _otherGroupId = '1b4e28ba-2fa1-41d2-883f-0016d3cca427';
const _idA = '507f1f77bcf86cd799439011';
const _idB = '507f1f77bcf86cd799439012';
const _idC = '507f1f77bcf86cd799439013';
const _idD = '507f1f77bcf86cd799439014';
const _seedA = 0x03;
const _seedB = 0x04;
const _seedC = 0x08;
const _t1 = 1760000000000;
const _t2 = 1760000600000;
const _t3 = 1760001200000;

Uint8List _seed(int byte) => Uint8List.fromList(List<int>.filled(32, byte));

String _hexOf(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String _b64Of(int byte, int length) =>
    base64Encode(List<int>.filled(length, byte));

String _key(int byte) => _b64Of(byte, 32);

String _sha256Hex(String s) => crypto.sha256.convert(utf8.encode(s)).toString();

Future<String> _pub(int seedByte) async {
  final kp = await Ed25519().newKeyPairFromSeed(_seed(seedByte));
  return base64Encode((await kp.extractPublicKey()).bytes);
}

/// Independent of the library: Ed25519 over the contract's domain bytes.
Future<String> _sign(
  int seedByte,
  String rosterJson, {
  bool domain = true,
}) async {
  final kp = await Ed25519().newKeyPairFromSeed(_seed(seedByte));
  final message = <int>[
    if (domain) ...utf8.encode('risaal-group-roster-v1'),
    if (domain) 0,
    ...utf8.encode(rosterJson),
  ];
  final sig = await Ed25519().sign(message, keyPair: kp);
  return base64Encode(sig.bytes);
}

String _mutate(String json, void Function(Map<String, dynamic> m) f) {
  final m = jsonDecode(json) as Map<String, dynamic>;
  f(m);
  return jsonEncode(m);
}

Map<String, dynamic> _memberAt(Map<String, dynamic> m, int i) =>
    (m['members'] as List)[i] as Map<String, dynamic>;

String _replaceOnce(String s, String from, String to) {
  if (!s.contains(from)) throw StateError('fixture builder: pattern missing');
  return s.replaceFirst(from, to);
}

typedef _Signers = ({
  GroupRosterSigner a,
  GroupRosterSigner b,
  GroupRosterSigner c,
});

Future<_Signers> _signers() async => (
  a: GroupRosterSigner(
    userId: _idA,
    deviceId: 'device-1',
    signingKey: await _pub(_seedA),
  ),
  b: GroupRosterSigner(
    userId: _idB,
    deviceId: 'device-2',
    signingKey: await _pub(_seedB),
  ),
  c: GroupRosterSigner(
    userId: _idC,
    deviceId: 'device-3',
    signingKey: await _pub(_seedC),
  ),
);

GroupRosterMember _m(String id, GroupRosterRole role, [String? key]) =>
    GroupRosterMember(userId: id, role: role, identityKey: key);

const _admin = GroupRosterRole.admin;
const _member = GroupRosterRole.member;

typedef _Chain = ({String e1, String e2, String e3});

Future<_Chain> _chain(_Signers s) async {
  final e1 = GroupRoster.encode(
    groupId: _groupId,
    epoch: 1,
    issuedAt: _t1,
    signer: s.a,
    // Deliberately unsorted: the producer sorts by userId.
    members: [_m(_idC, _member), _m(_idA, _admin), _m(_idB, _member, _key(5))],
    prev: null,
  );
  final e2 = GroupRoster.encode(
    groupId: _groupId,
    epoch: 2,
    issuedAt: _t2,
    signer: s.a,
    members: [_m(_idA, _admin), _m(_idB, _admin, _key(5))],
    prev: _sha256Hex(e1),
  );
  final e3 = GroupRoster.encode(
    groupId: _groupId,
    epoch: 3,
    issuedAt: _t3,
    signer: s.b,
    members: [
      _m(_idA, _admin),
      _m(_idB, _admin, _key(5)),
      _m(_idD, _member, _key(6)),
    ],
    prev: _sha256Hex(e2),
  );
  return (e1: e1, e2: e2, e3: e3);
}

Future<Map<String, Object?>> _deriveVectors() async {
  final s = await _signers();
  final r = await _chain(s);
  final e1 = r.e1;
  final h1 = _sha256Hex(e1);
  final sig1 = await _sign(_seedA, e1);
  String e1Rep(String from, String to) => _replaceOnce(e1, from, to);
  String e1Mut(void Function(Map<String, dynamic> m) f) => _mutate(e1, f);

  Map<String, Object?> valid(String name, String json, int seed, String who) =>
      {'name': name, 'rosterJson': json, 'signer': who};

  final validList = <Map<String, Object?>>[
    valid('epoch1', r.e1, _seedA, 'A'),
    valid('epoch2', r.e2, _seedA, 'A'),
    valid('epoch3', r.e3, _seedB, 'B'),
  ];
  for (final v in validList) {
    final json = v['rosterJson']! as String;
    v['signature'] = await _sign(v['signer'] == 'A' ? _seedA : _seedB, json);
    v['rosterHash'] = _sha256Hex(json);
    v['signingKey'] = v['signer'] == 'A' ? s.a.signingKey : s.b.signingKey;
  }

  Map<String, Object?> accepted(String name, String json, int epoch, int at) =>
      {
        'name': name,
        'rosterJson': json,
        'epoch': epoch,
        'issuedAt': at,
        'rosterHash': _sha256Hex(json),
      };

  Map<String, Object?> neg(String name, String json, String code) => {
    'name': name,
    'rosterJson': json,
    'code': code,
  };

  final urlSafe = _b64Of(0xfb, 32).replaceAll('+', '-').replaceAll('/', '_');
  final k5 = _key(5);
  final whitespace = '${k5.substring(0, 10)} ${k5.substring(11)}';
  final nonCanonicalBits = '${k5.substring(0, 42)}V=';

  return {
    'description':
        'GroupRoster v1 shared vector (R4-H10). Generated by '
        'packages/risaal_crypto/test/group_roster_test.dart with '
        'RISAAL_REGEN_FIXTURES=1; byte-identical copy in '
        'risaal-server/test/fixtures/group-roster-v1.json. Test-only seeds.',
    'domain': 'risaal-group-roster-v1\u0000',
    'groupId': _groupId,
    'signers': {
      'A': {
        'seedHex': _hexOf(_seed(_seedA)),
        'userId': s.a.userId,
        'deviceId': s.a.deviceId,
        'signingKey': s.a.signingKey,
      },
      'B': {
        'seedHex': _hexOf(_seed(_seedB)),
        'userId': s.b.userId,
        'deviceId': s.b.deviceId,
        'signingKey': s.b.signingKey,
      },
    },
    'valid': validList,
    'parseAccepted': [
      accepted(
        'epoch_written_1.0',
        e1Rep('"epoch":1,', '"epoch":1.0,'),
        1,
        _t1,
      ),
      accepted(
        'epoch_written_2e0',
        _replaceOnce(r.e2, '"epoch":2,', '"epoch":2e0,'),
        2,
        _t2,
      ),
      accepted('version_written_1.0', e1Rep('{"v":1,', '{"v":1.0,'), 1, _t1),
      accepted(
        'issued_at_max_safe_integer',
        e1Rep('"issuedAt":$_t1', '"issuedAt":9007199254740991'),
        1,
        9007199254740991,
      ),
      accepted(
        'key_written_as_unicode_escape',
        e1Rep('{"v":1,', '{"\\u0076":1,'),
        1,
        _t1,
      ),
    ],
    'parseNegatives': [
      neg(
        'invalid_json_truncated',
        e1.substring(0, e1.length - 1),
        'invalid_json',
      ),
      neg('not_object_array', '[]', 'not_object'),
      neg(
        'duplicate_key_top',
        e1Rep('{"v":1,', '{"v":1,"v":1,'),
        'duplicate_key',
      ),
      neg(
        'duplicate_key_unicode_escape',
        e1Rep('{"v":1,', '{"v":1,"\\u0076":1,'),
        'duplicate_key',
      ),
      neg(
        'duplicate_key_signer',
        e1Rep('"deviceId":"device-1"', '"deviceId":"device-1","deviceId":"x"'),
        'duplicate_key',
      ),
      neg(
        'duplicate_key_before_not_object',
        '[{"a":1,"a":2}]',
        'duplicate_key',
      ),
      neg(
        'unknown_field_top',
        e1Mut((m) => m['extra'] = true),
        'unknown_field',
      ),
      neg(
        'unknown_field_before_missing_field',
        e1Mut((m) {
          m.remove('issuedAt');
          m['extra'] = true;
        }),
        'unknown_field',
      ),
      neg(
        'unknown_field_member',
        e1Mut((m) => _memberAt(m, 0)['nickname'] = 'x'),
        'unknown_field',
      ),
      neg('missing_field_top', e1Mut((m) => m.remove('prev')), 'missing_field'),
      neg(
        'missing_field_signer',
        e1Mut((m) => (m['signer'] as Map).remove('deviceId')),
        'missing_field',
      ),
      neg(
        'unsupported_version',
        e1Mut((m) => m['v'] = 2),
        'unsupported_version',
      ),
      neg(
        'unsupported_version_string',
        e1Mut((m) => m['v'] = '1'),
        'unsupported_version',
      ),
      neg(
        'invalid_group_id_uppercase',
        e1Mut((m) => m['groupId'] = _groupId.toUpperCase()),
        'invalid_group_id',
      ),
      neg('invalid_epoch_zero', e1Mut((m) => m['epoch'] = 0), 'invalid_epoch'),
      neg(
        'invalid_epoch_fraction',
        e1Rep('"epoch":1,', '"epoch":1.5,'),
        'invalid_epoch',
      ),
      neg(
        'invalid_epoch_2pow53',
        e1Rep('"epoch":1,', '"epoch":9007199254740992,'),
        'invalid_epoch',
      ),
      neg(
        'invalid_epoch_string',
        e1Mut((m) => m['epoch'] = '1'),
        'invalid_epoch',
      ),
      neg(
        'invalid_issued_at_negative',
        e1Mut((m) => m['issuedAt'] = -1),
        'invalid_issued_at',
      ),
      neg(
        'invalid_issued_at_fraction',
        e1Rep('"issuedAt":$_t1', '"issuedAt":$_t1.5'),
        'invalid_issued_at',
      ),
      neg(
        'invalid_signer_null',
        e1Mut((m) => m['signer'] = null),
        'invalid_signer',
      ),
      neg(
        'invalid_user_id_uppercase_signer',
        e1Mut((m) => (m['signer'] as Map)['userId'] = _idA.toUpperCase()),
        'invalid_user_id',
      ),
      neg(
        'invalid_device_id_empty',
        e1Mut((m) => (m['signer'] as Map)['deviceId'] = ''),
        'invalid_device_id',
      ),
      neg(
        'invalid_device_id_129_chars',
        e1Mut((m) => (m['signer'] as Map)['deviceId'] = 'd' * 129),
        'invalid_device_id',
      ),
      neg(
        'invalid_signing_key_33_bytes',
        e1Mut((m) => (m['signer'] as Map)['signingKey'] = _b64Of(3, 33)),
        'invalid_signing_key',
      ),
      neg(
        'invalid_members_empty',
        e1Mut((m) => m['members'] = <Object?>[]),
        'invalid_members',
      ),
      neg(
        'invalid_member_null',
        e1Mut((m) => (m['members'] as List)[0] = null),
        'invalid_member',
      ),
      neg(
        'invalid_role',
        e1Mut((m) => _memberAt(m, 1)['role'] = 'owner'),
        'invalid_role',
      ),
      neg(
        'invalid_identity_key_31_bytes',
        e1Mut((m) => _memberAt(m, 1)['identityKey'] = _b64Of(5, 31)),
        'invalid_identity_key',
      ),
      neg(
        'invalid_identity_key_33_bytes',
        e1Mut((m) => _memberAt(m, 1)['identityKey'] = _b64Of(5, 33)),
        'invalid_identity_key',
      ),
      neg(
        'invalid_identity_key_unpadded',
        e1Mut((m) => _memberAt(m, 1)['identityKey'] = k5.replaceAll('=', '')),
        'invalid_identity_key',
      ),
      neg(
        'invalid_identity_key_url_safe_alphabet',
        e1Mut((m) => _memberAt(m, 1)['identityKey'] = urlSafe),
        'invalid_identity_key',
      ),
      neg(
        'invalid_identity_key_whitespace',
        e1Mut((m) => _memberAt(m, 1)['identityKey'] = whitespace),
        'invalid_identity_key',
      ),
      neg(
        'invalid_identity_key_non_zero_padding_bits',
        e1Mut((m) => _memberAt(m, 1)['identityKey'] = nonCanonicalBits),
        'invalid_identity_key',
      ),
      neg(
        'member_error_before_unsorted',
        e1Mut((m) {
          final members = m['members'] as List;
          m['members'] = members.reversed.toList();
          _memberAt(m, 2)['role'] = 'owner';
        }),
        'invalid_role',
      ),
      neg(
        'members_unsorted',
        e1Mut((m) {
          final members = m['members'] as List;
          m['members'] = [members[1], members[0], members[2]];
        }),
        'members_unsorted',
      ),
      neg(
        'members_duplicate',
        e1Mut((m) {
          final members = m['members'] as List;
          m['members'] = [members[0], members[0], members[2]];
        }),
        'members_duplicate',
      ),
      neg(
        'invalid_prev_epoch1_not_null',
        e1Mut((m) => m['prev'] = h1),
        'invalid_prev',
      ),
      neg(
        'invalid_prev_epoch2_null',
        _mutate(r.e2, (m) => m['prev'] = null),
        'invalid_prev',
      ),
      neg(
        'invalid_prev_uppercase',
        _mutate(r.e2, (m) => m['prev'] = (m['prev'] as String).toUpperCase()),
        'invalid_prev',
      ),
    ],
    'signatureNegatives': [
      {
        'name': 'one_byte_flipped',
        'rosterJson': e1Rep('"issuedAt":$_t1', '"issuedAt":${_t1 + 1}'),
        'signature': sig1,
        'signingKey': s.a.signingKey,
        'code': 'bad_signature',
      },
      {
        'name': 'wrong_signing_key',
        'rosterJson': e1,
        'signature': sig1,
        'signingKey': s.b.signingKey,
        'code': 'bad_signature',
      },
      {
        'name': 'signed_by_other_key',
        'rosterJson': e1,
        'signature': await _sign(_seedB, e1),
        'signingKey': s.a.signingKey,
        'code': 'bad_signature',
      },
      {
        'name': 'signed_without_domain',
        'rosterJson': e1,
        'signature': await _sign(_seedA, e1, domain: false),
        'signingKey': s.a.signingKey,
        'code': 'bad_signature',
      },
      {
        'name': 'signature_unpadded',
        'rosterJson': e1,
        'signature': sig1.replaceAll('=', ''),
        'signingKey': s.a.signingKey,
        'code': 'bad_signature',
      },
    ],
  };
}

String _encodeFixture(Map<String, Object?> vectors) =>
    '${const JsonEncoder.withIndent('  ').convert(vectors)}\n';

String _codeOf(String json) {
  try {
    GroupRoster.parse(json);
  } on GroupRosterError catch (e) {
    return e.code;
  }
  return 'accepted';
}

Future<GroupRosterSignerTrust> _trusted(GroupRosterSigner _) async =>
    GroupRosterSignerTrust.trusted;

void main() {
  late Map<String, dynamic> fixture;
  late String fixtureText;
  late _Signers s;
  late _Chain r;
  late GroupRoster g1;
  late GroupRoster g2;
  late GroupRoster g3;
  late String sig1;
  late String sig2;
  late String sig3;

  setUpAll(() async {
    if (Platform.environment['RISAAL_REGEN_FIXTURES'] == '1') {
      final file = File(_fixturePath);
      file.parent.createSync(recursive: true);
      file.writeAsStringSync(_encodeFixture(await _deriveVectors()));
    }
    fixtureText = File(_fixturePath).readAsStringSync();
    fixture = jsonDecode(fixtureText) as Map<String, dynamic>;
    s = await _signers();
    r = await _chain(s);
    g1 = GroupRoster.parse(r.e1);
    g2 = GroupRoster.parse(r.e2);
    g3 = GroupRoster.parse(r.e3);
    sig1 = await _sign(_seedA, r.e1);
    sig2 = await _sign(_seedA, r.e2);
    sig3 = await _sign(_seedB, r.e3);
  });

  List<Map<String, dynamic>> section(String name) =>
      (fixture[name] as List).cast<Map<String, dynamic>>();

  group('shared v1 vector', () {
    test('re-derived from the seeds byte-for-byte (whole file)', () async {
      expect(_encodeFixture(await _deriveVectors()), fixtureText);
    });

    test('constants match the contract and the fixture', () {
      expect(groupRosterVersion, 1);
      expect(groupRosterDomain, fixture['domain']);
      expect(groupRosterMaxBytes, 65536);
      expect(groupRosterMaxMembers, 256);
    });

    test('every valid roster parses, hashes and verifies', () async {
      for (final v in section('valid')) {
        final json = v['rosterJson'] as String;
        final roster = GroupRoster.parse(json);
        expect(roster.rosterJson, json);
        expect(roster.groupId, fixture['groupId']);
        expect(roster.rosterHash, v['rosterHash']);
        expect(GroupRoster.rosterHashOf(json), v['rosterHash']);
        expect(
          await GroupRoster.verifySignature(
            json,
            v['signature'] as String,
            v['signingKey'] as String,
          ),
          isTrue,
          reason: v['name'] as String,
        );
      }
    });

    test('valid rosters chain by prev hash', () {
      final valid = section('valid');
      for (var i = 1; i < valid.length; i++) {
        final roster = GroupRoster.parse(valid[i]['rosterJson'] as String);
        expect(roster.prev, valid[i - 1]['rosterHash']);
        expect(roster.epoch, i + 1);
      }
    });

    test('parseAccepted entries parse with JS number semantics', () {
      for (final v in section('parseAccepted')) {
        final roster = GroupRoster.parse(v['rosterJson'] as String);
        expect(roster.epoch, v['epoch'], reason: v['name'] as String);
        expect(roster.issuedAt, v['issuedAt'], reason: v['name'] as String);
        expect(roster.rosterHash, v['rosterHash']);
      }
    });

    test('every parse negative fails with its stated code', () {
      final negatives = section('parseNegatives');
      expect(negatives, isNotEmpty);
      for (final v in negatives) {
        expect(
          _codeOf(v['rosterJson'] as String),
          v['code'],
          reason: v['name'] as String,
        );
      }
    });

    test(
      'every signature negative verifies false and is bad_signature',
      () async {
        for (final v in section('signatureNegatives')) {
          final json = v['rosterJson'] as String;
          expect(_codeOf(json), 'accepted', reason: v['name'] as String);
          expect(
            await GroupRoster.verifySignature(
              json,
              v['signature'] as String,
              v['signingKey'] as String,
            ),
            isFalse,
            reason: v['name'] as String,
          );
          expect(v['code'], 'bad_signature');
        }
      },
    );

    test('canonical base64 rule matches the TS rule on the key negatives', () {
      // TS decodeCanonicalBase64(s, 32) rejects all of these (see the
      // parseNegatives above, asserted against Node by the server spec).
      final k5 = _key(5);
      for (final bad in [
        _b64Of(5, 31),
        _b64Of(5, 33),
        k5.replaceAll('=', ''),
        _b64Of(0xfb, 32).replaceAll('+', '-').replaceAll('/', '_'),
        '${k5.substring(0, 10)} ${k5.substring(11)}',
        '${k5.substring(0, 42)}V=',
        '',
      ]) {
        expect(SenderCertificate.isCanonicalBase64(bad, length: 32), isFalse);
      }
      expect(SenderCertificate.isCanonicalBase64(k5, length: 32), isTrue);
      expect(
        SenderCertificate.isCanonicalBase64(_b64Of(0xfb, 32), length: 32),
        isTrue,
      );
    });
  });

  group('parse', () {
    test('exposes the parsed fields and helpers', () {
      expect(g1.v, 1);
      expect(g1.epoch, 1);
      expect(g1.issuedAt, _t1);
      expect(g1.prev, isNull);
      expect(g1.signer, s.a);
      expect(g1.members.map((m) => m.userId), [_idA, _idB, _idC]);
      expect(g1.memberIds, {_idA, _idB, _idC});
      expect(g1.isAdmin(_idA), isTrue);
      expect(g1.isAdmin(_idB), isFalse);
      expect(g1.isAdmin(_idD), isFalse);
      expect(g1.identityKeyFor(_idB), _key(5));
      expect(g1.identityKeyFor(_idC), isNull);
      expect(g1.identityKeyFor(_idD), isNull);
      expect(g2.prev, g1.rosterHash);
      expect(
        () => (g1.members as List).add(g1.members.first),
        throwsA(anything),
      );
    });

    test('too_large counts UTF-8 bytes, not characters', () {
      final padded = r.e1 + ' ' * (groupRosterMaxBytes - r.e1.length);
      expect(utf8.encode(padded).length, groupRosterMaxBytes);
      expect(_codeOf(padded), 'accepted');
      expect(_codeOf('$padded '), 'too_large');
      final multiByte = '"${'é' * 32768}"';
      expect(multiByte.length, lessThan(groupRosterMaxBytes));
      expect(_codeOf(multiByte), 'too_large');
    });

    test('invalid_json and not_object', () {
      expect(_codeOf(''), 'invalid_json');
      expect(_codeOf('{'), 'invalid_json');
      expect(_codeOf('"x"'), 'not_object');
      expect(_codeOf('null'), 'not_object');
      expect(_codeOf('1'), 'not_object');
    });

    test('duplicate keys nested in arrays and members', () {
      expect(
        _codeOf(
          _replaceOnce(r.e1, '"role":"admin"', '"role":"admin","role":"admin"'),
        ),
        'duplicate_key',
      );
      // Same key in sibling objects is fine.
      expect(_codeOf('{"a":{"k":1},"b":{"k":1}}'), 'unknown_field');
      // Escaped quotes inside strings do not confuse the scanner.
      expect(
        _codeOf(
          _mutate(r.e1, (m) => (m['signer'] as Map)['deviceId'] = 'a"b\\'),
        ),
        'accepted',
      );
    });

    test('number parity with JS Number.isSafeInteger', () {
      String epoch(String text) =>
          _replaceOnce(r.e1, '"epoch":1,', '"epoch":$text,');
      expect(GroupRoster.parse(epoch('1.0')).epoch, 1);
      expect(GroupRoster.parse(epoch('1E0')).epoch, 1);
      expect(_codeOf(epoch('1.5')), 'invalid_epoch');
      expect(_codeOf(epoch('9007199254740992')), 'invalid_epoch');
      expect(_codeOf(epoch('1e400')), 'invalid_epoch');
      expect(_codeOf(epoch('-1')), 'invalid_epoch');
      expect(_codeOf(epoch('true')), 'invalid_epoch');
      String issued(String text) =>
          _replaceOnce(r.e1, '"issuedAt":$_t1', '"issuedAt":$text');
      expect(GroupRoster.parse(issued('0')).issuedAt, 0);
      expect(
        GroupRoster.parse(issued('9007199254740991')).issuedAt,
        9007199254740991,
      );
      expect(_codeOf(issued('9007199254740992')), 'invalid_issued_at');
      expect(_codeOf(issued('99999999999999999999')), 'invalid_issued_at');
      expect(_codeOf(issued('"1"')), 'invalid_issued_at');
      expect(_codeOf(issued('null')), 'invalid_issued_at');
    });

    test('signer, member and members shape codes', () {
      expect(_codeOf(_mutate(r.e1, (m) => m['signer'] = [])), 'invalid_signer');
      expect(
        _codeOf(_mutate(r.e1, (m) => (m['signer'] as Map)['deviceId'] = 7)),
        'invalid_device_id',
      );
      expect(
        _codeOf(
          _mutate(r.e1, (m) => (m['signer'] as Map)['deviceId'] = 'd' * 128),
        ),
        'accepted',
      );
      expect(
        _codeOf(
          _mutate(r.e1, (m) => (m['signer'] as Map)['signingKey'] = null),
        ),
        'invalid_signing_key',
      );
      expect(
        _codeOf(_mutate(r.e1, (m) => _memberAt(m, 0)['userId'] = 'abc')),
        'invalid_user_id',
      );
      expect(
        _codeOf(_mutate(r.e1, (m) => _memberAt(m, 0)['identityKey'] = 5)),
        'invalid_identity_key',
      );
      expect(
        _codeOf(_mutate(r.e1, (m) => m['members'] = {})),
        'invalid_members',
      );
      expect(
        _codeOf(_mutate(r.e1, (m) => (m['members'] as List)[0] = [])),
        'invalid_member',
      );
      expect(
        _codeOf(_mutate(r.e1, (m) => _memberAt(m, 0).remove('identityKey'))),
        'missing_field',
      );
      expect(_codeOf(_mutate(r.e1, (m) => m['prev'] = 'ab')), 'invalid_prev');
    });

    test('too_many_members: 256 accepted, 257 rejected', () {
      String id(int i) =>
          '507f1f77bcf86cd7994${i.toRadixString(16).padLeft(5, '0')}';
      final members = [
        for (var i = 0; i < 257; i++) _m(id(i), i == 0 ? _admin : _member),
      ];
      final ok = GroupRoster.encode(
        groupId: _groupId,
        epoch: 1,
        issuedAt: _t1,
        signer: GroupRosterSigner(
          userId: id(0),
          deviceId: 'd',
          signingKey: s.a.signingKey,
        ),
        members: members.sublist(0, 256),
        prev: null,
      );
      expect(GroupRoster.parse(ok).members, hasLength(256));
      final tooMany = _mutate(ok, (m) {
        (m['members'] as List).add({
          'userId': id(256),
          'role': 'member',
          'identityKey': null,
        });
      });
      expect(_codeOf(tooMany), 'too_many_members');
    });

    test('error carries only the code', () {
      try {
        GroupRoster.parse(_mutate(r.e1, (m) => m['groupId'] = 'SECRET'));
        fail('expected GroupRosterError');
      } on GroupRosterError catch (e) {
        expect(e.code, 'invalid_group_id');
        expect(e.toString(), isNot(contains('SECRET')));
        expect(e.toString(), contains('invalid_group_id'));
      }
    });
  });

  group('encode', () {
    test('round-trips, sorts members and uses the fixed key order', () {
      expect(
        r.e1,
        startsWith(
          '{"v":1,"groupId":"$_groupId","epoch":1,"issuedAt":$_t1,'
          '"signer":{"userId":"$_idA","deviceId":"device-1","signingKey":',
        ),
      );
      expect(r.e1, endsWith('"prev":null}'));
      expect(
        r.e1,
        contains(
          '"members":[{"userId":"$_idA","role":"admin","identityKey":null},'
          '{"userId":"$_idB","role":"member","identityKey":"${_key(5)}"},'
          '{"userId":"$_idC","role":"member","identityKey":null}]',
        ),
      );
      final again = GroupRoster.encode(
        groupId: g3.groupId,
        epoch: g3.epoch,
        issuedAt: g3.issuedAt,
        signer: g3.signer,
        members: g3.members.reversed.toList(),
        prev: g3.prev,
      );
      expect(again, r.e3);
    });

    test('validates its own output', () {
      expect(
        () => GroupRoster.encode(
          groupId: _groupId,
          epoch: 1,
          issuedAt: _t1,
          signer: s.a,
          members: [_m(_idA, _admin), _m(_idA, _member)],
          prev: null,
        ),
        throwsA(
          isA<GroupRosterError>().having(
            (e) => e.code,
            'code',
            'members_duplicate',
          ),
        ),
      );
      expect(
        () => GroupRoster.encode(
          groupId: _groupId.toUpperCase(),
          epoch: 1,
          issuedAt: _t1,
          signer: s.a,
          members: [_m(_idA, _admin)],
          prev: null,
        ),
        throwsA(isA<GroupRosterError>()),
      );
      expect(
        () => GroupRoster.encode(
          groupId: _groupId,
          epoch: 2,
          issuedAt: _t1,
          signer: s.a,
          members: [_m(_idA, _admin)],
          prev: null,
        ),
        throwsA(
          isA<GroupRosterError>().having((e) => e.code, 'code', 'invalid_prev'),
        ),
      );
    });
  });

  group('hash and signature', () {
    test('rosterHashOf is lowercase sha256 hex of the exact bytes', () {
      expect(GroupRoster.rosterHashOf(r.e1), _sha256Hex(r.e1));
      expect(
        GroupRoster.rosterHashOf(r.e1),
        matches(RegExp(r'^[0-9a-f]{64}$')),
      );
      expect(GroupRoster.rosterHashOf('${r.e1} '), isNot(g1.rosterHash));
    });

    test('signingInput is domain || utf8(rosterJson)', () {
      expect(GroupRoster.signingInput(r.e1), [
        ...utf8.encode('risaal-group-roster-v1'),
        0,
        ...utf8.encode(r.e1),
      ]);
    });

    test('verifySignature never throws and fails closed', () async {
      expect(
        await GroupRoster.verifySignature(r.e1, sig1, s.a.signingKey),
        isTrue,
      );
      for (final (json, sig, key) in [
        (r.e1, '', s.a.signingKey),
        (r.e1, 'not base64!', s.a.signingKey),
        (r.e1, sig1, ''),
        (r.e1, sig1, 'AAAA'),
        (r.e1, base64Encode(List<int>.filled(64, 0)), s.a.signingKey),
        (r.e1, sig1, _key(0)),
        ('${r.e1}${' ' * groupRosterMaxBytes}', sig1, s.a.signingKey),
        ('', sig1, s.a.signingKey),
      ]) {
        expect(await GroupRoster.verifySignature(json, sig, key), isFalse);
      }
    });
  });

  group('chain', () {
    Future<GroupRosterVerdict> next(
      GroupRoster? previous,
      String json,
      String signature, {
      String? creator = _idA,
      String expectedGroupId = _groupId,
      Future<GroupRosterSignerTrust> Function(GroupRosterSigner)? trust,
    }) => GroupRosterChain.verifyNext(
      previous: previous,
      rosterJson: json,
      signature: signature,
      expectedGroupId: expectedGroupId,
      creatorUserId: creator,
      signerTrust: trust ?? _trusted,
    );

    void expectRejected(GroupRosterVerdict v, String code) {
      expect(v, isA<GroupRosterRejected>());
      expect((v as GroupRosterRejected).code, code);
    }

    Future<(String, String)> signed(
      int seed,
      GroupRosterSigner signer, {
      required int epoch,
      required List<GroupRosterMember> members,
      String? prev,
      int issuedAt = _t2,
      String groupId = _groupId,
    }) async {
      final json = GroupRoster.encode(
        groupId: groupId,
        epoch: epoch,
        issuedAt: issuedAt,
        signer: signer,
        members: members,
        prev: prev,
      );
      return (json, await _sign(seed, json));
    }

    test('genesis signed by the creator admin is accepted', () async {
      final v = await next(null, r.e1, sig1);
      expect(v, isA<GroupRosterAccepted>());
      final a = v as GroupRosterAccepted;
      expect(a.roster.rosterHash, g1.rosterHash);
      expect(a.bootstrap, isFalse);
      expect(a.gap, isFalse);
    });

    test('genesis: signer_not_creator and signer_not_admin', () async {
      expectRejected(
        await next(null, r.e1, sig1, creator: _idB),
        'signer_not_creator',
      );
      expectRejected(
        await next(null, r.e1, sig1, creator: null),
        'signer_not_creator',
      );
      final (json, sig) = await signed(
        _seedA,
        s.a,
        epoch: 1,
        members: [_m(_idA, _member), _m(_idB, _admin)],
      );
      expectRejected(await next(null, json, sig), 'signer_not_admin');
    });

    test('epoch+1 signed by a previous admin is accepted', () async {
      final v2 = await next(g1, r.e2, sig2);
      expect(v2, isA<GroupRosterAccepted>());
      expect((v2 as GroupRosterAccepted).gap, isFalse);
      // B was promoted in epoch 2, so B may sign epoch 3.
      expect(await next(g2, r.e3, sig3), isA<GroupRosterAccepted>());
    });

    test(
      'signer_not_admin: epoch 2 signed by a plain member of epoch 1',
      () async {
        final (json, sig) = await signed(
          _seedC,
          s.c,
          epoch: 2,
          members: [_m(_idA, _admin), _m(_idC, _admin)],
          prev: g1.rosterHash,
        );
        expectRejected(await next(g1, json, sig), 'signer_not_admin');
      },
    );

    test('prev_mismatch', () async {
      final (json, sig) = await signed(
        _seedA,
        s.a,
        epoch: 2,
        members: [_m(_idA, _admin)],
        prev: g3.rosterHash,
      );
      expectRejected(await next(g1, json, sig), 'prev_mismatch');
    });

    test(
      'same epoch: identical is unchanged, different is epoch_fork',
      () async {
        var trustCalls = 0;
        final same = await next(
          g2,
          r.e2,
          sig2,
          trust: (_) async {
            trustCalls++;
            return GroupRosterSignerTrust.trusted;
          },
        );
        expect(same, isA<GroupRosterUnchanged>());
        expect(trustCalls, 0);
        final (json, sig) = await signed(
          _seedA,
          s.a,
          epoch: 2,
          issuedAt: _t2 + 1,
          members: [_m(_idA, _admin), _m(_idB, _admin, _key(5))],
          prev: g1.rosterHash,
        );
        expectRejected(await next(g2, json, sig), 'epoch_fork');
      },
    );

    test('rollback', () async {
      expectRejected(await next(g2, r.e1, sig1), 'rollback');
      expectRejected(await next(g3, r.e2, sig2), 'rollback');
    });

    test(
      'epoch gap is accepted only when the signer was admin in previous',
      () async {
        // B was a plain member at epoch 1.
        expectRejected(await next(g1, r.e3, sig3), 'signer_not_admin');
        final (json, sig) = await signed(
          _seedA,
          s.a,
          epoch: 3,
          members: [_m(_idA, _admin)],
          prev: _sha256Hex('unseen epoch 2'),
        );
        final v = await next(g1, json, sig);
        expect(v, isA<GroupRosterAccepted>());
        expect((v as GroupRosterAccepted).gap, isTrue);
        expect(v.bootstrap, isFalse);
      },
    );

    test(
      'bootstrap: first roster seen at epoch > 1 needs an admin signer',
      () async {
        final v = await next(null, r.e3, sig3, creator: null);
        expect(v, isA<GroupRosterAccepted>());
        expect((v as GroupRosterAccepted).bootstrap, isTrue);
        expect(v.gap, isFalse);
        final (json, sig) = await signed(
          _seedC,
          s.c,
          epoch: 4,
          members: [_m(_idA, _admin), _m(_idC, _member)],
          prev: g3.rosterHash,
        );
        expectRejected(await next(null, json, sig), 'signer_not_admin');
      },
    );

    test('group_mismatch, checked before the signature', () async {
      expectRejected(
        await next(null, r.e1, sig1, expectedGroupId: _otherGroupId),
        'group_mismatch',
      );
      expectRejected(
        await next(g1, r.e2, 'bad', expectedGroupId: _otherGroupId),
        'group_mismatch',
      );
      final other = GroupRoster.parse(
        GroupRoster.encode(
          groupId: _otherGroupId,
          epoch: 1,
          issuedAt: _t1,
          signer: s.a,
          members: [_m(_idA, _admin)],
          prev: null,
        ),
      );
      expectRejected(await next(other, r.e2, sig2), 'group_mismatch');
    });

    test('bad_signature, checked before epoch rules', () async {
      for (final v in section('signatureNegatives')) {
        // The chain verifies under the roster's own signer key, so the
        // `wrong_signing_key` vector (valid sig, other key) is n/a here.
        if (v['signingKey'] != s.a.signingKey) continue;
        expectRejected(
          await next(null, v['rosterJson'] as String, v['signature'] as String),
          'bad_signature',
        );
      }
      // A rollback with a bad signature reports bad_signature.
      expectRejected(await next(g2, r.e1, sig2), 'bad_signature');
    });

    test('parse codes propagate', () async {
      expectRejected(await next(null, '[]', sig1), 'not_object');
      expectRejected(
        await next(null, _replaceOnce(r.e1, '{"v":1,', '{"v":1,"v":1,'), sig1),
        'duplicate_key',
      );
    });

    test('signer trust: untrusted, unavailable, throwing', () async {
      GroupRosterSigner? seen;
      final ok = await next(
        g1,
        r.e2,
        sig2,
        trust: (signer) async {
          seen = signer;
          return GroupRosterSignerTrust.trusted;
        },
      );
      expect(ok, isA<GroupRosterAccepted>());
      expect(seen, s.a);
      expectRejected(
        await next(
          g1,
          r.e2,
          sig2,
          trust: (_) async => GroupRosterSignerTrust.untrusted,
        ),
        'signer_untrusted',
      );
      expect(
        await next(
          g1,
          r.e2,
          sig2,
          trust: (_) async => GroupRosterSignerTrust.unavailable,
        ),
        isA<GroupRosterDeferred>(),
      );
      expect(
        await next(
          g1,
          r.e2,
          sig2,
          trust: (_) async => throw StateError('offline'),
        ),
        isA<GroupRosterDeferred>(),
      );
    });
  });

  group('policy', () {
    test('allowedRecipients: the relay can only shrink the verified set', () {
      expect(
        GroupRosterPolicy.allowedRecipients(
          verified: g2,
          relayParticipants: {_idA, _idB, _idC, _idD},
          requireVerifiedRoster: false,
        ),
        {_idA, _idB},
      );
      expect(
        GroupRosterPolicy.allowedRecipients(
          verified: g2,
          relayParticipants: {_idA},
          requireVerifiedRoster: true,
        ),
        {_idA},
      );
      expect(
        GroupRosterPolicy.allowedRecipients(
          verified: null,
          relayParticipants: {_idA, _idC},
          requireVerifiedRoster: true,
        ),
        isEmpty,
      );
      expect(
        GroupRosterPolicy.allowedRecipients(
          verified: null,
          relayParticipants: {_idA, _idC},
          requireVerifiedRoster: false,
        ),
        {_idA, _idC},
      );
    });

    test('removedMembers', () {
      expect(GroupRosterPolicy.removedMembers(g1, g2), {_idC});
      expect(GroupRosterPolicy.removedMembers(g2, g3), isEmpty);
      expect(GroupRosterPolicy.removedMembers(g3, g1), {_idD});
    });
  });

  group('manager', () {
    test(
      'signs a roster naming this device; refuses any other signer',
      () async {
        final (manager, storage) =
            await CryptoTestFixtures.createInitializedManager();
        await expectLater(manager.localGroupRosterSigner(), throwsStateError);
        await storage.write(key: 'user_id', value: _idA);
        await storage.write(key: 'device_id', value: 'device-9');
        final local = await manager.localGroupRosterSigner();
        expect(local.userId, _idA);
        expect(local.deviceId, 'device-9');
        expect(
          SenderCertificate.isCanonicalBase64(local.signingKey, length: 32),
          isTrue,
        );

        final roster = GroupRoster.encode(
          groupId: _groupId,
          epoch: 1,
          issuedAt: _t1,
          signer: local,
          members: [_m(_idA, _admin), _m(_idB, _member, _key(5))],
          prev: null,
        );
        final signature = await manager.signGroupRoster(roster);
        expect(
          await GroupRoster.verifySignature(
            roster,
            signature,
            local.signingKey,
          ),
          isTrue,
        );
        final verdict = await GroupRosterChain.verifyNext(
          rosterJson: roster,
          signature: signature,
          expectedGroupId: _groupId,
          creatorUserId: _idA,
          signerTrust: _trusted,
        );
        expect(verdict, isA<GroupRosterAccepted>());

        for (final other in [
          s.a,
          GroupRosterSigner(
            userId: _idA,
            deviceId: 'device-1',
            signingKey: local.signingKey,
          ),
          GroupRosterSigner(
            userId: _idB,
            deviceId: 'device-9',
            signingKey: local.signingKey,
          ),
        ]) {
          final foreign = GroupRoster.encode(
            groupId: _groupId,
            epoch: 1,
            issuedAt: _t1,
            signer: other,
            members: [_m(_idA, _admin), _m(_idB, _admin)],
            prev: null,
          );
          await expectLater(
            manager.signGroupRoster(foreign),
            throwsA(
              isA<StateError>().having(
                (e) => e.message,
                'message',
                'Roster signer is not this device',
              ),
            ),
          );
        }
        await expectLater(
          manager.signGroupRoster('[]'),
          throwsA(isA<GroupRosterError>()),
        );
      },
    );
  });
}
