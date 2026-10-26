@TestOn('vm')
@Retry(0)
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashes;
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

typedef _Json = Map<String, dynamic>;

const _keyGenRelativePath = 'ML-KEM-keyGen-FIPS203/internalProjection.json';
const _encapDecapRelativePath =
    'ML-KEM-encapDecap-FIPS203/internalProjection.json';
const _keyGenSha256 =
    'd7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b';
const _encapDecapSha256 =
    'a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f';

File _fixture(String relativePath) {
  final candidates = <File>[
    File('test/fixtures/mlkem_acvp/$relativePath'),
    File('packages/risaal_crypto/test/fixtures/mlkem_acvp/$relativePath'),
  ];

  for (final candidate in candidates) {
    if (candidate.existsSync()) return candidate;
  }

  throw StateError('Required NIST ACVP fixture is missing: $relativePath');
}

_Json _loadVerifiedCorpus(String relativePath, String expectedSha256) {
  final bytes = _fixture(relativePath).readAsBytesSync();
  expect(bytes, isNotEmpty, reason: '$relativePath must not be empty');
  expect(
    hashes.sha256.convert(bytes).toString(),
    expectedSha256,
    reason: '$relativePath must match the pinned NIST ACVP source bytes',
  );

  final decoded = jsonDecode(utf8.decode(bytes));
  if (decoded is! _Json) {
    throw StateError('$relativePath must contain one JSON object');
  }
  return decoded;
}

List<_Json> _objectList(Object? value, String label) {
  if (value is! List<dynamic> || value.any((item) => item is! _Json)) {
    throw StateError('$label must be a JSON object list');
  }
  return value.cast<_Json>();
}

List<_Json> _groups(_Json corpus) =>
    _objectList(corpus['testGroups'], 'testGroups');

List<_Json> _vectors(_Json group) => _objectList(group['tests'], 'tests');

_Json _singleMlKem768Group(
  _Json corpus, {
  required int tgId,
  required String testType,
  String? function,
}) {
  final matches = _groups(corpus)
      .where(
        (group) =>
            group['parameterSet'] == 'ML-KEM-768' &&
            group['function'] == function,
      )
      .toList(growable: false);

  expect(
    matches.length,
    1,
    reason:
        'The pinned corpus must contain exactly one requested '
        'ML-KEM-768 group',
  );
  final group = matches.single;
  expect(group['tgId'], tgId);
  expect(group['testType'], testType);
  return group;
}

void _expectCorpusHeader(
  _Json corpus, {
  required String mode,
  required bool expectedIsSample,
  required int expectedGroupCount,
  required int expectedVectorCount,
}) {
  expect(corpus['vsId'], 42);
  expect(corpus['algorithm'], 'ML-KEM');
  expect(corpus['mode'], mode);
  expect(corpus['revision'], 'FIPS203');
  expect(corpus['isSample'], expectedIsSample);

  final groups = _groups(corpus);
  expect(groups.length, expectedGroupCount);
  final vectorCount = groups.fold<int>(
    0,
    (count, group) => count + _vectors(group).length,
  );
  expect(vectorCount, expectedVectorCount);
}

int _requiredInt(_Json vector, String field, String label) {
  final value = vector[field];
  if (value is! int) throw StateError('$label has an invalid $field');
  return value;
}

bool _requiredBool(_Json vector, String field, String label) {
  final value = vector[field];
  if (value is! bool) throw StateError('$label has an invalid $field');
  return value;
}

Uint8List _requiredHex(
  _Json vector,
  String field,
  int expectedBytes,
  String label,
) {
  final value = vector[field];
  if (value is! String ||
      value.length != expectedBytes * 2 ||
      !RegExp(r'^[0-9A-F]+$').hasMatch(value)) {
    throw StateError('$label has malformed $field');
  }

  final result = Uint8List(expectedBytes);
  for (var offset = 0; offset < value.length; offset += 2) {
    final byte = int.tryParse(value.substring(offset, offset + 2), radix: 16);
    if (byte == null) throw StateError('$label has malformed $field');
    result[offset ~/ 2] = byte;
  }
  return result;
}

Uint8List _concat(Uint8List first, Uint8List second) {
  final result = Uint8List(first.length + second.length);
  result.setAll(0, first);
  result.setAll(first.length, second);
  return result;
}

T _runWithoutSensitiveDiagnostics<T>(String label, T Function() operation) {
  try {
    return operation();
  } catch (_) {
    throw StateError('$label failed without exposing vector material');
  }
}

void _expectByteExact(Uint8List actual, Uint8List expected, String label) {
  var difference = actual.length ^ expected.length;
  final sharedLength = actual.length < expected.length
      ? actual.length
      : expected.length;
  for (var index = 0; index < sharedLength; index++) {
    difference |= actual[index] ^ expected[index];
  }
  expect(difference, 0, reason: '$label is not byte-exact');
}

int _keyCheckDisposition(void Function() operation) {
  try {
    operation();
    return 0;
  } on ArgumentError {
    return 1;
  } catch (_) {
    return 2;
  }
}

void _expectConcreteVector(_Json vector, String label) {
  final tcId = _requiredInt(vector, 'tcId', label);
  expect(tcId, greaterThan(0), reason: '$label must have a positive tcId');
  expect(
    _requiredBool(vector, 'deferred', label),
    isFalse,
    reason: '$label must be a concrete, non-deferred case',
  );
}

void main() {
  test('official NIST ACVP ML-KEM-768 gate passes exactly 80 cases', () {
    final keyGen = _loadVerifiedCorpus(_keyGenRelativePath, _keyGenSha256);
    final encapDecap = _loadVerifiedCorpus(
      _encapDecapRelativePath,
      _encapDecapSha256,
    );

    _expectCorpusHeader(
      keyGen,
      mode: 'keyGen',
      expectedIsSample: false,
      expectedGroupCount: 3,
      expectedVectorCount: 75,
    );
    _expectCorpusHeader(
      encapDecap,
      mode: 'encapDecap',
      expectedIsSample: true,
      expectedGroupCount: 12,
      expectedVectorCount: 165,
    );

    final keyGenVectors = _vectors(
      _singleMlKem768Group(keyGen, tgId: 2, testType: 'AFT'),
    );
    final encapsulationVectors = _vectors(
      _singleMlKem768Group(
        encapDecap,
        tgId: 2,
        testType: 'AFT',
        function: 'encapsulation',
      ),
    );
    final decapsulationVectors = _vectors(
      _singleMlKem768Group(
        encapDecap,
        tgId: 5,
        testType: 'VAL',
        function: 'decapsulation',
      ),
    );
    final decapsulationKeyChecks = _vectors(
      _singleMlKem768Group(
        encapDecap,
        tgId: 9,
        testType: 'VAL',
        function: 'decapsulationKeyCheck',
      ),
    );
    final encapsulationKeyChecks = _vectors(
      _singleMlKem768Group(
        encapDecap,
        tgId: 10,
        testType: 'VAL',
        function: 'encapsulationKeyCheck',
      ),
    );

    expect(keyGenVectors.length, 25);
    expect(encapsulationVectors.length, 25);
    expect(decapsulationVectors.length, 10);
    expect(decapsulationKeyChecks.length, 10);
    expect(encapsulationKeyChecks.length, 10);

    final kem = PqcKem.kyber768;
    var exercisedCases = 0;

    for (final vector in keyGenVectors) {
      const label = 'ML-KEM-768 key generation vector';
      _expectConcreteVector(vector, label);
      final seed = _concat(
        _requiredHex(vector, 'd', 32, label),
        _requiredHex(vector, 'z', 32, label),
      );
      final expectedPublicKey = _requiredHex(
        vector,
        'ek',
        kem.params.publicKeyBytes,
        label,
      );
      final expectedSecretKey = _requiredHex(
        vector,
        'dk',
        kem.params.secretKeyBytes,
        label,
      );
      final generated = _runWithoutSensitiveDiagnostics(
        label,
        () => kem.generateKeyPair(seed),
      );
      _expectByteExact(generated.$1, expectedPublicKey, '$label public key');
      _expectByteExact(generated.$2, expectedSecretKey, '$label secret key');
      exercisedCases++;
    }

    for (final vector in encapsulationVectors) {
      const label = 'ML-KEM-768 encapsulation vector';
      _expectConcreteVector(vector, label);
      final publicKey = _requiredHex(
        vector,
        'ek',
        kem.params.publicKeyBytes,
        label,
      );
      final secretKey = _requiredHex(
        vector,
        'dk',
        kem.params.secretKeyBytes,
        label,
      );
      final nonce = _requiredHex(vector, 'm', 32, label);
      final expectedCiphertext = _requiredHex(
        vector,
        'c',
        kem.params.ciphertextBytes,
        label,
      );
      final expectedSharedSecret = _requiredHex(vector, 'k', 32, label);
      final encapsulated = _runWithoutSensitiveDiagnostics(
        label,
        () => kem.encapsulate(publicKey, nonce),
      );
      _expectByteExact(
        encapsulated.$1,
        expectedCiphertext,
        '$label ciphertext',
      );
      _expectByteExact(
        encapsulated.$2,
        expectedSharedSecret,
        '$label shared secret',
      );
      final roundTripSecret = _runWithoutSensitiveDiagnostics(
        '$label round trip',
        () => kem.decapsulate(secretKey, encapsulated.$1),
      );
      _expectByteExact(
        roundTripSecret,
        expectedSharedSecret,
        '$label round-trip secret',
      );
      exercisedCases++;
    }

    for (final vector in decapsulationVectors) {
      const label = 'ML-KEM-768 decapsulation vector';
      _expectConcreteVector(vector, label);
      final secretKey = _requiredHex(
        vector,
        'dk',
        kem.params.secretKeyBytes,
        label,
      );
      final ciphertext = _requiredHex(
        vector,
        'c',
        kem.params.ciphertextBytes,
        label,
      );
      final expectedSharedSecret = _requiredHex(vector, 'k', 32, label);
      final sharedSecret = _runWithoutSensitiveDiagnostics(
        label,
        () => kem.decapsulate(secretKey, ciphertext),
      );
      _expectByteExact(sharedSecret, expectedSharedSecret, label);
      exercisedCases++;
    }

    for (final vector in encapsulationKeyChecks) {
      const label = 'ML-KEM-768 encapsulation key-check vector';
      _expectConcreteVector(vector, label);
      final expectedPass = _requiredBool(vector, 'testPassed', label);
      final publicKey = _requiredHex(
        vector,
        'ek',
        kem.params.publicKeyBytes,
        label,
      );
      final disposition = _keyCheckDisposition(
        () => kem.encapsulate(publicKey, Uint8List(32)),
      );
      expect(
        disposition,
        expectedPass ? 0 : 1,
        reason: '$label disposition must match NIST',
      );
      exercisedCases++;
    }

    for (final vector in decapsulationKeyChecks) {
      const label = 'ML-KEM-768 decapsulation key-check vector';
      _expectConcreteVector(vector, label);
      final expectedPass = _requiredBool(vector, 'testPassed', label);
      final secretKey = _requiredHex(
        vector,
        'dk',
        kem.params.secretKeyBytes,
        label,
      );
      final disposition = _keyCheckDisposition(
        () => kem.decapsulate(secretKey, Uint8List(kem.params.ciphertextBytes)),
      );
      expect(
        disposition,
        expectedPass ? 0 : 1,
        reason: '$label disposition must match NIST',
      );
      exercisedCases++;
    }

    expect(
      exercisedCases,
      80,
      reason: 'The blocking ML-KEM-768 ACVP gate must execute exactly 80 cases',
    );
  });
}
