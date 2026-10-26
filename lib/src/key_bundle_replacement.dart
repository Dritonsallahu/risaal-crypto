import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'crypto_protocol.dart';
import 'models/signal_keys.dart';

/// An authenticated existing account was opened while this installation still
/// holds an unaccepted generation-1 registration proposal for a different or
/// abandoned signup attempt. The proposal must never be uploaded to the
/// authenticated account; the host must explicitly replace it with recovery
/// rooted in the authenticated owner receipt.
class UnacceptedFreshRegistrationRecoveryRequired implements Exception {
  const UnacceptedFreshRegistrationRecoveryRequired();

  @override
  String toString() =>
      'Unaccepted fresh registration must be replaced by authenticated recovery';
}

/// Canonical commitments shared with the immutable server OPK contract.
abstract final class KeyBundleReplacementCommitment {
  static final RegExp _sha256 = RegExp(r'^[0-9a-f]{64}$');

  static List<OneTimePreKeyPublic> canonicalOneTimePreKeys(
    Iterable<OneTimePreKeyPublic> values,
  ) {
    final result = values.toList()
      ..sort((left, right) => left.keyId.compareTo(right.keyId));
    if (result.isEmpty || result.length > 100) {
      throw const FormatException('Invalid one-time pre-key set size');
    }
    final ids = <int>{};
    final publicKeys = <String>{};
    for (final value in result) {
      if (value.keyId <= 0 ||
          value.keyId > RisaalCryptoProtocol.maxKeyId ||
          !_isCanonicalX25519PublicKey(value.publicKey) ||
          !ids.add(value.keyId) ||
          !publicKeys.add(value.publicKey)) {
        throw const FormatException('Invalid one-time pre-key set');
      }
    }
    return List<OneTimePreKeyPublic>.unmodifiable(result);
  }

  static String opkSetDigest({
    required int opkGeneration,
    required Iterable<OneTimePreKeyPublic> oneTimePreKeys,
  }) {
    _requireServerSafePositive(opkGeneration, 'OPK generation');
    final canonical = canonicalOneTimePreKeys(oneTimePreKeys);
    return _sha256OfJson(<Object>[
      'Risaal-OPK-Set-v1',
      opkGeneration,
      canonical
          .map<Object>((key) => <Object>[key.keyId, key.publicKey])
          .toList(growable: false),
    ]);
  }

  static String bundlePublicMaterialDigest({
    required String identityKey,
    required String identitySigningKey,
    required int signedPreKeyId,
    required String signedPreKeyPublicKey,
    required String signedPreKeySignature,
    required int kemKeyId,
    required String kemPublicKey,
    required String kemSignature,
    required int cryptoProtocolEpoch,
    required String kemSuite,
    required String kemStandard,
    required int kemWireVersion,
    required int opkGeneration,
    required String opkSetDigest,
    required int opkSetCount,
    required int opkHighWaterKeyId,
  }) {
    if (identityKey.isEmpty ||
        identitySigningKey.isEmpty ||
        signedPreKeyPublicKey.isEmpty ||
        signedPreKeySignature.isEmpty ||
        kemPublicKey.isEmpty ||
        kemSignature.isEmpty ||
        !_sha256.hasMatch(opkSetDigest)) {
      throw const FormatException('Invalid bundle public material');
    }
    _requireKeyId(signedPreKeyId, 'signed pre-key ID');
    _requireKeyId(kemKeyId, 'KEM key ID');
    _requireServerSafePositive(opkGeneration, 'OPK generation');
    if (opkSetCount <= 0 || opkSetCount > 100) {
      throw const FormatException('Invalid OPK set count');
    }
    _requireKeyId(opkHighWaterKeyId, 'OPK high-water key ID');
    return _sha256OfJson(<Object>[
      RisaalCryptoProtocol.clientProtocol,
      identityKey,
      identitySigningKey,
      signedPreKeyId,
      signedPreKeyPublicKey,
      signedPreKeySignature,
      kemKeyId,
      kemPublicKey,
      kemSignature,
      cryptoProtocolEpoch,
      kemSuite,
      kemStandard,
      kemWireVersion,
      opkGeneration,
      opkSetDigest,
      opkSetCount,
      opkHighWaterKeyId,
    ]);
  }

  static bool isCanonicalSha256(String value) => _sha256.hasMatch(value);

  static bool _isCanonicalX25519PublicKey(String value) {
    try {
      final decoded = base64Decode(value);
      return decoded.length == 32 && base64Encode(decoded) == value;
    } on FormatException {
      return false;
    }
  }

  static String _sha256OfJson(Object value) =>
      crypto.sha256.convert(utf8.encode(jsonEncode(value))).toString();

  static void _requireKeyId(int value, String field) {
    if (value <= 0 || value > RisaalCryptoProtocol.maxKeyId) {
      throw FormatException('Invalid $field');
    }
  }

  static void _requireServerSafePositive(int value, String field) {
    if (value <= 0 || value > KeyBundleReplacementJournal.maxServerSafeInt) {
      throw FormatException('Invalid $field');
    }
  }
}

/// The complete immutable receipt returned by registration, replacement, or
/// an authenticated owner GET. No field is reconstructed from the mutable pool.
class KeyBundleAcceptedReceipt {
  final int bundleRevision;
  final int signedPreKeyId;
  final int kemKeyId;
  final int cryptoProtocolEpoch;
  final String replacementId;
  final int opkAcceptedBundleRevision;
  final int opkGeneration;
  final String opkSetDigest;
  final int opkSetCount;
  final int opkHighWaterKeyId;
  final String bundlePublicMaterialDigest;

  const KeyBundleAcceptedReceipt({
    required this.bundleRevision,
    required this.signedPreKeyId,
    required this.kemKeyId,
    required this.cryptoProtocolEpoch,
    required this.replacementId,
    required this.opkAcceptedBundleRevision,
    required this.opkGeneration,
    required this.opkSetDigest,
    required this.opkSetCount,
    required this.opkHighWaterKeyId,
    required this.bundlePublicMaterialDigest,
  });

  void requireValid() {
    if (bundleRevision <= 0 ||
        bundleRevision > KeyBundleReplacementJournal.maxServerSafeInt ||
        opkAcceptedBundleRevision != bundleRevision ||
        signedPreKeyId <= 0 ||
        signedPreKeyId > RisaalCryptoProtocol.maxKeyId ||
        kemKeyId <= 0 ||
        kemKeyId > RisaalCryptoProtocol.maxKeyId ||
        cryptoProtocolEpoch != RisaalCryptoProtocol.cryptoProtocolEpoch ||
        replacementId.isEmpty ||
        replacementId.length > 64 ||
        !RegExp(r'^[A-Za-z0-9._:-]+$').hasMatch(replacementId) ||
        opkGeneration <= 0 ||
        opkGeneration > KeyBundleReplacementJournal.maxServerSafeInt ||
        !KeyBundleReplacementCommitment.isCanonicalSha256(opkSetDigest) ||
        opkSetCount <= 0 ||
        opkSetCount > 100 ||
        opkHighWaterKeyId <= 0 ||
        opkHighWaterKeyId > RisaalCryptoProtocol.maxKeyId ||
        !KeyBundleReplacementCommitment.isCanonicalSha256(
          bundlePublicMaterialDigest,
        )) {
      throw const FormatException('Invalid accepted key-bundle receipt');
    }
  }

  bool matchesSnapshot(KeyBundleReplacementSnapshot snapshot) {
    requireValid();
    return bundleRevision == snapshot.expectedBundleRevision + 1 &&
        opkAcceptedBundleRevision == snapshot.expectedBundleRevision + 1 &&
        signedPreKeyId == snapshot.signedPreKeyId &&
        kemKeyId == snapshot.kemKeyId &&
        cryptoProtocolEpoch == RisaalCryptoProtocol.cryptoProtocolEpoch &&
        replacementId == snapshot.replacementId &&
        opkGeneration == snapshot.opkGeneration &&
        opkSetDigest == snapshot.opkSetDigest &&
        opkSetCount == snapshot.opkSetCount &&
        opkHighWaterKeyId == snapshot.opkHighWaterKeyId &&
        bundlePublicMaterialDigest == snapshot.bundlePublicMaterialDigest;
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'bundleRevision': bundleRevision,
    'signedPreKeyId': signedPreKeyId,
    'kemKeyId': kemKeyId,
    'cryptoProtocolEpoch': cryptoProtocolEpoch,
    'replacementId': replacementId,
    'opkAcceptedBundleRevision': opkAcceptedBundleRevision,
    'opkGeneration': opkGeneration,
    'opkSetDigest': opkSetDigest,
    'opkSetCount': opkSetCount,
    'opkHighWaterKeyId': opkHighWaterKeyId,
    'bundlePublicMaterialDigest': bundlePublicMaterialDigest,
  };

  factory KeyBundleAcceptedReceipt.fromJson(Map<String, dynamic> json) {
    try {
      final receipt = KeyBundleAcceptedReceipt(
        bundleRevision: json['bundleRevision'] as int? ?? -1,
        signedPreKeyId: json['signedPreKeyId'] as int? ?? -1,
        kemKeyId: json['kemKeyId'] as int? ?? -1,
        cryptoProtocolEpoch: json['cryptoProtocolEpoch'] as int? ?? -1,
        replacementId: json['replacementId'] as String? ?? '',
        opkAcceptedBundleRevision:
            json['opkAcceptedBundleRevision'] as int? ?? -1,
        opkGeneration: json['opkGeneration'] as int? ?? -1,
        opkSetDigest: json['opkSetDigest'] as String? ?? '',
        opkSetCount: json['opkSetCount'] as int? ?? -1,
        opkHighWaterKeyId: json['opkHighWaterKeyId'] as int? ?? -1,
        bundlePublicMaterialDigest:
            json['bundlePublicMaterialDigest'] as String? ?? '',
      );
      receipt.requireValid();
      return receipt;
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Invalid accepted key-bundle receipt');
    }
  }

  /// Parse a registration/replacement mutation response.
  ///
  /// The server may return the immutable tuple directly or under `accepted`.
  /// An owner-GET-shaped response is rejected so callers cannot accidentally
  /// skip [fromOwnerKeyBundleData]'s outer public-material cross-check.
  factory KeyBundleAcceptedReceipt.fromMutationResponseData(Object? data) {
    if (data is! Map) {
      throw const FormatException('Missing accepted key-bundle receipt');
    }
    final normalized = Map<String, dynamic>.from(data);
    final accepted = normalized['accepted'];
    if (accepted != null && accepted is! Map) {
      throw const FormatException('Invalid accepted key-bundle receipt');
    }
    if (accepted is Map &&
        const <String>{
          'identityKey',
          'identitySigningKey',
          'signedPreKey',
          'kyberPreKey',
          'bundleRevision',
          'opkGeneration',
          'opkSetDigest',
        }.any(normalized.containsKey)) {
      throw const FormatException(
        'Owner key bundle requires owner-bound receipt parsing',
      );
    }
    return KeyBundleAcceptedReceipt.fromJson(
      accepted is Map ? Map<String, dynamic>.from(accepted) : normalized,
    );
  }

  /// Parse an authenticated owner GET and bind its readable public material
  /// back to the immutable nested receipt. The mutable OPK suffix is neither
  /// required nor trusted for reconciliation.
  factory KeyBundleAcceptedReceipt.fromOwnerKeyBundleData(Object? data) {
    if (data is! Map) {
      throw const FormatException('Missing owner key bundle');
    }
    try {
      final outer = Map<String, dynamic>.from(data);
      final accepted = outer['accepted'];
      if (accepted is! Map) {
        throw const FormatException('Missing accepted owner receipt');
      }
      final receipt = KeyBundleAcceptedReceipt.fromJson(
        Map<String, dynamic>.from(accepted),
      );
      final signed = outer['signedPreKey'];
      final kyber = outer['kyberPreKey'];
      final identityKey = outer['identityKey'];
      final identitySigningKey = outer['identitySigningKey'];
      if (outer['bundleRevision'] != receipt.bundleRevision ||
          outer['opkGeneration'] != receipt.opkGeneration ||
          outer['opkSetDigest'] != receipt.opkSetDigest ||
          signed is! Map ||
          kyber is! Map ||
          identityKey is! String ||
          identitySigningKey is! String) {
        throw const FormatException('Owner key-bundle receipt drift');
      }
      final signedMap = Map<String, dynamic>.from(signed);
      final kyberMap = Map<String, dynamic>.from(kyber);
      final computed =
          KeyBundleReplacementCommitment.bundlePublicMaterialDigest(
            identityKey: identityKey,
            identitySigningKey: identitySigningKey,
            signedPreKeyId: signedMap['keyId'] as int? ?? -1,
            signedPreKeyPublicKey: signedMap['publicKey'] as String? ?? '',
            signedPreKeySignature: signedMap['signature'] as String? ?? '',
            kemKeyId: kyberMap['keyId'] as int? ?? -1,
            kemPublicKey: kyberMap['publicKey'] as String? ?? '',
            kemSignature: kyberMap['signature'] as String? ?? '',
            cryptoProtocolEpoch: kyberMap['cryptoProtocolEpoch'] as int? ?? -1,
            kemSuite: kyberMap['kemSuite'] as String? ?? '',
            kemStandard: kyberMap['kemStandard'] as String? ?? '',
            kemWireVersion: kyberMap['kemWireVersion'] as int? ?? -1,
            opkGeneration: receipt.opkGeneration,
            opkSetDigest: receipt.opkSetDigest,
            opkSetCount: receipt.opkSetCount,
            opkHighWaterKeyId: receipt.opkHighWaterKeyId,
          );
      if (signedMap['keyId'] != receipt.signedPreKeyId ||
          kyberMap['keyId'] != receipt.kemKeyId ||
          kyberMap['cryptoProtocolEpoch'] != receipt.cryptoProtocolEpoch ||
          computed != receipt.bundlePublicMaterialDigest) {
        throw const FormatException('Owner key-bundle receipt drift');
      }
      return receipt;
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Owner key-bundle receipt drift');
    }
  }

  KeyBundleAcceptedReceipt copyWith({
    int? bundleRevision,
    int? signedPreKeyId,
    int? kemKeyId,
    int? cryptoProtocolEpoch,
    String? replacementId,
    int? opkAcceptedBundleRevision,
    int? opkGeneration,
    String? opkSetDigest,
    int? opkSetCount,
    int? opkHighWaterKeyId,
    String? bundlePublicMaterialDigest,
  }) => KeyBundleAcceptedReceipt(
    bundleRevision: bundleRevision ?? this.bundleRevision,
    signedPreKeyId: signedPreKeyId ?? this.signedPreKeyId,
    kemKeyId: kemKeyId ?? this.kemKeyId,
    cryptoProtocolEpoch: cryptoProtocolEpoch ?? this.cryptoProtocolEpoch,
    replacementId: replacementId ?? this.replacementId,
    opkAcceptedBundleRevision:
        opkAcceptedBundleRevision ?? this.opkAcceptedBundleRevision,
    opkGeneration: opkGeneration ?? this.opkGeneration,
    opkSetDigest: opkSetDigest ?? this.opkSetDigest,
    opkSetCount: opkSetCount ?? this.opkSetCount,
    opkHighWaterKeyId: opkHighWaterKeyId ?? this.opkHighWaterKeyId,
    bundlePublicMaterialDigest:
        bundlePublicMaterialDigest ?? this.bundlePublicMaterialDigest,
  );

  @override
  bool operator ==(Object other) =>
      other is KeyBundleAcceptedReceipt &&
      jsonEncode(other.toJson()) == jsonEncode(toJson());

  @override
  int get hashCode => Object.hashAll(<Object?>[
    bundleRevision,
    signedPreKeyId,
    kemKeyId,
    cryptoProtocolEpoch,
    replacementId,
    opkAcceptedBundleRevision,
    opkGeneration,
    opkSetDigest,
    opkSetCount,
    opkHighWaterKeyId,
    bundlePublicMaterialDigest,
  ]);
}

enum KeyBundleReplacementPhase {
  reserved,
  prepared,
  installStarted,
  installed,
  dispatchStarted,
  localAckPending,
}

enum OpkGenerationRole {
  stagedUploadOnly,
  acceptedLookupOnly,
  retainedLookupOnly,
  legacyQuarantined,
}

class KeyBundleReplacementReservation {
  final int expectedBundleRevision;
  final String replacementId;
  final int opkGeneration;
  final int signedPreKeyId;
  final int kemKeyId;
  final int opkStartKeyId;
  final int opkSetCount;
  final int opkHighWaterKeyId;

  const KeyBundleReplacementReservation({
    required this.expectedBundleRevision,
    required this.replacementId,
    required this.opkGeneration,
    required this.signedPreKeyId,
    required this.kemKeyId,
    required this.opkStartKeyId,
    required this.opkSetCount,
    required this.opkHighWaterKeyId,
  });

  void requireValid() {
    if (expectedBundleRevision < 0 ||
        expectedBundleRevision >=
            KeyBundleReplacementJournal.maxServerSafeInt ||
        replacementId.isEmpty ||
        replacementId.length > 64 ||
        !RegExp(r'^[A-Za-z0-9._:-]+$').hasMatch(replacementId) ||
        opkGeneration <= 0 ||
        opkGeneration > KeyBundleReplacementJournal.maxServerSafeInt ||
        signedPreKeyId <= 0 ||
        signedPreKeyId > RisaalCryptoProtocol.maxKeyId ||
        kemKeyId <= 0 ||
        kemKeyId > RisaalCryptoProtocol.maxKeyId ||
        opkStartKeyId <= 0 ||
        opkSetCount <= 0 ||
        opkSetCount > 100 ||
        opkHighWaterKeyId != opkStartKeyId + opkSetCount - 1 ||
        opkHighWaterKeyId > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('Invalid key-bundle reservation');
    }
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'expectedBundleRevision': expectedBundleRevision,
    'replacementId': replacementId,
    'opkGeneration': opkGeneration,
    'signedPreKeyId': signedPreKeyId,
    'kemKeyId': kemKeyId,
    'opkStartKeyId': opkStartKeyId,
    'opkSetCount': opkSetCount,
    'opkHighWaterKeyId': opkHighWaterKeyId,
  };

  factory KeyBundleReplacementReservation.fromJson(Map<String, dynamic> json) {
    final reservation = KeyBundleReplacementReservation(
      expectedBundleRevision: json['expectedBundleRevision'] as int? ?? -1,
      replacementId: json['replacementId'] as String? ?? '',
      opkGeneration: json['opkGeneration'] as int? ?? -1,
      signedPreKeyId: json['signedPreKeyId'] as int? ?? -1,
      kemKeyId: json['kemKeyId'] as int? ?? -1,
      opkStartKeyId: json['opkStartKeyId'] as int? ?? -1,
      opkSetCount: json['opkSetCount'] as int? ?? -1,
      opkHighWaterKeyId: json['opkHighWaterKeyId'] as int? ?? -1,
    );
    reservation.requireValid();
    return reservation;
  }
}

/// Immutable public proposal. It deliberately has no network-payload method;
/// only [KeyBundleReplacementDispatch] exposes bytes after durable intent.
class KeyBundleReplacementSnapshot {
  final int expectedBundleRevision;
  final String replacementId;
  final int opkGeneration;
  final String opkSetDigest;
  final int opkSetCount;
  final int opkHighWaterKeyId;
  final String bundlePublicMaterialDigest;
  final int signedPreKeyId;
  final int kemKeyId;
  final List<int> _oneTimePreKeyIds;

  KeyBundleReplacementSnapshot({
    required this.expectedBundleRevision,
    required this.replacementId,
    required this.opkGeneration,
    required this.opkSetDigest,
    required this.opkSetCount,
    required this.opkHighWaterKeyId,
    required this.bundlePublicMaterialDigest,
    required this.signedPreKeyId,
    required this.kemKeyId,
    required Iterable<int> oneTimePreKeyIds,
  }) : _oneTimePreKeyIds = List<int>.unmodifiable(oneTimePreKeyIds) {
    requireValid();
  }

  List<int> get oneTimePreKeyIds => _oneTimePreKeyIds;

  void requireValid() {
    if (expectedBundleRevision < 0 ||
        expectedBundleRevision >=
            KeyBundleReplacementJournal.maxServerSafeInt ||
        replacementId.isEmpty ||
        replacementId.length > 64 ||
        !RegExp(r'^[A-Za-z0-9._:-]+$').hasMatch(replacementId) ||
        opkGeneration <= 0 ||
        opkGeneration > KeyBundleReplacementJournal.maxServerSafeInt ||
        !KeyBundleReplacementCommitment.isCanonicalSha256(opkSetDigest) ||
        opkSetCount <= 0 ||
        opkSetCount > 100 ||
        opkSetCount != _oneTimePreKeyIds.length ||
        opkHighWaterKeyId <= 0 ||
        opkHighWaterKeyId > RisaalCryptoProtocol.maxKeyId ||
        !KeyBundleReplacementCommitment.isCanonicalSha256(
          bundlePublicMaterialDigest,
        ) ||
        signedPreKeyId <= 0 ||
        signedPreKeyId > RisaalCryptoProtocol.maxKeyId ||
        kemKeyId <= 0 ||
        kemKeyId > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException('Invalid key-bundle replacement snapshot');
    }
    var priorId = 0;
    for (final keyId in _oneTimePreKeyIds) {
      if (keyId <= priorId || keyId > RisaalCryptoProtocol.maxKeyId) {
        throw const FormatException('Invalid replacement OPK identifiers');
      }
      priorId = keyId;
    }
    if (_oneTimePreKeyIds.last != opkHighWaterKeyId) {
      throw const FormatException('Invalid replacement OPK high-water mark');
    }
  }

  bool matches(KeyBundleReplacementSnapshot other) =>
      jsonEncode(toJournalJson()) == jsonEncode(other.toJournalJson());

  Map<String, dynamic> toJournalJson() => <String, dynamic>{
    'expectedBundleRevision': expectedBundleRevision,
    'replacementId': replacementId,
    'opkGeneration': opkGeneration,
    'opkSetDigest': opkSetDigest,
    'opkSetCount': opkSetCount,
    'opkHighWaterKeyId': opkHighWaterKeyId,
    'bundlePublicMaterialDigest': bundlePublicMaterialDigest,
    'signedPreKeyId': signedPreKeyId,
    'kemKeyId': kemKeyId,
    'oneTimePreKeyIds': _oneTimePreKeyIds,
  };

  factory KeyBundleReplacementSnapshot.fromJournalJson(
    Map<String, dynamic> json,
  ) => KeyBundleReplacementSnapshot(
    expectedBundleRevision: json['expectedBundleRevision'] as int? ?? -1,
    replacementId: json['replacementId'] as String? ?? '',
    opkGeneration: json['opkGeneration'] as int? ?? -1,
    opkSetDigest: json['opkSetDigest'] as String? ?? '',
    opkSetCount: json['opkSetCount'] as int? ?? -1,
    opkHighWaterKeyId: json['opkHighWaterKeyId'] as int? ?? -1,
    bundlePublicMaterialDigest:
        json['bundlePublicMaterialDigest'] as String? ?? '',
    signedPreKeyId: json['signedPreKeyId'] as int? ?? -1,
    kemKeyId: json['kemKeyId'] as int? ?? -1,
    oneTimePreKeyIds: (json['oneTimePreKeyIds'] as List? ?? const <Object>[])
        .cast<int>(),
  );
}

class KeyBundleReplacementProposal {
  final KeyBundleReplacementSnapshot snapshot;
  final SignedPreKey signedPreKey;
  final KyberKeyPair kyberKeyPair;

  const KeyBundleReplacementProposal({
    required this.snapshot,
    required this.signedPreKey,
    required this.kyberKeyPair,
  });

  Map<String, dynamic> toJson() => <String, dynamic>{
    'snapshot': snapshot.toJournalJson(),
    'signedPreKey': signedPreKey.toJson(),
    'kyberKeyPair': kyberKeyPair.toJson(),
  };

  factory KeyBundleReplacementProposal.fromJson(Map<String, dynamic> json) =>
      KeyBundleReplacementProposal(
        snapshot: KeyBundleReplacementSnapshot.fromJournalJson(
          Map<String, dynamic>.from(json['snapshot'] as Map),
        ),
        signedPreKey: SignedPreKey.fromJson(
          Map<String, dynamic>.from(json['signedPreKey'] as Map),
        ),
        kyberKeyPair: KyberKeyPair.fromJson(
          Map<String, dynamic>.from(json['kyberKeyPair'] as Map),
        ),
      );
}

class KeyBundleKeyringGeneration {
  final int opkGeneration;
  final OpkGenerationRole role;
  final KeyBundleAcceptedReceipt? acceptedReceipt;
  final String identityKey;
  final String identitySigningKey;
  final String kemSignature;
  final SignedPreKey? signedPreKey;
  final KyberKeyPair? kyberKeyPair;
  final List<OneTimePreKeyPublic> publicOneTimePreKeys;
  final List<OneTimePreKey> oneTimePreKeys;
  final Set<int> consumedOneTimePreKeyIds;

  /// When this generation stopped being the accepted one, in milliseconds since
  /// the epoch. Null while it is staged or accepted, and null on journals
  /// written before retirement existed.
  ///
  /// Retirement is timed from this rather than from creation: a bundle fetched
  /// while the generation was still current can be used to send long after, and
  /// a PreKey envelope can target the signed-prekey and KEM key with no
  /// one-time key at all — so "every one-time key is consumed" is not a safe
  /// bound on its own.
  final int? demotedAtMillis;

  KeyBundleKeyringGeneration({
    required this.opkGeneration,
    required this.role,
    this.acceptedReceipt,
    this.demotedAtMillis,
    required this.identityKey,
    required this.identitySigningKey,
    required this.kemSignature,
    this.signedPreKey,
    this.kyberKeyPair,
    required Iterable<OneTimePreKeyPublic> publicOneTimePreKeys,
    required Iterable<OneTimePreKey> oneTimePreKeys,
    Iterable<int> consumedOneTimePreKeyIds = const <int>[],
  }) : publicOneTimePreKeys = List<OneTimePreKeyPublic>.unmodifiable(
         publicOneTimePreKeys,
       ),
       oneTimePreKeys = List<OneTimePreKey>.unmodifiable(oneTimePreKeys),
       consumedOneTimePreKeyIds = Set<int>.unmodifiable(
         consumedOneTimePreKeyIds,
       ) {
    requireValid();
  }

  void requireValid() {
    final legacy = role == OpkGenerationRole.legacyQuarantined;
    if ((legacy && opkGeneration != 0) || (!legacy && opkGeneration <= 0)) {
      throw const FormatException('Invalid keyring generation identity');
    }
    if ((role == OpkGenerationRole.acceptedLookupOnly ||
            role == OpkGenerationRole.retainedLookupOnly) !=
        (acceptedReceipt != null)) {
      throw const FormatException('Invalid keyring receipt role');
    }
    if (identityKey.isEmpty ||
        identitySigningKey.isEmpty ||
        kemSignature.isEmpty ||
        signedPreKey == null ||
        kyberKeyPair == null ||
        kyberKeyPair!.isCurrentProtocol != true) {
      throw const FormatException('Incomplete keyring generation secrets');
    }
    if (!legacy && publicOneTimePreKeys.isEmpty) {
      throw const FormatException('Versioned keyring generation is empty');
    }
    if (acceptedReceipt != null) {
      acceptedReceipt!.requireValid();
      if (acceptedReceipt!.opkGeneration != opkGeneration ||
          acceptedReceipt!.signedPreKeyId != signedPreKey!.keyId ||
          acceptedReceipt!.kemKeyId != kyberKeyPair!.keyId ||
          acceptedReceipt!.opkSetCount != publicOneTimePreKeys.length ||
          acceptedReceipt!.opkHighWaterKeyId <
              publicOneTimePreKeys.last.keyId ||
          acceptedReceipt!.opkSetDigest !=
              KeyBundleReplacementCommitment.opkSetDigest(
                opkGeneration: opkGeneration,
                oneTimePreKeys: publicOneTimePreKeys,
              ) ||
          acceptedReceipt!.bundlePublicMaterialDigest !=
              KeyBundleReplacementCommitment.bundlePublicMaterialDigest(
                identityKey: identityKey,
                identitySigningKey: identitySigningKey,
                signedPreKeyId: signedPreKey!.keyId,
                signedPreKeyPublicKey: signedPreKey!.keyPair.publicKey,
                signedPreKeySignature: signedPreKey!.signature,
                kemKeyId: kyberKeyPair!.keyId!,
                kemPublicKey: kyberKeyPair!.publicKey,
                kemSignature: kemSignature,
                cryptoProtocolEpoch: kyberKeyPair!.cryptoProtocolEpoch!,
                kemSuite: kyberKeyPair!.kemSuite!,
                kemStandard: kyberKeyPair!.kemStandard!,
                kemWireVersion: kyberKeyPair!.kemWireVersion!,
                opkGeneration: opkGeneration,
                opkSetDigest: acceptedReceipt!.opkSetDigest,
                opkSetCount: acceptedReceipt!.opkSetCount,
                opkHighWaterKeyId: acceptedReceipt!.opkHighWaterKeyId,
              )) {
        throw const FormatException('Keyring receipt generation mismatch');
      }
    }
    final canonical = publicOneTimePreKeys.isEmpty
        ? const <OneTimePreKeyPublic>[]
        : KeyBundleReplacementCommitment.canonicalOneTimePreKeys(
            publicOneTimePreKeys,
          );
    if (!_samePublicPreKeys(publicOneTimePreKeys, canonical)) {
      throw const FormatException('Invalid keyring public history');
    }
    final publicById = <int, String>{
      for (final key in publicOneTimePreKeys) key.keyId: key.publicKey,
    };
    final privateIds = <int>{};
    for (final key in oneTimePreKeys) {
      if (!privateIds.add(key.keyId) ||
          publicById[key.keyId] != key.keyPair.publicKey ||
          consumedOneTimePreKeyIds.contains(key.keyId)) {
        throw const FormatException('Invalid keyring private material');
      }
    }
    if (consumedOneTimePreKeyIds.any((id) => !publicById.containsKey(id))) {
      throw const FormatException('Invalid keyring consumption tombstone');
    }
    if (privateIds.length + consumedOneTimePreKeyIds.length !=
        publicById.length) {
      throw const FormatException('Incomplete keyring private/tombstone set');
    }
  }

  OneTimePreKey? findOneTimePreKey(int keyId) =>
      oneTimePreKeys.where((key) => key.keyId == keyId).firstOrNull;

  KeyBundleKeyringGeneration copyWith({
    OpkGenerationRole? role,
    KeyBundleAcceptedReceipt? acceptedReceipt,
    Iterable<OneTimePreKey>? oneTimePreKeys,
    Iterable<int>? consumedOneTimePreKeyIds,
    int? demotedAtMillis,
  }) => KeyBundleKeyringGeneration(
    opkGeneration: opkGeneration,
    role: role ?? this.role,
    acceptedReceipt: acceptedReceipt ?? this.acceptedReceipt,
    demotedAtMillis: demotedAtMillis ?? this.demotedAtMillis,
    identityKey: identityKey,
    identitySigningKey: identitySigningKey,
    kemSignature: kemSignature,
    signedPreKey: signedPreKey,
    kyberKeyPair: kyberKeyPair,
    publicOneTimePreKeys: publicOneTimePreKeys,
    oneTimePreKeys: oneTimePreKeys ?? this.oneTimePreKeys,
    consumedOneTimePreKeyIds:
        consumedOneTimePreKeyIds ?? this.consumedOneTimePreKeyIds,
  );

  Map<String, dynamic> toJson() => <String, dynamic>{
    'opkGeneration': opkGeneration,
    'role': role.name,
    if (acceptedReceipt != null) 'acceptedReceipt': acceptedReceipt!.toJson(),
    if (demotedAtMillis != null) 'demotedAtMillis': demotedAtMillis,
    'identityKey': identityKey,
    'identitySigningKey': identitySigningKey,
    'kemSignature': kemSignature,
    if (signedPreKey != null) 'signedPreKey': signedPreKey!.toJson(),
    if (kyberKeyPair != null) 'kyberKeyPair': kyberKeyPair!.toJson(),
    'publicOneTimePreKeys': publicOneTimePreKeys
        .map((key) => key.toJson())
        .toList(growable: false),
    'oneTimePreKeys': oneTimePreKeys
        .map((key) => key.toJson())
        .toList(growable: false),
    'consumedOneTimePreKeyIds': consumedOneTimePreKeyIds.toList()..sort(),
  };

  factory KeyBundleKeyringGeneration.fromJson(
    Map<String, dynamic> json,
  ) => KeyBundleKeyringGeneration(
    opkGeneration: json['opkGeneration'] as int? ?? -1,
    role: OpkGenerationRole.values.byName(json['role'] as String? ?? ''),
    demotedAtMillis: json['demotedAtMillis'] as int?,
    acceptedReceipt: json['acceptedReceipt'] == null
        ? null
        : KeyBundleAcceptedReceipt.fromJson(
            Map<String, dynamic>.from(json['acceptedReceipt'] as Map),
          ),
    identityKey: json['identityKey'] as String? ?? '',
    identitySigningKey: json['identitySigningKey'] as String? ?? '',
    kemSignature: json['kemSignature'] as String? ?? '',
    signedPreKey: json['signedPreKey'] == null
        ? null
        : SignedPreKey.fromJson(
            Map<String, dynamic>.from(json['signedPreKey'] as Map),
          ),
    kyberKeyPair: json['kyberKeyPair'] == null
        ? null
        : KyberKeyPair.fromJson(
            Map<String, dynamic>.from(json['kyberKeyPair'] as Map),
          ),
    publicOneTimePreKeys:
        (json['publicOneTimePreKeys'] as List? ?? const <Object>[]).map(
          (value) => OneTimePreKeyPublic.fromJson(
            Map<String, dynamic>.from(value as Map),
          ),
        ),
    oneTimePreKeys: (json['oneTimePreKeys'] as List? ?? const <Object>[]).map(
      (value) =>
          OneTimePreKey.fromJson(Map<String, dynamic>.from(value as Map)),
    ),
    consumedOneTimePreKeyIds:
        (json['consumedOneTimePreKeyIds'] as List? ?? const <Object>[])
            .cast<int>(),
  );
}

/// Which retained generations may be dropped from a keyring, and which may not.
///
/// The keyring is capped at [KeyBundleReplacementJournal.maxGenerations] and had
/// no retirement at all: on the ninth rotation the device threw
/// `Key-bundle generation keyring capacity reached` and **could never rotate or
/// replenish its one-time pre-keys again**. For someone who suspects their key
/// is compromised that is the worst possible failure — the control that replaces
/// a key stops existing — and it also arrives on its own through ordinary
/// replenishment, with no attacker.
///
/// Retirement is nevertheless the dangerous direction: dropping a generation a
/// server-deliverable envelope can still target loses that message permanently.
/// So the rule is deliberately conservative and fails closed.
///
/// A generation may be retired only when ALL of these hold:
///  * its role is `retainedLookupOnly` — never the accepted or staged one, and
///    never a legacy-quarantined record, which is evidence rather than a key;
///  * it was demoted at least [retirementGrace] ago, timed from the moment it
///    stopped being current rather than from creation, because a bundle fetched
///    while it was current can be used to send long afterwards and a PreKey
///    envelope can target its signed-prekey and KEM key with no one-time key at
///    all;
///  * at least [minimumRetainedGenerations] generations survive the drop, so a
///    device always keeps history behind the current key.
///
/// A generation whose demotion time is unknown — written by a build from before
/// this existed — is never retired on age. The caller stamps it on first sight
/// instead, so its grace period starts at the upgrade rather than being guessed.
/// Bounds on generation retirement.
///
/// These live outside [KeyBundleReplacementJournal] on purpose: the journal is
/// deliberately NOT exported from the package barrel — it carries raw keyring
/// authority — and the retirement rule has to be callable and testable without
/// handing that authority out.
abstract final class GenerationRetirementPolicy {
  /// How long a generation stays reachable after it stops being current.
  ///
  /// A sender who fetched the bundle while it was current may not come online
  /// for weeks. Thirty days is the same order Signal keeps a signed pre-key for
  /// and is far longer than any queue this relay holds.
  static const Duration grace = Duration(days: 30);

  /// Never leave fewer than this many generations, whatever their age.
  static const int minimumRetained = 3;
}

typedef GenerationRetirementView = ({
  int opkGeneration,
  OpkGenerationRole role,
  int? demotedAtMillis,
});

/// The ids of retained generations that may be dropped from a keyring.
///
/// Takes a view rather than whole generations on purpose: the decision needs an
/// id, a role and a demotion time, and nothing else. Requiring valid key
/// material to ASK the question would mean the rule could only be tested
/// through a full rotation, which is how a policy ends up with no direct test
/// at all.
List<int> retirableGenerationIds({
  required List<GenerationRetirementView> generations,
  required DateTime now,
  Duration grace = GenerationRetirementPolicy.grace,
  int minimumRetained = GenerationRetirementPolicy.minimumRetained,
}) {
  final droppable = generations.length - minimumRetained;
  if (droppable <= 0) return const <int>[];

  final candidates =
      generations
          .where(
            (generation) =>
                generation.role == OpkGenerationRole.retainedLookupOnly &&
                generation.demotedAtMillis != null &&
                !now
                    .difference(
                      DateTime.fromMillisecondsSinceEpoch(
                        generation.demotedAtMillis!,
                      ),
                    )
                    .isNegative &&
                now
                        .difference(
                          DateTime.fromMillisecondsSinceEpoch(
                            generation.demotedAtMillis!,
                          ),
                        )
                        .compareTo(grace) >=
                    0,
          )
          .toList()
        // Oldest demotion first: if only some may go, the ones unreachable
        // longest go first.
        ..sort((a, b) => a.demotedAtMillis!.compareTo(b.demotedAtMillis!));

  return candidates
      .take(droppable)
      .map((generation) => generation.opkGeneration)
      .toList(growable: false);
}

class KeyBundleReplacementJournal {
  static const int schemaVersion = 1;
  static const int maxServerSafeInt = 9007199254740991;
  static const int maxGenerations = 8;
  static const int maxEncodedBytes = 512 * 1024;

  final int journalRevision;
  final KeyBundleReplacementPhase? phase;
  final bool installationApplied;
  final KeyBundleAcceptedReceipt? acceptedReceipt;
  final KeyBundleAcceptedReceipt? pendingAcceptedReceipt;
  final KeyBundleReplacementReservation? reservation;
  final KeyBundleReplacementProposal? proposal;
  final List<KeyBundleKeyringGeneration> generations;

  /// What the ACCOUNT had already published when this device was adopted from a
  /// pre-journal install.
  ///
  /// An adopted device has no local history, so monotonicity has nothing to
  /// measure against and every replacement it proposes reads as non-monotonic —
  /// which left an existing user unable to log back in at all. This records the
  /// authenticated server receipt that the adoption was performed against, so
  /// the next generation is checked against what the account published rather
  /// than against a history this device never had.
  ///
  /// Only ever set on an adoption-only journal, and never a substitute for
  /// [acceptedReceipt]: it is a floor, not a claim that this device owns that
  /// generation.
  final KeyBundleAcceptedReceipt? adoptedBaselineReceipt;

  KeyBundleReplacementJournal({
    required this.journalRevision,
    required this.phase,
    required this.installationApplied,
    required this.acceptedReceipt,
    required this.pendingAcceptedReceipt,
    required this.reservation,
    required this.proposal,
    required Iterable<KeyBundleKeyringGeneration> generations,
    required this.adoptedBaselineReceipt,
  }) : generations = List<KeyBundleKeyringGeneration>.unmodifiable(
         generations,
       ) {
    requireValid();
  }

  factory KeyBundleReplacementJournal.empty() => KeyBundleReplacementJournal(
    journalRevision: 1,
    phase: null,
    installationApplied: false,
    acceptedReceipt: null,
    pendingAcceptedReceipt: null,
    reservation: null,
    proposal: null,
    generations: const <KeyBundleKeyringGeneration>[],
    adoptedBaselineReceipt: null,
  );

  void requireValid() {
    if (journalRevision <= 0 || generations.length > maxGenerations) {
      throw const FormatException('Invalid key-bundle journal');
    }
    if (acceptedReceipt != null) acceptedReceipt!.requireValid();
    if (pendingAcceptedReceipt != null) pendingAcceptedReceipt!.requireValid();
    if (reservation != null) reservation!.requireValid();
    if (phase == null) {
      if (reservation != null ||
          proposal != null ||
          installationApplied ||
          pendingAcceptedReceipt != null) {
        throw const FormatException('Idle journal contains pending state');
      }
    } else if (phase == KeyBundleReplacementPhase.reserved) {
      if (reservation == null ||
          proposal != null ||
          installationApplied ||
          pendingAcceptedReceipt != null) {
        throw const FormatException('Invalid reserved journal state');
      }
    } else {
      if (reservation == null || proposal == null) {
        throw const FormatException('Pending journal is incomplete');
      }
      if ((phase == KeyBundleReplacementPhase.prepared ||
              phase == KeyBundleReplacementPhase.installStarted) &&
          installationApplied) {
        throw const FormatException('Prepared journal cannot be installed');
      }
      if ((phase == KeyBundleReplacementPhase.installed ||
              phase == KeyBundleReplacementPhase.dispatchStarted ||
              phase == KeyBundleReplacementPhase.localAckPending) &&
          !installationApplied) {
        throw const FormatException('Installed journal is not applied');
      }
      if ((phase == KeyBundleReplacementPhase.localAckPending) !=
          (pendingAcceptedReceipt != null)) {
        throw const FormatException('Invalid pending acceptance state');
      }
    }

    final generationIds = <int>{};
    final allOpkIds = <int>{};
    final allOpkPublic = <String>{};
    final allSignedPreKeyIds = <int>{};
    final allSignedPreKeyPublic = <String>{};
    final allKemKeyIds = <int>{};
    final allKemPublic = <String>{};
    var stagedCount = 0;
    var acceptedCount = 0;
    for (final generation in generations) {
      generation.requireValid();
      if (!generationIds.add(generation.opkGeneration)) {
        throw const FormatException('Duplicate keyring generation');
      }
      if (generation.role == OpkGenerationRole.stagedUploadOnly) stagedCount++;
      if (generation.role == OpkGenerationRole.acceptedLookupOnly) {
        acceptedCount++;
      }
      if (!allSignedPreKeyIds.add(generation.signedPreKey!.keyId) ||
          !allSignedPreKeyPublic.add(
            generation.signedPreKey!.keyPair.publicKey,
          ) ||
          !allKemKeyIds.add(generation.kyberKeyPair!.keyId!) ||
          !allKemPublic.add(generation.kyberKeyPair!.publicKey)) {
        throw const FormatException('Reused keyring SPK/KEM material');
      }
      for (final key in generation.publicOneTimePreKeys) {
        if (!allOpkIds.add(key.keyId) || !allOpkPublic.add(key.publicKey)) {
          throw const FormatException('Reused keyring OPK material');
        }
      }
    }
    if (stagedCount > 1 || acceptedCount > 1) {
      throw const FormatException('Invalid keyring roles');
    }
    if ((proposal == null && stagedCount != 0) ||
        (proposal != null && stagedCount != 1) ||
        (acceptedReceipt == null && acceptedCount != 0) ||
        (acceptedReceipt != null && acceptedCount != 1)) {
      throw const FormatException('Orphan keyring generation role');
    }
    if (proposal != null) {
      final staged = generations.where(
        (generation) => generation.role == OpkGenerationRole.stagedUploadOnly,
      );
      final snapshot = proposal!.snapshot;
      if (staged.length != 1) {
        throw const FormatException('Proposal/keyring mismatch');
      }
      final stagedGeneration = staged.single;
      final stagedSignedPreKey = stagedGeneration.signedPreKey!;
      final stagedKyberKeyPair = stagedGeneration.kyberKeyPair!;
      final stagedOpkDigest = KeyBundleReplacementCommitment.opkSetDigest(
        opkGeneration: stagedGeneration.opkGeneration,
        oneTimePreKeys: stagedGeneration.publicOneTimePreKeys,
      );
      final stagedBundleDigest =
          KeyBundleReplacementCommitment.bundlePublicMaterialDigest(
            identityKey: stagedGeneration.identityKey,
            identitySigningKey: stagedGeneration.identitySigningKey,
            signedPreKeyId: stagedSignedPreKey.keyId,
            signedPreKeyPublicKey: stagedSignedPreKey.keyPair.publicKey,
            signedPreKeySignature: stagedSignedPreKey.signature,
            kemKeyId: stagedKyberKeyPair.keyId!,
            kemPublicKey: stagedKyberKeyPair.publicKey,
            kemSignature: stagedGeneration.kemSignature,
            cryptoProtocolEpoch: stagedKyberKeyPair.cryptoProtocolEpoch!,
            kemSuite: stagedKyberKeyPair.kemSuite!,
            kemStandard: stagedKyberKeyPair.kemStandard!,
            kemWireVersion: stagedKyberKeyPair.kemWireVersion!,
            opkGeneration: stagedGeneration.opkGeneration,
            opkSetDigest: stagedOpkDigest,
            opkSetCount: stagedGeneration.publicOneTimePreKeys.length,
            opkHighWaterKeyId: stagedGeneration.publicOneTimePreKeys.last.keyId,
          );
      if (stagedGeneration.opkGeneration != snapshot.opkGeneration ||
          reservation!.replacementId != snapshot.replacementId ||
          reservation!.expectedBundleRevision !=
              snapshot.expectedBundleRevision ||
          reservation!.opkGeneration != snapshot.opkGeneration ||
          reservation!.signedPreKeyId != snapshot.signedPreKeyId ||
          reservation!.kemKeyId != snapshot.kemKeyId ||
          reservation!.opkSetCount != snapshot.opkSetCount ||
          reservation!.opkStartKeyId != snapshot.oneTimePreKeyIds.first ||
          reservation!.opkHighWaterKeyId != snapshot.opkHighWaterKeyId ||
          proposal!.signedPreKey.keyId != snapshot.signedPreKeyId ||
          jsonEncode(proposal!.signedPreKey.toJson()) !=
              jsonEncode(stagedSignedPreKey.toJson()) ||
          proposal!.kyberKeyPair.keyId != snapshot.kemKeyId ||
          jsonEncode(proposal!.kyberKeyPair.toJson()) !=
              jsonEncode(stagedKyberKeyPair.toJson()) ||
          stagedSignedPreKey.keyId != snapshot.signedPreKeyId ||
          stagedKyberKeyPair.keyId != snapshot.kemKeyId ||
          !_sameIntValues(
            stagedGeneration.publicOneTimePreKeys.map((key) => key.keyId),
            snapshot.oneTimePreKeyIds,
          ) ||
          stagedOpkDigest != snapshot.opkSetDigest ||
          stagedGeneration.publicOneTimePreKeys.length !=
              snapshot.opkSetCount ||
          stagedGeneration.publicOneTimePreKeys.last.keyId !=
              snapshot.opkHighWaterKeyId ||
          stagedBundleDigest != snapshot.bundlePublicMaterialDigest) {
        throw const FormatException('Proposal/keyring mismatch');
      }
      if (pendingAcceptedReceipt != null &&
          !pendingAcceptedReceipt!.matchesSnapshot(snapshot)) {
        throw const FormatException('Pending receipt/proposal mismatch');
      }
    }
    if (acceptedReceipt != null) {
      final accepted = generations.where(
        (generation) => generation.role == OpkGenerationRole.acceptedLookupOnly,
      );
      if (accepted.length != 1 ||
          accepted.single.acceptedReceipt != acceptedReceipt) {
        throw const FormatException('Accepted journal/keyring mismatch');
      }
    }
    final receiptedGenerations =
        generations
            .where((generation) => generation.acceptedReceipt != null)
            .toList(growable: false)
          ..sort(
            (left, right) => left.acceptedReceipt!.bundleRevision.compareTo(
              right.acceptedReceipt!.bundleRevision,
            ),
          );
    if (acceptedReceipt == null) {
      if (receiptedGenerations.isNotEmpty) {
        throw const FormatException('Orphan receipted keyring history');
      }
    } else if (receiptedGenerations.isEmpty ||
        receiptedGenerations.last.role !=
            OpkGenerationRole.acceptedLookupOnly ||
        receiptedGenerations.last.acceptedReceipt != acceptedReceipt ||
        receiptedGenerations
            .take(receiptedGenerations.length - 1)
            .any(
              (generation) =>
                  generation.role != OpkGenerationRole.retainedLookupOnly,
            )) {
      throw const FormatException('Accepted role is not the newest receipt');
    }
    _validateMonotonicGenerationHistory();
  }

  void _validateMonotonicGenerationHistory() {
    final versioned =
        generations.where((generation) => generation.opkGeneration > 0).toList()
          ..sort(
            (left, right) => left.opkGeneration.compareTo(right.opkGeneration),
          );
    final replacementIds = <String>{};
    // An adopted device measures against what the ACCOUNT published, because it
    // has no local history of its own. Seeding from zero made every proposal it
    // could make read as non-monotonic.
    // The adopted receipt is a permanent monotonic floor for history this
    // device never possessed. It remains the predecessor after the first local
    // N+1 generation is accepted; dropping it at that moment incorrectly
    // compares generation N+1 against zero and rejects the server ACK.
    final baseline = adoptedBaselineReceipt;
    var priorRevision = baseline?.bundleRevision ?? 0;
    var priorHighWater = baseline?.opkHighWaterKeyId ?? 0;
    var priorGeneration = baseline?.opkGeneration ?? 0;
    var priorSignedPreKeyId = baseline?.signedPreKeyId ?? 0;
    var priorKemKeyId = baseline?.kemKeyId ?? 0;
    for (final generation in versioned) {
      final receipt = generation.acceptedReceipt;
      if (receipt != null) {
        if (receipt.opkGeneration != priorGeneration + 1 ||
            receipt.bundleRevision != priorRevision + 1 ||
            receipt.opkHighWaterKeyId <= priorHighWater ||
            generation.publicOneTimePreKeys.first.keyId <= priorHighWater ||
            receipt.signedPreKeyId <= priorSignedPreKeyId ||
            receipt.kemKeyId <= priorKemKeyId ||
            !replacementIds.add(receipt.replacementId)) {
          throw const FormatException('Non-monotonic keyring history');
        }
        priorGeneration = receipt.opkGeneration;
        priorRevision = receipt.bundleRevision;
        priorHighWater = receipt.opkHighWaterKeyId;
        priorSignedPreKeyId = receipt.signedPreKeyId;
        priorKemKeyId = receipt.kemKeyId;
      }
    }
    if (proposal != null &&
        (proposal!.snapshot.expectedBundleRevision != priorRevision ||
            proposal!.snapshot.opkGeneration != priorGeneration + 1 ||
            proposal!.snapshot.opkHighWaterKeyId <= priorHighWater ||
            proposal!.snapshot.oneTimePreKeyIds.first <= priorHighWater ||
            proposal!.snapshot.signedPreKeyId <= priorSignedPreKeyId ||
            proposal!.snapshot.kemKeyId <= priorKemKeyId ||
            !replacementIds.add(proposal!.snapshot.replacementId))) {
      throw const FormatException('Non-monotonic replacement proposal');
    }
  }

  int get greatestOneTimePreKeyId => generations.fold<int>(
    0,
    (greatest, generation) => generation.publicOneTimePreKeys.fold<int>(
      greatest,
      (value, key) => key.keyId > value ? key.keyId : value,
    ),
  );

  Map<String, dynamic> toJson() => <String, dynamic>{
    'schemaVersion': schemaVersion,
    'journalRevision': journalRevision,
    if (phase != null) 'phase': phase!.name,
    'installationApplied': installationApplied,
    if (acceptedReceipt != null) 'acceptedReceipt': acceptedReceipt!.toJson(),
    if (adoptedBaselineReceipt != null)
      'adoptedBaselineReceipt': adoptedBaselineReceipt!.toJson(),
    if (pendingAcceptedReceipt != null)
      'pendingAcceptedReceipt': pendingAcceptedReceipt!.toJson(),
    if (reservation != null) 'reservation': reservation!.toJson(),
    if (proposal != null) 'proposal': proposal!.toJson(),
    'generations': generations
        .map((generation) => generation.toJson())
        .toList(growable: false),
  };

  factory KeyBundleReplacementJournal.fromJson(Map<String, dynamic> json) {
    if (json['schemaVersion'] != schemaVersion) {
      throw const FormatException('Unknown key-bundle journal schema');
    }
    try {
      return KeyBundleReplacementJournal(
        journalRevision: json['journalRevision'] as int? ?? -1,
        phase: json['phase'] == null
            ? null
            : KeyBundleReplacementPhase.values.byName(json['phase'] as String),
        installationApplied: json['installationApplied'] as bool? ?? false,
        acceptedReceipt: json['acceptedReceipt'] == null
            ? null
            : KeyBundleAcceptedReceipt.fromJson(
                Map<String, dynamic>.from(json['acceptedReceipt'] as Map),
              ),
        adoptedBaselineReceipt: json['adoptedBaselineReceipt'] == null
            ? null
            : KeyBundleAcceptedReceipt.fromJson(
                Map<String, dynamic>.from(
                  json['adoptedBaselineReceipt'] as Map,
                ),
              ),
        pendingAcceptedReceipt: json['pendingAcceptedReceipt'] == null
            ? null
            : KeyBundleAcceptedReceipt.fromJson(
                Map<String, dynamic>.from(
                  json['pendingAcceptedReceipt'] as Map,
                ),
              ),
        reservation: json['reservation'] == null
            ? null
            : KeyBundleReplacementReservation.fromJson(
                Map<String, dynamic>.from(json['reservation'] as Map),
              ),
        proposal: json['proposal'] == null
            ? null
            : KeyBundleReplacementProposal.fromJson(
                Map<String, dynamic>.from(json['proposal'] as Map),
              ),
        generations: (json['generations'] as List? ?? const <Object>[]).map(
          (value) => KeyBundleKeyringGeneration.fromJson(
            Map<String, dynamic>.from(value as Map),
          ),
        ),
      );
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Corrupt key-bundle journal');
    }
  }
}

bool _samePublicPreKeys(
  List<OneTimePreKeyPublic> left,
  List<OneTimePreKeyPublic> right,
) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index].keyId != right[index].keyId ||
        left[index].publicKey != right[index].publicKey) {
      return false;
    }
  }
  return true;
}

bool _sameIntValues(Iterable<int> left, List<int> right) {
  final leftValues = left.toList(growable: false);
  if (leftValues.length != right.length) return false;
  for (var index = 0; index < leftValues.length; index++) {
    if (leftValues[index] != right[index]) return false;
  }
  return true;
}
