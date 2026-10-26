import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// R4-L1 Part B: send Double Ratchet wire version 3 and initiate PQXDH
/// transcript 2, which bind both identity keys. Off until Part C, which the
/// owner flips only once the minimum client build is enforced
/// (contracts/R4-L1-IDENTITY-BINDING.md §4). Receiving both is always on.
const bool kSendRatchetV3 = false;

/// Test-only override of [kSendRatchetV3]; `null` uses the constant. It is
/// honoured only while assertions are enabled, so a release build always
/// follows [kSendRatchetV3].
bool? debugSendRatchetV3Override;

/// The effective R4-L1 send switch: [kSendRatchetV3], or the test override.
bool get sendRatchetV3Enabled {
  var enabled = kSendRatchetV3;
  assert(() {
    enabled = debugSendRatchetV3Override ?? enabled;
    return true;
  }());
  return enabled;
}

/// The fail-closed protocol boundary for the ML-KEM hard cutover.
///
/// Epoch 1/unversioned material was produced by the incompatible
/// `pqcrypto 0.1.0` implementation. Epoch 2 is the first Risaal epoch that uses
/// the FIPS 203 ML-KEM-768 wire format. Byte lengths are deliberately not used
/// for detection because both implementations use the same lengths.
abstract final class RisaalCryptoProtocol {
  static const String clientProtocol = 'risaal-e2ee-2';
  static const String httpHeaderName = 'X-Risaal-Crypto-Protocol';

  static const int cryptoProtocolEpoch = 2;
  static const String kemSuite = 'ML-KEM-768';
  static const String kemStandard = 'FIPS203';
  static const int kemWireVersion = 1;
  static const int maxKeyId = 0x7fffffff;
  static const int maxServerSafeInt = 9007199254740991;

  static bool isCurrentKemMetadata({
    required int cryptoProtocolEpoch,
    required String kemSuite,
    required String kemStandard,
    required int kemWireVersion,
  }) =>
      cryptoProtocolEpoch == RisaalCryptoProtocol.cryptoProtocolEpoch &&
      kemSuite == RisaalCryptoProtocol.kemSuite &&
      kemStandard == RisaalCryptoProtocol.kemStandard &&
      kemWireVersion == RisaalCryptoProtocol.kemWireVersion;

  /// Domain-separated transcript signed by the device identity signing key.
  /// It binds the public key to its exact protocol epoch, suite, wire version,
  /// and rotation key id so metadata cannot be swapped independently.
  static Uint8List kyberPreKeySignatureTranscript({
    required int keyId,
    required String publicKey,
  }) {
    final header = utf8.encode(
      'Risaal-KEM-PreKey\u0000'
      '$cryptoProtocolEpoch\u0000'
      '$kemSuite\u0000'
      '$kemStandard\u0000'
      '$kemWireVersion\u0000'
      '$keyId\u0000',
    );
    return Uint8List.fromList(<int>[...header, ...base64Decode(publicKey)]);
  }

  /// Stable digest of every public value that defines an uploadable bundle.
  static String keyBundlePublicMaterialDigest({
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
  }) => crypto.sha256
      .convert(
        utf8.encode(
          jsonEncode(<Object>[
            clientProtocol,
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
          ]),
        ),
      )
      .toString();
}

/// Public, non-secret identity of one exact uploadable device-key generation.
///
/// This tuple is carried through the local pending record, HTTP request and
/// server acknowledgement. It prevents a delayed response for generation A
/// from acknowledging a newer generation B.
class KeyBundleGeneration {
  final int signedPreKeyId;
  final int kemKeyId;
  final int cryptoProtocolEpoch;
  final String? publicMaterialDigest;

  const KeyBundleGeneration({
    required this.signedPreKeyId,
    required this.kemKeyId,
    required this.cryptoProtocolEpoch,
    this.publicMaterialDigest,
  });

  void requireCurrent({bool requirePublicMaterialDigest = false}) {
    if (signedPreKeyId <= 0 ||
        signedPreKeyId > RisaalCryptoProtocol.maxKeyId ||
        kemKeyId <= 0 ||
        kemKeyId > RisaalCryptoProtocol.maxKeyId ||
        cryptoProtocolEpoch != RisaalCryptoProtocol.cryptoProtocolEpoch) {
      throw const FormatException('Invalid key-bundle generation');
    }
    if (requirePublicMaterialDigest &&
        (publicMaterialDigest == null ||
            !RegExp(r'^[0-9a-f]{64}$').hasMatch(publicMaterialDigest!))) {
      throw const FormatException('Missing key-bundle public-material digest');
    }
  }

  bool matches(KeyBundleGeneration other) =>
      signedPreKeyId == other.signedPreKeyId &&
      kemKeyId == other.kemKeyId &&
      cryptoProtocolEpoch == other.cryptoProtocolEpoch;

  bool matchesExact(KeyBundleGeneration other) =>
      matches(other) &&
      publicMaterialDigest != null &&
      publicMaterialDigest == other.publicMaterialDigest;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'signedPreKeyId': signedPreKeyId,
    'kemKeyId': kemKeyId,
    'cryptoProtocolEpoch': cryptoProtocolEpoch,
    if (publicMaterialDigest != null)
      'publicMaterialDigest': publicMaterialDigest,
  };

  factory KeyBundleGeneration.fromJson(Map<String, dynamic> json) {
    final generation = KeyBundleGeneration(
      signedPreKeyId: json['signedPreKeyId'] as int? ?? -1,
      kemKeyId: json['kemKeyId'] as int? ?? -1,
      cryptoProtocolEpoch: json['cryptoProtocolEpoch'] as int? ?? -1,
      publicMaterialDigest: json['publicMaterialDigest'] as String?,
    );
    generation.requireCurrent();
    return generation;
  }
}

/// Immutable public-key payload plus its optimistic-concurrency boundary.
class KeyBundleUploadSnapshot {
  final Map<String, dynamic> keyBundle;
  final KeyBundleGeneration generation;
  final int expectedBundleRevision;

  KeyBundleUploadSnapshot({
    required Map<String, dynamic> keyBundle,
    required this.generation,
    required this.expectedBundleRevision,
  }) : keyBundle = _deepFreezeJsonMap(keyBundle);

  Map<String, dynamic> toReplacementPayload({required String deviceId}) =>
      Map<String, dynamic>.unmodifiable(<String, dynamic>{
        'deviceId': deviceId,
        'expectedBundleRevision': expectedBundleRevision,
        ...keyBundle,
      });

  static Map<String, dynamic> _deepFreezeJsonMap(Map<String, dynamic> source) =>
      Map<String, dynamic>.unmodifiable(
        source.map(
          (key, value) =>
              MapEntry<String, dynamic>(key, _deepFreezeJson(value)),
        ),
      );

  static Object? _deepFreezeJson(Object? value) {
    if (value is Map) {
      return _deepFreezeJsonMap(Map<String, dynamic>.from(value));
    }
    if (value is List) {
      return List<Object?>.unmodifiable(value.map(_deepFreezeJson));
    }
    return value;
  }
}

/// Exact server result for a successful bundle mutation.
class KeyBundleUploadAcceptance {
  final int bundleRevision;
  final KeyBundleGeneration generation;

  const KeyBundleUploadAcceptance({
    required this.bundleRevision,
    required this.generation,
  });

  factory KeyBundleUploadAcceptance.fromResponseData(Object? data) {
    if (data is! Map) {
      throw const FormatException('Missing key-bundle acceptance');
    }
    final accepted = data['accepted'];
    if (accepted is! Map) {
      throw const FormatException('Missing key-bundle acceptance');
    }
    final normalized = Map<String, dynamic>.from(accepted);
    final revision = normalized['bundleRevision'];
    if (revision is! int || revision <= 0) {
      throw const FormatException('Invalid accepted bundle revision');
    }
    return KeyBundleUploadAcceptance(
      bundleRevision: revision,
      generation: KeyBundleGeneration.fromJson(normalized),
    );
  }

  /// Parse the authenticated current-bundle read used to reconcile a restart
  /// where the server committed but the client crashed before local ACK.
  factory KeyBundleUploadAcceptance.fromKeyBundleData(Object? data) {
    if (data is! Map) {
      throw const FormatException('Missing current key bundle');
    }
    final normalized = Map<String, dynamic>.from(data);
    final revision = normalized['bundleRevision'];
    final signedPreKey = normalized['signedPreKey'];
    final kyberPreKey = normalized['kyberPreKey'];
    if (revision is! int ||
        revision <= 0 ||
        signedPreKey is! Map ||
        kyberPreKey is! Map) {
      throw const FormatException('Invalid current key bundle');
    }
    final kem = Map<String, dynamic>.from(kyberPreKey);
    final spk = Map<String, dynamic>.from(signedPreKey);
    final identityKey = normalized['identityKey'];
    final identitySigningKey = normalized['identitySigningKey'];
    final signedPublicKey = spk['publicKey'];
    final signedSignature = spk['signature'];
    final kemPublicKey = kem['publicKey'];
    final kemSignature = kem['signature'];
    final kemSuite = kem['kemSuite'];
    final kemStandard = kem['kemStandard'];
    final kemWireVersion = kem['kemWireVersion'];
    if (identityKey is! String ||
        identityKey.isEmpty ||
        identitySigningKey is! String ||
        identitySigningKey.isEmpty ||
        signedPublicKey is! String ||
        signedPublicKey.isEmpty ||
        signedSignature is! String ||
        signedSignature.isEmpty ||
        kemPublicKey is! String ||
        kemPublicKey.isEmpty ||
        kemSignature is! String ||
        kemSignature.isEmpty ||
        kemSuite != RisaalCryptoProtocol.kemSuite ||
        kemStandard != RisaalCryptoProtocol.kemStandard ||
        kemWireVersion != RisaalCryptoProtocol.kemWireVersion) {
      throw const FormatException('Incomplete current key bundle');
    }
    final generation = KeyBundleGeneration(
      signedPreKeyId: spk['keyId'] as int? ?? -1,
      kemKeyId: kem['keyId'] as int? ?? -1,
      cryptoProtocolEpoch: kem['cryptoProtocolEpoch'] as int? ?? -1,
      publicMaterialDigest: RisaalCryptoProtocol.keyBundlePublicMaterialDigest(
        identityKey: identityKey,
        identitySigningKey: identitySigningKey,
        signedPreKeyId: spk['keyId'] as int? ?? -1,
        signedPreKeyPublicKey: signedPublicKey,
        signedPreKeySignature: signedSignature,
        kemKeyId: kem['keyId'] as int? ?? -1,
        kemPublicKey: kemPublicKey,
        kemSignature: kemSignature,
        cryptoProtocolEpoch: kem['cryptoProtocolEpoch'] as int? ?? -1,
        kemSuite: kemSuite,
        kemStandard: kemStandard,
        kemWireVersion: kemWireVersion,
      ),
    );
    generation.requireCurrent(requirePublicMaterialDigest: true);
    return KeyBundleUploadAcceptance(
      bundleRevision: revision,
      generation: generation,
    );
  }
}

/// Exact routing metadata carried beside every ML-KEM ciphertext.
class MlKemEnvelopeMetadata {
  final int cryptoProtocolEpoch;
  final String kemSuite;
  final String kemStandard;
  final int kemWireVersion;
  final int recipientKeyId;

  const MlKemEnvelopeMetadata({
    required this.cryptoProtocolEpoch,
    required this.kemSuite,
    required this.kemStandard,
    required this.kemWireVersion,
    required this.recipientKeyId,
  });

  const MlKemEnvelopeMetadata.current({required this.recipientKeyId})
    : cryptoProtocolEpoch = RisaalCryptoProtocol.cryptoProtocolEpoch,
      kemSuite = RisaalCryptoProtocol.kemSuite,
      kemStandard = RisaalCryptoProtocol.kemStandard,
      kemWireVersion = RisaalCryptoProtocol.kemWireVersion;

  bool get isCurrent => RisaalCryptoProtocol.isCurrentKemMetadata(
    cryptoProtocolEpoch: cryptoProtocolEpoch,
    kemSuite: kemSuite,
    kemStandard: kemStandard,
    kemWireVersion: kemWireVersion,
  );

  void requireCurrent() {
    if (!isCurrent ||
        recipientKeyId <= 0 ||
        recipientKeyId > RisaalCryptoProtocol.maxKeyId) {
      throw const FormatException(
        'Unsupported or legacy ML-KEM envelope metadata',
      );
    }
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'cryptoProtocolEpoch': cryptoProtocolEpoch,
    'kemSuite': kemSuite,
    'kemStandard': kemStandard,
    'kemWireVersion': kemWireVersion,
    'recipientKeyId': recipientKeyId,
  };

  factory MlKemEnvelopeMetadata.fromJson(Map<String, dynamic> json) {
    final metadata = MlKemEnvelopeMetadata(
      cryptoProtocolEpoch: json['cryptoProtocolEpoch'] as int? ?? -1,
      kemSuite: json['kemSuite'] as String? ?? '',
      kemStandard: json['kemStandard'] as String? ?? '',
      kemWireVersion: json['kemWireVersion'] as int? ?? -1,
      recipientKeyId: json['recipientKeyId'] as int? ?? -1,
    );
    metadata.requireCurrent();
    return metadata;
  }
}

/// Immutable server-accepted identity of one exact OPK generation.
///
/// All three fields are mandatory even when a consumer fetch returns no OPK.
/// A key ID alone is never sufficient to select retained private material.
class OpkGenerationRouting {
  final int bundleRevision;
  final int opkGeneration;
  final String opkSetDigest;

  const OpkGenerationRouting({
    required this.bundleRevision,
    required this.opkGeneration,
    required this.opkSetDigest,
  });

  void requireValid() {
    if (bundleRevision <= 0 ||
        bundleRevision > RisaalCryptoProtocol.maxServerSafeInt ||
        opkGeneration <= 0 ||
        opkGeneration > RisaalCryptoProtocol.maxServerSafeInt ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(opkSetDigest)) {
      throw const FormatException('Invalid OPK generation routing');
    }
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'bundleRevision': bundleRevision,
    'opkGeneration': opkGeneration,
    'opkSetDigest': opkSetDigest,
  };

  factory OpkGenerationRouting.fromJson(Map<String, dynamic> json) {
    final revision = json['bundleRevision'];
    final generation = json['opkGeneration'];
    final digest = json['opkSetDigest'];
    if (revision is! int || generation is! int || digest is! String) {
      throw const FormatException('Missing OPK generation routing');
    }
    final route = OpkGenerationRouting(
      bundleRevision: revision,
      opkGeneration: generation,
      opkSetDigest: digest,
    );
    route.requireValid();
    return route;
  }

  @override
  bool operator ==(Object other) =>
      other is OpkGenerationRouting &&
      bundleRevision == other.bundleRevision &&
      opkGeneration == other.opkGeneration &&
      opkSetDigest == other.opkSetDigest;

  @override
  int get hashCode => Object.hash(bundleRevision, opkGeneration, opkSetDigest);
}

/// Complete authenticated routing transcript for a first-contact handshake.
///
/// The canonical binary encoding is used as PQXDH HKDF info. It deliberately
/// avoids JSON ordering and string concatenation: integers have fixed width,
/// variable fields are length-prefixed, and the digest is bound as raw bytes.
class PreKeyHandshakeRouting {
  static const _transcriptDomain = 'RISAAL_PQXDH_OPK_ROUTE_v1';

  /// Transcript 2 (R4-L1): the v1 fields under this domain, then both raw
  /// X25519 identity keys, initiator first.
  static const _transcriptDomainV2 = 'RISAAL_PQXDH_OPK_ROUTE_v2';

  /// The transcript that binds both identity keys (R4-L1).
  static const int identityBoundTranscriptVersion = 2;

  final OpkGenerationRouting opkRoute;
  final int recipientSignedPreKeyId;
  final int? usedOneTimePreKeyId;
  final MlKemEnvelopeMetadata kemMetadata;

  /// PQXDH transcript version (R4-L1): 1 (absent on the wire) or 2. It is
  /// bound into the HKDF info through its transcript domain, so a version
  /// changed in transit derives a different root key.
  final int transcriptVersion;

  /// Base64 identity keys bound by [bindIdentityKeys] for transcript 2. KDF
  /// inputs only: never serialized and not part of equality.
  final String? _initiatorIdentityKey;
  final String? _responderIdentityKey;

  const PreKeyHandshakeRouting({
    required this.opkRoute,
    required this.recipientSignedPreKeyId,
    required this.usedOneTimePreKeyId,
    required this.kemMetadata,
    this.transcriptVersion = 1,
  }) : _initiatorIdentityKey = null,
       _responderIdentityKey = null;

  const PreKeyHandshakeRouting._bound({
    required this.opkRoute,
    required this.recipientSignedPreKeyId,
    required this.usedOneTimePreKeyId,
    required this.kemMetadata,
    required this.transcriptVersion,
    required String initiatorIdentityKey,
    required String responderIdentityKey,
  }) : _initiatorIdentityKey = initiatorIdentityKey,
       _responderIdentityKey = responderIdentityKey;

  /// This routing with PQXDH transcript [version].
  PreKeyHandshakeRouting withTranscriptVersion(int version) =>
      PreKeyHandshakeRouting(
        opkRoute: opkRoute,
        recipientSignedPreKeyId: recipientSignedPreKeyId,
        usedOneTimePreKeyId: usedOneTimePreKeyId,
        kemMetadata: kemMetadata,
        transcriptVersion: version,
      );

  /// This routing with both base64 X25519 identity keys bound for the KDF.
  /// Transcript 2 refuses to serialize without them; transcript 1 ignores them.
  PreKeyHandshakeRouting bindIdentityKeys({
    required String initiatorIdentityKey,
    required String responderIdentityKey,
  }) => PreKeyHandshakeRouting._bound(
    opkRoute: opkRoute,
    recipientSignedPreKeyId: recipientSignedPreKeyId,
    usedOneTimePreKeyId: usedOneTimePreKeyId,
    kemMetadata: kemMetadata,
    transcriptVersion: transcriptVersion,
    initiatorIdentityKey: initiatorIdentityKey,
    responderIdentityKey: responderIdentityKey,
  );

  void requireCurrent() {
    opkRoute.requireValid();
    kemMetadata.requireCurrent();
    if ((transcriptVersion != 1 &&
            transcriptVersion != identityBoundTranscriptVersion) ||
        recipientSignedPreKeyId <= 0 ||
        recipientSignedPreKeyId > RisaalCryptoProtocol.maxKeyId ||
        (usedOneTimePreKeyId != null &&
            (usedOneTimePreKeyId! <= 0 ||
                usedOneTimePreKeyId! > RisaalCryptoProtocol.maxKeyId))) {
      throw const FormatException('Invalid PreKey handshake routing');
    }
  }

  /// Transcript 1 stays absent, so a transcript-1 envelope is byte-identical
  /// to the pre-R4-L1 format.
  Map<String, dynamic> toEnvelopeJson() => <String, dynamic>{
    ...opkRoute.toJson(),
    'recipientSignedPreKeyId': recipientSignedPreKeyId,
    'usedOneTimePreKeyId': usedOneTimePreKeyId,
    ...kemMetadata.toJson(),
    if (transcriptVersion != 1) 'transcriptVersion': transcriptVersion,
  };

  Map<String, dynamic> toSealedProjectionJson() => <String, dynamic>{
    ...opkRoute.toJson(),
    'recipientSignedPreKeyId': recipientSignedPreKeyId,
    ...kemMetadata.toJson(),
  };

  factory PreKeyHandshakeRouting.fromEnvelopeJson(Map<String, dynamic> json) {
    if (!json.containsKey('usedOneTimePreKeyId')) {
      throw const FormatException(
        'PreKey routing requires an explicit one-time pre-key selection',
      );
    }
    final signedPreKeyId = json['recipientSignedPreKeyId'];
    final oneTimePreKeyId = json['usedOneTimePreKeyId'];
    // R4-L1: absent means transcript 1; the only explicit value is 2.
    final transcriptVersion = json.containsKey('transcriptVersion')
        ? json['transcriptVersion']
        : 1;
    if (signedPreKeyId is! int ||
        (oneTimePreKeyId != null && oneTimePreKeyId is! int) ||
        transcriptVersion is! int ||
        (json.containsKey('transcriptVersion') &&
            transcriptVersion != identityBoundTranscriptVersion)) {
      throw const FormatException('Invalid PreKey handshake routing');
    }
    try {
      final routing = PreKeyHandshakeRouting(
        opkRoute: OpkGenerationRouting.fromJson(json),
        recipientSignedPreKeyId: signedPreKeyId,
        usedOneTimePreKeyId: oneTimePreKeyId as int?,
        kemMetadata: MlKemEnvelopeMetadata.fromJson(json),
        transcriptVersion: transcriptVersion,
      );
      routing.requireCurrent();
      return routing;
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Invalid PreKey handshake routing');
    }
  }

  /// Validate the visible sealed-sender projection against protected routing.
  /// The OPK ID intentionally remains only in the protected inner envelope.
  void requireMatchingSealedProjection(Map<String, dynamic> projection) {
    if (projection.containsKey('usedOneTimePreKeyId')) {
      throw const FormatException(
        'Sealed outer routing must not expose a one-time pre-key id',
      );
    }
    final signedPreKeyId = projection['recipientSignedPreKeyId'];
    if (signedPreKeyId is! int) {
      throw const FormatException('Incomplete sealed PreKey routing');
    }
    try {
      final outerRoute = OpkGenerationRouting.fromJson(projection);
      final outerKem = MlKemEnvelopeMetadata.fromJson(projection);
      if (outerRoute != opkRoute ||
          signedPreKeyId != recipientSignedPreKeyId ||
          outerKem.cryptoProtocolEpoch != kemMetadata.cryptoProtocolEpoch ||
          outerKem.kemSuite != kemMetadata.kemSuite ||
          outerKem.kemStandard != kemMetadata.kemStandard ||
          outerKem.kemWireVersion != kemMetadata.kemWireVersion ||
          outerKem.recipientKeyId != kemMetadata.recipientKeyId) {
        throw const FormatException(
          'Sealed-sender routing does not match protected content',
        );
      }
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Invalid sealed PreKey routing');
    }
  }

  /// The PQXDH HKDF info. Transcript 2 (R4-L1) is the transcript-1 layout
  /// under its own domain followed by `u32 len ‖ IK_initiator ‖ u32 len ‖
  /// IK_responder` (raw X25519 bytes); it fails closed unless
  /// [bindIdentityKeys] supplied both keys.
  Uint8List canonicalTranscript() {
    requireCurrent();
    final identityBound = transcriptVersion == identityBoundTranscriptVersion;
    final output = BytesBuilder(copy: false);
    _appendLengthPrefixed(
      output,
      utf8.encode(identityBound ? _transcriptDomainV2 : _transcriptDomain),
    );
    _appendU32(output, kemMetadata.cryptoProtocolEpoch);
    _appendU64(output, opkRoute.bundleRevision);
    _appendU64(output, opkRoute.opkGeneration);
    _appendLengthPrefixed(output, _decodeLowercaseHex(opkRoute.opkSetDigest));
    _appendU32(output, recipientSignedPreKeyId);
    output.add(<int>[usedOneTimePreKeyId == null ? 0 : 1]);
    if (usedOneTimePreKeyId != null) {
      _appendU32(output, usedOneTimePreKeyId!);
    }
    _appendU32(output, kemMetadata.recipientKeyId);
    _appendU32(output, kemMetadata.kemWireVersion);
    _appendLengthPrefixed(output, utf8.encode(kemMetadata.kemSuite));
    _appendLengthPrefixed(output, utf8.encode(kemMetadata.kemStandard));
    if (identityBound) {
      _appendLengthPrefixed(output, _rawIdentityKey(_initiatorIdentityKey));
      _appendLengthPrefixed(output, _rawIdentityKey(_responderIdentityKey));
    }
    return output.toBytes();
  }

  static Uint8List _rawIdentityKey(String? identityKey) {
    if (identityKey == null) {
      throw const FormatException(
        'PQXDH transcript 2 requires both identity keys',
      );
    }
    final Uint8List raw;
    try {
      raw = base64Decode(identityKey);
    } on FormatException {
      throw const FormatException('Invalid PQXDH transcript identity key');
    }
    if (raw.length != 32) {
      throw const FormatException('Invalid PQXDH transcript identity key');
    }
    return raw;
  }

  static Uint8List _decodeLowercaseHex(String value) => Uint8List.fromList(
    List<int>.generate(
      value.length ~/ 2,
      (index) =>
          int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
      growable: false,
    ),
  );

  static void _appendLengthPrefixed(BytesBuilder output, List<int> value) {
    _appendU32(output, value.length);
    output.add(value);
  }

  static void _appendU32(BytesBuilder output, int value) {
    final bytes = ByteData(4)..setUint32(0, value, Endian.big);
    output.add(bytes.buffer.asUint8List());
  }

  static void _appendU64(BytesBuilder output, int value) {
    if (value < 0 || value > RisaalCryptoProtocol.maxServerSafeInt) {
      throw const FormatException('Integer exceeds canonical u64 boundary');
    }
    const u32Radix = 0x100000000;
    final high = value ~/ u32Radix;
    final low = value % u32Radix;
    final bytes = ByteData(8)
      ..setUint32(0, high, Endian.big)
      ..setUint32(4, low, Endian.big);
    output.add(bytes.buffer.asUint8List());
  }

  @override
  bool operator ==(Object other) =>
      other is PreKeyHandshakeRouting &&
      opkRoute == other.opkRoute &&
      recipientSignedPreKeyId == other.recipientSignedPreKeyId &&
      usedOneTimePreKeyId == other.usedOneTimePreKeyId &&
      transcriptVersion == other.transcriptVersion &&
      kemMetadata.cryptoProtocolEpoch ==
          other.kemMetadata.cryptoProtocolEpoch &&
      kemMetadata.kemSuite == other.kemMetadata.kemSuite &&
      kemMetadata.kemStandard == other.kemMetadata.kemStandard &&
      kemMetadata.kemWireVersion == other.kemMetadata.kemWireVersion &&
      kemMetadata.recipientKeyId == other.kemMetadata.recipientKeyId;

  @override
  int get hashCode => Object.hash(
    opkRoute,
    recipientSignedPreKeyId,
    usedOneTimePreKeyId,
    transcriptVersion,
    kemMetadata.cryptoProtocolEpoch,
    kemMetadata.kemSuite,
    kemMetadata.kemStandard,
    kemMetadata.kemWireVersion,
    kemMetadata.recipientKeyId,
  );
}
