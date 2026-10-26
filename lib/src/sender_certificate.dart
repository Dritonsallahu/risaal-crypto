import 'dart:convert';
import 'dart:typed_data';

import 'key_helper.dart';
import 'sealed_sender_errors.dart';

/// Domain separator for the Sender Certificate v1 server signature. The
/// trailing `\u0000` is the 0x00 separator byte required by the contract.
///
/// Contract v2 (R4-C3-V2) removed the per-recipient sender binding: an
/// Ed25519 signature by the sender's long-term key over the certificate and
/// the recipient's identity key was a transferable, non-deniable proof of
/// contact. Impersonation resistance comes from the identity-key equality
/// checks plus the deniable inner-message authentication (PQXDH / ratchet).
abstract final class SenderCertificateDomains {
  /// Prefix of the server signature input: `domain || certBytes`.
  static const String serverSignature = 'Risaal-SenderCert-v1\u0000';
}

/// A parsed Risaal Sender Certificate v1.
///
/// The certificate is the exact UTF-8 JSON the server signed, transported
/// opaque. [bytes] keeps those exact bytes; signatures are always checked
/// over [bytes] and the certificate is never re-serialized.
final class SenderCertificate {
  const SenderCertificate._({
    required this.bytes,
    required this.keyId,
    required this.senderId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
    required this.senderSigningKey,
    required this.issuedAt,
    required this.expiresAt,
  });

  /// Wire version (`v`).
  static const int version = 1;

  /// Longest accepted `expiresAt - issuedAt`.
  static const Duration maxValidity = Duration(days: 30);

  /// Tolerance applied around the validity window for sealed timestamps.
  static const Duration clockSkew = Duration(minutes: 5);

  static const _fields = {
    'expiresAt',
    'issuedAt',
    'keyId',
    'senderDeviceId',
    'senderId',
    'senderIdentityKey',
    'senderSigningKey',
    'v',
  };
  static final _keyIdPattern = RegExp(r'^[A-Za-z0-9_-]{1,64}$');
  static const _maxIdLength = 128;

  /// The exact certificate bytes as signed by the server.
  final Uint8List bytes;
  final String keyId;
  final String senderId;
  final String senderDeviceId;

  /// Standard base64 of the sender's 32-byte X25519 identity public key.
  final String senderIdentityKey;

  /// Standard base64 of the sender's 32-byte Ed25519 signing public key.
  final String senderSigningKey;

  /// Unix milliseconds.
  final int issuedAt;

  /// Unix milliseconds.
  final int expiresAt;

  /// Strictly parses certificate bytes (contract §1 / §5a).
  ///
  /// Throws [SealedSenderCertificateError] with
  /// [SenderCertificateFailure.malformed] unless the bytes are UTF-8 JSON
  /// with exactly the eight v1 fields, correct types, canonical 32-byte keys
  /// and `0 < expiresAt - issuedAt <= 30 days`.
  static SenderCertificate parse(Uint8List bytes) {
    final Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(bytes));
    } on Object {
      throw SealedSenderCertificateError(SenderCertificateFailure.malformed);
    }
    if (decoded is! Map<String, dynamic> ||
        decoded.length != _fields.length ||
        !decoded.keys.every(_fields.contains)) {
      throw SealedSenderCertificateError(SenderCertificateFailure.malformed);
    }
    final v = decoded['v'];
    final keyId = decoded['keyId'];
    final senderId = decoded['senderId'];
    final senderDeviceId = decoded['senderDeviceId'];
    final identityKey = decoded['senderIdentityKey'];
    final signingKey = decoded['senderSigningKey'];
    final issuedAt = decoded['issuedAt'];
    final expiresAt = decoded['expiresAt'];
    if (v is! int ||
        v != version ||
        keyId is! String ||
        !_keyIdPattern.hasMatch(keyId) ||
        !_isId(senderId) ||
        !_isId(senderDeviceId) ||
        !isCanonicalBase64(identityKey, length: 32) ||
        !isCanonicalBase64(signingKey, length: 32) ||
        issuedAt is! int ||
        expiresAt is! int ||
        issuedAt < 0) {
      throw SealedSenderCertificateError(SenderCertificateFailure.malformed);
    }
    final validity = expiresAt - issuedAt;
    if (validity <= 0 || validity > maxValidity.inMilliseconds) {
      throw SealedSenderCertificateError(SenderCertificateFailure.malformed);
    }
    return SenderCertificate._(
      bytes: Uint8List.fromList(bytes),
      keyId: keyId,
      senderId: senderId as String,
      senderDeviceId: senderDeviceId as String,
      senderIdentityKey: identityKey as String,
      senderSigningKey: signingKey as String,
      issuedAt: issuedAt,
      expiresAt: expiresAt,
    );
  }

  /// Whether a SEALED timestamp (set by the sender inside the AEAD) falls in
  /// `[issuedAt - clockSkew, expiresAt + clockSkew]`.
  bool coversSealedTimestamp(int tsMs) =>
      tsMs >= issuedAt - clockSkew.inMilliseconds &&
      tsMs <= expiresAt + clockSkew.inMilliseconds;

  /// Whether a sender may still seal with this certificate at [nowMs].
  bool usableAt(int nowMs) =>
      nowMs >= issuedAt - clockSkew.inMilliseconds && nowMs < expiresAt;

  static bool _isId(Object? value) =>
      value is String && value.isNotEmpty && value.length <= _maxIdLength;

  /// True when [value] is standard, padded base64 that round-trips exactly
  /// (and, when [length] is given, decodes to exactly that many bytes).
  static bool isCanonicalBase64(Object? value, {int? length}) {
    if (value is! String || value.isEmpty) return false;
    if (length != null && value.length != ((length + 2) ~/ 3) * 4) {
      return false;
    }
    try {
      final decoded = base64Decode(value);
      return (length == null || decoded.length == length) &&
          base64Encode(decoded) == value;
    } on Object {
      return false;
    }
  }
}

/// The server's issuance: opaque certificate bytes + server signature.
final class IssuedSenderCertificate {
  const IssuedSenderCertificate({
    required this.certificateBytes,
    required this.serverSignature,
  });

  /// Reads `certificate` + `serverSignature` from the server response (or a
  /// cached copy) and IGNORES every other key.
  ///
  /// Throws [SealedSenderCertificateError] ([SenderCertificateFailure.malformed])
  /// when either is missing or not canonical base64.
  factory IssuedSenderCertificate.fromIssuedJson(Map<String, dynamic> json) {
    final certificate = json['certificate'];
    final serverSignature = json['serverSignature'];
    if (!SenderCertificate.isCanonicalBase64(certificate) ||
        !SenderCertificate.isCanonicalBase64(serverSignature, length: 64)) {
      throw SealedSenderCertificateError(SenderCertificateFailure.malformed);
    }
    return IssuedSenderCertificate(
      certificateBytes: base64Decode(certificate as String),
      serverSignature: serverSignature as String,
    );
  }

  /// Exact certificate bytes (decoded from the `certificate` base64).
  final Uint8List certificateBytes;

  /// Standard base64 of the 64-byte Ed25519 server signature.
  final String serverSignature;

  /// Standard base64 of [certificateBytes].
  String get certificateBase64 => base64Encode(certificateBytes);

  Map<String, dynamic> toIssuedJson() => {
    'certificate': certificateBase64,
    'serverSignature': serverSignature,
  };
}

/// Sender Certificate v1 signing and verification (all Ed25519 via
/// [SignalKeyHelper.sign] / [SignalKeyHelper.verify]).
final class SenderCertificateVerifier {
  const SenderCertificateVerifier._();

  /// Contract steps a–c: parse, `keyId` pinned, server signature valid.
  ///
  /// Throws [SealedSenderCertificateError] with `malformed`, `unknownKeyId`
  /// or `badServerSignature`. A pinned key that is not canonical 32-byte
  /// base64 is treated as not pinned (fail closed).
  static Future<SenderCertificate> verifyIssued({
    required IssuedSenderCertificate issued,
    required Map<String, String> trustedServerSigningKeys,
  }) async {
    final cert = SenderCertificate.parse(issued.certificateBytes);
    if (!SenderCertificate.isCanonicalBase64(
      issued.serverSignature,
      length: 64,
    )) {
      throw SealedSenderCertificateError(SenderCertificateFailure.malformed);
    }
    final serverKey = trustedServerSigningKeys[cert.keyId];
    if (!SenderCertificate.isCanonicalBase64(serverKey, length: 32)) {
      throw SealedSenderCertificateError(SenderCertificateFailure.unknownKeyId);
    }
    if (!await _verify(
      serverKey!,
      _serverSignatureInput(cert.bytes),
      issued.serverSignature,
    )) {
      throw SealedSenderCertificateError(
        SenderCertificateFailure.badServerSignature,
      );
    }
    return cert;
  }

  /// Full recipient-side check in contract order (v2: malformed →
  /// unknownKeyId → badServerSignature → identityMismatch → time window) for
  /// one sealed payload. Returns the verified certificate or throws
  /// [SealedSenderCertificateError] with the first failing reason.
  static Future<SenderCertificate> verifyForEnvelope({
    required IssuedSenderCertificate issued,
    required Map<String, String> trustedServerSigningKeys,
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required int sealedTimestamp,
  }) async {
    final cert = await verifyIssued(
      issued: issued,
      trustedServerSigningKeys: trustedServerSigningKeys,
    );
    if (cert.senderId != senderId ||
        cert.senderDeviceId != senderDeviceId ||
        cert.senderIdentityKey != senderIdentityKey) {
      throw SealedSenderCertificateError(
        SenderCertificateFailure.identityMismatch,
      );
    }
    if (!cert.coversSealedTimestamp(sealedTimestamp)) {
      throw SealedSenderCertificateError(
        sealedTimestamp < cert.issuedAt
            ? SenderCertificateFailure.notYetValid
            : SenderCertificateFailure.expired,
      );
    }
    return cert;
  }

  /// TEST / SERVER-SIMULATION ONLY. Production certificates are issued by
  /// the server (`POST /auth/sender-certificate`); clients never hold the
  /// server signing key.
  ///
  /// Builds the compact, key-sorted v1 JSON exactly as the server does and
  /// signs it with [serverSigningPrivateKey] (base64 32-byte seed). No field
  /// validation is applied so tests can sign deliberately bad certificates.
  static Future<IssuedSenderCertificate> issueForTesting({
    required String serverSigningPrivateKey,
    required String keyId,
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
    required String senderSigningKey,
    required int issuedAt,
    required int expiresAt,
  }) async {
    final bytes = Uint8List.fromList(
      utf8.encode(
        jsonEncode(<String, Object>{
          'expiresAt': expiresAt,
          'issuedAt': issuedAt,
          'keyId': keyId,
          'senderDeviceId': senderDeviceId,
          'senderId': senderId,
          'senderIdentityKey': senderIdentityKey,
          'senderSigningKey': senderSigningKey,
          'v': SenderCertificate.version,
        }),
      ),
    );
    return IssuedSenderCertificate(
      certificateBytes: bytes,
      serverSignature: await SignalKeyHelper.sign(
        serverSigningPrivateKey,
        _serverSignatureInput(bytes),
      ),
    );
  }

  static Uint8List _serverSignatureInput(Uint8List certBytes) =>
      Uint8List.fromList([
        ...utf8.encode(SenderCertificateDomains.serverSignature),
        ...certBytes,
      ]);

  static Future<bool> _verify(
    String publicKey,
    List<int> data,
    String signature,
  ) async {
    try {
      return await SignalKeyHelper.verify(publicKey, data, signature);
    } on Object {
      return false;
    }
  }
}
