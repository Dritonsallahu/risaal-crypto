import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashing;
import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart';

import '../secure_memory.dart';

/// Constants of the device-transfer handshake (R4-M37, contract §2).
///
/// Notation (normative, mirrored by the vectors in
/// `test/vectors/r4_m37_transfer_v1.json`):
///   - `lp(x) = u32be(len(x)) || x`; every `a || b` of the contract is
///     `lp(a) || lp(b)`; a named composite (the transcript) is one operand.
///   - QR bytes = `0x01 || lp(s) || lp(eO.pub) || lp(kO.pub) || lp(apiHost)`,
///     shown as `rx1:` + base64url without padding.
///   - `slot = SHA-256(lp("risaal-xfer-slot-v1") || lp(s))`; the slot id is its
///     lowercase hex.
///   - `transcript = lp(eO.pub) || lp(kO.pub) || lp(eN.pub) || lp(ct)`.
///   - `K = HKDF-SHA-256(salt = s, ikm = lp(X25519) || lp(ssKem),
///     info = lp("risaal-xfer-v1") || lp(transcript))`, 32 bytes.
///   - `K_mac`, `K_enc` and the SAS bytes are `HKDF-SHA-256(salt = 32 zero
///     bytes, ikm = K, info = lp(domain))` with the three subkey domains below.
///   - `getTag = HMAC(K_mac, lp("get") || lp(transcript))`, `completeTag`
///     likewise with "complete", and the join
///     `mac = HMAC(K_mac, lp("join") || lp(transcript) || lp(getTag) ||
///     lp(completeTag))`.
///   - Key confirmation O -> N (§2f): `confirmTag = HMAC(K_mac,
///     lp("confirm") || lp(transcript))`. The new phone's SAS is readable only
///     after its own `confirmTag` matched the old phone's.
///   - Chunk `i` of `total`: AES-256-GCM under `K_enc`, nonce
///     `0x00000000 || u64be(i)`, AAD `lp(slot) || lp(u32be(i)) ||
///     lp(u32be(total))`, sent as ciphertext || 16-byte tag.
abstract final class TransferProtocol {
  static const int version = 1;
  static const String qrPrefix = 'rx1:';

  static const String slotDomain = 'risaal-xfer-slot-v1';
  static const String keyDomain = 'risaal-xfer-v1';

  /// Subkey domains. The contract names K only; these separate its uses.
  static const String macKeyDomain = 'risaal-xfer-mac-v1';
  static const String encKeyDomain = 'risaal-xfer-enc-v1';
  static const String sasDomain = 'risaal-xfer-sas-v1';

  static const String getLabel = 'get';
  static const String completeLabel = 'complete';
  static const String joinLabel = 'join';
  static const String confirmLabel = 'confirm';

  static const int secretBytes = 32;
  static const int x25519Bytes = 32;
  static const int kemPublicKeyBytes = 1184;
  static const int kemCiphertextBytes = 1088;
  static const int tagBytes = 32;
  static const int gcmTagBytes = 16;
  static const int maxApiHostBytes = 253;

  static const int defaultChunkBytes = 1024 * 1024;
  static const int maxChunkBytes = 16 * 1024 * 1024;
  static const int maxChunks = 65536;
}

/// The old phone refused a join: a wrong QR, relay tampering, or a foreign
/// joiner. The offer is burned; start a new transfer.
final class TransferJoinRejected implements Exception {
  const TransferJoinRejected();

  @override
  String toString() => 'TransferJoinRejected';
}

/// The new phone refused the old phone's key confirmation: the old phone
/// accepted a join other than this phone's (a relay substituted it, or someone
/// else used the QR), or the tag was altered. This phone's keys are burned and
/// its code is never shown; stop and start a new transfer.
final class TransferConfirmRejected implements Exception {
  const TransferConfirmRejected();

  @override
  String toString() => 'TransferConfirmRejected';
}

/// An archive chunk did not authenticate: tampered, reordered, dropped,
/// added, or from another transfer. Discard everything staged.
final class TransferArchiveDecryptFailed implements Exception {
  const TransferArchiveDecryptFailed();

  @override
  String toString() => 'TransferArchiveDecryptFailed';
}

/// Entry point of the QR handshake.
abstract final class TransferHandshake {
  /// Old phone: generate `s`, `eO` and `kO` for one transfer to [apiHost]
  /// (`host` or `host:port`, ASCII). Throws [ArgumentError] on a bad host.
  static Future<TransferOffer> offer({required String apiHost}) async {
    if (!_isValidHost(apiHost)) {
      throw ArgumentError.value(apiHost, 'apiHost', 'not a valid host');
    }
    final secret = _randomBytes(TransferProtocol.secretBytes);
    final keyPair = await _x25519.newKeyPair();
    final private = SecureMemory.ownedCopy(
      await keyPair.extractPrivateKeyBytes(),
    );
    final public = Uint8List.fromList((await keyPair.extractPublicKey()).bytes);
    keyPair.destroy();
    final (kemPublic, kemSecret) = PqcKem.kyber768.generateKeyPair();
    return TransferOffer._(
      _TransferQr(secret, public, kemPublic, apiHost),
      private,
      kemSecret,
    );
  }

  /// New phone: scan [qrText], generate `eN`, encapsulate to `kO.pub` and
  /// derive the session keys and the join body. Throws [FormatException] for
  /// anything but a well-formed v1 QR.
  static Future<TransferJoin> join(String qrText) async {
    final qr = _TransferQr.decode(qrText);
    Uint8List? private;
    Uint8List? sharedSecret;
    try {
      final (Uint8List ciphertext, Uint8List secret) encapsulated;
      try {
        encapsulated = PqcKem.kyber768.encapsulate(qr.oldKemPublic);
      } on Object {
        throw const FormatException('Invalid ML-KEM key in the transfer QR');
      }
      sharedSecret = encapsulated.$2;
      final keyPair = await _x25519.newKeyPair();
      private = SecureMemory.ownedCopy(await keyPair.extractPrivateKeyBytes());
      keyPair.destroy();
      return await TransferJoin._derive(
        qr,
        private,
        encapsulated.$1,
        sharedSecret,
      );
    } finally {
      if (private != null) SecureMemory.zeroBytes(private);
      if (sharedSecret != null) SecureMemory.zeroBytes(sharedSecret);
      qr.dispose();
    }
  }
}

/// The old phone's side of one transfer: the QR, then the join check.
final class TransferOffer {
  TransferOffer._(this._qr, this._x25519Private, this._kemSecret)
    : _qrText = _qr.encode();

  final _TransferQr _qr;
  Uint8List? _x25519Private;
  Uint8List? _kemSecret;
  String? _qrText;
  bool _used = false;

  /// `rx1:` + base64url(QR bytes). It carries `s`: show it only on the
  /// secure QR screen and drop it when the screen closes.
  String get qrText {
    final text = _qrText;
    if (text == null) throw StateError('Transfer offer disposed');
    return text;
  }

  /// Lowercase hex SHA-256 slot id the server keys the transfer on.
  String get slotId => _qr.slotId;

  String get apiHost => _qr.apiHost;

  /// Recompute `K` from the new phone's join and check its MAC and both
  /// tags in constant time. Single use, whatever the outcome: a refused join
  /// burns the offer ([TransferJoinRejected]), and the private keys are
  /// zeroed either way. The returned keys seal the archive.
  Future<TransferSessionKeys> verifyJoin(TransferJoinRequest join) async {
    final x25519Private = _x25519Private;
    final kemSecret = _kemSecret;
    if (_used || x25519Private == null || kemSecret == null) {
      throw StateError('Transfer offer already used or disposed');
    }
    _used = true;
    Uint8List? dh;
    Uint8List? sharedSecret;
    _KeySchedule? schedule;
    try {
      dh = await _x25519SharedSecret(x25519Private, join._newX25519Public);
      sharedSecret = PqcKem.kyber768.decapsulate(
        kemSecret,
        join._kemCiphertext,
      );
      final transcript = _lengthPrefixed(<List<int>>[
        _qr.oldX25519Public,
        _qr.oldKemPublic,
        join._newX25519Public,
        join._kemCiphertext,
      ]);
      schedule = await _KeySchedule.derive(
        secret: _qr.secret,
        x25519Shared: dh,
        kemSharedSecret: sharedSecret,
        transcript: transcript,
      );
      final tags = await _Tags.compute(schedule.kMac, transcript);
      // Non-short-circuit `&`: every comparison always runs.
      final accepted =
          _constantTimeEquals(tags.mac, join._mac) &
          _constantTimeEquals(tags.getTag, join._getTag) &
          _constantTimeEquals(tags.completeTag, join._completeTag) &
          !_isAllZero(dh);
      if (!accepted) throw const TransferJoinRejected();
      return TransferSessionKeys._(
        slot: _qr.slot,
        encKey: SecureMemory.ownedCopy(schedule.kEnc),
        sas: _sas6(schedule.sasBytes),
        getTag: tags.getTag,
        completeTag: tags.completeTag,
        confirmTag: tags.confirmTag,
        sealer: true,
      );
    } on TransferJoinRejected {
      rethrow;
    } on Object {
      throw const TransferJoinRejected();
    } finally {
      if (dh != null) SecureMemory.zeroBytes(dh);
      if (sharedSecret != null) SecureMemory.zeroBytes(sharedSecret);
      schedule?.zero();
      dispose();
    }
  }

  /// Zero `s`, `eO` and `kO` (best effort, see [SecureMemory]) and drop the
  /// QR text. The offer cannot be used afterwards.
  void dispose() {
    final x25519Private = _x25519Private;
    final kemSecret = _kemSecret;
    if (x25519Private != null) SecureMemory.zeroBytes(x25519Private);
    if (kemSecret != null) SecureMemory.zeroBytes(kemSecret);
    _x25519Private = null;
    _kemSecret = null;
    _qrText = null;
    _qr.dispose();
  }
}

/// The new phone's side: the join body for the server and the session keys.
final class TransferJoin {
  TransferJoin._(this.apiHost, this.slotId, this.request, this.keys);

  /// The server the QR names (`host` or `host:port`).
  final String apiHost;

  /// Lowercase hex slot id for `POST /devices/transfer/{slot}/join`.
  final String slotId;

  /// The join body (`toJson()`).
  final TransferJoinRequest request;

  /// Tags, the key confirmation check, the SAS (only after
  /// [TransferSessionKeys.verifyConfirm]) and the archive opener.
  final TransferSessionKeys keys;

  void dispose() => keys.dispose();

  static Future<TransferJoin> _derive(
    _TransferQr qr,
    Uint8List x25519Private,
    Uint8List kemCiphertext,
    Uint8List kemSharedSecret,
  ) async {
    Uint8List? dh;
    _KeySchedule? schedule;
    try {
      dh = await _x25519SharedSecret(x25519Private, qr.oldX25519Public);
      if (_isAllZero(dh)) {
        throw const FormatException('Invalid X25519 key in the transfer QR');
      }
      final newPublic = await _x25519PublicKey(x25519Private);
      final transcript = _lengthPrefixed(<List<int>>[
        qr.oldX25519Public,
        qr.oldKemPublic,
        newPublic,
        kemCiphertext,
      ]);
      schedule = await _KeySchedule.derive(
        secret: qr.secret,
        x25519Shared: dh,
        kemSharedSecret: kemSharedSecret,
        transcript: transcript,
      );
      final tags = await _Tags.compute(schedule.kMac, transcript);
      return TransferJoin._(
        qr.apiHost,
        qr.slotId,
        TransferJoinRequest._(
          newPublic,
          Uint8List.fromList(kemCiphertext),
          tags.getTag,
          tags.completeTag,
          tags.mac,
        ),
        TransferSessionKeys._(
          slot: qr.slot,
          encKey: SecureMemory.ownedCopy(schedule.kEnc),
          sas: _sas6(schedule.sasBytes),
          getTag: tags.getTag,
          completeTag: tags.completeTag,
          confirmTag: tags.confirmTag,
          sealer: false,
        ),
      );
    } finally {
      if (dh != null) SecureMemory.zeroBytes(dh);
      schedule?.zero();
    }
  }
}

/// The join body `{eN, ct, getTag, completeTag, mac}` (contract §2 step 2).
/// Every field is base64url without padding.
final class TransferJoinRequest {
  TransferJoinRequest._(
    this._newX25519Public,
    this._kemCiphertext,
    this._getTag,
    this._completeTag,
    this._mac,
  );

  /// Strict: exactly the five fields, canonical unpadded base64url, exact
  /// lengths. Throws [FormatException] otherwise.
  factory TransferJoinRequest.fromJson(Map<String, Object?> json) {
    if (json.length != _fieldBytes.length ||
        !_fieldBytes.keys.every(json.containsKey)) {
      throw const FormatException('Invalid transfer join body');
    }
    Uint8List field(String name) {
      final value = json[name];
      if (value is! String) {
        throw const FormatException('Invalid transfer join body');
      }
      return _decodeBase64Url(value, _fieldBytes[name]!);
    }

    return TransferJoinRequest._(
      field('eN'),
      field('ct'),
      field('getTag'),
      field('completeTag'),
      field('mac'),
    );
  }

  static const Map<String, int> _fieldBytes = <String, int>{
    'eN': TransferProtocol.x25519Bytes,
    'ct': TransferProtocol.kemCiphertextBytes,
    'getTag': TransferProtocol.tagBytes,
    'completeTag': TransferProtocol.tagBytes,
    'mac': TransferProtocol.tagBytes,
  };

  final Uint8List _newX25519Public;
  final Uint8List _kemCiphertext;
  final Uint8List _getTag;
  final Uint8List _completeTag;
  final Uint8List _mac;

  Uint8List get newX25519PublicKey => Uint8List.fromList(_newX25519Public);
  Uint8List get kemCiphertext => Uint8List.fromList(_kemCiphertext);
  Uint8List get getTag => Uint8List.fromList(_getTag);
  Uint8List get completeTag => Uint8List.fromList(_completeTag);
  Uint8List get mac => Uint8List.fromList(_mac);

  Map<String, String> toJson() => <String, String>{
    'eN': _encodeBase64Url(_newX25519Public),
    'ct': _encodeBase64Url(_kemCiphertext),
    'getTag': _encodeBase64Url(_getTag),
    'completeTag': _encodeBase64Url(_completeTag),
    'mac': _encodeBase64Url(_mac),
  };
}

/// What both phones hold after the handshake: the SAS, the server
/// capabilities, the key confirmation, and `K_enc` for the archive.
///
/// The old phone's keys seal the archive exactly once (the nonces are a
/// counter, so a second sealing under the same key would reuse them); the
/// new phone's keys only open it.
final class TransferSessionKeys {
  TransferSessionKeys._({
    required Uint8List slot,
    required Uint8List encKey,
    required String sas,
    required Uint8List getTag,
    required Uint8List completeTag,
    required Uint8List confirmTag,
    required bool sealer,
  }) : _slot = Uint8List.fromList(slot),
       _encKey = encKey,
       _sas = sas,
       getTag = _encodeBase64Url(getTag),
       completeTag = _encodeBase64Url(completeTag),
       _confirmTag = confirmTag,
       _sealer = sealer,
       // The old phone committed to this one join in verifyJoin (single use).
       // The new phone must first see the old phone's confirmTag.
       _confirmed = sealer;

  static final AesGcm _aesGcm = AesGcm.with256bits();

  final Uint8List _slot;
  Uint8List? _encKey;
  final bool _sealer;
  bool _sealed = false;
  final String _sas;
  final Uint8List _confirmTag;
  bool _confirmed;
  bool _confirmChecked = false;

  /// The 6-digit short authentication string both phones show.
  ///
  /// The old phone's is readable once [TransferOffer.verifyJoin] returned.
  /// The new phone's throws [StateError] until [verifyConfirm] accepted the
  /// old phone's [confirmTag] (contract §2f): a code shown before that is a
  /// target a relay holding the QR could grind a substituted join against.
  String get sas {
    if (!_confirmed) {
      throw StateError('Transfer code not confirmed by the old phone');
    }
    return _sas;
  }

  /// Old phone only: `confirmTag`, base64url without padding (43 characters).
  /// Publish it with `PUT /devices/transfer/:slot/confirm` right after
  /// [TransferOffer.verifyJoin]: it tells the new phone which join this
  /// phone accepted. Not secret. Throws [StateError] on the new phone.
  String get confirmTag {
    if (!_sealer) {
      throw StateError('Only the old phone publishes the key confirmation');
    }
    return _encodeBase64Url(_confirmTag);
  }

  /// New phone only, once: check the old phone's [confirmTag] (from
  /// `GET /devices/transfer/:slot/confirm`) against this phone's own `K`, in
  /// constant time. On success [sas] becomes readable.
  ///
  /// Anything else (a tag under another `K`, an altered or malformed tag)
  /// throws [TransferConfirmRejected] and burns these keys: the code is never
  /// shown and the archive cannot be opened. A second call throws
  /// [StateError], whatever the first outcome.
  void verifyConfirm(String confirmTag) {
    if (_sealer) {
      throw StateError('Only the new phone verifies the key confirmation');
    }
    _requireKey();
    if (_confirmChecked) throw StateError('Key confirmation already checked');
    _confirmChecked = true;
    Uint8List? received;
    try {
      received = _decodeBase64Url(confirmTag, TransferProtocol.tagBytes);
    } on FormatException {
      received = null;
    }
    if (received == null || !_constantTimeEquals(_confirmTag, received)) {
      // Never confirmed, never checked again: the code stays unreadable.
      dispose();
      throw const TransferConfirmRejected();
    }
    _confirmed = true;
  }

  /// `getTag`, base64url: the `X-Risaal-Transfer-Proof` header for the
  /// archive download.
  final String getTag;

  /// `completeTag`, base64url: the proof for `POST .../complete`.
  final String completeTag;

  String get slotId => _hex(_slot);

  /// Old phone only, once: split [archive] into chunks of [chunkBytes] and
  /// seal each. Cache the result for retries; never seal again.
  Future<List<Uint8List>> sealArchive(
    List<int> archive, {
    int chunkBytes = TransferProtocol.defaultChunkBytes,
  }) async {
    final key = _requireKey();
    if (!_sealer) throw StateError('Only the old phone seals the archive');
    if (_sealed) throw StateError('The archive of this transfer is sealed');
    if (chunkBytes <= 0 || chunkBytes > TransferProtocol.maxChunkBytes) {
      throw ArgumentError.value(chunkBytes, 'chunkBytes');
    }
    if (archive.isEmpty) {
      throw ArgumentError.value(archive.length, 'archive', 'is empty');
    }
    final total = (archive.length + chunkBytes - 1) ~/ chunkBytes;
    if (total > TransferProtocol.maxChunks) {
      throw ArgumentError.value(total, 'archive', 'needs too many chunks');
    }
    // Before the first encryption: a failure midway must not allow a second
    // sealing under the same (key, nonce) pairs.
    _sealed = true;
    final chunks = <Uint8List>[];
    for (var index = 0; index < total; index++) {
      final start = index * chunkBytes;
      final end = min(start + chunkBytes, archive.length);
      final plain = Uint8List(end - start)
        ..setRange(0, end - start, archive, start);
      final SecretBox box;
      try {
        box = await _aesGcm.encrypt(
          plain,
          secretKey: SecretKey(key),
          nonce: _chunkNonce(index),
          aad: _chunkAad(_slot, index, total),
        );
      } finally {
        SecureMemory.zeroBytes(plain);
      }
      final chunk = Uint8List(box.cipherText.length + box.mac.bytes.length)
        ..setAll(0, box.cipherText)
        ..setAll(box.cipherText.length, box.mac.bytes);
      chunks.add(chunk);
    }
    return chunks;
  }

  /// New phone only: authenticate and decrypt chunk [index] of [total].
  Future<Uint8List> openChunk({
    required int index,
    required int total,
    required List<int> chunk,
  }) async {
    final key = _requireKey();
    if (_sealer) throw StateError('Only the new phone opens the archive');
    if (total < 1 ||
        total > TransferProtocol.maxChunks ||
        index < 0 ||
        index >= total ||
        chunk.length <= TransferProtocol.gcmTagBytes ||
        chunk.length >
            TransferProtocol.maxChunkBytes + TransferProtocol.gcmTagBytes) {
      throw const TransferArchiveDecryptFailed();
    }
    final split = chunk.length - TransferProtocol.gcmTagBytes;
    try {
      final plain = await _aesGcm.decrypt(
        SecretBox(
          chunk.sublist(0, split),
          nonce: _chunkNonce(index),
          mac: Mac(chunk.sublist(split)),
        ),
        secretKey: SecretKey(key),
        aad: _chunkAad(_slot, index, total),
      );
      if (plain is Uint8List) return plain;
      final out = Uint8List.fromList(plain);
      SecureMemory.zeroBytes(plain);
      return out;
    } on Object {
      throw const TransferArchiveDecryptFailed();
    }
  }

  /// New phone only: open every chunk, in order, as one archive. The chunk
  /// count is the `total` each chunk was sealed with, so a dropped, added or
  /// reordered chunk fails.
  Future<Uint8List> openArchive(List<List<int>> chunks) async {
    _requireKey();
    if (_sealer) throw StateError('Only the new phone opens the archive');
    if (chunks.isEmpty || chunks.length > TransferProtocol.maxChunks) {
      throw const TransferArchiveDecryptFailed();
    }
    final parts = <Uint8List>[];
    try {
      for (var index = 0; index < chunks.length; index++) {
        parts.add(
          await openChunk(
            index: index,
            total: chunks.length,
            chunk: chunks[index],
          ),
        );
      }
      final out = Uint8List(parts.fold<int>(0, (sum, p) => sum + p.length));
      var offset = 0;
      for (final part in parts) {
        out.setAll(offset, part);
        offset += part.length;
      }
      return out;
    } finally {
      for (final part in parts) {
        SecureMemory.zeroBytes(part);
      }
    }
  }

  /// Zero `K_enc` (best effort). The keys cannot be used afterwards.
  void dispose() {
    final key = _encKey;
    if (key != null) SecureMemory.zeroBytes(key);
    _encKey = null;
  }

  Uint8List _requireKey() {
    final key = _encKey;
    if (key == null) throw StateError('Transfer keys disposed');
    return key;
  }
}

// ── Internals ──────────────────────────────────────────────────────────

final X25519 _x25519 = X25519();
final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
final Hmac _hmac = Hmac.sha256();
final Random _random = Random.secure();

/// `host` or `host:port`: ASCII letters, digits, dots and hyphens.
final RegExp _hostPattern = RegExp(
  r'^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::([0-9]{1,5}))?$',
);
final RegExp _base64UrlPattern = RegExp(r'^[A-Za-z0-9_-]*$');

bool _isValidHost(String host) {
  if (host.isEmpty || host.length > TransferProtocol.maxApiHostBytes) {
    return false;
  }
  final match = _hostPattern.firstMatch(host);
  if (match == null) return false;
  final port = match.group(1);
  return port == null || int.parse(port) <= 65535;
}

Uint8List _randomBytes(int length) =>
    Uint8List.fromList(List<int>.generate(length, (_) => _random.nextInt(256)));

Uint8List _utf8(String value) => Uint8List.fromList(utf8.encode(value));

/// `lp(p0) || lp(p1) || ...` with `lp(x) = u32be(len(x)) || x`.
Uint8List _lengthPrefixed(List<List<int>> parts) {
  var length = 0;
  for (final part in parts) {
    length += 4 + part.length;
  }
  final out = Uint8List(length);
  final view = ByteData.sublistView(out);
  var offset = 0;
  for (final part in parts) {
    view.setUint32(offset, part.length);
    out.setAll(offset + 4, part);
    offset += 4 + part.length;
  }
  return out;
}

Uint8List _u32(int value) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, value);

Uint8List _chunkNonce(int index) {
  final nonce = Uint8List(12);
  final view = ByteData.sublistView(nonce);
  view.setUint32(4, index ~/ 0x100000000);
  view.setUint32(8, index % 0x100000000);
  return nonce;
}

Uint8List _chunkAad(Uint8List slot, int index, int total) =>
    _lengthPrefixed(<List<int>>[slot, _u32(index), _u32(total)]);

bool _constantTimeEquals(List<int> left, List<int> right) {
  var difference = left.length ^ right.length;
  final shared = left.length < right.length ? left.length : right.length;
  for (var i = 0; i < shared; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference == 0;
}

bool _isAllZero(List<int> bytes) {
  var accumulator = 0;
  for (final byte in bytes) {
    accumulator |= byte;
  }
  return accumulator == 0;
}

String _hex(List<int> bytes) {
  final out = StringBuffer();
  for (final byte in bytes) {
    out.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

String _encodeBase64Url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Canonical unpadded base64url of exactly [length] bytes (any length when
/// null), or [FormatException].
Uint8List _decodeBase64Url(String text, int? length) {
  if (!_base64UrlPattern.hasMatch(text) || text.length % 4 == 1) {
    throw const FormatException('Invalid base64url');
  }
  final Uint8List bytes;
  try {
    bytes = base64Url.decode(base64Url.normalize(text));
  } on FormatException {
    throw const FormatException('Invalid base64url');
  }
  if (_encodeBase64Url(bytes) != text ||
      (length != null && bytes.length != length)) {
    throw const FormatException('Invalid base64url field');
  }
  return bytes;
}

Future<Uint8List> _x25519SharedSecret(
  Uint8List privateKey,
  Uint8List remotePublic,
) async {
  final keyPair = await _x25519.newKeyPairFromSeed(privateKey);
  try {
    final secret = await _x25519.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: SimplePublicKey(
        Uint8List.fromList(remotePublic),
        type: KeyPairType.x25519,
      ),
    );
    final out = SecureMemory.ownedCopy(await secret.extractBytes());
    secret.destroy();
    return out;
  } finally {
    keyPair.destroy();
  }
}

Future<Uint8List> _x25519PublicKey(Uint8List privateKey) async {
  final keyPair = await _x25519.newKeyPairFromSeed(privateKey);
  final public = Uint8List.fromList((await keyPair.extractPublicKey()).bytes);
  keyPair.destroy();
  return public;
}

Future<Uint8List> _hkdf32({
  required List<int> ikm,
  required List<int> salt,
  required List<int> info,
}) async {
  final key = await _hkdf.deriveKey(
    secretKey: SecretKey(ikm),
    nonce: salt,
    info: info,
  );
  final out = SecureMemory.ownedCopy(await key.extractBytes());
  key.destroy();
  return out;
}

Future<Uint8List> _hmacSha256(List<int> key, List<int> data) async {
  final mac = await _hmac.calculateMac(data, secretKey: SecretKey(key));
  return Uint8List.fromList(mac.bytes);
}

/// Six uniform decimal digits by rejection sampling: each big-endian u32 of
/// [bytes] below `floor(2^32 / 10^6) * 10^6` is accepted and reduced mod
/// 10^6; the first accepted word wins. 32 bytes give 8 candidates; all eight
/// are rejected with probability about 6.6e-30, and then this throws.
String _sas6(List<int> bytes) {
  const limit = 4294000000;
  final data = ByteData.sublistView(Uint8List.fromList(bytes));
  for (var offset = 0; offset + 4 <= data.lengthInBytes; offset += 4) {
    final word = data.getUint32(offset);
    if (word < limit) return (word % 1000000).toString().padLeft(6, '0');
  }
  throw StateError('No SAS candidate accepted');
}

final class _KeySchedule {
  _KeySchedule(this.k, this.kMac, this.kEnc, this.sasBytes);

  final Uint8List k;
  final Uint8List kMac;
  final Uint8List kEnc;
  final Uint8List sasBytes;

  static Future<_KeySchedule> derive({
    required List<int> secret,
    required List<int> x25519Shared,
    required List<int> kemSharedSecret,
    required Uint8List transcript,
  }) async {
    final ikm = _lengthPrefixed(<List<int>>[x25519Shared, kemSharedSecret]);
    final Uint8List k;
    try {
      k = await _hkdf32(
        ikm: ikm,
        salt: secret,
        info: _lengthPrefixed(<List<int>>[
          _utf8(TransferProtocol.keyDomain),
          transcript,
        ]),
      );
    } finally {
      SecureMemory.zeroBytes(ikm);
    }
    final zeroSalt = Uint8List(32);
    Future<Uint8List> subkey(String domain) => _hkdf32(
      ikm: k,
      salt: zeroSalt,
      info: _lengthPrefixed(<List<int>>[_utf8(domain)]),
    );
    return _KeySchedule(
      k,
      await subkey(TransferProtocol.macKeyDomain),
      await subkey(TransferProtocol.encKeyDomain),
      await subkey(TransferProtocol.sasDomain),
    );
  }

  void zero() {
    SecureMemory.zeroBytes(k);
    SecureMemory.zeroBytes(kMac);
    SecureMemory.zeroBytes(kEnc);
    SecureMemory.zeroBytes(sasBytes);
  }
}

final class _Tags {
  _Tags(this.getTag, this.completeTag, this.mac, this.confirmTag);

  final Uint8List getTag;
  final Uint8List completeTag;
  final Uint8List mac;
  final Uint8List confirmTag;

  static Future<_Tags> compute(Uint8List kMac, Uint8List transcript) async {
    final getTag = await _hmacSha256(
      kMac,
      _lengthPrefixed(<List<int>>[
        _utf8(TransferProtocol.getLabel),
        transcript,
      ]),
    );
    final completeTag = await _hmacSha256(
      kMac,
      _lengthPrefixed(<List<int>>[
        _utf8(TransferProtocol.completeLabel),
        transcript,
      ]),
    );
    final mac = await _hmacSha256(
      kMac,
      _lengthPrefixed(<List<int>>[
        _utf8(TransferProtocol.joinLabel),
        transcript,
        getTag,
        completeTag,
      ]),
    );
    final confirmTag = await _hmacSha256(
      kMac,
      _lengthPrefixed(<List<int>>[
        _utf8(TransferProtocol.confirmLabel),
        transcript,
      ]),
    );
    return _Tags(getTag, completeTag, mac, confirmTag);
  }
}

/// The QR payload. Holds `s` until [dispose].
final class _TransferQr {
  _TransferQr(
    this.secret,
    this.oldX25519Public,
    this.oldKemPublic,
    this.apiHost,
  ) : slot = Uint8List.fromList(
        hashing.sha256
            .convert(
              _lengthPrefixed(<List<int>>[
                _utf8(TransferProtocol.slotDomain),
                secret,
              ]),
            )
            .bytes,
      );

  final Uint8List secret;
  final Uint8List oldX25519Public;
  final Uint8List oldKemPublic;
  final String apiHost;
  final Uint8List slot;

  String get slotId => _hex(slot);

  String encode() {
    final payload = Uint8List.fromList(<int>[
      TransferProtocol.version,
      ..._lengthPrefixed(<List<int>>[
        secret,
        oldX25519Public,
        oldKemPublic,
        _utf8(apiHost),
      ]),
    ]);
    try {
      return '${TransferProtocol.qrPrefix}${_encodeBase64Url(payload)}';
    } finally {
      SecureMemory.zeroBytes(payload);
    }
  }

  /// Strict decode of `rx1:` + base64url(QR bytes); [FormatException]
  /// otherwise.
  static _TransferQr decode(String text) {
    if (!text.startsWith(TransferProtocol.qrPrefix)) {
      throw const FormatException('Not a transfer QR');
    }
    final payload = _decodeBase64Url(
      text.substring(TransferProtocol.qrPrefix.length),
      null,
    );
    try {
      if (payload.isEmpty || payload[0] != TransferProtocol.version) {
        throw const FormatException('Unsupported transfer QR version');
      }
      final view = ByteData.sublistView(payload);
      var offset = 1;
      Uint8List field(int minLength, int maxLength) {
        if (payload.length - offset < 4) {
          throw const FormatException('Truncated transfer QR');
        }
        final length = view.getUint32(offset);
        offset += 4;
        if (length < minLength ||
            length > maxLength ||
            payload.length - offset < length) {
          throw const FormatException('Invalid transfer QR field');
        }
        final value = Uint8List.fromList(
          Uint8List.sublistView(payload, offset, offset + length),
        );
        offset += length;
        return value;
      }

      final secret = field(
        TransferProtocol.secretBytes,
        TransferProtocol.secretBytes,
      );
      final oldX25519Public = field(
        TransferProtocol.x25519Bytes,
        TransferProtocol.x25519Bytes,
      );
      final oldKemPublic = field(
        TransferProtocol.kemPublicKeyBytes,
        TransferProtocol.kemPublicKeyBytes,
      );
      final hostBytes = field(1, TransferProtocol.maxApiHostBytes);
      if (offset != payload.length) {
        SecureMemory.zeroBytes(secret);
        throw const FormatException('Trailing bytes in the transfer QR');
      }
      final String apiHost;
      try {
        apiHost = ascii.decode(hostBytes);
      } on FormatException {
        SecureMemory.zeroBytes(secret);
        throw const FormatException('Invalid host in the transfer QR');
      }
      if (!_isValidHost(apiHost)) {
        SecureMemory.zeroBytes(secret);
        throw const FormatException('Invalid host in the transfer QR');
      }
      return _TransferQr(secret, oldX25519Public, oldKemPublic, apiHost);
    } finally {
      SecureMemory.zeroBytes(payload);
    }
  }

  void dispose() => SecureMemory.zeroBytes(secret);
}

// ── Test hooks (not exported from the package library) ──────────────────

/// Builds an offer from fixed material (vectors only).
Future<TransferOffer> debugTransferOfferFromMaterial({
  required List<int> secret,
  required List<int> x25519Private,
  required List<int> kemPublic,
  required List<int> kemSecret,
  required String apiHost,
}) async {
  final private = Uint8List.fromList(x25519Private);
  return TransferOffer._(
    _TransferQr(
      Uint8List.fromList(secret),
      await _x25519PublicKey(private),
      Uint8List.fromList(kemPublic),
      apiHost,
    ),
    private,
    Uint8List.fromList(kemSecret),
  );
}

/// The new phone's side with a fixed `eN` and a fixed encapsulation
/// (vectors only).
Future<TransferJoin> debugTransferJoinFromMaterial({
  required String qrText,
  required List<int> x25519Private,
  required List<int> kemCiphertext,
  required List<int> kemSharedSecret,
}) async {
  final qr = _TransferQr.decode(qrText);
  try {
    return await TransferJoin._derive(
      qr,
      Uint8List.fromList(x25519Private),
      Uint8List.fromList(kemCiphertext),
      Uint8List.fromList(kemSharedSecret),
    );
  } finally {
    qr.dispose();
  }
}

/// The key schedule from fixed inputs (vectors only).
Future<({Uint8List k, Uint8List kMac, Uint8List kEnc, Uint8List sasBytes})>
debugTransferKeySchedule({
  required List<int> secret,
  required List<int> x25519Shared,
  required List<int> kemSharedSecret,
  required List<int> oldX25519Public,
  required List<int> oldKemPublic,
  required List<int> newX25519Public,
  required List<int> kemCiphertext,
}) async {
  final schedule = await _KeySchedule.derive(
    secret: secret,
    x25519Shared: x25519Shared,
    kemSharedSecret: kemSharedSecret,
    transcript: _lengthPrefixed(<List<int>>[
      oldX25519Public,
      oldKemPublic,
      newX25519Public,
      kemCiphertext,
    ]),
  );
  return (
    k: schedule.k,
    kMac: schedule.kMac,
    kEnc: schedule.kEnc,
    sasBytes: schedule.sasBytes,
  );
}

/// `sas6` over raw SAS bytes (vectors only).
String debugTransferSas6(List<int> sasBytes) => _sas6(sasBytes);
