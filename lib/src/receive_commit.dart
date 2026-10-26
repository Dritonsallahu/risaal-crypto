import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'sealed_sender_trust_policy.dart';

/// The authenticated envelope family owned by one receive receipt.
enum ReceiveEnvelopeKind {
  directPreKey,
  directMessage,
  sealedPreKey,
  sealedMessage,
}

/// Stable, non-plaintext identity for one authenticated delivery.
final class ReceiveReceipt {
  static final RegExp _digestPattern = RegExp(r'^[0-9a-f]{64}$');

  final String deliveryIdHash;
  final String receiptId;
  final String envelopeDigest;
  final String senderId;
  final String senderDeviceId;
  final ReceiveEnvelopeKind kind;

  const ReceiveReceipt({
    required this.deliveryIdHash,
    required this.receiptId,
    required this.envelopeDigest,
    required this.senderId,
    required this.senderDeviceId,
    required this.kind,
  });

  factory ReceiveReceipt.create({
    required String deliveryId,
    required String envelopeDigest,
    required String senderId,
    required String senderDeviceId,
    required ReceiveEnvelopeKind kind,
  }) {
    final deliveryIdHash = hashDeliveryId(deliveryId);
    final normalizedSenderId = _requireIdentifier(senderId, field: 'sender id');
    final normalizedSenderDeviceId = _requireIdentifier(
      senderDeviceId,
      field: 'sender device id',
    );
    if (!_digestPattern.hasMatch(envelopeDigest)) {
      throw const FormatException('Invalid receive envelope digest');
    }
    final receiptId = crypto.sha256
        .convert(
          utf8.encode(
            jsonEncode(<Object>[
              'Risaal-Receive-Receipt-v1',
              deliveryIdHash,
              envelopeDigest,
              normalizedSenderId,
              normalizedSenderDeviceId,
              kind.name,
            ]),
          ),
        )
        .toString();
    return ReceiveReceipt(
      deliveryIdHash: deliveryIdHash,
      receiptId: receiptId,
      envelopeDigest: envelopeDigest,
      senderId: normalizedSenderId,
      senderDeviceId: normalizedSenderDeviceId,
      kind: kind,
    );
  }

  void requireValid() {
    if (!_digestPattern.hasMatch(deliveryIdHash) ||
        !_digestPattern.hasMatch(envelopeDigest)) {
      throw const FormatException('Invalid receive receipt');
    }
    final expectedReceiptId = _receiptId(
      deliveryIdHash: deliveryIdHash,
      envelopeDigest: envelopeDigest,
      senderId: _requireIdentifier(senderId, field: 'sender id'),
      senderDeviceId: _requireIdentifier(
        senderDeviceId,
        field: 'sender device id',
      ),
      kind: kind,
    );
    if (receiptId != expectedReceiptId || !_digestPattern.hasMatch(receiptId)) {
      throw const FormatException('Invalid receive receipt');
    }
  }

  bool matchesExact(ReceiveReceipt other) =>
      deliveryIdHash == other.deliveryIdHash &&
      receiptId == other.receiptId &&
      envelopeDigest == other.envelopeDigest &&
      senderId == other.senderId &&
      senderDeviceId == other.senderDeviceId &&
      kind == other.kind;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'deliveryIdHash': deliveryIdHash,
    'receiptId': receiptId,
    'envelopeDigest': envelopeDigest,
    'senderId': senderId,
    'senderDeviceId': senderDeviceId,
    'kind': kind.name,
  };

  factory ReceiveReceipt.fromJson(Map<String, dynamic> json) {
    final rawKind = json['kind'];
    final kinds = ReceiveEnvelopeKind.values.where(
      (candidate) => candidate.name == rawKind,
    );
    if (kinds.length != 1) {
      throw const FormatException('Invalid receive receipt kind');
    }
    final receipt = ReceiveReceipt(
      deliveryIdHash: json['deliveryIdHash'] as String? ?? '',
      receiptId: json['receiptId'] as String? ?? '',
      envelopeDigest: json['envelopeDigest'] as String? ?? '',
      senderId: json['senderId'] as String? ?? '',
      senderDeviceId: json['senderDeviceId'] as String? ?? '',
      kind: kinds.single,
    );
    receipt.requireValid();
    return receipt;
  }

  /// Identifiers that are safe to interpolate into a storage key.
  ///
  /// Storage keys are built by joining an id and a device id with `_`, and
  /// sibling namespaces live inside that same prefix
  /// (`crypto_e2_session_<id>_<dev>` vs `crypto_e2_session_ik_<id>_<dev>`).
  /// A peer-chosen id containing `_` therefore aliases another namespace and
  /// can overwrite a different peer's pinned identity key, and `("a","b_c")`
  /// would collide with `("a_b","c")`. Real identifiers are UUID v4 device ids
  /// and hex account ids, so restricting to unreserved characters makes the
  /// join bijective without needing any stored-data migration.
  static final RegExp _identifierPattern = RegExp(r'^[A-Za-z0-9-]{1,64}$');

  /// Words that name a namespace segment inside another key template.
  /// `crypto_e2_session_<id>_<dev>`, `crypto_e2_session_ik_<id>_<dev>` and
  /// `crypto_e2_session_devices_<id>` share a prefix, so an identifier equal to
  /// `ik` or `devices` makes one template's key collide with another's. A
  /// charset alone cannot separate templates of differing arity (P0-B).
  static const Set<String> _reservedIdSegments = <String>{'ik', 'devices'};

  static String _requireIdentifier(String value, {required String field}) {
    if (!_identifierPattern.hasMatch(value) ||
        _reservedIdSegments.contains(value)) {
      throw FormatException('Invalid $field');
    }
    return value;
  }

  /// A delivery id is only ever hashed — it never becomes a storage-key
  /// segment — so it must NOT be held to the storage-key charset.
  ///
  /// Applying that charset here was a real receive outage: production ids are
  /// built as `<namespace>:<sha256 hex>`, which is 72 characters and contains a
  /// colon, so every inbound message, edit, story, sender-key distribution and
  /// live-location update threw before any decryption was attempted. The
  /// package tests missed it because they all used short hyphen-only ids.
  ///
  /// What actually matters for a hashed value is that it is present and
  /// bounded: SHA-256 with a domain separator already makes it unambiguous.
  static final RegExp _deliveryIdPattern = RegExp(r'^[ -~]{1,512}$');

  static String _requireDeliveryId(String value) {
    if (!_deliveryIdPattern.hasMatch(value)) {
      throw const FormatException('Invalid delivery id');
    }
    return value;
  }

  static String hashDeliveryId(String deliveryId) {
    final normalized = _requireDeliveryId(deliveryId);
    return crypto.sha256.convert(<int>[
      ...utf8.encode('Risaal-Receive-Delivery-v1\u0000'),
      ...utf8.encode(normalized),
    ]).toString();
  }

  static String _receiptId({
    required String deliveryIdHash,
    required String envelopeDigest,
    required String senderId,
    required String senderDeviceId,
    required ReceiveEnvelopeKind kind,
  }) => crypto.sha256
      .convert(
        utf8.encode(
          jsonEncode(<Object>[
            'Risaal-Receive-Receipt-v1',
            deliveryIdHash,
            envelopeDigest,
            senderId,
            senderDeviceId,
            kind.name,
          ]),
        ),
      )
      .toString();
}

/// Result returned before the host commits its DB/media representation.
///
/// [plaintext] is deliberately absent for an already-acknowledged delivery;
/// the host must use its durable row rather than asking the crypto WAL to retain
/// message content.
final class PreparedReceive {
  final ReceiveReceipt receipt;
  final String? plaintext;

  /// What this receive established about the sender (R4-C3); `null` for an
  /// already-acknowledged delivery, whose evidence is not retained.
  final SenderAuthentication? senderAuthentication;

  const PreparedReceive._({
    required this.receipt,
    required this.plaintext,
    this.senderAuthentication,
  });

  factory PreparedReceive.pending({
    required ReceiveReceipt receipt,
    required String plaintext,
    SenderAuthentication? senderAuthentication,
  }) => PreparedReceive._(
    receipt: receipt,
    plaintext: plaintext,
    senderAuthentication: senderAuthentication,
  );

  factory PreparedReceive.alreadyAcknowledged(ReceiveReceipt receipt) =>
      PreparedReceive._(receipt: receipt, plaintext: null);

  bool get requiresHostPersistence => plaintext != null;
  bool get alreadyAcknowledged => plaintext == null;
}

/// Startup gate for a provisional receive whose host durability is unknown.
///
/// The host must look up [receipt] in its own durable store. If present, call
/// `acknowledgeReceive(receipt)`; otherwise call
/// `abortPreparedReceive(receipt)`. Initialization can then be retried.
final class ReceiveCommitRecoveryRequired extends StateError {
  final ReceiveReceipt receipt;

  ReceiveCommitRecoveryRequired(this.receipt)
    : super(
        'Receive host-durability reconciliation is required '
        '(receiptId=${receipt.receiptId})',
      );
}

enum ReceiveCommitPhase { prepared, commitDecided }

/// One exact secure-storage target in a receive WAL.
///
/// Only the target value is retained. The pre-state is represented by a
/// domain-separated digest, which is enough to detect drift while avoiding a
/// second full copy of large ratchet state.
final class ReceiveStorageMutation {
  final String key;
  final String beforeDigest;
  final String? afterValue;
  final String afterDigest;

  ReceiveStorageMutation({
    required this.key,
    required this.beforeDigest,
    required this.afterValue,
  }) : afterDigest = digestValue(afterValue) {
    requireValid();
  }

  ReceiveStorageMutation._({
    required this.key,
    required this.beforeDigest,
    required this.afterValue,
    required this.afterDigest,
  });

  static String digestValue(String? value) => crypto.sha256.convert(<int>[
    ...utf8.encode('Risaal-Receive-Value-v1\u0000'),
    if (value == null) 0 else 1,
    if (value != null) ...utf8.encode(value),
  ]).toString();

  /// Exactly the storage keys a receive commit is allowed to write.
  ///
  /// `startsWith('crypto_')` is not a namespace check: it accepts every crypto
  /// key in the store, including the identity key pair and the key-transparency
  /// records. Each template below pins its own prefix and constrains its
  /// interpolated segments to the storage-safe identifier charset, so a receive
  /// can only ever write the slots its planners are meant to produce.
  static final List<RegExp> _allowedKeyPatterns = <RegExp>[
    RegExp(r'^crypto_e2_session_[A-Za-z0-9-]{1,64}_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_session_ik_[A-Za-z0-9-]{1,64}_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_session_devices_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_peer_cap_[A-Za-z0-9-]{1,64}_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_peer_identity_[A-Za-z0-9-]{1,64}_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_peer_signing_[A-Za-z0-9-]{1,64}_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_pending_prekey_[A-Za-z0-9-]{1,64}_[A-Za-z0-9-]{1,64}$'),
    RegExp(r'^crypto_e2_handshake_tombstones$'),
    RegExp(r'^crypto_e2_seen_nonces$'),
    RegExp(r'^crypto_e2_bundle_replacement_journal_v1$'),
  ];

  static bool isAllowedKey(String key) =>
      _allowedKeyPatterns.any((pattern) => pattern.hasMatch(key));

  void requireValid() {
    if (key.isEmpty ||
        key.length > 512 ||
        !isAllowedKey(key) ||
        !ReceiveReceipt._digestPattern.hasMatch(beforeDigest) ||
        !ReceiveReceipt._digestPattern.hasMatch(afterDigest) ||
        digestValue(afterValue) != afterDigest) {
      throw const FormatException('Invalid receive storage mutation');
    }
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'key': key,
    'beforeDigest': beforeDigest,
    'afterValue': afterValue,
    'afterDigest': afterDigest,
  };

  factory ReceiveStorageMutation.fromJson(Map<String, dynamic> json) {
    final mutation = ReceiveStorageMutation._(
      key: json['key'] as String? ?? '',
      beforeDigest: json['beforeDigest'] as String? ?? '',
      afterValue: json['afterValue'] as String?,
      afterDigest: json['afterDigest'] as String? ?? '',
    );
    mutation.requireValid();
    return mutation;
  }
}

final class ReceivePendingCommit {
  final ReceiveReceipt receipt;
  final ReceiveCommitPhase phase;
  final List<ReceiveStorageMutation> mutations;

  ReceivePendingCommit({
    required this.receipt,
    required this.phase,
    required Iterable<ReceiveStorageMutation> mutations,
  }) : mutations = List<ReceiveStorageMutation>.unmodifiable(mutations) {
    requireValid();
  }

  void requireValid() {
    receipt.requireValid();
    if (mutations.isEmpty || mutations.length > 16) {
      throw const FormatException('Invalid receive mutation count');
    }
    final keys = mutations.map((mutation) => mutation.key).toSet();
    if (keys.length != mutations.length) {
      throw const FormatException('Duplicate receive storage mutation');
    }
    for (final mutation in mutations) {
      mutation.requireValid();
    }
  }

  ReceivePendingCommit copyWith({ReceiveCommitPhase? phase}) =>
      ReceivePendingCommit(
        receipt: receipt,
        phase: phase ?? this.phase,
        mutations: mutations,
      );

  Map<String, dynamic> toJson() => <String, dynamic>{
    'receipt': receipt.toJson(),
    'phase': phase.name,
    'mutations': mutations.map((mutation) => mutation.toJson()).toList(),
  };

  factory ReceivePendingCommit.fromJson(Map<String, dynamic> json) {
    final rawPhase = json['phase'];
    final phases = ReceiveCommitPhase.values.where(
      (candidate) => candidate.name == rawPhase,
    );
    final rawMutations = json['mutations'];
    if (phases.length != 1 || rawMutations is! List) {
      throw const FormatException('Invalid receive pending commit');
    }
    return ReceivePendingCommit(
      receipt: ReceiveReceipt.fromJson(
        Map<String, dynamic>.from(json['receipt'] as Map),
      ),
      phase: phases.single,
      mutations: rawMutations.map(
        (value) => ReceiveStorageMutation.fromJson(
          Map<String, dynamic>.from(value as Map),
        ),
      ),
    );
  }
}

/// Single-writer, bounded receive WAL plus recent completed receipts.
final class ReceiveCommitJournal {
  static const int maxCompletedReceipts = 64;

  /// Hard ceiling on the encoded WAL.
  ///
  /// This cap must be strictly larger than the worst-case commit it has to
  /// hold, or the WAL fails closed on ordinary traffic and the receive
  /// direction of a conversation dies permanently: `encode()` throws at
  /// prepare, nothing is written, and the peer's next message skips past the
  /// failed one so it fails identically. The previous 512 KiB was smaller than
  /// the sum of the after-images a single sealed commit embeds.
  ///
  /// Worst case a sealed PreKey commit can carry, as escaped JSON:
  ///   - `crypto_e2_seen_nonces` at its 10 000-entry cap    ≈ 210 KiB
  ///   - a full `RatchetState` at 2 000 skipped keys and
  ///     2 000 received-message ids                          ≈ 336 KiB
  ///   - the key-bundle journal at 8 generations × 100 OPKs  ≈ 220 KiB
  ///   - receipts, identity/capability records and the
  ///     `prepared` → `commitDecided` phase growth           ≈  10 KiB
  /// ≈ 776 KiB. 2 MiB leaves headroom for a future generation or cap increase
  /// while still bounding abuse; the underlying secure storage imposes no
  /// value-size limit of its own, so this is not a new exposure.
  /// `receive_wal_p0_remediation_test.dart` asserts a realistic worst-case plan
  /// actually FITS — asserting only that oversize is rejected is what let the
  /// original cap ship too small.
  static const int maxEncodedBytes = 2 * 1024 * 1024;

  final int revision;
  final ReceivePendingCommit? pending;
  final List<ReceiveReceipt> completed;

  ReceiveCommitJournal({
    required this.revision,
    required this.pending,
    required Iterable<ReceiveReceipt> completed,
  }) : completed = List<ReceiveReceipt>.unmodifiable(completed) {
    requireValid();
  }

  factory ReceiveCommitJournal.empty() => ReceiveCommitJournal(
    revision: 0,
    pending: null,
    completed: const <ReceiveReceipt>[],
  );

  void requireValid() {
    if (revision < 0 || completed.length > maxCompletedReceipts) {
      throw const FormatException('Invalid receive commit journal');
    }
    pending?.requireValid();
    final deliveryIds = <String>{};
    for (final receipt in completed) {
      receipt.requireValid();
      if (!deliveryIds.add(receipt.deliveryIdHash)) {
        throw const FormatException('Duplicate completed receive delivery');
      }
    }
    if (pending != null &&
        deliveryIds.contains(pending!.receipt.deliveryIdHash)) {
      throw const FormatException('Pending receive is already completed');
    }
  }

  ReceiveReceipt? completedForHash(String deliveryIdHash) {
    final matches = completed.where(
      (receipt) => receipt.deliveryIdHash == deliveryIdHash,
    );
    return matches.isEmpty ? null : matches.single;
  }

  ReceiveCommitJournal copyWith({
    required ReceivePendingCommit? pending,
    Iterable<ReceiveReceipt>? completed,
  }) => ReceiveCommitJournal(
    revision: revision + 1,
    pending: pending,
    completed: completed ?? this.completed,
  );

  Map<String, dynamic> toJson() => <String, dynamic>{
    'version': 1,
    'revision': revision,
    'pending': pending?.toJson(),
    'completed': completed.map((receipt) => receipt.toJson()).toList(),
  };

  String encode() {
    final encoded = jsonEncode(toJson());
    if (utf8.encode(encoded).length > maxEncodedBytes) {
      throw StateError('Receive commit journal capacity reached');
    }
    return encoded;
  }

  factory ReceiveCommitJournal.decode(String raw) {
    if (utf8.encode(raw).length > maxEncodedBytes) {
      throw const FormatException('Oversized receive commit journal');
    }
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map || decoded['version'] != 1) {
        throw const FormatException('Invalid receive commit journal');
      }
      final completed = decoded['completed'];
      if (completed is! List) {
        throw const FormatException('Invalid receive commit journal');
      }
      return ReceiveCommitJournal(
        revision: decoded['revision'] as int? ?? -1,
        pending: decoded['pending'] == null
            ? null
            : ReceivePendingCommit.fromJson(
                Map<String, dynamic>.from(decoded['pending'] as Map),
              ),
        completed: completed.map(
          (value) =>
              ReceiveReceipt.fromJson(Map<String, dynamic>.from(value as Map)),
        ),
      );
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Corrupt receive commit journal');
    }
  }
}

const int _maxEnvelopeDepth = 32;
const int _maxEnvelopeEncodedBytes = 1024 * 1024;

/// Canonical, domain-separated digest of a bounded JSON-compatible envelope.
String receiveEnvelopeDigest(Map<String, dynamic> envelope) {
  final canonical = jsonEncode(_canonicalJson(envelope, depth: 0));
  final encoded = utf8.encode(canonical);
  if (encoded.length > _maxEnvelopeEncodedBytes) {
    throw const FormatException('Receive envelope exceeds the size limit');
  }
  return crypto.sha256.convert(<int>[
    ...utf8.encode('Risaal-Receive-Envelope-v1\u0000'),
    ...encoded,
  ]).toString();
}

Object? _canonicalJson(Object? value, {required int depth}) {
  if (depth > _maxEnvelopeDepth) {
    throw const FormatException('Receive envelope exceeds the depth limit');
  }
  if (value is Map) {
    if (value.keys.any((key) => key is! String)) {
      throw const FormatException('Envelope JSON keys must be strings');
    }
    final keys = value.keys.cast<String>().toList()..sort();
    return <String, Object?>{
      for (final key in keys) key: _canonicalJson(value[key], depth: depth + 1),
    };
  }
  if (value is List) {
    return value
        .map((item) => _canonicalJson(item, depth: depth + 1))
        .toList(growable: false);
  }
  if (value is double && !value.isFinite) {
    throw const FormatException('Envelope numbers must be finite');
  }
  if (value == null || value is String || value is num || value is bool) {
    return value;
  }
  throw const FormatException('Envelope is not canonical JSON');
}
