import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'receive_commit.dart';

enum SendCommitPhase { prepared, commitDecided }

/// Stable proof connecting one host queue row to one provisional ratchet step.
final class SendReceipt {
  static final RegExp _digestPattern = RegExp(r'^[0-9a-f]{64}$');
  static final RegExp _identifierPattern = RegExp(r'^[A-Za-z0-9-]{1,64}$');

  final String deliveryId;
  final String deliveryIdHash;
  final String receiptId;
  final String envelopeDigest;
  final String plaintextDigest;
  final String recipientId;
  final String recipientDeviceId;

  const SendReceipt._({
    required this.deliveryId,
    required this.deliveryIdHash,
    required this.receiptId,
    required this.envelopeDigest,
    required this.plaintextDigest,
    required this.recipientId,
    required this.recipientDeviceId,
  });

  factory SendReceipt.create({
    required String deliveryId,
    required String envelopeDigest,
    required String plaintext,
    required String recipientId,
    required String recipientDeviceId,
  }) {
    final deliveryIdHash = ReceiveReceipt.hashDeliveryId(deliveryId);
    _requireIdentifier(recipientId, 'recipient id');
    _requireIdentifier(recipientDeviceId, 'recipient device id');
    if (!_digestPattern.hasMatch(envelopeDigest)) {
      throw const FormatException('Invalid send envelope digest');
    }
    return SendReceipt._(
      deliveryId: deliveryId,
      deliveryIdHash: deliveryIdHash,
      receiptId: _receiptId(
        deliveryIdHash: deliveryIdHash,
        envelopeDigest: envelopeDigest,
        plaintextDigest: _plaintextDigest(plaintext),
        recipientId: recipientId,
        recipientDeviceId: recipientDeviceId,
      ),
      envelopeDigest: envelopeDigest,
      plaintextDigest: _plaintextDigest(plaintext),
      recipientId: recipientId,
      recipientDeviceId: recipientDeviceId,
    );
  }

  void requireValid() {
    final expectedDeliveryHash = ReceiveReceipt.hashDeliveryId(deliveryId);
    _requireIdentifier(recipientId, 'recipient id');
    _requireIdentifier(recipientDeviceId, 'recipient device id');
    final expectedReceiptId = _receiptId(
      deliveryIdHash: expectedDeliveryHash,
      envelopeDigest: envelopeDigest,
      plaintextDigest: plaintextDigest,
      recipientId: recipientId,
      recipientDeviceId: recipientDeviceId,
    );
    if (deliveryIdHash != expectedDeliveryHash ||
        !_digestPattern.hasMatch(envelopeDigest) ||
        !_digestPattern.hasMatch(plaintextDigest) ||
        receiptId != expectedReceiptId ||
        !_digestPattern.hasMatch(receiptId)) {
      throw const FormatException('Invalid send receipt');
    }
  }

  bool matchesExact(SendReceipt other) =>
      deliveryId == other.deliveryId &&
      deliveryIdHash == other.deliveryIdHash &&
      receiptId == other.receiptId &&
      envelopeDigest == other.envelopeDigest &&
      plaintextDigest == other.plaintextDigest &&
      recipientId == other.recipientId &&
      recipientDeviceId == other.recipientDeviceId;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'deliveryId': deliveryId,
    'deliveryIdHash': deliveryIdHash,
    'receiptId': receiptId,
    'envelopeDigest': envelopeDigest,
    'plaintextDigest': plaintextDigest,
    'recipientId': recipientId,
    'recipientDeviceId': recipientDeviceId,
  };

  factory SendReceipt.fromJson(Map<String, dynamic> json) {
    final receipt = SendReceipt._(
      deliveryId: json['deliveryId'] as String? ?? '',
      deliveryIdHash: json['deliveryIdHash'] as String? ?? '',
      receiptId: json['receiptId'] as String? ?? '',
      envelopeDigest: json['envelopeDigest'] as String? ?? '',
      plaintextDigest: json['plaintextDigest'] as String? ?? '',
      recipientId: json['recipientId'] as String? ?? '',
      recipientDeviceId: json['recipientDeviceId'] as String? ?? '',
    );
    receipt.requireValid();
    return receipt;
  }

  static void _requireIdentifier(String value, String field) {
    if (!_identifierPattern.hasMatch(value) ||
        value == 'ik' ||
        value == 'devices') {
      throw FormatException('Invalid $field');
    }
  }

  static String _receiptId({
    required String deliveryIdHash,
    required String envelopeDigest,
    required String plaintextDigest,
    required String recipientId,
    required String recipientDeviceId,
  }) => crypto.sha256
      .convert(
        utf8.encode(
          jsonEncode(<Object>[
            'Risaal-Send-Receipt-v1',
            deliveryIdHash,
            envelopeDigest,
            plaintextDigest,
            recipientId,
            recipientDeviceId,
          ]),
        ),
      )
      .toString();

  static String digestPlaintext(String plaintext) =>
      _plaintextDigest(plaintext);

  static String _plaintextDigest(String plaintext) =>
      crypto.sha256.convert(<int>[
        ...utf8.encode('Risaal-Send-Plaintext-v1\u0000'),
        ...utf8.encode(plaintext),
      ]).toString();
}

final class PreparedSend {
  final SendReceipt receipt;
  final Map<String, dynamic> envelope;

  PreparedSend({required this.receipt, required Map<String, dynamic> envelope})
    : envelope = Map<String, dynamic>.unmodifiable(envelope) {
    receipt.requireValid();
    if (receiveEnvelopeDigest(this.envelope) != receipt.envelopeDigest) {
      throw const FormatException('Prepared send envelope drift');
    }
  }
}

final class SendPendingCommit {
  final SendReceipt receipt;
  final SendCommitPhase phase;
  final Map<String, dynamic> envelope;
  final List<ReceiveStorageMutation> mutations;

  SendPendingCommit({
    required this.receipt,
    required this.phase,
    required Map<String, dynamic> envelope,
    required Iterable<ReceiveStorageMutation> mutations,
  }) : envelope = Map<String, dynamic>.unmodifiable(envelope),
       mutations = List<ReceiveStorageMutation>.unmodifiable(mutations) {
    requireValid();
  }

  void requireValid() {
    receipt.requireValid();
    if (receiveEnvelopeDigest(envelope) != receipt.envelopeDigest ||
        mutations.isEmpty ||
        mutations.length > 2) {
      throw const FormatException('Invalid send pending commit');
    }
    final keys = mutations.map((mutation) => mutation.key).toSet();
    if (keys.length != mutations.length) {
      throw const FormatException('Duplicate send storage mutation');
    }
    final sessionKey =
        'crypto_e2_session_${receipt.recipientId}_${receipt.recipientDeviceId}';
    final pendingPreKey =
        'crypto_e2_pending_prekey_${receipt.recipientId}_${receipt.recipientDeviceId}';
    for (final mutation in mutations) {
      mutation.requireValid();
      if (mutation.key != sessionKey && mutation.key != pendingPreKey) {
        throw const FormatException('Invalid send storage mutation target');
      }
      if ((mutation.key == sessionKey && mutation.afterValue == null) ||
          (mutation.key == pendingPreKey && mutation.afterValue != null)) {
        throw const FormatException('Invalid send storage mutation value');
      }
    }
    if (!keys.contains(sessionKey)) {
      throw const FormatException('Send commit is missing session mutation');
    }
  }

  SendPendingCommit copyWith({SendCommitPhase? phase}) => SendPendingCommit(
    receipt: receipt,
    phase: phase ?? this.phase,
    envelope: envelope,
    mutations: mutations,
  );

  Map<String, dynamic> toJson() => <String, dynamic>{
    'receipt': receipt.toJson(),
    'phase': phase.name,
    'envelope': envelope,
    'mutations': mutations.map((mutation) => mutation.toJson()).toList(),
  };

  factory SendPendingCommit.fromJson(Map<String, dynamic> json) {
    final phases = SendCommitPhase.values.where(
      (candidate) => candidate.name == json['phase'],
    );
    final rawEnvelope = json['envelope'];
    final rawMutations = json['mutations'];
    if (phases.length != 1 || rawEnvelope is! Map || rawMutations is! List) {
      throw const FormatException('Invalid send pending commit');
    }
    return SendPendingCommit(
      receipt: SendReceipt.fromJson(
        Map<String, dynamic>.from(json['receipt'] as Map),
      ),
      phase: phases.single,
      envelope: Map<String, dynamic>.from(rawEnvelope),
      mutations: rawMutations.map(
        (value) => ReceiveStorageMutation.fromJson(
          Map<String, dynamic>.from(value as Map),
        ),
      ),
    );
  }
}

final class SendCommitJournal {
  static const int maxCompletedReceipts = 64;
  static const int maxEncodedBytes = 2 * 1024 * 1024;

  final int revision;
  final SendPendingCommit? pending;
  final List<SendReceipt> completed;

  SendCommitJournal({
    required this.revision,
    required this.pending,
    required Iterable<SendReceipt> completed,
  }) : completed = List<SendReceipt>.unmodifiable(completed) {
    requireValid();
  }

  factory SendCommitJournal.empty() => SendCommitJournal(
    revision: 0,
    pending: null,
    completed: const <SendReceipt>[],
  );

  void requireValid() {
    if (revision < 0 || completed.length > maxCompletedReceipts) {
      throw const FormatException('Invalid send commit journal');
    }
    pending?.requireValid();
    final hashes = <String>{};
    for (final receipt in completed) {
      receipt.requireValid();
      if (!hashes.add(receipt.deliveryIdHash)) {
        throw const FormatException('Duplicate completed send delivery');
      }
    }
    if (pending != null && hashes.contains(pending!.receipt.deliveryIdHash)) {
      throw const FormatException('Pending send is already completed');
    }
  }

  SendReceipt? completedForHash(String deliveryIdHash) {
    final matches = completed.where(
      (receipt) => receipt.deliveryIdHash == deliveryIdHash,
    );
    return matches.isEmpty ? null : matches.single;
  }

  SendCommitJournal copyWith({
    required SendPendingCommit? pending,
    Iterable<SendReceipt>? completed,
  }) => SendCommitJournal(
    revision: revision + 1,
    pending: pending,
    completed: completed ?? this.completed,
  );

  String encode() {
    final raw = jsonEncode(<String, Object?>{
      'version': 1,
      'revision': revision,
      'pending': pending?.toJson(),
      'completed': completed.map((receipt) => receipt.toJson()).toList(),
    });
    if (utf8.encode(raw).length > maxEncodedBytes) {
      throw StateError('Send commit journal capacity reached');
    }
    return raw;
  }

  factory SendCommitJournal.decode(String raw) {
    if (utf8.encode(raw).length > maxEncodedBytes) {
      throw const FormatException('Oversized send commit journal');
    }
    try {
      final json = jsonDecode(raw);
      if (json is! Map || json['version'] != 1 || json['completed'] is! List) {
        throw const FormatException('Invalid send commit journal');
      }
      return SendCommitJournal(
        revision: json['revision'] as int? ?? -1,
        pending: json['pending'] == null
            ? null
            : SendPendingCommit.fromJson(
                Map<String, dynamic>.from(json['pending'] as Map),
              ),
        completed: (json['completed'] as List).map(
          (value) =>
              SendReceipt.fromJson(Map<String, dynamic>.from(value as Map)),
        ),
      );
    } on FormatException {
      rethrow;
    } on Object {
      throw const FormatException('Corrupt send commit journal');
    }
  }
}
