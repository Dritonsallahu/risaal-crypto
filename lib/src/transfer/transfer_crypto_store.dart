import 'dart:convert';

import '../crypto_secure_storage.dart';
import '../key_bundle_replacement.dart';
import '../key_helper.dart';
import '../models/signal_keys.dart';
import '../receive_commit.dart';
import '../send_commit.dart';
import 'transfer_archive.dart';

/// A [CryptoSecureStorage] that can list the keys it holds.
///
/// [CryptoStorage.exportForTransfer] needs it: sessions, pins and sender keys
/// live under per-peer and per-group keys that cannot be derived from
/// anything the package stores. The adapter lists its keys; the package then
/// reads only the keys it owns, through [CryptoSecureStorage.read], so no
/// token, PIN or other app secret ever reaches the export.
abstract interface class TransferKeyListing {
  /// Every key the storage currently holds (any order).
  Future<Iterable<String>> listKeys();
}

/// Why the crypto store cannot be exported now.
enum TransferExportBlockedReason {
  /// The storage does not implement [TransferKeyListing].
  storageNotListable,

  /// The account's registration was never accepted by the server.
  unregisteredAccount,

  /// The identity, the signing key or the key-bundle journal is missing.
  incompleteAccount,

  /// A receive is between prepare and acknowledge: finish it first.
  pendingReceive,

  /// A send is between prepare and acknowledge: finish it first.
  pendingSend,

  /// A commit journal cannot be decoded.
  corruptState,

  /// A listed key vanished before it was read: the store moved under the
  /// export (transfer mode must hold sends and receives).
  storeChanged,
}

/// The crypto store cannot be exported now. Nothing was exported.
final class TransferExportBlocked implements Exception {
  const TransferExportBlocked(this.reason);

  final TransferExportBlockedReason reason;

  @override
  String toString() => 'TransferExportBlocked(${reason.name})';
}

// ── What moves ─────────────────────────────────────────────────────────

const String _identityKey = 'crypto_identity_key_pair';
const String _signingKey = 'crypto_signing_key_pair';
const String _bundleJournalKey = 'crypto_e2_bundle_replacement_journal_v1';
const String _receiveJournalKey = 'crypto_e2_receive_commit_journal_v1';
const String _sendJournalKey = 'crypto_e2_send_commit_journal_v1';
const String _registrationIntentKey =
    'crypto_e2_initial_registration_intent_v1';

const Set<String> _requiredKeys = <String>{
  _identityKey,
  _signingKey,
  _bundleJournalKey,
};

/// Every fixed key the package owns that moves. Not here on purpose:
/// `crypto_e2_initial_registration_intent_v1` (export refuses an account that
/// has it), `crypto_e2_receive_commit_journal_quarantine_v1` (diagnostics),
/// legacy pre-epoch-2 keys nothing reads, and every app-owned `crypto_*` key
/// (KT, roster, intents, the sender certificate, the crypto owner).
const Set<String> _transferableKeys = <String>{
  _identityKey,
  _signingKey,
  'crypto_signed_pre_key',
  'crypto_signed_prekey_created_at',
  'crypto_one_time_pre_keys',
  'crypto_next_pre_key_id',
  'crypto_e2_protocol',
  'crypto_e2_kyber_key_pair',
  'crypto_e2_kyber_created_at',
  'crypto_e2_next_kyber_key_id',
  'crypto_e2_next_signed_pre_key_id',
  'crypto_e2_previous_signed_pre_key',
  'crypto_e2_previous_spk_expiry',
  'crypto_e2_previous_kyber_key_pair',
  'crypto_e2_previous_kyber_expiry',
  'crypto_e2_one_time_pre_key_recovery',
  'crypto_e2_bundle_upload_pending',
  'crypto_e2_server_bundle_revision',
  'crypto_e2_last_accepted_bundle_generation',
  _bundleJournalKey,
  _receiveJournalKey,
  _sendJournalKey,
  'crypto_e2_handshake_tombstones',
  'crypto_e2_seen_nonces',
};

/// Per-peer and per-group keys, with the storage-safe identifier charset
/// that [CryptoStorage] enforces when it builds them.
const String _id = '[A-Za-z0-9-]{1,64}';
final List<RegExp> _transferablePatterns = <RegExp>[
  for (final template in <String>[
    'session_${_id}_$_id',
    'session_ik_${_id}_$_id',
    'session_devices_$_id',
    'session_resets_${_id}_$_id',
    'peer_identity_${_id}_$_id',
    'peer_signing_${_id}_$_id',
    'peer_cap_${_id}_$_id',
    'pending_prekey_${_id}_$_id',
    'replay_${_id}_$_id',
    'sender_key_${_id}_$_id',
    'sender_key_rotation_${_id}_$_id',
  ])
    RegExp('^crypto_e2_$template\$'),
];

bool _isTransferable(String key) =>
    _transferableKeys.contains(key) ||
    _transferablePatterns.any((pattern) => pattern.hasMatch(key));

/// Whether [key] is a package key that moves (tests only).
bool debugIsTransferableCryptoKey(String key) => _isTransferable(key);

// ── Export ─────────────────────────────────────────────────────────────

/// See [CryptoStorage.exportForTransfer].
Future<List<TransferArchiveEntry>> exportCryptoStoreForTransfer(
  CryptoSecureStorage storage,
) async {
  if (storage is! TransferKeyListing) {
    throw const TransferExportBlocked(
      TransferExportBlockedReason.storageNotListable,
    );
  }
  if (await storage.read(key: _registrationIntentKey) != null) {
    throw const TransferExportBlocked(
      TransferExportBlockedReason.unregisteredAccount,
    );
  }
  final keys =
      (await (storage as TransferKeyListing).listKeys())
          .where(_isTransferable)
          .toSet()
          .toList()
        ..sort();
  final values = <String, String>{};
  for (final key in keys) {
    final value = await storage.read(key: key);
    if (value == null) {
      throw const TransferExportBlocked(
        TransferExportBlockedReason.storeChanged,
      );
    }
    values[key] = value;
  }
  if (!_requiredKeys.every(values.containsKey)) {
    throw const TransferExportBlocked(
      TransferExportBlockedReason.incompleteAccount,
    );
  }
  _requireNoPendingCommit(values, export: true);
  return <TransferArchiveEntry>[
    for (final key in keys)
      TransferArchiveEntry.text(
        TransferArchiveKind.cryptoStore,
        key,
        values[key]!,
      ),
  ];
}

// ── Import ─────────────────────────────────────────────────────────────

/// See [CryptoStorage.importForTransfer].
Future<void> importCryptoStoreForTransfer({
  required TransferArchive archive,
  required CryptoSecureStorage live,
  required CryptoSecureStorage staging,
}) async {
  if (identical(live, staging)) {
    throw ArgumentError.value(
      staging,
      'staging',
      'must be a staging scope, never the live storage',
    );
  }
  final values = <String, String>{};
  for (final entry in archive.ofKind(TransferArchiveKind.cryptoStore)) {
    if (!_isTransferable(entry.key)) {
      throw const FormatException('Not a transferable crypto key');
    }
    // Strict UTF-8: throws FormatException.
    values[entry.key] = entry.valueText;
  }
  if (!_requiredKeys.every(values.containsKey)) {
    throw const FormatException('Incomplete crypto store in the archive');
  }
  _requireNoPendingCommit(values, export: false);
  await _requireConsistentAccount(values);

  // A staging scope starts empty: never overwrite, never merge two accounts.
  for (final key in <String>{_identityKey, ...values.keys}) {
    if (await staging.read(key: key) != null) {
      throw StateError('The staging scope is not empty');
    }
  }
  if (staging is TransferKeyListing &&
      (await (staging as TransferKeyListing).listKeys()).any(_isTransferable)) {
    throw StateError('The staging scope is not empty');
  }

  final keys = values.keys.toList()..sort();
  for (final key in keys) {
    await staging.write(key: key, value: values[key]!);
  }
}

void _requireNoPendingCommit(
  Map<String, String> values, {
  required bool export,
}) {
  Never fail(TransferExportBlockedReason reason) {
    if (export) throw TransferExportBlocked(reason);
    throw FormatException('Crypto store refused: ${reason.name}');
  }

  final receive = values[_receiveJournalKey];
  if (receive != null) {
    final ReceiveCommitJournal journal;
    try {
      journal = ReceiveCommitJournal.decode(receive);
    } on Object {
      fail(TransferExportBlockedReason.corruptState);
    }
    if (journal.pending != null) {
      fail(TransferExportBlockedReason.pendingReceive);
    }
  }
  final send = values[_sendJournalKey];
  if (send != null) {
    final SendCommitJournal journal;
    try {
      journal = SendCommitJournal.decode(send);
    } on Object {
      fail(TransferExportBlockedReason.corruptState);
    }
    if (journal.pending != null) fail(TransferExportBlockedReason.pendingSend);
  }
}

/// The identity and signing pairs are real pairs, and the key-bundle journal
/// decodes and belongs to them. Cheap checks only: the full private-material
/// audit runs when the committed store is first used.
Future<void> _requireConsistentAccount(Map<String, String> values) async {
  try {
    final identity = KeyPair.fromJson(
      Map<String, dynamic>.from(jsonDecode(values[_identityKey]!) as Map),
    );
    final signing = KeyPair.fromJson(
      Map<String, dynamic>.from(jsonDecode(values[_signingKey]!) as Map),
    );
    if (!await SignalKeyHelper.isValidX25519KeyPair(identity) ||
        !await SignalKeyHelper.isValidEd25519KeyPair(signing)) {
      throw const FormatException('Invalid identity in the archive');
    }
    final rawJournal = values[_bundleJournalKey]!;
    if (utf8.encode(rawJournal).length >
        KeyBundleReplacementJournal.maxEncodedBytes) {
      throw const FormatException('Oversized key-bundle journal');
    }
    final journal = KeyBundleReplacementJournal.fromJson(
      Map<String, dynamic>.from(jsonDecode(rawJournal) as Map),
    );
    journal.requireValid();
    for (final generation in journal.generations) {
      if (generation.identityKey != identity.publicKey ||
          generation.identitySigningKey != signing.publicKey) {
        throw const FormatException('Key-bundle journal of another identity');
      }
    }
  } on FormatException {
    rethrow;
  } on Object {
    throw const FormatException('Invalid account in the archive');
  }
}
