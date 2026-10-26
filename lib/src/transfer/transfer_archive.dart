import 'dart:convert';
import 'dart:typed_data';

/// What an archive entry holds (R4-M37 §3). The wire id is a format
/// commitment: never renumber, only append.
enum TransferArchiveKind {
  /// Every crypto key the package owns ([CryptoStorage.exportForTransfer]).
  cryptoStore(1, 'crypto_store'),

  /// Key-transparency state (app-owned).
  kt(2, 'kt'),

  /// The user's own profile (app-owned).
  profileOwn(3, 'profile_own'),

  /// Peer profiles (app-owned).
  peerProfiles(4, 'peer_profiles'),

  /// The contacts cache (app-owned).
  contactsCache(5, 'contacts_cache'),

  /// The conversation list (app-owned).
  conversationsCache(6, 'conversations_cache'),

  /// Group rosters and membership intents (app-owned).
  groupRoster(7, 'group_roster'),

  /// Whitelisted user settings, never device-bound security toggles.
  prefs(8, 'prefs'),

  /// Optional message history (off by default).
  history(9, 'history');

  const TransferArchiveKind(this.wireId, this.wireName);

  /// The byte that names this kind in the archive.
  final int wireId;

  /// The contract's name for this kind.
  final String wireName;

  static TransferArchiveKind? _fromWireId(int id) {
    for (final kind in values) {
      if (kind.wireId == id) return kind;
    }
    return null;
  }
}

/// One `(kind, key, value)` record of a [TransferArchive].
final class TransferArchiveEntry {
  /// [key] must be 1 to [TransferArchive.maxKeyBytes] bytes of UTF-8.
  /// [value] is copied.
  TransferArchiveEntry(this.kind, this.key, List<int> value)
    : value = Uint8List.fromList(value),
      _keyBytes = _encodeKey(key);

  /// An entry whose value is the UTF-8 encoding of [value].
  TransferArchiveEntry.text(TransferArchiveKind kind, String key, String value)
    : this(kind, key, utf8.encode(value));

  /// A decoded entry: [value] is a view into the decoded buffer, so zeroing
  /// that buffer after the import also clears what the entries held, and a
  /// large archive is not held twice.
  TransferArchiveEntry._view(this.kind, this.key, this.value, this._keyBytes);

  final TransferArchiveKind kind;
  final String key;
  final Uint8List value;
  final Uint8List _keyBytes;

  /// The value decoded as strict UTF-8. Throws [FormatException] otherwise.
  String get valueText => utf8.decode(value);

  static Uint8List _encodeKey(String key) {
    final bytes = utf8.encode(key);
    if (bytes.isEmpty || bytes.length > TransferArchive.maxKeyBytes) {
      throw ArgumentError.value(
        bytes.length,
        'key',
        'must be 1..${TransferArchive.maxKeyBytes} UTF-8 bytes',
      );
    }
    return Uint8List.fromList(bytes);
  }
}

/// The versioned, length-prefixed archive that moves an account (R4-M37 §3).
///
/// Layout, version 1 (all integers big-endian):
///
///     "RXA" || version u8 (= 1) || count u32 ||
///     count × ( kind u8 || keyLen u16 || key || valueLen u32 || value )
///
/// Entries are in canonical order: by [TransferArchiveKind.wireId], then by
/// the key's UTF-8 bytes, strictly increasing. One archive therefore has
/// exactly one encoding, and [decode] refuses anything else: an unknown
/// version, a wrong magic, an unknown kind, a duplicate or out-of-order entry,
/// an empty, oversized or non-UTF-8 key, a length past the end, and any
/// trailing byte. The archive is only ever read after the chunk AEAD has
/// authenticated it; the strictness is defence in depth, not the trust anchor.
final class TransferArchive {
  /// Entries in canonical order. Throws [ArgumentError] on a duplicate
  /// `(kind, key)`.
  TransferArchive(Iterable<TransferArchiveEntry> entries)
    : entries = List<TransferArchiveEntry>.unmodifiable(
        _canonical(entries.toList()),
      );

  TransferArchive._decoded(List<TransferArchiveEntry> entries)
    : entries = List<TransferArchiveEntry>.unmodifiable(entries);

  /// The archive format version this code reads and writes.
  static const int version = 1;

  /// Upper bound on an encoded archive (the server cap with history).
  static const int maxEncodedBytes = 512 * 1024 * 1024;

  /// Upper bound on one key's UTF-8 encoding.
  static const int maxKeyBytes = 1024;

  static const List<int> _magic = <int>[0x52, 0x58, 0x41]; // "RXA"
  static const int _headerBytes = 3 + 1 + 4;
  static const int _minEntryBytes = 1 + 2 + 1 + 4;

  final List<TransferArchiveEntry> entries;

  /// The entries of one [kind], in canonical order.
  Iterable<TransferArchiveEntry> ofKind(TransferArchiveKind kind) =>
      entries.where((entry) => entry.kind == kind);

  /// The canonical encoding.
  Uint8List encode() {
    var length = _headerBytes;
    for (final entry in entries) {
      length += 1 + 2 + entry._keyBytes.length + 4 + entry.value.length;
    }
    if (length > maxEncodedBytes) {
      throw StateError('Transfer archive exceeds $maxEncodedBytes bytes');
    }
    final out = Uint8List(length);
    final view = ByteData.sublistView(out);
    out.setAll(0, _magic);
    out[3] = version;
    view.setUint32(4, entries.length);
    var offset = _headerBytes;
    for (final entry in entries) {
      out[offset] = entry.kind.wireId;
      view.setUint16(offset + 1, entry._keyBytes.length);
      out.setAll(offset + 3, entry._keyBytes);
      offset += 3 + entry._keyBytes.length;
      view.setUint32(offset, entry.value.length);
      out.setAll(offset + 4, entry.value);
      offset += 4 + entry.value.length;
    }
    return out;
  }

  /// Strict decode. Throws [FormatException] on anything but a canonical v1
  /// archive. Entry values are views into [encoded] when it is a
  /// [Uint8List]: do not change it while the archive is in use.
  static TransferArchive decode(List<int> encoded) {
    final bytes = encoded is Uint8List ? encoded : Uint8List.fromList(encoded);
    if (bytes.length > maxEncodedBytes) {
      throw const FormatException('Transfer archive is too large');
    }
    if (bytes.length < _headerBytes) {
      throw const FormatException('Truncated transfer archive');
    }
    for (var i = 0; i < _magic.length; i++) {
      if (bytes[i] != _magic[i]) {
        throw const FormatException('Not a transfer archive');
      }
    }
    if (bytes[3] != version) {
      throw const FormatException('Unsupported transfer archive version');
    }
    final view = ByteData.sublistView(bytes);
    final count = view.getUint32(4);
    if (count > (bytes.length - _headerBytes) ~/ _minEntryBytes) {
      throw const FormatException('Transfer archive count exceeds its size');
    }

    final entries = <TransferArchiveEntry>[];
    var offset = _headerBytes;
    TransferArchiveEntry? previous;
    for (var i = 0; i < count; i++) {
      if (bytes.length - offset < 3) {
        throw const FormatException('Truncated transfer archive entry');
      }
      final kind = TransferArchiveKind._fromWireId(bytes[offset]);
      if (kind == null) {
        throw const FormatException('Unknown transfer archive kind');
      }
      final keyLength = view.getUint16(offset + 1);
      offset += 3;
      if (keyLength == 0 || keyLength > maxKeyBytes) {
        throw const FormatException('Invalid transfer archive key length');
      }
      if (bytes.length - offset < keyLength + 4) {
        throw const FormatException('Truncated transfer archive entry');
      }
      final keyBytes = Uint8List.sublistView(bytes, offset, offset + keyLength);
      // Strict UTF-8 (no replacement characters): throws FormatException.
      final key = utf8.decode(keyBytes);
      offset += keyLength;
      final valueLength = view.getUint32(offset);
      offset += 4;
      if (bytes.length - offset < valueLength) {
        throw const FormatException('Truncated transfer archive value');
      }
      final entry = TransferArchiveEntry._view(
        kind,
        key,
        Uint8List.sublistView(bytes, offset, offset + valueLength),
        keyBytes,
      );
      offset += valueLength;
      if (previous != null && _compare(previous, entry) >= 0) {
        throw const FormatException(
          'Transfer archive entries are duplicate or out of order',
        );
      }
      entries.add(entry);
      previous = entry;
    }
    if (offset != bytes.length) {
      throw const FormatException('Trailing bytes after the transfer archive');
    }
    return TransferArchive._decoded(entries);
  }

  static List<TransferArchiveEntry> _canonical(
    List<TransferArchiveEntry> entries,
  ) {
    entries.sort(_compare);
    for (var i = 1; i < entries.length; i++) {
      if (_compare(entries[i - 1], entries[i]) == 0) {
        throw ArgumentError('Duplicate transfer archive entry');
      }
    }
    return entries;
  }

  static int _compare(TransferArchiveEntry a, TransferArchiveEntry b) {
    final byKind = a.kind.wireId.compareTo(b.kind.wireId);
    if (byKind != 0) return byKind;
    final x = a._keyBytes;
    final y = b._keyBytes;
    final shared = x.length < y.length ? x.length : y.length;
    for (var i = 0; i < shared; i++) {
      if (x[i] != y[i]) return x[i].compareTo(y[i]);
    }
    return x.length.compareTo(y.length);
  }
}
