import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

/// R4-M37 §3: the versioned, length-prefixed `(kind, key, value)` archive.
///
/// Layout (v1): "RXA" || version u8 || count u32be ||
///   count × (kind u8 || keyLen u16be || key UTF-8 || valueLen u32be || value),
/// entries in canonical order (kind id, then key bytes), no trailing byte.
Uint8List _header({int version = 1, required int count}) => Uint8List.fromList([
  0x52, 0x58, 0x41, version, //
  (count >> 24) & 0xff, (count >> 16) & 0xff, (count >> 8) & 0xff, count & 0xff,
]);

Uint8List _entry(int kind, List<int> key, List<int> value) =>
    Uint8List.fromList([
      kind,
      (key.length >> 8) & 0xff,
      key.length & 0xff,
      ...key,
      (value.length >> 24) & 0xff,
      (value.length >> 16) & 0xff,
      (value.length >> 8) & 0xff,
      value.length & 0xff,
      ...value,
    ]);

Uint8List _archive(List<Uint8List> entries, {int version = 1, int? count}) =>
    Uint8List.fromList([
      ..._header(version: version, count: count ?? entries.length),
      for (final entry in entries) ...entry,
    ]);

void _refused(List<int> bytes) => expect(
  () => TransferArchive.decode(bytes),
  throwsA(isA<FormatException>()),
);

void main() {
  test('the kind table is pinned (wire ids are a format commitment)', () {
    expect(
      {
        for (final kind in TransferArchiveKind.values)
          kind.wireName: kind.wireId,
      },
      {
        'crypto_store': 1,
        'kt': 2,
        'profile_own': 3,
        'peer_profiles': 4,
        'contacts_cache': 5,
        'conversations_cache': 6,
        'group_roster': 7,
        'prefs': 8,
        'history': 9,
      },
    );
  });

  test('round trip over every kind, binary and empty values', () {
    final entries = <TransferArchiveEntry>[
      for (final kind in TransferArchiveKind.values) ...[
        TransferArchiveEntry.text(
          kind,
          'k-${kind.wireName}',
          'v ✓ ${kind.wireId}',
        ),
        TransferArchiveEntry(kind, 'bin', [0, 255, 1, 128]),
        TransferArchiveEntry(kind, 'empty', const <int>[]),
      ],
    ];
    final encoded = TransferArchive(entries).encode();
    final decoded = TransferArchive.decode(encoded);
    expect(decoded.entries, hasLength(entries.length));
    expect(decoded.encode(), encoded);
    final cryptoEntries = decoded
        .ofKind(TransferArchiveKind.cryptoStore)
        .toList();
    expect(cryptoEntries.map((e) => e.key), ['bin', 'empty', 'k-crypto_store']);
    expect(cryptoEntries.last.valueText, 'v ✓ 1');
    expect(cryptoEntries.first.value, [0, 255, 1, 128]);
    expect(cryptoEntries[1].value, isEmpty);
  });

  test('an empty archive is valid and canonical', () {
    final bytes = TransferArchive(const <TransferArchiveEntry>[]).encode();
    expect(bytes, _header(count: 0));
    expect(TransferArchive.decode(bytes).entries, isEmpty);
  });

  test('a hand-built canonical archive decodes', () {
    final bytes = _archive([
      _entry(1, utf8.encode('a'), [1]),
      _entry(1, utf8.encode('b'), [2]),
      _entry(9, utf8.encode('a'), [3]),
    ]);
    final decoded = TransferArchive.decode(bytes);
    expect(decoded.entries.map((e) => '${e.kind.wireName}/${e.key}'), [
      'crypto_store/a',
      'crypto_store/b',
      'history/a',
    ]);
  });

  group('strict decode refuses', () {
    test('an unknown version', () {
      for (final version in [0, 2, 255]) {
        _refused(
          _archive([
            _entry(1, [0x61], [1]),
          ], version: version),
        );
      }
    });

    test('a wrong magic', () {
      final bytes = _archive([
        _entry(1, [0x61], [1]),
      ]);
      for (var i = 0; i < 3; i++) {
        _refused(Uint8List.fromList(bytes)..[i] ^= 0x20);
      }
    });

    test('a trailing byte', () {
      _refused([
        ..._archive([
          _entry(1, [0x61], [1]),
        ]),
        0,
      ]);
      _refused([..._archive(const []), 0]);
    });

    test('every truncation', () {
      final bytes = _archive([
        _entry(1, [0x61], [1, 2, 3]),
        _entry(2, [0x62], [4]),
      ]);
      for (var length = 0; length < bytes.length; length++) {
        _refused(bytes.sublist(0, length));
      }
    });

    test('an unknown kind', () {
      for (final kind in [0, 10, 127, 255]) {
        _refused(
          _archive([
            _entry(kind, [0x61], [1]),
          ]),
        );
      }
    });

    test('a duplicate or out-of-order entry', () {
      _refused(
        _archive([
          _entry(1, [0x61], [1]),
          _entry(1, [0x61], [2]),
        ]),
      );
      _refused(
        _archive([
          _entry(1, [0x62], [1]),
          _entry(1, [0x61], [2]),
        ]),
      );
      _refused(
        _archive([
          _entry(2, [0x61], [1]),
          _entry(1, [0x61], [2]),
        ]),
      );
    });

    test('an empty, oversized or non-UTF-8 key', () {
      _refused(
        _archive([
          _entry(1, const [], [1]),
        ]),
      );
      _refused(
        _archive([
          _entry(1, List<int>.filled(1025, 0x61), [1]),
        ]),
      );
      _refused(
        _archive([
          _entry(1, [0xc3, 0x28], [1]),
        ]),
      );
      _refused(
        _archive([
          _entry(1, [0xff], [1]),
        ]),
      );
    });

    test('a count that does not match the entries', () {
      _refused(
        _archive([
          _entry(1, [0x61], [1]),
        ], count: 2),
      );
      _refused(
        _archive([
          _entry(1, [0x61], [1]),
        ], count: 0),
      );
      _refused(_archive(const [], count: 0xffffffff));
    });

    test('a value length past the end', () {
      final bytes = _archive([
        _entry(1, [0x61], [1, 2]),
      ]);
      // value length 2 -> 0xffffffff
      final tampered = Uint8List.fromList(bytes);
      tampered.setRange(8 + 1 + 2 + 1, 8 + 1 + 2 + 1 + 4, [
        0xff,
        0xff,
        0xff,
        0xff,
      ]);
      _refused(tampered);
    });
  });

  group('the encoder refuses', () {
    test('duplicate (kind, key)', () {
      expect(
        () => TransferArchive([
          TransferArchiveEntry.text(TransferArchiveKind.prefs, 'theme', 'a'),
          TransferArchiveEntry.text(TransferArchiveKind.prefs, 'theme', 'b'),
        ]),
        throwsArgumentError,
      );
    });

    test('an empty or oversized key', () {
      expect(
        () => TransferArchiveEntry.text(TransferArchiveKind.prefs, '', 'a'),
        throwsArgumentError,
      );
      expect(
        () => TransferArchiveEntry.text(
          TransferArchiveKind.prefs,
          'a' * 1025,
          'a',
        ),
        throwsArgumentError,
      );
    });

    test('a value that is not UTF-8 when read as text', () {
      final entry = TransferArchiveEntry(TransferArchiveKind.prefs, 'k', [
        0xff,
      ]);
      expect(() => entry.valueText, throwsA(isA<FormatException>()));
    });
  });
}
