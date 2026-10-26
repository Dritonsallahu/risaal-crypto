import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:risaal_crypto/src/transfer/transfer_archive.dart';
import 'package:risaal_crypto/src/transfer/transfer_handshake.dart';

/// R4-M37 fixed vectors (contracts/R4-M37-DEVICE-TRANSFER.md §2-§3).
///
/// `test/vectors/r4_m37_transfer_v1.json` was produced by
/// `test/vectors/r4_m37_transfer_v1_gen.js`: Node.js `crypto` (OpenSSL) for
/// X25519, HKDF/HMAC-SHA-256, SHA-256 and AES-256-GCM, and the OpenSSL 3.6 CLI
/// for ML-KEM-768 (keygen from a seed, encapsulation, decapsulation check). No
/// Dart code took part, so these tests compare the implementation with an
/// independent derivation of the same byte layouts.
final Map<String, dynamic> _vectors =
    jsonDecode(File('test/vectors/r4_m37_transfer_v1.json').readAsStringSync())
        as Map<String, dynamic>;

Map<String, dynamic> _section(String name) =>
    Map<String, dynamic>.from(_vectors[name] as Map);

Uint8List _unhex(String value) => Uint8List.fromList([
  for (var i = 0; i < value.length; i += 2)
    int.parse(value.substring(i, i + 2), radix: 16),
]);

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String _b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

final Map<String, dynamic> _h = _section('handshake');

Future<TransferOffer> _vectorOffer() => debugTransferOfferFromMaterial(
  secret: _unhex(_h['secretHex'] as String),
  x25519Private: _unhex(_h['oldX25519PrivateHex'] as String),
  kemPublic: _unhex(_h['oldKemPublicHex'] as String),
  kemSecret: _unhex(_h['oldKemSecretHex'] as String),
  apiHost: _h['apiHost'] as String,
);

Future<TransferJoin> _vectorJoin(String qrText) =>
    debugTransferJoinFromMaterial(
      qrText: qrText,
      x25519Private: _unhex(_h['newX25519PrivateHex'] as String),
      kemCiphertext: _unhex(_h['kemCiphertextHex'] as String),
      kemSharedSecret: _unhex(_h['kemSharedSecretHex'] as String),
    );

void main() {
  final qr = _section('qr');
  final archive = _section('archive');

  test('the OpenSSL ML-KEM-768 vector key decapsulates to the vector '
      'secret with the package KEM', () {
    final seeded = PqcKem.kyber768.generateKeyPair(
      _unhex(_h['oldKemSeedHex'] as String),
    );
    expect(_hex(seeded.$1), _h['oldKemPublicHex']);
    expect(_hex(seeded.$2), _h['oldKemSecretHex']);
    expect(
      _hex(
        PqcKem.kyber768.decapsulate(
          _unhex(_h['oldKemSecretHex'] as String),
          _unhex(_h['kemCiphertextHex'] as String),
        ),
      ),
      _h['kemSharedSecretHex'],
    );
  });

  test('the QR payload and the slot id match the vector', () async {
    final offer = await _vectorOffer();
    expect(offer.qrText, qr['qr']);
    expect(offer.slotId, _h['slotHex']);
    expect(offer.apiHost, _h['apiHost']);
    offer.dispose();
  });

  test('the key schedule (K, K_mac, K_enc, SAS bytes) matches the '
      'vector', () async {
    final schedule = await debugTransferKeySchedule(
      secret: _unhex(_h['secretHex'] as String),
      x25519Shared: _unhex(_h['x25519SharedHex'] as String),
      kemSharedSecret: _unhex(_h['kemSharedSecretHex'] as String),
      oldX25519Public: _unhex(_h['oldX25519PublicHex'] as String),
      oldKemPublic: _unhex(_h['oldKemPublicHex'] as String),
      newX25519Public: _unhex(_h['newX25519PublicHex'] as String),
      kemCiphertext: _unhex(_h['kemCiphertextHex'] as String),
    );
    expect(_hex(schedule.k), _h['kHex']);
    expect(_hex(schedule.kMac), _h['kMacHex']);
    expect(_hex(schedule.kEnc), _h['kEncHex']);
    expect(_hex(schedule.sasBytes), _h['sasBytesHex']);
  });

  test('the new phone builds the vector join body and SAS', () async {
    final join = await _vectorJoin(qr['qr'] as String);
    expect(join.request.toJson(), Map<String, dynamic>.from(_h['joinBody']));
    expect(join.slotId, _h['slotHex']);
    expect(join.apiHost, _h['apiHost']);
    // §2f: no code before the old phone's vector confirmTag verified.
    expect(() => join.keys.sas, throwsStateError);
    join.keys.verifyConfirm(_b64url(_unhex(_h['confirmTagHex'] as String)));
    expect(join.keys.sas, _h['sas']);
    expect(join.keys.getTag, _b64url(_unhex(_h['getTagHex'] as String)));
    expect(
      join.keys.completeTag,
      _b64url(_unhex(_h['completeTagHex'] as String)),
    );
    join.dispose();
  });

  test(
    'the old phone accepts the vector join and shows the same SAS',
    () async {
      final offer = await _vectorOffer();
      final keys = await offer.verifyJoin(
        TransferJoinRequest.fromJson(Map<String, Object?>.from(_h['joinBody'])),
      );
      expect(keys.sas, _h['sas']);
      expect(keys.slotId, _h['slotHex']);
      expect(keys.confirmTag, _b64url(_unhex(_h['confirmTagHex'] as String)));
      keys.dispose();
      offer.dispose();
    },
  );

  test('a wrong secret gives the vector K, a different SAS, and the old '
      'phone refuses its join', () async {
    final wrong = Map<String, dynamic>.from(_h['wrongSecret'] as Map);
    final schedule = await debugTransferKeySchedule(
      secret: _unhex(wrong['secretHex'] as String),
      x25519Shared: _unhex(_h['x25519SharedHex'] as String),
      kemSharedSecret: _unhex(_h['kemSharedSecretHex'] as String),
      oldX25519Public: _unhex(_h['oldX25519PublicHex'] as String),
      oldKemPublic: _unhex(_h['oldKemPublicHex'] as String),
      newX25519Public: _unhex(_h['newX25519PublicHex'] as String),
      kemCiphertext: _unhex(_h['kemCiphertextHex'] as String),
    );
    expect(_hex(schedule.k), wrong['kHex']);
    expect(_hex(schedule.k), isNot(_h['kHex']));

    // The new phone scanned a QR whose secret differs in one bit.
    final qrBytes = _unhex(qr['qrBytesHex'] as String);
    // version(1) || u32 len || s: the last byte of s is at offset 1 + 4 + 31.
    qrBytes[1 + 4 + 31] ^= 0x01;
    final join = await _vectorJoin('rx1:${_b64url(qrBytes)}');
    expect(_hex(join.request.mac), wrong['joinMacHex']);
    // The old phone's confirmation under the vector K is refused under K',
    // and this joiner never shows a code.
    expect(
      () => join.keys.verifyConfirm(
        _b64url(_unhex(_h['confirmTagHex'] as String)),
      ),
      throwsA(isA<TransferConfirmRejected>()),
    );
    expect(() => join.keys.sas, throwsStateError);
    // Under its own K' the code is the vector's wrong-secret SAS.
    final same = await _vectorJoin('rx1:${_b64url(qrBytes)}');
    same.keys.verifyConfirm(_b64url(_unhex(wrong['confirmTagHex'] as String)));
    expect(same.keys.sas, wrong['sas']);
    expect(same.keys.sas, isNot(_h['sas']));

    final offer = await _vectorOffer();
    await expectLater(
      offer.verifyJoin(join.request),
      throwsA(isA<TransferJoinRejected>()),
    );
    join.dispose();
    same.dispose();
    offer.dispose();
  });

  test('M37-CRYPTO-1: a relay join ground to the exact vector code is '
      'accepted by the old phone, but the new phone refuses its confirmTag '
      'and never shows a code', () async {
    final relay = Map<String, dynamic>.from(_h['relayJoin'] as Map);
    final relayBody = Map<String, Object?>.from(relay['joinBody'] as Map);
    // The independent generator ground a full 6-digit collision under K'.
    expect(relay['sas'], _h['sas']);
    expect(relay['kHex'], isNot(_h['kHex']));
    final schedule = await debugTransferKeySchedule(
      secret: _unhex(_h['secretHex'] as String),
      x25519Shared: _unhex(relay['x25519SharedHex'] as String),
      kemSharedSecret: _unhex(relay['kemSharedSecretHex'] as String),
      oldX25519Public: _unhex(_h['oldX25519PublicHex'] as String),
      oldKemPublic: _unhex(_h['oldKemPublicHex'] as String),
      newX25519Public: _unhex(relay['newX25519PublicHex'] as String),
      kemCiphertext: _unhex(relay['kemCiphertextHex'] as String),
    );
    expect(_hex(schedule.k), relay['kHex']);
    expect(debugTransferSas6(schedule.sasBytes), _h['sas']);

    // The relay builds that join from the QR alone.
    final relayJoin = await debugTransferJoinFromMaterial(
      qrText: qr['qr'] as String,
      x25519Private: _unhex(relay['newX25519PrivateHex'] as String),
      kemCiphertext: _unhex(relay['kemCiphertextHex'] as String),
      kemSharedSecret: _unhex(relay['kemSharedSecretHex'] as String),
    );
    expect(relayJoin.request.toJson(), relayBody);

    // The old phone accepts it and shows exactly the new phone's digits.
    final offer = await _vectorOffer();
    final oldKeys = await offer.verifyJoin(
      TransferJoinRequest.fromJson(relayBody),
    );
    expect(oldKeys.sas, _h['sas']);
    expect(
      oldKeys.confirmTag,
      _b64url(_unhex(relay['confirmTagHex'] as String)),
    );

    // The new phone (the vector join) refuses that confirmation: K' != K.
    final join = await _vectorJoin(qr['qr'] as String);
    expect(() => join.keys.sas, throwsStateError);
    expect(
      () => join.keys.verifyConfirm(oldKeys.confirmTag),
      throwsA(isA<TransferConfirmRejected>()),
    );
    expect(() => join.keys.sas, throwsStateError);
    expect(() => join.keys.verifyConfirm(oldKeys.confirmTag), throwsStateError);

    // The confirmation is genuine, for the relay's own K'.
    relayJoin.keys.verifyConfirm(oldKeys.confirmTag);
    expect(relayJoin.keys.sas, _h['sas']);

    oldKeys.dispose();
    offer.dispose();
    join.dispose();
    relayJoin.dispose();
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('sas6 uses rejection sampling exactly as the vector cases', () {
    final sas = _section('sas');
    for (final raw in sas['cases'] as List) {
      final c = Map<String, dynamic>.from(raw as Map);
      final bytes = _unhex(c['bytesHex'] as String);
      if (c['sas'] == null) {
        expect(() => debugTransferSas6(bytes), throwsStateError);
      } else {
        expect(debugTransferSas6(bytes), c['sas']);
      }
    }
  });

  test('the archive encodes and decodes to the vector bytes', () {
    final expected = <TransferArchiveEntry>[
      for (final raw in archive['entries'] as List)
        TransferArchiveEntry(
          TransferArchiveKind.values.singleWhere(
            (k) => k.wireName == (raw as Map)['kind'],
          ),
          (raw as Map)['key'] as String,
          _unhex(raw['valueHex'] as String),
        ),
    ];
    for (final raw in archive['entries'] as List) {
      final kind = TransferArchiveKind.values.singleWhere(
        (k) => k.wireName == (raw as Map)['kind'],
      );
      expect(kind.wireId, (raw as Map)['kindId']);
    }
    // Encoding is canonical whatever the input order.
    final encoded = TransferArchive(expected.reversed).encode();
    expect(_hex(encoded), archive['archiveHex']);

    final decoded = TransferArchive.decode(
      _unhex(archive['archiveHex'] as String),
    );
    expect(decoded.entries, hasLength(expected.length));
    for (var i = 0; i < expected.length; i++) {
      expect(decoded.entries[i].kind, expected[i].kind);
      expect(decoded.entries[i].key, expected[i].key);
      expect(decoded.entries[i].value, expected[i].value);
    }
  });

  test('the two-chunk archive seals to the vector chunks and opens', () async {
    final archiveBytes = _unhex(archive['archiveHex'] as String);
    final chunks = [
      for (final raw in archive['chunks'] as List)
        _unhex((raw as Map)['chunkHex'] as String),
    ];
    expect(chunks, hasLength(archive['total'] as int));

    final offer = await _vectorOffer();
    final oldKeys = await offer.verifyJoin(
      TransferJoinRequest.fromJson(Map<String, Object?>.from(_h['joinBody'])),
    );
    final sealed = await oldKeys.sealArchive(
      archiveBytes,
      chunkBytes: archive['chunkBytes'] as int,
    );
    expect(sealed.map(_hex).toList(), chunks.map(_hex).toList());

    final join = await _vectorJoin(qr['qr'] as String);
    expect(_hex(await join.keys.openArchive(chunks)), _hex(archiveBytes));
    for (final raw in archive['chunks'] as List) {
      final c = Map<String, dynamic>.from(raw as Map);
      final index = c['index'] as int;
      final plain = await join.keys.openChunk(
        index: index,
        total: chunks.length,
        chunk: _unhex(c['chunkHex'] as String),
      );
      final size = archive['chunkBytes'] as int;
      final end = (index + 1) * size < archiveBytes.length
          ? (index + 1) * size
          : archiveBytes.length;
      expect(_hex(plain), _hex(archiveBytes.sublist(index * size, end)));
    }
    oldKeys.dispose();
    offer.dispose();
    join.dispose();
  });
}
