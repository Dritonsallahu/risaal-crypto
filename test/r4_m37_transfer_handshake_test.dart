import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

/// R4-M37 §2: the QR handshake between the old phone (O) and the new phone
/// (N), the join MAC, the SAS and the chunked archive AEAD.
String _b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _randomBytes(int length, [int seed = 7]) {
  final random = Random(seed);
  return Uint8List.fromList(
    List<int>.generate(length, (_) => random.nextInt(256)),
  );
}

Future<({TransferOffer offer, TransferJoin join})> _pair() async {
  final offer = await TransferHandshake.offer(apiHost: 'api.example.test');
  final join = await TransferHandshake.join(offer.qrText);
  return (offer: offer, join: join);
}

Map<String, Object?> _tamper(Map<String, String> body, String field) {
  final bytes = base64Url.decode(base64Url.normalize(body[field]!));
  bytes[bytes.length ~/ 2] ^= 0x01;
  return <String, Object?>{...body, field: _b64url(bytes)};
}

void main() {
  group('round trip', () {
    test('both phones derive the same SAS, slot and tags, and the archive '
        'survives the chunked AEAD', () async {
      final p = await _pair();
      expect(p.offer.qrText, startsWith('rx1:'));
      expect(p.offer.slotId, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(p.join.slotId, p.offer.slotId);
      expect(p.join.apiHost, 'api.example.test');

      final body = p.join.request.toJson();
      expect(body.keys.toSet(), {'eN', 'ct', 'getTag', 'completeTag', 'mac'});
      final oldKeys = await p.offer.verifyJoin(
        TransferJoinRequest.fromJson(
          jsonDecode(jsonEncode(body)) as Map<String, Object?>,
        ),
      );
      expect(oldKeys.sas, matches(RegExp(r'^[0-9]{6}$')));
      // §2f: the new phone shows its code only after the old phone's
      // key confirmation verified.
      expect(() => p.join.keys.sas, throwsStateError);
      p.join.keys.verifyConfirm(oldKeys.confirmTag);
      expect(oldKeys.sas, p.join.keys.sas);
      expect(oldKeys.slotId, p.join.keys.slotId);
      expect(p.join.keys.getTag, body['getTag']);
      expect(p.join.keys.completeTag, body['completeTag']);
      expect(p.join.keys.getTag, isNot(p.join.keys.completeTag));

      final archive = _randomBytes(5000);
      final chunks = await oldKeys.sealArchive(archive, chunkBytes: 1024);
      expect(chunks, hasLength(5));
      expect(await p.join.keys.openArchive(chunks), archive);

      oldKeys.dispose();
      p.offer.dispose();
      p.join.dispose();
    });

    test('every transfer is fresh: secrets, slots and SAS differ', () async {
      final a = await _pair();
      final b = await _pair();
      expect(a.offer.qrText, isNot(b.offer.qrText));
      expect(a.offer.slotId, isNot(b.offer.slotId));
      expect(
        a.join.request.toJson()['eN'],
        isNot(b.join.request.toJson()['eN']),
      );
      for (final p in [a, b]) {
        p.offer.dispose();
        p.join.dispose();
      }
    });

    test(
      'the default chunk size is used and the last chunk may be short',
      () async {
        final p = await _pair();
        final oldKeys = await p.offer.verifyJoin(p.join.request);
        final archive = _randomBytes(TransferProtocol.defaultChunkBytes + 3);
        final chunks = await oldKeys.sealArchive(archive);
        expect(chunks, hasLength(2));
        expect(chunks[1].length, 3 + 16);
        expect(await p.join.keys.openArchive(chunks), archive);
        oldKeys.dispose();
        p.offer.dispose();
        p.join.dispose();
      },
    );
  });

  group('join MAC (O refuses a tampered or foreign join)', () {
    for (final field in ['mac', 'getTag', 'completeTag', 'eN', 'ct']) {
      test('a flipped bit in $field is refused and burns the offer', () async {
        final p = await _pair();
        final body = p.join.request.toJson();
        await expectLater(
          p.offer.verifyJoin(
            TransferJoinRequest.fromJson(_tamper(body, field)),
          ),
          throwsA(isA<TransferJoinRejected>()),
        );
        // Abort and burn: the genuine join cannot be accepted afterwards.
        await expectLater(p.offer.verifyJoin(p.join.request), throwsStateError);
        p.offer.dispose();
        p.join.dispose();
      });
    }

    test('a join built from another transfer QR is refused', () async {
      final a = await _pair();
      final b = await _pair();
      await expectLater(
        a.offer.verifyJoin(b.join.request),
        throwsA(isA<TransferJoinRejected>()),
      );
      for (final p in [a, b]) {
        p.offer.dispose();
        p.join.dispose();
      }
    });

    test('a joiner with a wrong secret derives a different SAS and is '
        'refused', () async {
      final offer = await TransferHandshake.offer(apiHost: 'api.example.test');
      final payload = base64Url.decode(
        base64Url.normalize(offer.qrText.substring(4)),
      );
      payload[1 + 4] ^= 0x80; // first byte of s
      final wrongJoin = await TransferHandshake.join('rx1:${_b64url(payload)}');
      expect(wrongJoin.slotId, isNot(offer.slotId));
      await expectLater(
        offer.verifyJoin(wrongJoin.request),
        throwsA(isA<TransferJoinRejected>()),
      );

      // Against a correct joiner of the same offer the SAS differs as well.
      final offer2 = await TransferHandshake.offer(apiHost: 'api.example.test');
      final good = await TransferHandshake.join(offer2.qrText);
      final payload2 = base64Url.decode(
        base64Url.normalize(offer2.qrText.substring(4)),
      );
      payload2[1 + 4] ^= 0x80;
      final bad = await TransferHandshake.join('rx1:${_b64url(payload2)}');
      final oldKeys = await offer2.verifyJoin(good.request);
      good.keys.verifyConfirm(oldKeys.confirmTag);
      expect(oldKeys.sas, good.keys.sas);
      // The wrong-secret joiner refuses that confirmation and shows no code.
      expect(
        () => bad.keys.verifyConfirm(oldKeys.confirmTag),
        throwsA(isA<TransferConfirmRejected>()),
      );
      expect(() => bad.keys.sas, throwsStateError);
      // A different K: the SAS mismatch itself is pinned by the vector test,
      // because two random 6-digit codes collide once in a million runs.
      expect(bad.keys.getTag, isNot(good.keys.getTag));
      expect(bad.keys.completeTag, isNot(good.keys.completeTag));
      for (final x in [offer, offer2]) {
        x.dispose();
      }
      for (final x in [wrongJoin, good, bad]) {
        x.dispose();
      }
      oldKeys.dispose();
    });

    test('a low-order (all-zero) eN is refused', () async {
      final p = await _pair();
      final body = p.join.request.toJson();
      final zero = <String, Object?>{...body, 'eN': _b64url(Uint8List(32))};
      await expectLater(
        p.offer.verifyJoin(TransferJoinRequest.fromJson(zero)),
        throwsA(isA<TransferJoinRejected>()),
      );
      p.offer.dispose();
      p.join.dispose();
    });

    test('verifyJoin is single use even after success', () async {
      final p = await _pair();
      final keys = await p.offer.verifyJoin(p.join.request);
      await expectLater(p.offer.verifyJoin(p.join.request), throwsStateError);
      keys.dispose();
      p.offer.dispose();
      p.join.dispose();
    });
  });

  group('chunk AEAD (AAD = slot || index || total)', () {
    late TransferOffer offer;
    late TransferJoin join;
    late TransferSessionKeys oldKeys;
    late Uint8List archive;
    late List<Uint8List> chunks;

    setUp(() async {
      final p = await _pair();
      offer = p.offer;
      join = p.join;
      oldKeys = await offer.verifyJoin(join.request);
      archive = _randomBytes(3 * 64 + 10, 11);
      chunks = await oldKeys.sealArchive(archive, chunkBytes: 64);
      expect(chunks, hasLength(4));
    });

    tearDown(() {
      oldKeys.dispose();
      offer.dispose();
      join.dispose();
    });

    Future<void> refuses(List<List<int>> candidate) => expectLater(
      join.keys.openArchive(candidate),
      throwsA(isA<TransferArchiveDecryptFailed>()),
    );

    test('reordered chunks fail', () async {
      await refuses([chunks[1], chunks[0], chunks[2], chunks[3]]);
      await refuses([chunks[0], chunks[1], chunks[3], chunks[2]]);
    });

    test('a dropped chunk fails (first, middle, last)', () async {
      await refuses(chunks.sublist(1));
      await refuses([chunks[0], chunks[2], chunks[3]]);
      await refuses(chunks.sublist(0, 3));
    });

    test('an appended or duplicated chunk fails', () async {
      await refuses([...chunks, chunks[3]]);
      await refuses([chunks[0], chunks[0], chunks[1], chunks[2], chunks[3]]);
    });

    test('a flipped bit anywhere in any chunk fails', () async {
      for (var c = 0; c < chunks.length; c++) {
        for (final position in [
          0,
          chunks[c].length - 17,
          chunks[c].length - 1,
        ]) {
          final tampered = [
            for (final chunk in chunks) Uint8List.fromList(chunk),
          ];
          tampered[c][position] ^= 0x01;
          await refuses(tampered);
        }
      }
    });

    test('a chunk opened under the wrong index or total fails', () async {
      await expectLater(
        join.keys.openChunk(index: 1, total: 4, chunk: chunks[0]),
        throwsA(isA<TransferArchiveDecryptFailed>()),
      );
      await expectLater(
        join.keys.openChunk(index: 0, total: 5, chunk: chunks[0]),
        throwsA(isA<TransferArchiveDecryptFailed>()),
      );
      expect(
        await join.keys.openChunk(index: 0, total: 4, chunk: chunks[0]),
        archive.sublist(0, 64),
      );
    });

    test('a chunk from another transfer fails', () async {
      final other = await _pair();
      final otherKeys = await other.offer.verifyJoin(other.join.request);
      final foreign = await otherKeys.sealArchive(archive, chunkBytes: 64);
      await refuses(foreign);
      await refuses([chunks[0], foreign[1], chunks[2], chunks[3]]);
      otherKeys.dispose();
      other.offer.dispose();
      other.join.dispose();
    });

    test('empty, truncated and out-of-range input fails', () async {
      await refuses(const <List<int>>[]);
      await refuses([
        chunks[0].sublist(0, 16),
        chunks[1],
        chunks[2],
        chunks[3],
      ]);
      await expectLater(
        join.keys.openChunk(index: 4, total: 4, chunk: chunks[0]),
        throwsA(isA<TransferArchiveDecryptFailed>()),
      );
      await expectLater(
        join.keys.openChunk(index: -1, total: 4, chunk: chunks[0]),
        throwsA(isA<TransferArchiveDecryptFailed>()),
      );
    });

    test('sealing is one-shot and only on the old phone; opening only on the '
        'new phone', () async {
      await expectLater(
        oldKeys.sealArchive(archive, chunkBytes: 64),
        throwsStateError,
      );
      await expectLater(
        join.keys.sealArchive(archive, chunkBytes: 64),
        throwsStateError,
      );
      await expectLater(oldKeys.openArchive(chunks), throwsStateError);
    });

    test('disposed keys refuse to work', () async {
      join.keys.dispose();
      await expectLater(join.keys.openArchive(chunks), throwsStateError);
    });
  });

  group('sealArchive input limits', () {
    test('empty archive and bad chunk sizes are refused', () async {
      for (final chunkBytes in [0, -1, TransferProtocol.maxChunkBytes + 1]) {
        final p = await _pair();
        final keys = await p.offer.verifyJoin(p.join.request);
        await expectLater(
          keys.sealArchive(_randomBytes(10), chunkBytes: chunkBytes),
          throwsArgumentError,
        );
        keys.dispose();
        p.offer.dispose();
        p.join.dispose();
      }
      final p = await _pair();
      final keys = await p.offer.verifyJoin(p.join.request);
      await expectLater(keys.sealArchive(Uint8List(0)), throwsArgumentError);
      keys.dispose();
      p.offer.dispose();
      p.join.dispose();
    });
  });

  group('QR payload (strict decode)', () {
    late TransferOffer offer;
    late Uint8List payload;

    setUp(() async {
      offer = await TransferHandshake.offer(apiHost: 'api.example.test');
      payload = base64Url.decode(
        base64Url.normalize(offer.qrText.substring(4)),
      );
    });

    tearDown(() => offer.dispose());

    Future<void> refused(String text) => expectLater(
      TransferHandshake.join(text),
      throwsA(isA<FormatException>()),
    );

    Uint8List withHost(String host) {
      final head = payload.sublist(0, 1 + 4 + 32 + 4 + 32 + 4 + 1184);
      final hostBytes = utf8.encode(host);
      return Uint8List.fromList([
        ...head,
        ...[0, 0, (hostBytes.length >> 8) & 0xff, hostBytes.length & 0xff],
        ...hostBytes,
      ]);
    }

    test('the payload layout is version || lp(s) || lp(eO) || lp(kO) || '
        'lp(host)', () {
      expect(payload[0], TransferProtocol.version);
      expect(payload.sublist(1, 5), [0, 0, 0, 32]);
      expect(payload.sublist(37, 41), [0, 0, 0, 32]);
      expect(payload.sublist(73, 77), [0, 0, 0x04, 0xa0]);
      expect(utf8.decode(payload.sublist(1261 + 4)), 'api.example.test');
      expect(payload.length, 1261 + 4 + 'api.example.test'.length);
    });

    test('the genuine QR is accepted', () async {
      final join = await TransferHandshake.join(offer.qrText);
      join.dispose();
    });

    test('a wrong prefix, padding or non-base64url text is refused', () async {
      final body = offer.qrText.substring(4);
      await refused('rx2:$body');
      await refused('RX1:$body');
      await refused(body);
      // A 15-byte host makes the payload length 1280, which base64 pads.
      final padded = base64Url.encode(withHost('api.example.tes'));
      expect(padded, endsWith('='));
      await refused('rx1:$padded');
      await refused('rx1:${base64.encode(payload).replaceAll('=', '')}');
      await refused('rx1:$body ');
      await refused('rx1:');
      await refused('');
    });

    test('an unknown version is refused', () async {
      for (final version in [0, 2, 255]) {
        final copy = Uint8List.fromList(payload)..[0] = version;
        await refused('rx1:${_b64url(copy)}');
      }
    });

    test('a trailing byte or a truncated payload is refused', () async {
      await refused('rx1:${_b64url([...payload, 0])}');
      await refused('rx1:${_b64url(payload.sublist(0, payload.length - 1))}');
      await refused('rx1:${_b64url(payload.sublist(0, 40))}');
    });

    test('a wrong field length is refused', () async {
      // s announced as 31 bytes.
      final copy = Uint8List.fromList(payload)..[4] = 31;
      await refused('rx1:${_b64url(copy)}');
    });

    test('an invalid ML-KEM public key is refused', () async {
      final copy = Uint8List.fromList(payload);
      for (var i = 77; i < 77 + 1184; i++) {
        copy[i] = 0xff;
      }
      await refused('rx1:${_b64url(copy)}');
    });

    test('an empty, oversized or malformed host is refused', () async {
      for (final host in [
        '',
        'a' * 254,
        'api example.test',
        'api.example.test/',
        'https://api.example.test',
        'api.example.test:99999',
        'ápi.example.test',
      ]) {
        await refused('rx1:${_b64url(withHost(host))}');
      }
      final ok = await TransferHandshake.join(
        'rx1:${_b64url(withHost('API-2.example.test:8443'))}',
      );
      expect(ok.apiHost, 'API-2.example.test:8443');
      ok.dispose();
    });

    test('offer refuses a malformed host', () async {
      for (final host in ['', 'a b', 'x/y']) {
        await expectLater(
          TransferHandshake.offer(apiHost: host),
          throwsArgumentError,
        );
      }
    });
  });

  group('join body (strict JSON)', () {
    late TransferJoin join;
    late Map<String, String> body;

    setUp(() async {
      final offer = await TransferHandshake.offer(apiHost: 'api.example.test');
      join = await TransferHandshake.join(offer.qrText);
      body = join.request.toJson();
      offer.dispose();
    });

    tearDown(() => join.dispose());

    void refused(Map<String, Object?> json) => expect(
      () => TransferJoinRequest.fromJson(json),
      throwsA(isA<FormatException>()),
    );

    test('missing, extra or non-string fields are refused', () {
      for (final field in body.keys) {
        refused(<String, Object?>{...body}..remove(field));
        refused(<String, Object?>{...body, field: 7});
        refused(<String, Object?>{...body, field: null});
      }
      refused(<String, Object?>{...body, 'slot': 'x'});
    });

    test('wrong lengths and non-canonical base64url are refused', () {
      for (final field in body.keys) {
        final bytes = base64Url.decode(base64Url.normalize(body[field]!));
        refused(<String, Object?>{...body, field: _b64url(bytes.sublist(1))});
        refused(<String, Object?>{
          ...body,
          field: _b64url([...bytes, 0]),
        });
        refused(<String, Object?>{...body, field: base64Url.encode(bytes)});
        refused(<String, Object?>{...body, field: base64.encode(bytes)});
        refused(<String, Object?>{...body, field: ' ${body[field]}'});
      }
    });

    test('the genuine body round-trips', () {
      expect(TransferJoinRequest.fromJson(body).toJson(), body);
    });
  });
}
