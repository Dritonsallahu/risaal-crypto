import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/transfer/transfer_handshake.dart'
    show
        debugTransferJoinFromMaterial,
        debugTransferKeySchedule,
        debugTransferSas6;

/// R4-M37 §2f (M37-CRYPTO-1): key confirmation from the old phone (O) to the
/// new phone (N). N shows no code before O's `confirmTag` verified under N's
/// own K, so a relay that holds a photo of the QR has no code to grind a
/// substituted join against, and N refuses the confirmation of any join but
/// its own.
const Timeout _timeout = Timeout(Duration(seconds: 60));

String _b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _unb64url(String text) => base64Url.decode(base64Url.normalize(text));

final Random _random = Random.secure();

Uint8List _secureBytes(int length) =>
    Uint8List.fromList(List<int>.generate(length, (_) => _random.nextInt(256)));

Future<({TransferOffer offer, TransferJoin join, TransferSessionKeys oldKeys})>
_joined() async {
  final offer = await TransferHandshake.offer(apiHost: 'api.example.test');
  final join = await TransferHandshake.join(offer.qrText);
  final oldKeys = await offer.verifyJoin(join.request);
  return (offer: offer, join: join, oldKeys: oldKeys);
}

/// What a photo of the QR gives: `s`, `eO.pub` and `kO.pub`.
final class _Qr {
  _Qr(String qrText) : _payload = _unb64url(qrText.substring(4));

  final Uint8List _payload;

  Uint8List get secret => _payload.sublist(5, 37);
  Uint8List get x25519Public => _payload.sublist(41, 73);
  Uint8List get kemPublic => _payload.sublist(77, 77 + 1184);
}

final X25519 _x25519 = X25519();

/// The code a joiner with this material gets, derived outside the session
/// keys (what an attacker computes for itself).
Future<String> _codeOf(
  _Qr qr,
  List<int> x25519Private,
  List<int> kemCiphertext,
  List<int> kemSharedSecret,
) async {
  final keyPair = await _x25519.newKeyPairFromSeed(x25519Private);
  final public = (await keyPair.extractPublicKey()).bytes;
  final shared = await _x25519.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: SimplePublicKey(qr.x25519Public, type: KeyPairType.x25519),
  );
  final schedule = await debugTransferKeySchedule(
    secret: qr.secret,
    x25519Shared: await shared.extractBytes(),
    kemSharedSecret: kemSharedSecret,
    oldX25519Public: qr.x25519Public,
    oldKemPublic: qr.kemPublic,
    newX25519Public: public,
    kemCiphertext: kemCiphertext,
  );
  return debugTransferSas6(schedule.sasBytes);
}

void main() {
  group('key confirmation (contract §2f)', () {
    test(
      "the new phone's code is unreadable until verifyConfirm accepted the "
      "old phone's confirmTag; the old phone's is readable at once",
      () async {
        final offer = await TransferHandshake.offer(
          apiHost: 'api.example.test',
        );
        final join = await TransferHandshake.join(offer.qrText);
        expect(() => join.keys.sas, throwsStateError);

        final oldKeys = await offer.verifyJoin(join.request);
        expect(oldKeys.sas, matches(RegExp(r'^[0-9]{6}$')));
        // O accepting the join is not enough: N waits for O's confirmation.
        expect(() => join.keys.sas, throwsStateError);
        expect(oldKeys.confirmTag, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));

        join.keys.verifyConfirm(oldKeys.confirmTag);
        expect(join.keys.sas, oldKeys.sas);
        // The archive still flows after the confirmation.
        final archive = _secureBytes(300);
        final chunks = await oldKeys.sealArchive(archive, chunkBytes: 128);
        expect(await join.keys.openArchive(chunks), archive);

        oldKeys.dispose();
        offer.dispose();
        join.dispose();
      },
      timeout: _timeout,
    );

    test('only the old phone publishes a confirmTag and only the new phone '
        'verifies one', () async {
      final p = await _joined();
      expect(() => p.join.keys.confirmTag, throwsStateError);
      expect(
        () => p.oldKeys.verifyConfirm(p.oldKeys.confirmTag),
        throwsStateError,
      );
      // Neither misuse spent anything: the genuine check still passes and
      // the old phone still seals.
      p.join.keys.verifyConfirm(p.oldKeys.confirmTag);
      expect(p.join.keys.sas, p.oldKeys.sas);
      final chunks = await p.oldKeys.sealArchive(_secureBytes(10));
      expect(chunks, hasLength(1));

      p.oldKeys.dispose();
      p.offer.dispose();
      p.join.dispose();
    }, timeout: _timeout);

    test(
      'a confirmTag computed under a different K is refused and burns the new '
      "phone's keys",
      () async {
        final a = await _joined();
        final b = await _joined();
        expect(a.oldKeys.confirmTag, isNot(b.oldKeys.confirmTag));
        expect(
          () => a.join.keys.verifyConfirm(b.oldKeys.confirmTag),
          throwsA(isA<TransferConfirmRejected>()),
        );
        // Burned: no code ever, no second check, no archive.
        expect(() => a.join.keys.sas, throwsStateError);
        expect(
          () => a.join.keys.verifyConfirm(a.oldKeys.confirmTag),
          throwsStateError,
        );
        final chunks = await a.oldKeys.sealArchive(
          _secureBytes(100),
          chunkBytes: 64,
        );
        await expectLater(a.join.keys.openArchive(chunks), throwsStateError);

        for (final p in [a, b]) {
          p.oldKeys.dispose();
          p.offer.dispose();
          p.join.dispose();
        }
      },
      timeout: _timeout,
    );

    test("the join's own tags and a tampered confirmTag are refused", () async {
      // The relay sees N's getTag, completeTag and mac in the join body:
      // none of them may pass as the confirmation (separate labels).
      Future<void> refused(
        String Function(Map<String, String> body, TransferSessionKeys oldKeys)
        pick,
      ) async {
        final p = await _joined();
        final candidate = pick(p.join.request.toJson(), p.oldKeys);
        expect(
          () => p.join.keys.verifyConfirm(candidate),
          throwsA(isA<TransferConfirmRejected>()),
        );
        expect(() => p.join.keys.sas, throwsStateError);
        p.oldKeys.dispose();
        p.offer.dispose();
        p.join.dispose();
      }

      await refused((body, _) => body['getTag']!);
      await refused((body, _) => body['completeTag']!);
      await refused((body, _) => body['mac']!);
      for (final position in [0, 15, 31]) {
        for (final bit in [0x01, 0x80]) {
          await refused((_, oldKeys) {
            final bytes = _unb64url(oldKeys.confirmTag);
            bytes[position] ^= bit;
            return _b64url(bytes);
          });
        }
      }
    }, timeout: _timeout);

    test('a malformed confirmTag is refused and burns the keys', () async {
      final candidates = <String Function(String genuine)>[
        (_) => '',
        (g) => '$g=',
        (g) => ' $g',
        (g) => '$g ',
        (g) => '+${g.substring(1)}',
        (g) => base64.encode(_unb64url(g)),
        (g) => _b64url(_unb64url(g).sublist(1)),
        (g) => _b64url([..._unb64url(g), 0]),
        // The same 32 bytes with a non-zero unused bit: not canonical.
        (g) {
          const alphabet =
              'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
              '0123456789-_';
          final last = alphabet.indexOf(g[g.length - 1]);
          return g.substring(0, g.length - 1) + alphabet[last | 1];
        },
      ];
      for (final candidate in candidates) {
        final p = await _joined();
        final genuine = p.oldKeys.confirmTag;
        expect(
          () => p.join.keys.verifyConfirm(candidate(genuine)),
          throwsA(isA<TransferConfirmRejected>()),
        );
        expect(() => p.join.keys.sas, throwsStateError);
        expect(() => p.join.keys.verifyConfirm(genuine), throwsStateError);
        p.oldKeys.dispose();
        p.offer.dispose();
        p.join.dispose();
      }
    }, timeout: _timeout);

    test(
      'verifyConfirm is single use; keys disposed before it never show a code',
      () async {
        final p = await _joined();
        p.join.keys.verifyConfirm(p.oldKeys.confirmTag);
        expect(
          () => p.join.keys.verifyConfirm(p.oldKeys.confirmTag),
          throwsStateError,
        );
        expect(p.join.keys.sas, p.oldKeys.sas);

        final q = await _joined();
        q.join.dispose();
        expect(
          () => q.join.keys.verifyConfirm(q.oldKeys.confirmTag),
          throwsStateError,
        );
        expect(() => q.join.keys.sas, throwsStateError);

        for (final x in [p, q]) {
          x.oldKeys.dispose();
          x.offer.dispose();
          x.join.dispose();
        }
      },
      timeout: _timeout,
    );

    test('verifyConfirm compares in constant time (static guard)', () {
      final source = File(
        'lib/src/transfer/transfer_handshake.dart',
      ).readAsStringSync();
      String body(String signature) {
        final start = source.indexOf(signature);
        expect(start, isNonNegative, reason: signature);
        return source.substring(start, source.indexOf('\n  }\n', start));
      }

      final verify = body('void verifyConfirm(String confirmTag) {');
      expect(verify, contains('_constantTimeEquals(_confirmTag, received)'));
      final comparisons = verify.replaceAll('received == null', '');
      for (final banned in ['==', '!=', 'listEquals', 'Equality', 'equals(']) {
        expect(comparisons, isNot(contains(banned)), reason: banned);
      }
      // The shared helper accumulates every byte and returns once.
      final helper = source.substring(
        source.indexOf('bool _constantTimeEquals('),
        source.indexOf('\n}\n', source.indexOf('bool _constantTimeEquals(')),
      );
      expect(helper, contains('difference |= left[i] ^ right[i];'));
      expect(RegExp(r'\breturn\b').allMatches(helper), hasLength(1));
    }, timeout: _timeout);
  });

  group('relay substitution (M37-CRYPTO-1)', () {
    test('a join substituted by anyone holding the QR is accepted by the old '
        'phone, but the new phone refuses its confirmation', () async {
      final offer = await TransferHandshake.offer(apiHost: 'api.example.test');
      final newPhone = await TransferHandshake.join(offer.qrText);
      // The relay withholds N's join and serves O one built from a photo
      // of the QR with the same public API.
      final relay = await TransferHandshake.join(offer.qrText);
      final oldKeys = await offer.verifyJoin(relay.request);

      expect(
        () => newPhone.keys.verifyConfirm(oldKeys.confirmTag),
        throwsA(isA<TransferConfirmRejected>()),
      );
      expect(() => newPhone.keys.sas, throwsStateError);
      // The confirmation is genuine for the relay's K': O talks to it.
      relay.keys.verifyConfirm(oldKeys.confirmTag);
      expect(relay.keys.sas, oldKeys.sas);

      oldKeys.dispose();
      offer.dispose();
      newPhone.dispose();
      relay.dispose();
    }, timeout: _timeout);

    test("grind: even knowing the new phone's code, a relay that holds the QR "
        'and grinds a join until the old phone shows matching digits cannot '
        'make the new phone show a code', () async {
      final offer = await TransferHandshake.offer(apiHost: 'api.example.test');
      final qr = _Qr(offer.qrText); // the relay's photo

      // N joins with fresh material; the relay answers 200 and withholds
      // the join. N shows nothing, so there is no code to grind against.
      final newPrivate = _secureBytes(32);
      final (newCiphertext, newSecret) = PqcKem.kyber768.encapsulate(
        qr.kemPublic,
      );
      final newPhone = await debugTransferJoinFromMaterial(
        qrText: offer.qrText,
        x25519Private: newPrivate,
        kemCiphertext: newCiphertext,
        kemSharedSecret: newSecret,
      );
      expect(() => newPhone.keys.sas, throwsStateError);

      // Assume the worst anyway: the relay learned N's code.
      final newCode = await _codeOf(qr, newPrivate, newCiphertext, newSecret);

      // The review's grind: one encapsulation of its own, then fresh eN'
      // until O's code ends in the same three digits (all six take about
      // 1e6 tries; the vector test holds such a full collision).
      final (relayCiphertext, relaySecret) = PqcKem.kyber768.encapsulate(
        qr.kemPublic,
      );
      Uint8List? relayPrivate;
      String? relayCode;
      for (var tries = 0; relayPrivate == null; tries++) {
        expect(tries, lessThan(100000));
        final candidate = _secureBytes(32);
        final code = await _codeOf(qr, candidate, relayCiphertext, relaySecret);
        if (code.substring(3) == newCode.substring(3)) {
          relayPrivate = candidate;
          relayCode = code;
        }
      }
      final relay = await debugTransferJoinFromMaterial(
        qrText: offer.qrText,
        x25519Private: relayPrivate,
        kemCiphertext: relayCiphertext,
        kemSharedSecret: relaySecret,
      );

      // O accepts the substituted join and shows the matching digits.
      final oldKeys = await offer.verifyJoin(
        TransferJoinRequest.fromJson(relay.request.toJson()),
      );
      expect(oldKeys.sas, relayCode);
      expect(oldKeys.sas.substring(3), newCode.substring(3));

      // N refuses O's confirmation and never shows a code.
      expect(
        () => newPhone.keys.verifyConfirm(oldKeys.confirmTag),
        throwsA(isA<TransferConfirmRejected>()),
      );
      expect(() => newPhone.keys.sas, throwsStateError);
      expect(
        () => newPhone.keys.verifyConfirm(oldKeys.confirmTag),
        throwsStateError,
      );

      // The relay's own keys accept it, and the code it computed for itself
      // is the one the package shows: the oracle above is the real code.
      relay.keys.verifyConfirm(oldKeys.confirmTag);
      expect(relay.keys.sas, relayCode);

      oldKeys.dispose();
      offer.dispose();
      newPhone.dispose();
      relay.dispose();
    }, timeout: const Timeout(Duration(minutes: 3)));
  });
}
