@Retry(0)
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'helpers/crypto_test_fixtures.dart';

const _sessionKey = 'crypto_e2_session_bob-id_bob-device';
const _pendingKey = 'crypto_e2_pending_prekey_bob-id_bob-device';

void main() {
  group('outbound first-contact preflight', () {
    final corruptions = <String, void Function(Map<String, dynamic>)>{
      'missing protocol epoch': (pending) {
        pending.remove('cryptoProtocolEpoch');
      },
      'future KEM wire version': (pending) {
        pending['kemWireVersion'] = 2;
      },
      'short ephemeral X25519 key': (pending) {
        pending['ephemeralPublicKey'] = base64Encode(List<int>.filled(31, 1));
      },
      'non-integer signed pre-key id': (pending) {
        pending['recipientSignedPreKeyId'] = '1';
      },
      'reserved one-time pre-key id zero': (pending) {
        pending['usedOneTimePreKeyId'] = 0;
      },
      'short ML-KEM ciphertext': (pending) {
        pending['kyberCiphertext'] = base64Encode(List<int>.filled(1087, 2));
      },
    };

    for (final entry in corruptions.entries) {
      test(
        'normal send rejects ${entry.key} without any storage mutation',
        () async {
          final setup = await CryptoTestFixtures.createPairedManagers();
          final rawPending = setup.aliceStorage.store[_pendingKey]!;
          final pending = Map<String, dynamic>.from(
            jsonDecode(rawPending) as Map,
          );
          entry.value(pending);
          await setup.aliceStorage.write(
            key: _pendingKey,
            value: jsonEncode(pending),
          );
          final before = Map<String, String>.from(setup.aliceStorage.store);

          await expectLater(
            setup.alice.encryptMessage(
              'bob-id',
              'bob-device',
              'must not advance',
            ),
            throwsA(anything),
          );

          expect(setup.aliceStorage.store, before);
          expect(setup.aliceStorage.store[_sessionKey], isNotNull);
          expect(setup.aliceStorage.store[_pendingKey], jsonEncode(pending));
        },
      );
    }

    test(
      'sealed send validates pending data before ratchet mutation',
      () async {
        final setup = await CryptoTestFixtures.createPairedManagers();
        final pending = Map<String, dynamic>.from(
          jsonDecode(setup.aliceStorage.store[_pendingKey]!) as Map,
        )..['recipientSignedPreKeyId'] = -1;
        await setup.aliceStorage.write(
          key: _pendingKey,
          value: jsonEncode(pending),
        );
        final before = Map<String, String>.from(setup.aliceStorage.store);
        final bobIdentity = await setup.bob.getIdentityPublicKey();

        await expectLater(
          setup.alice.encryptSealedSender(
            'bob-id',
            'bob-device',
            bobIdentity,
            'must not advance',
          ),
          throwsA(anything),
        );

        expect(setup.aliceStorage.store, before);
      },
    );

    test(
      'sealed send validates local and recipient identity before mutation',
      () async {
        final setup = await CryptoTestFixtures.createPairedManagers();
        await setup.aliceStorage.delete(key: 'user_id');
        final beforeMissingSender = Map<String, String>.from(
          setup.aliceStorage.store,
        );
        final bobIdentity = await setup.bob.getIdentityPublicKey();

        await expectLater(
          setup.alice.encryptSealedSender(
            'bob-id',
            'bob-device',
            bobIdentity,
            'missing sender',
          ),
          throwsA(isA<StateError>()),
        );
        expect(setup.aliceStorage.store, beforeMissingSender);

        await setup.aliceStorage.write(key: 'user_id', value: 'alice-id');
        final beforeBadRecipient = Map<String, String>.from(
          setup.aliceStorage.store,
        );
        await expectLater(
          setup.alice.encryptSealedSender(
            'bob-id',
            'bob-device',
            base64Encode(List<int>.filled(31, 3)),
            'bad recipient',
          ),
          throwsA(isA<FormatException>()),
        );
        expect(setup.aliceStorage.store, beforeBadRecipient);
      },
    );
  });
}
