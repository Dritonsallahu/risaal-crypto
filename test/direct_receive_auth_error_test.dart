@TestOn('vm')
library;

import 'dart:convert';

import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:test/test.dart';

import 'helpers/crypto_test_fixtures.dart';
import 'helpers/fake_secure_storage.dart';

/// A tampered normal (non-PreKey) message on the direct receive path must
/// surface as [MessageAuthenticationError] and emit
/// messageAuthenticationRejected. The handler sat around a non-awaited future,
/// so for async failures it never ran: the raw cipher error escaped and the
/// tamper signal was never raised.
void main() {
  test(
    'tampered normal message → MessageAuthenticationError + event',
    () async {
      final (alice, aliceStorage) =
          await CryptoTestFixtures.createInitializedManager();
      final bus = SecurityEventBus();
      final bobStorage = FakeSecureStorage();
      final bob = SignalProtocolManager(
        secureStorage: bobStorage,
        securityEventBus: bus,
      );
      await bob.wipeForFreshRegistration();
      await bob.initialize();
      await aliceStorage.write(key: 'user_id', value: 'alice-id');
      await aliceStorage.write(key: 'device_id', value: 'alice-device');
      await bobStorage.write(key: 'user_id', value: 'bob-id');
      await bobStorage.write(key: 'device_id', value: 'bob-device');
      final accepted = await CryptoTestFixtures.acceptInitialGeneration(bob);
      await alice.createSession(accepted.consumerBundle());

      final opener = await alice.encryptMessage('bob-id', 'bob-device', 'one');
      final second = await alice.encryptMessage('bob-id', 'bob-device', 'two');
      final first = await bob.prepareReceive(
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: opener,
        deliveryId: 'd-1',
      );
      await bob.acknowledgeReceive(first.receipt);

      final message = Map<String, dynamic>.from(second['message'] as Map);
      final bytes = base64Decode(message['ciphertext'] as String);
      bytes[bytes.length - 1] ^= 0x01; // flip one bit of the GCM tag
      message['ciphertext'] = base64Encode(bytes);
      final tampered = Map<String, dynamic>.from(second)..['message'] = message;

      final events = <SecurityEventType>[];
      final sub = bus.events.listen((e) => events.add(e.type));
      await expectLater(
        bob.prepareReceive(
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: tampered,
          deliveryId: 'd-2',
        ),
        throwsA(isA<MessageAuthenticationError>()),
      );
      await Future<void>.delayed(Duration.zero);
      await sub.cancel();
      expect(events, contains(SecurityEventType.messageAuthenticationRejected));
    },
  );
}
