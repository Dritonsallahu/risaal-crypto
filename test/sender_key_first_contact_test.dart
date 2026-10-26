import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/crypto_test_fixtures.dart';

void main() {
  test(
    'a no-session recipient establishes from the PreKey SKDM and decrypts the first group message',
    () async {
      final pair = await CryptoTestFixtures.createPairedManagers();
      const groupId = 'group-first-contact';

      expect(await pair.bob.hasSession('alice-id', 'alice-device'), isFalse);
      expect(await pair.bob.hasGroupSenderKeyFor(groupId, 'alice-id'), isFalse);

      final distribution = await pair.alice.generateGroupSenderKey(groupId);
      final distributionEnvelope = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        jsonEncode(distribution.toJson()),
      );
      expect(distributionEnvelope['type'], 'prekey');

      // Alice's next direct ratchet step is a normal envelope. Delivering it
      // before the PreKey bootstrap must not fabricate a recipient session or
      // mutate any of Bob's durable crypto state.
      final prematureNormal = await pair.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'normal-before-bootstrap',
      );
      expect(prematureNormal['type'], 'message');
      final beforePremature = pair.bobStorage.store;
      await expectLater(
        pair.bob.prepareReceive(
          deliveryId: 'skdm-premature-normal',
          senderId: 'alice-id',
          senderDeviceId: 'alice-device',
          envelope: prematureNormal,
        ),
        throwsA(isA<StateError>()),
      );
      expect(pair.bobStorage.store, beforePremature);

      final firstGroupCiphertext = await pair.alice.encryptGroupMessage(
        groupId,
        'first group message',
      );
      final prepared = await pair.bob.prepareReceive(
        deliveryId: 'skdm-first-contact-prekey',
        senderId: 'alice-id',
        senderDeviceId: 'alice-device',
        envelope: distributionEnvelope,
      );
      expect(prepared.receipt.kind, ReceiveEnvelopeKind.directPreKey);
      expect(
        await pair.bob.hasSession('alice-id', 'alice-device'),
        isFalse,
        reason: 'the direct session stays provisional until host ACK',
      );

      final decoded = jsonDecode(prepared.plaintext!);
      final receivedDistribution = SenderKeyDistribution.fromJson(
        Map<String, dynamic>.from(decoded as Map),
      );
      await pair.bob.processGroupSenderKey(
        groupId,
        'alice-id',
        receivedDistribution,
      );
      await pair.bob.acknowledgeReceive(prepared.receipt);

      expect(await pair.bob.hasSession('alice-id', 'alice-device'), isTrue);
      expect(await pair.bob.hasGroupSenderKeyFor(groupId, 'alice-id'), isTrue);
      expect(
        await pair.bob.decryptGroupMessage(
          groupId,
          'alice-id',
          firstGroupCiphertext,
        ),
        'first group message',
      );
    },
  );
}
