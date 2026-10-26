import 'package:flutter_test/flutter_test.dart';

import 'helpers/crypto_test_fixtures.dart';

/// H8 — dropping the in-memory ratchet cache (done on app background to keep key
/// material out of the live Dart heap) must NEVER lose a message: the session
/// reloads transparently from secure storage on the next use.
void main() {
  test(
    'wipeAllSessions does not break decryption — session reloads from storage',
    () async {
      final m = await CryptoTestFixtures.createPairedManagers();

      // alice → bob (first message; the PreKey message establishes bob's session
      // and persists it to secure storage).
      final e1 = await m.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'msg one',
      );
      expect(
        await m.bob.decryptMessage('alice-id', 'alice-device', e1),
        'msg one',
      );

      // Simulate the app backgrounding on bob's device: drop the in-memory
      // ratchet cache (the MemoryGuard wipe callback).
      m.bob.wipeAllSessions();

      // alice → bob again; bob must still decrypt by reloading from storage.
      final e2 = await m.alice.encryptMessage(
        'bob-id',
        'bob-device',
        'msg two',
      );
      expect(
        await m.bob.decryptMessage('alice-id', 'alice-device', e2),
        'msg two',
        reason:
            'the session must reload from secure storage after the cache wipe',
      );
    },
  );
}
