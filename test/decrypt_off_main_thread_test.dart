import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';

import 'helpers/crypto_test_fixtures.dart';

/// Audit 2026-06 performance: with [SignalProtocolManager.decryptOffMainThread]
/// on, the ratchet decrypt runs in a background isolate. The result and the
/// session-state advancement must be IDENTICAL to the inline path — verified
/// end-to-end through the full decryptMessage path (the same path sealed-sender
/// inner messages take).
void main() {
  tearDown(() => SignalProtocolManager.decryptOffMainThread = false);

  Future<(SignalProtocolManager bob, SignalProtocolManager alice)>
  handshaken() async {
    final p = await CryptoTestFixtures.createPairedManagers();
    final alice = p.alice;
    final bob = p.bob;
    // PreKey handshake (stays inline — prekey path establishes the session).
    final init = await alice.encryptMessage('bob-id', 'bob-device', 'init');
    await bob.decryptMessage('alice-id', 'alice-device', init);
    final reply = await bob.encryptMessage('alice-id', 'alice-device', 'reply');
    await alice.decryptMessage('bob-id', 'bob-device', reply);
    return (bob, alice);
  }

  test(
    'off-thread decrypt returns the correct plaintext for a backlog',
    () async {
      SignalProtocolManager.decryptOffMainThread = true;
      final (bob, alice) = await handshaken();

      for (final t in ['one', 'two', 'three', 'four', 'five']) {
        final env = await alice.encryptMessage('bob-id', 'bob-device', t);
        final dec = await bob.decryptMessage('alice-id', 'alice-device', env);
        expect(dec, t, reason: 'off-thread decrypt must match the plaintext');
      }
    },
  );

  test(
    'off-thread decrypt advances session state so later messages still work',
    () async {
      final (bob, alice) = await handshaken();

      // First two inline (flag off), then flip on mid-stream — state must stay
      // consistent across the boundary.
      final e1 = await alice.encryptMessage('bob-id', 'bob-device', 'inline-1');
      expect(
        await bob.decryptMessage('alice-id', 'alice-device', e1),
        'inline-1',
      );

      SignalProtocolManager.decryptOffMainThread = true;
      final e2 = await alice.encryptMessage(
        'bob-id',
        'bob-device',
        'offthread-2',
      );
      expect(
        await bob.decryptMessage('alice-id', 'alice-device', e2),
        'offthread-2',
      );

      SignalProtocolManager.decryptOffMainThread = false;
      final e3 = await alice.encryptMessage('bob-id', 'bob-device', 'inline-3');
      expect(
        await bob.decryptMessage('alice-id', 'alice-device', e3),
        'inline-3',
        reason: 'state committed off-thread must be usable by the inline path',
      );
    },
  );
}
