/// Safety Number verification.
///
/// Safety numbers allow two users to verify each other's identity
/// out-of-band (in person, via phone call, etc.). Both users see
/// the same 60-digit code. If the codes match, the session has not
/// been intercepted by a man-in-the-middle.
library;

import 'package:risaal_crypto/risaal_crypto.dart';

// In-memory storage for demonstration
class InMemoryStorage implements CryptoSecureStorage {
  final _store = <String, String>{};

  @override
  Future<void> write({required String key, required String value}) async =>
      _store[key] = value;

  @override
  Future<String?> read({required String key}) async => _store[key];

  @override
  Future<void> delete({required String key}) async => _store.remove(key);

  @override
  Future<void> clearAll() async => _store.clear();
}

Future<void> main() async {
  // ── Setup Alice and Bob ─────────────────────────────────────────
  final aliceStorage = InMemoryStorage();
  final bobStorage = InMemoryStorage();

  await aliceStorage.write(key: 'user_id', value: 'alice-001');
  await aliceStorage.write(key: 'device_id', value: 'alice-device-1');
  await bobStorage.write(key: 'user_id', value: 'bob-001');
  await bobStorage.write(key: 'device_id', value: 'bob-device-1');

  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);

  await alice.initialize();
  await bob.initialize();

  // ── Both users generate safety numbers from their conversation ──
  final aliceSafetyNumber = await alice.getSafetyNumber(
    myUserId: 'alice-001',
    theirUserId: 'bob-001',
    theirIdentityKey: await bob.getIdentityPublicKey(),
  );

  final bobSafetyNumber = await bob.getSafetyNumber(
    myUserId: 'bob-001',
    theirUserId: 'alice-001',
    theirIdentityKey: await alice.getIdentityPublicKey(),
  );

  // Both see the same number (commutative)
  print('Alice sees: $aliceSafetyNumber');
  print('Bob sees:   $bobSafetyNumber');
  assert(aliceSafetyNumber == bobSafetyNumber);
  // Example: "12345 67890 11111 22222 33333 44444 55555 66666 77777 88888 99999 00000"

  print('Safety numbers match: ${aliceSafetyNumber == bobSafetyNumber}');

  // ── QR Code verification ────────────────────────────────────────
  // Alice generates QR payload
  final qrPayload = await alice.getSafetyNumberQrPayload(
    myUserId: 'alice-001',
    theirUserId: 'bob-001',
    theirIdentityKey: await bob.getIdentityPublicKey(),
  );
  print('QR payload: $qrPayload');
  // Format: "risaal-verify:v0:<60-digit-number>"

  // Bob scans the QR code and verifies
  final parsed = SafetyNumber.parseQrPayload(qrPayload);
  if (parsed != null) {
    final rawNumber = SafetyNumber.generate(
      myUserId: 'bob-001',
      myIdentityKey: await bob.getIdentityPublicKey(),
      theirUserId: 'alice-001',
      theirIdentityKey: await alice.getIdentityPublicKey(),
    );
    print('Verified via QR: ${parsed == rawNumber}'); // true
  }
}
