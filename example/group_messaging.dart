/// Group E2EE with Sender Keys.
///
/// In a group conversation, each member generates their own Sender Key
/// and distributes it to all other members via existing 1-to-1 encrypted
/// sessions. When sending to the group, the sender encrypts ONCE with
/// their Sender Key — all members can decrypt. The chain ratchets
/// forward after each message, providing forward secrecy.
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
  // ── Setup Alice, Bob, and Carol ─────────────────────────────────
  final aliceStorage = InMemoryStorage();
  final bobStorage = InMemoryStorage();
  final carolStorage = InMemoryStorage();

  await aliceStorage.write(key: 'user_id', value: 'alice-001');
  await aliceStorage.write(key: 'device_id', value: 'alice-device-1');
  await bobStorage.write(key: 'user_id', value: 'bob-001');
  await bobStorage.write(key: 'device_id', value: 'bob-device-1');
  await carolStorage.write(key: 'user_id', value: 'carol-001');
  await carolStorage.write(key: 'device_id', value: 'carol-device-1');

  final alice = SignalProtocolManager(secureStorage: aliceStorage);
  final bob = SignalProtocolManager(secureStorage: bobStorage);
  final carol = SignalProtocolManager(secureStorage: carolStorage);

  await alice.initialize();
  await bob.initialize();
  await carol.initialize();

  // Establish 1-to-1 sessions (Alice ↔ Bob, Alice ↔ Carol, Bob ↔ Carol)
  // This is required before we can distribute Sender Keys
  final bobBundle = await bob.generateKeyBundle();
  final carolBundle = await carol.generateKeyBundle();

  // Alice establishes sessions with Bob and Carol
  await alice.createSession(PreKeyBundle(
    userId: 'bob-001',
    deviceId: 'bob-device-1',
    identityKey: bobBundle['identityKey'] as String,
    identitySigningKey: bobBundle['identitySigningKey'] as String,
    signedPreKey: SignedPreKeyPublic(
      keyId: (bobBundle['signedPreKey'] as Map)['keyId'] as int,
      publicKey: (bobBundle['signedPreKey'] as Map)['publicKey'] as String,
      signature: (bobBundle['signedPreKey'] as Map)['signature'] as String,
    ),
    oneTimePreKey: (bobBundle['oneTimePreKeys'] as List).isNotEmpty
        ? OneTimePreKeyPublic(
            keyId: ((bobBundle['oneTimePreKeys'] as List)[0] as Map)['keyId']
                as int,
            publicKey: ((bobBundle['oneTimePreKeys'] as List)[0]
                as Map)['publicKey'] as String,
          )
        : null,
  ));

  await alice.createSession(PreKeyBundle(
    userId: 'carol-001',
    deviceId: 'carol-device-1',
    identityKey: carolBundle['identityKey'] as String,
    identitySigningKey: carolBundle['identitySigningKey'] as String,
    signedPreKey: SignedPreKeyPublic(
      keyId: (carolBundle['signedPreKey'] as Map)['keyId'] as int,
      publicKey: (carolBundle['signedPreKey'] as Map)['publicKey'] as String,
      signature: (carolBundle['signedPreKey'] as Map)['signature'] as String,
    ),
    oneTimePreKey: (carolBundle['oneTimePreKeys'] as List).isNotEmpty
        ? OneTimePreKeyPublic(
            keyId: ((carolBundle['oneTimePreKeys'] as List)[0] as Map)['keyId']
                as int,
            publicKey: ((carolBundle['oneTimePreKeys'] as List)[0]
                as Map)['publicKey'] as String,
          )
        : null,
  ));

  print('1-to-1 sessions established');

  final groupId = 'group-secret-project';

  // ── Step 1: Alice generates her Sender Key ──────────────────────
  final aliceDistribution = await alice.generateGroupSenderKey(groupId);
  print('Alice generated Sender Key for group $groupId');

  // ── Step 2: Distribute via existing encrypted sessions ──────────
  // In production, serialize the distribution and send via 1-to-1
  // encrypted messages to each group member
  await bob.processGroupSenderKey(groupId, 'alice-001', aliceDistribution);
  await carol.processGroupSenderKey(groupId, 'alice-001', aliceDistribution);
  print('Alice distributed Sender Key to Bob and Carol');

  // Bob and Carol do the same...
  final bobDistribution = await bob.generateGroupSenderKey(groupId);
  await alice.processGroupSenderKey(groupId, 'bob-001', bobDistribution);
  await carol.processGroupSenderKey(groupId, 'bob-001', bobDistribution);

  final carolDistribution = await carol.generateGroupSenderKey(groupId);
  await alice.processGroupSenderKey(groupId, 'carol-001', carolDistribution);
  await bob.processGroupSenderKey(groupId, 'carol-001', carolDistribution);

  print('All members have distributed their Sender Keys');

  // ── Step 3: Alice sends an encrypted group message ──────────────
  final ciphertext = await alice.encryptGroupMessage(
    groupId,
    'Meeting at 3pm. Bring the documents.',
  );
  print('Alice encrypted group message (sent once to server)');

  // ── Step 4: All members decrypt with Alice\'s Sender Key ─────────
  final bobDecrypted = await bob.decryptGroupMessage(
    groupId,
    'alice-001',
    ciphertext,
  );
  final carolDecrypted = await carol.decryptGroupMessage(
    groupId,
    'alice-001',
    ciphertext,
  );

  print('Bob sees: $bobDecrypted');
  print('Carol sees: $carolDecrypted');
  // Both see: "Meeting at 3pm. Bring the documents."
}
