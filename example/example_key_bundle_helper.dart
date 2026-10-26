import 'package:risaal_crypto/risaal_crypto.dart';

/// Simulates the server's immutable acceptance receipt for runnable examples.
/// Production clients must use the receipt returned by the authenticated API.
Future<PreKeyBundle> acceptInitialExampleGeneration(
  SignalProtocolManager manager, {
  required String userId,
  required String deviceId,
  int oneTimePreKeyCount = 5,
}) async {
  final snapshot = await manager.prepareInitialKeyBundleRegistration(
    oneTimePreKeyCount: oneTimePreKeyCount,
  );
  await manager.installKeyBundleReplacement(snapshot);
  final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
    snapshot,
  );
  final publicMaterial = dispatch.toInitialRegistrationKeyBundle();
  final receipt = KeyBundleAcceptedReceipt(
    bundleRevision: snapshot.expectedBundleRevision + 1,
    signedPreKeyId: snapshot.signedPreKeyId,
    kemKeyId: snapshot.kemKeyId,
    cryptoProtocolEpoch: RisaalCryptoProtocol.cryptoProtocolEpoch,
    replacementId: snapshot.replacementId,
    opkAcceptedBundleRevision: snapshot.expectedBundleRevision + 1,
    opkGeneration: snapshot.opkGeneration,
    opkSetDigest: snapshot.opkSetDigest,
    opkSetCount: snapshot.opkSetCount,
    opkHighWaterKeyId: snapshot.opkHighWaterKeyId,
    bundlePublicMaterialDigest: snapshot.bundlePublicMaterialDigest,
  );
  await manager.acknowledgeKeyBundleReplacement(
    snapshot: snapshot,
    acceptance: receipt,
  );

  final route = OpkGenerationRouting(
    bundleRevision: receipt.opkAcceptedBundleRevision,
    opkGeneration: receipt.opkGeneration,
    opkSetDigest: receipt.opkSetDigest,
  );
  final firstOpk = Map<String, dynamic>.from(
    (publicMaterial['oneTimePreKeys'] as List).first as Map,
  );
  return PreKeyBundle.fromServerJson(<String, dynamic>{
    ...publicMaterial,
    'userId': userId,
    'deviceId': deviceId,
    ...route.toJson(),
    'oneTimePreKey': <String, dynamic>{...firstOpk, ...route.toJson()},
  });
}
