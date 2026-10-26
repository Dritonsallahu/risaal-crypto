import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Regression guard for the sealed-sender replay transaction.
///
/// Decrypts are serialized because the replay cache is persisted as one set.
/// Every failure after `unseal` must roll the nonce back, and the in-flight
/// reservation must always be released. The persistent seen-nonce store is
/// written only on the successful path.
@Retry(0)
void main() {
  test(
    'decryptSealedSender serializes and rolls back replay state on failure',
    () {
      final src = File(
        'lib/src/signal_protocol_manager.dart',
      ).readAsStringSync();

      expect(src, contains('Future<void> _sealedDecryptTail'));
      expect(src, contains('_withSealedDecryptLock('));

      final start = src.indexOf(
        'Future<SealedSenderResult> _decryptSealedSenderUnlocked(',
      );
      expect(start, greaterThan(-1));
      final body = src.substring(start);

      final reserveIdx = body.indexOf('_inFlightSealedNonces.add(nonce)');
      final rollbackIdx = body.indexOf('_seenNonces.remove(nonce)');
      final releaseIdx = body.indexOf('_inFlightSealedNonces.remove(nonce)');
      final persistIdx = body.indexOf('saveSeenNonces(_seenNonces)');
      final returnIdx = body.indexOf('return SealedSenderResult(');

      expect(reserveIdx, greaterThan(-1));
      expect(rollbackIdx, greaterThan(reserveIdx));
      expect(releaseIdx, greaterThan(rollbackIdx));
      expect(persistIdx, greaterThan(releaseIdx));
      expect(returnIdx, greaterThan(persistIdx));
    },
  );
}
