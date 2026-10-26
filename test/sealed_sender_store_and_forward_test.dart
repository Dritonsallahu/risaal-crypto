import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/sealed_sender.dart';

/// Audit 2026-06 showstopper #4: sealed-sender store-and-forward.
///
/// The default 5-minute replay window rejected any 1:1 message first opened
/// > ~5 min after sealing — i.e. whenever the recipient had been offline — and
/// the message became permanently undecryptable while the sender saw
/// delivered/read. The actual replay control is the PERSISTENT seen-nonce set,
/// not the timestamp window, so widening the window restores delivery without
/// weakening replay protection. These tests prove both halves of that claim.
void main() {
  const wideWindowMs = 30 * 24 * 60 * 60 * 1000; // 30 days — the new bound

  test(
    'a tight window rejects a delayed message (reproduces the bug)',
    () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();
      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: const {'type': 'prekey', 'data': 'hi'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );

      // Simulate the recipient opening it "late" relative to a tiny window.
      await Future<void>.delayed(const Duration(milliseconds: 40));

      await expectLater(
        SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          seenNonces: <String>{},
          maxReplayWindowMs: 5, // anything older than 5ms is rejected
        ),
        throwsA(isA<StateError>()),
        reason: 'a too-tight window is exactly what broke offline delivery',
      );
    },
  );

  test('the widened window accepts the same delayed message', () async {
    final senderKp = await SignalKeyHelper.generateX25519KeyPair();
    final recipientKp = await SignalKeyHelper.generateX25519KeyPair();
    final sealed = await SealedSenderEnvelope.seal(
      senderId: 'alice',
      senderDeviceId: 'dev-1',
      senderIdentityKey: senderKp.publicKey,
      encryptedMessage: const {'type': 'prekey', 'data': 'hi'},
      recipientIdentityPublicKey: recipientKp.publicKey,
    );

    await Future<void>.delayed(const Duration(milliseconds: 40));

    final content = await SealedSenderEnvelope.unseal(
      sealedEnvelope: sealed,
      recipientIdentityKeyPair: recipientKp,
      seenNonces: <String>{},
      maxReplayWindowMs: wideWindowMs,
    );
    expect(content.senderId, 'alice');
    expect(content.encryptedMessage['data'], 'hi');
  });

  test(
    'replay is still rejected with the wide window (nonce dedup is the control)',
    () async {
      final senderKp = await SignalKeyHelper.generateX25519KeyPair();
      final recipientKp = await SignalKeyHelper.generateX25519KeyPair();
      final sealed = await SealedSenderEnvelope.seal(
        senderId: 'alice',
        senderDeviceId: 'dev-1',
        senderIdentityKey: senderKp.publicKey,
        encryptedMessage: const {'type': 'prekey', 'data': 'hi'},
        recipientIdentityPublicKey: recipientKp.publicKey,
      );
      final nonce = sealed['nonce'] as String;

      // Recipient has already seen this nonce — replay must be rejected even though
      // the timestamp is well within the 30-day window.
      await expectLater(
        SealedSenderEnvelope.unseal(
          sealedEnvelope: sealed,
          recipientIdentityKeyPair: recipientKp,
          seenNonces: <String>{nonce},
          maxReplayWindowMs: wideWindowMs,
        ),
        throwsA(isA<StateError>()),
        reason: 'persistent nonce dedup, not the window, prevents replays',
      );
    },
  );

  test('the live caller passes the widened window to unseal', () {
    final src = File('lib/src/signal_protocol_manager.dart').readAsStringSync();
    expect(
      src.contains('maxReplayWindowMs: _sealedSenderReplayWindowMs'),
      isTrue,
      reason:
          'decryptSealedSender must use the widened store-and-forward window',
    );
    expect(
      src.contains('30 * 24 * 60 * 60 * 1000'),
      isTrue,
      reason: 'the window constant should cover realistic offline gaps',
    );
  });
}
