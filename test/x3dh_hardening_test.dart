import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/src/key_helper.dart';
import 'package:risaal_crypto/src/models/signal_keys.dart';
import 'package:risaal_crypto/src/security_event_bus.dart';
import 'package:risaal_crypto/src/session_reset_errors.dart';
import 'package:risaal_crypto/src/signal_protocol_manager.dart';
import 'package:risaal_crypto/src/x3dh.dart';

import 'helpers/fake_secure_storage.dart';

// ── Helpers ────────────────────────────────────────────────────────────

/// Generate a valid PreKeyBundle with all fields populated.
Future<
    ({
      PreKeyBundle bundle,
      KeyPair identityKP,
      KeyPair signingKP,
      SignedPreKey signedPreKey,
      OneTimePreKey otpk,
      KyberKeyPair kyberKP,
    })> _generateFullBundle() async {
  final identityKP = await SignalKeyHelper.generateX25519KeyPair();
  final signingKP = await SignalKeyHelper.generateSigningKeyPair();
  final signedPreKey = await SignalKeyHelper.generateSignedPreKey(1, signingKP);
  final otpks = await SignalKeyHelper.generateOneTimePreKeys(1, 1);
  final kyberKP = SignalKeyHelper.generateKyberKeyPair();

  final bundle = PreKeyBundle(
    userId: 'bob-123',
    deviceId: 'device-1',
    identityKey: identityKP.publicKey,
    identitySigningKey: signingKP.publicKey,
    signedPreKey: SignedPreKeyPublic(
      keyId: signedPreKey.keyId,
      publicKey: signedPreKey.keyPair.publicKey,
      signature: signedPreKey.signature,
    ),
    oneTimePreKey: OneTimePreKeyPublic(
      keyId: otpks.first.keyId,
      publicKey: otpks.first.keyPair.publicKey,
    ),
    kyberPreKey: KyberPreKeyPublic(
      keyId: 1,
      publicKey: kyberKP.publicKey,
    ),
  );

  return (
    bundle: bundle,
    identityKP: identityKP,
    signingKP: signingKP,
    signedPreKey: signedPreKey,
    otpk: otpks.first,
    kyberKP: kyberKP,
  );
}

/// Generate a valid PreKeyBundle WITHOUT a Kyber pre-key (classical only).
Future<
    ({
      PreKeyBundle bundle,
      KeyPair identityKP,
      KeyPair signingKP,
      SignedPreKey signedPreKey,
      OneTimePreKey otpk,
    })> _generateClassicalBundle() async {
  final identityKP = await SignalKeyHelper.generateX25519KeyPair();
  final signingKP = await SignalKeyHelper.generateSigningKeyPair();
  final signedPreKey = await SignalKeyHelper.generateSignedPreKey(1, signingKP);
  final otpks = await SignalKeyHelper.generateOneTimePreKeys(1, 1);

  final bundle = PreKeyBundle(
    userId: 'bob-123',
    deviceId: 'device-1',
    identityKey: identityKP.publicKey,
    identitySigningKey: signingKP.publicKey,
    signedPreKey: SignedPreKeyPublic(
      keyId: signedPreKey.keyId,
      publicKey: signedPreKey.keyPair.publicKey,
      signature: signedPreKey.signature,
    ),
    oneTimePreKey: OneTimePreKeyPublic(
      keyId: otpks.first.keyId,
      publicKey: otpks.first.keyPair.publicKey,
    ),
    // No kyberPreKey
  );

  return (
    bundle: bundle,
    identityKP: identityKP,
    signingKP: signingKP,
    signedPreKey: signedPreKey,
    otpk: otpks.first,
  );
}

void main() {
  // ═══════════════════════════════════════════════════════════════════════
  // Issue #1: Signed Pre-Key Verification Downgrade Prevention
  // ═══════════════════════════════════════════════════════════════════════

  group('Signed Pre-Key Verification (Issue #1)', () {
    test('rejects bundle with missing identitySigningKey (fromJson)', () {
      // Construct a JSON bundle that omits identitySigningKey entirely.
      // The model should reject this at parse time.
      final json = {
        'userId': 'bob-123',
        'deviceId': 'device-1',
        'identityKey': base64Encode(List.filled(32, 0x42)),
        // identitySigningKey deliberately missing
        'signedPreKey': {
          'keyId': 1,
          'publicKey': base64Encode(List.filled(32, 0x41)),
          'signature': base64Encode(List.filled(64, 0x43)),
        },
      };

      expect(
        () => PreKeyBundle.fromJson(json),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('identitySigningKey'),
          ),
        ),
      );
    });

    test('rejects bundle with null identitySigningKey (fromJson)', () {
      final json = {
        'userId': 'bob-123',
        'deviceId': 'device-1',
        'identityKey': base64Encode(List.filled(32, 0x42)),
        'identitySigningKey': null, // Explicitly null
        'signedPreKey': {
          'keyId': 1,
          'publicKey': base64Encode(List.filled(32, 0x41)),
          'signature': base64Encode(List.filled(64, 0x43)),
        },
      };

      expect(
        () => PreKeyBundle.fromJson(json),
        throwsA(isA<StateError>()),
      );
    });

    test('rejects bundle with empty identitySigningKey (fromJson)', () {
      final json = {
        'userId': 'bob-123',
        'deviceId': 'device-1',
        'identityKey': base64Encode(List.filled(32, 0x42)),
        'identitySigningKey': '', // Empty string
        'signedPreKey': {
          'keyId': 1,
          'publicKey': base64Encode(List.filled(32, 0x41)),
          'signature': base64Encode(List.filled(64, 0x43)),
        },
      };

      expect(
        () => PreKeyBundle.fromJson(json),
        throwsA(isA<StateError>()),
      );
    });

    test('rejects bundle with invalid signature', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final identityKP = await SignalKeyHelper.generateX25519KeyPair();
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(1, signingKP);

      // Use a DIFFERENT signing key in the bundle so the signature
      // (which was signed with the real key) won't verify.
      final wrongSigningKP = await SignalKeyHelper.generateSigningKeyPair();

      final bundle = PreKeyBundle(
        userId: 'bob-123',
        deviceId: 'device-1',
        identityKey: identityKP.publicKey,
        identitySigningKey: wrongSigningKP.publicKey, // WRONG key
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.keyPair.publicKey,
          signature: signedPreKey.signature,
        ),
      );

      expect(
        () => X3DH.initiateKeyAgreement(
          identityKeyPair: aliceKP,
          recipientBundle: bundle,
        ),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('signature verification failed'),
          ),
        ),
      );
    });

    test('accepts bundle with valid signature', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final data = await _generateFullBundle();

      // Normal flow with correct signing key should succeed.
      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
      );

      expect(result.sharedSecret, hasLength(32));
      expect(result.ephemeralPublicKey, isNotEmpty);
    });

    test('identitySigningKey is always included in toJson', () async {
      final data = await _generateFullBundle();
      final json = data.bundle.toJson();

      expect(json, contains('identitySigningKey'));
      expect(json['identitySigningKey'], isA<String>());
      expect(json['identitySigningKey'], isNotEmpty);
    });

    test('fromJson -> toJson round-trip preserves identitySigningKey',
        () async {
      final data = await _generateFullBundle();
      final json = data.bundle.toJson();
      final restored = PreKeyBundle.fromJson(json);

      expect(restored.identitySigningKey, equals(data.signingKP.publicKey));
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Issue #4: PQXDH Anti-Downgrade Policy
  // ═══════════════════════════════════════════════════════════════════════

  group('PQXDH Anti-Downgrade Policy (Issue #4)', () {
    // ── requirePq ──────────────────────────────────────────────────────

    test('requirePq throws when recipient has no Kyber key', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final classical = await _generateClassicalBundle();

      expect(
        () => X3DH.initiateKeyAgreement(
          identityKeyPair: aliceKP,
          recipientBundle: classical.bundle,
          pqxdhPolicy: PqxdhPolicy.requirePq,
        ),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('no Kyber pre-key'),
          ),
        ),
      );
    });

    test('requirePq throws when Kyber encapsulation fails', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final identityKP = await SignalKeyHelper.generateX25519KeyPair();
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(1, signingKP);

      // Provide an invalid Kyber public key (garbage bytes) to force
      // encapsulation failure.
      final bundle = PreKeyBundle(
        userId: 'bob-123',
        deviceId: 'device-1',
        identityKey: identityKP.publicKey,
        identitySigningKey: signingKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.keyPair.publicKey,
          signature: signedPreKey.signature,
        ),
        kyberPreKey: KyberPreKeyPublic(
          keyId: 1,
          publicKey: base64Encode(List.filled(32, 0xAA)), // Invalid Kyber key
        ),
      );

      expect(
        () => X3DH.initiateKeyAgreement(
          identityKeyPair: aliceKP,
          recipientBundle: bundle,
          pqxdhPolicy: PqxdhPolicy.requirePq,
        ),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Kyber encapsulation failed'),
          ),
        ),
      );
    });

    test('requirePq responder throws when Kyber decapsulation fails', () async {
      final data = await _generateFullBundle();
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();

      // First, do a normal initiate to get a valid ephemeral key
      final aliceResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
        pqxdhPolicy: PqxdhPolicy.preferPq,
      );

      // Provide garbage Kyber ciphertext to force decapsulation failure
      expect(
        () => X3DH.respondKeyAgreement(
          identityKeyPair: data.identityKP,
          signedPreKey: data.signedPreKey,
          oneTimePreKey: data.otpk,
          senderIdentityKey: aliceKP.publicKey,
          senderEphemeralKey: aliceResult.ephemeralPublicKey,
          kyberKeyPair: data.kyberKP,
          kyberCiphertext: base64Encode(List.filled(32, 0xBB)), // Garbage
          pqxdhPolicy: PqxdhPolicy.requirePq,
        ),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Kyber decapsulation failed'),
          ),
        ),
      );
    });

    // ── preferPq ───────────────────────────────────────────────────────

    test('preferPq degrades gracefully when no Kyber key', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final classical = await _generateClassicalBundle();

      // Should NOT throw — degrades to classical X25519
      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: classical.bundle,
        pqxdhPolicy: PqxdhPolicy.preferPq,
      );

      expect(result.sharedSecret, hasLength(32));
      expect(result.pqxdhUsed, isFalse);
      expect(result.kyberCiphertext, isNull);
    });

    test('preferPq succeeds with Kyber and reports pqxdhUsed=true', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final data = await _generateFullBundle();

      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
        pqxdhPolicy: PqxdhPolicy.preferPq,
      );

      expect(result.sharedSecret, hasLength(32));
      expect(result.pqxdhUsed, isTrue);
      expect(result.kyberCiphertext, isNotNull);
      expect(result.kyberCiphertext, isNotEmpty);
    });

    test('preferPq degrades gracefully on Kyber encapsulation failure',
        () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final identityKP = await SignalKeyHelper.generateX25519KeyPair();
      final signingKP = await SignalKeyHelper.generateSigningKeyPair();
      final signedPreKey =
          await SignalKeyHelper.generateSignedPreKey(1, signingKP);

      // Invalid Kyber key forces encapsulation failure
      final bundle = PreKeyBundle(
        userId: 'bob-123',
        deviceId: 'device-1',
        identityKey: identityKP.publicKey,
        identitySigningKey: signingKP.publicKey,
        signedPreKey: SignedPreKeyPublic(
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.keyPair.publicKey,
          signature: signedPreKey.signature,
        ),
        kyberPreKey: KyberPreKeyPublic(
          keyId: 1,
          publicKey: base64Encode(List.filled(32, 0xAA)), // Bad key
        ),
      );

      // Should NOT throw (preferPq) — degrades gracefully
      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: bundle,
        pqxdhPolicy: PqxdhPolicy.preferPq,
      );

      expect(result.sharedSecret, hasLength(32));
      expect(result.pqxdhUsed, isFalse);
      expect(result.kyberCiphertext, isNull);
    });

    // ── classicalOnly ──────────────────────────────────────────────────

    test('classicalOnly ignores Kyber even when bundle has Kyber key',
        () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final data = await _generateFullBundle();

      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      expect(result.sharedSecret, hasLength(32));
      expect(result.pqxdhUsed, isFalse);
      expect(result.kyberCiphertext, isNull);
    });

    test('classicalOnly responder ignores Kyber ciphertext', () async {
      final data = await _generateFullBundle();
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();

      // Initiate with classicalOnly (no Kyber ciphertext produced)
      final aliceResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      // Responder with classicalOnly should also produce the same secret
      final bobSecret = await X3DH.respondKeyAgreement(
        identityKeyPair: data.identityKP,
        signedPreKey: data.signedPreKey,
        oneTimePreKey: data.otpk,
        senderIdentityKey: aliceKP.publicKey,
        senderEphemeralKey: aliceResult.ephemeralPublicKey,
        kyberKeyPair: data.kyberKP,
        kyberCiphertext: aliceResult.kyberCiphertext,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      expect(aliceResult.sharedSecret, equals(bobSecret));
    });

    // ── pqxdhUsed flag correctness ─────────────────────────────────────

    test('pqxdhUsed is true when full PQXDH succeeds', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final data = await _generateFullBundle();

      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
      );

      expect(result.pqxdhUsed, isTrue);
      expect(result.kyberCiphertext, isNotNull);

      // Verify the full round-trip: Bob should derive the same secret
      final bobSecret = await X3DH.respondKeyAgreement(
        identityKeyPair: data.identityKP,
        signedPreKey: data.signedPreKey,
        oneTimePreKey: data.otpk,
        senderIdentityKey: aliceKP.publicKey,
        senderEphemeralKey: result.ephemeralPublicKey,
        kyberKeyPair: data.kyberKP,
        kyberCiphertext: result.kyberCiphertext,
      );

      expect(result.sharedSecret, equals(bobSecret));
    });

    test('pqxdhUsed is false when no Kyber key available (default policy)',
        () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final classical = await _generateClassicalBundle();

      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: classical.bundle,
      );

      expect(result.pqxdhUsed, isFalse);
      expect(result.kyberCiphertext, isNull);
    });

    // ── PQXDH shared secret differs from classical-only ────────────────

    test('PQXDH shared secret differs from classical-only for same bundle',
        () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final data = await _generateFullBundle();

      // Cannot directly compare secrets because ephemeral keys differ per
      // invocation. Instead, verify that classicalOnly produces a different
      // secret structure (no Kyber contribution).
      final pqResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
        pqxdhPolicy: PqxdhPolicy.preferPq,
      );

      final classicalResult = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
        pqxdhPolicy: PqxdhPolicy.classicalOnly,
      );

      // Both should produce valid 32-byte secrets, but they will differ
      // because (a) different ephemeral keys and (b) different KDF input.
      expect(pqResult.sharedSecret, hasLength(32));
      expect(classicalResult.sharedSecret, hasLength(32));
      expect(pqResult.pqxdhUsed, isTrue);
      expect(classicalResult.pqxdhUsed, isFalse);

      // The secrets should differ (different ephemeral keys + Kyber)
      expect(
          pqResult.sharedSecret, isNot(equals(classicalResult.sharedSecret)));
    });

    // ── Default policy is preferPq ─────────────────────────────────────

    test('default policy is preferPq (Kyber used when available)', () async {
      final aliceKP = await SignalKeyHelper.generateX25519KeyPair();
      final data = await _generateFullBundle();

      // No explicit policy — should default to preferPq
      final result = await X3DH.initiateKeyAgreement(
        identityKeyPair: aliceKP,
        recipientBundle: data.bundle,
      );

      expect(result.pqxdhUsed, isTrue);
      expect(result.kyberCiphertext, isNotNull);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Issue #5: First-Session Kyber Downgrade Protection
  // ═══════════════════════════════════════════════════════════════════════

  group('First-Session Kyber Downgrade Protection (Issue #5)', () {
    test(
        'first-contact + requirePq + no Kyber → throws PqxdhDowngradeError',
        () async {
      final storage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final manager = SignalProtocolManager(
        secureStorage: storage,
        securityEventBus: eventBus,
      );
      await manager.initialize();

      // Generate a classical bundle (no Kyber key)
      final classical = await _generateClassicalBundle();

      // createSession with requirePq should throw on first contact
      expect(
        () => manager.createSession(
          classical.bundle,
          pqxdhPolicy: PqxdhPolicy.requirePq,
        ),
        throwsA(isA<PqxdhDowngradeError>()),
      );
    });

    test(
        'first-contact + preferPq + no Kyber → emits firstSessionNoPqxdh, session proceeds',
        () async {
      final storage = FakeSecureStorage();
      final eventBus = SecurityEventBus();
      final manager = SignalProtocolManager(
        secureStorage: storage,
        securityEventBus: eventBus,
      );
      await manager.initialize();

      // Generate a classical bundle (no Kyber key)
      final classical = await _generateClassicalBundle();

      // Collect events
      final events = <SecurityEvent>[];
      eventBus.events.listen(events.add);

      // createSession with preferPq should proceed
      await manager.createSession(
        classical.bundle,
        pqxdhPolicy: PqxdhPolicy.preferPq,
      );

      // Should have a session now
      final hasSession = await manager.hasSession(
        classical.bundle.userId,
        classical.bundle.deviceId,
      );
      expect(hasSession, isTrue);

      // Should have emitted firstSessionNoPqxdh event
      expect(
        events.any((e) => e.type == SecurityEventType.firstSessionNoPqxdh),
        isTrue,
      );

      // Check metadata
      final event = events.firstWhere(
        (e) => e.type == SecurityEventType.firstSessionNoPqxdh,
      );
      expect(event.metadata['policy'], equals('preferPq'));
      expect(event.metadata['action'], equals('proceeding_without_pq'));
    });
  });
}
