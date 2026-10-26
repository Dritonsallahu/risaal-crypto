@Retry(0)
@Tags(<String>['live'])
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:risaal_crypto/risaal_crypto.dart';

import 'helpers/fake_secure_storage.dart';

/// Live end-to-end proof against a deployed server.
///
/// Every other gate in this repository is source-level or local. This is the
/// only test that answers the question that actually matters: can two real
/// accounts, registered against the running API, exchange a message that
/// decrypts? It exercises the whole flag-day chain — registration, the
/// authenticated one-time-prekey route, the envelope projection, the server's
/// persistence and the receive WAL — against bytes the server really stores.
///
/// Opt-in, because it mutates a real server:
///   RISAAL_LIVE_API=https://<your-api-host> flutter test --tags live \
///     test/live_e2e_test.dart
///
/// Skipped silently when the variable is absent, so ordinary runs are unaffected.
const String _protocolHeader = 'X-Risaal-Crypto-Protocol';
const String _protocolValue = 'risaal-e2ee-2';

String? get _baseUrl {
  final raw = Platform.environment['RISAAL_LIVE_API'];
  return (raw == null || raw.isEmpty) ? null : raw;
}

class _Api {
  _Api(this.baseUrl);

  final String baseUrl;
  final HttpClient _client = HttpClient();
  String? accessToken;

  Future<(int, Map<String, dynamic>)> send(
    String method,
    String path, {
    Map<String, dynamic>? body,
  }) async {
    final request = await _client.openUrl(method, Uri.parse('$baseUrl$path'));
    request.headers.set(_protocolHeader, _protocolValue);
    request.headers.set('content-type', 'application/json');
    if (accessToken != null) {
      request.headers.set('authorization', 'Bearer $accessToken');
    }
    if (body != null) request.add(utf8.encode(jsonEncode(body)));
    final response = await request.close();
    final text = await response.transform(utf8.decoder).join();
    if (text.isEmpty) return (response.statusCode, <String, dynamic>{});
    final decoded = jsonDecode(text);
    return (
      response.statusCode,
      decoded is Map<String, dynamic>
          ? decoded
          : <String, dynamic>{'data': decoded},
    );
  }

  void close() => _client.close(force: true);
}

Future<
  ({SignalProtocolManager manager, String userId, String deviceId, _Api api})
>
_registerAccount(String baseUrl, String label) async {
  final storage = FakeSecureStorage();
  final manager = SignalProtocolManager(secureStorage: storage);
  await manager.wipeForFreshRegistration();
  await manager.initialize();

  final prepared = await manager.prepareInitialKeyBundleRegistration();
  await manager.installKeyBundleReplacement(prepared);
  final dispatch = await manager.markKeyBundleReplacementDispatchStarted(
    prepared,
  );

  final stamp = DateTime.now().microsecondsSinceEpoch;
  final username = 'e2e_${label}_$stamp';
  final deviceId = 'e2e-$label-$stamp';

  final api = _Api(baseUrl);
  final (status, payload) = await api.send(
    'POST',
    '/auth/register',
    body: {
      'username': username,
      'password': 'Risaal-E2E-\$${stamp}aA1!',
      'deviceId': deviceId,
      'deviceName': 'live-e2e-$label',
      'registrationIdempotencyKey': 'e2e-$label-$stamp',
      'keyBundle': dispatch.toInitialRegistrationKeyBundle(),
    },
  );

  expect(
    status,
    anyOf(200, 201),
    reason: 'registration failed for $label: $payload',
  );

  api.accessToken =
      payload['accessToken'] as String? ??
      (payload['tokens'] as Map<String, dynamic>?)?['accessToken'] as String?;
  expect(
    api.accessToken,
    isNotNull,
    // Never print the payload itself: it carries tokens.
    reason: 'no access token; response keys were ${payload.keys.toList()}',
  );

  final userId =
      (payload['user'] as Map<String, dynamic>?)?['id'] as String? ??
      payload['userId'] as String? ??
      (payload['user'] as Map<String, dynamic>?)?['userId'] as String? ??
      '';
  expect(
    userId,
    isNotEmpty,
    reason: 'no user id; response keys were ${payload.keys.toList()}',
  );

  // The app writes these at login; sealed sender reads them to stamp the
  // envelope with its own identity.
  await storage.write(key: 'user_id', value: userId);
  await storage.write(key: 'device_id', value: deviceId);

  // Converge exactly the way the app does: read the owner view back from the
  // server and reconcile the pending replacement against it, rather than
  // hand-building a receipt the server never issued.
  final (ownerStatus, ownerData) = await api.send(
    'GET',
    '/keys/$userId?deviceId=$deviceId&infoOnly=true',
  );
  expect(
    ownerStatus,
    200,
    reason: 'owner bundle fetch failed; keys ${ownerData.keys.toList()}',
  );
  await manager.reconcileKeyBundleReplacement(ownerData);

  return (manager: manager, userId: userId, deviceId: deviceId, api: api);
}

void main() {
  final baseUrl = _baseUrl;

  test(
    'two live accounts exchange a message that decrypts',
    () async {
      final alice = await _registerAccount(baseUrl!, 'a');
      final bob = await _registerAccount(baseUrl, 'b');
      addTearDown(() {
        alice.api.close();
        bob.api.close();
      });

      // Alice fetches Bob's published bundle from the live server.
      final (bundleStatus, bundlePayload) = await alice.api.send(
        'GET',
        '/keys/${bob.userId}?deviceId=${bob.deviceId}',
      );
      expect(bundleStatus, 200, reason: 'bundle fetch failed: $bundlePayload');

      final bundle = PreKeyBundle.fromJson(
        (bundlePayload['bundle'] ?? bundlePayload) as Map<String, dynamic>,
      );
      await alice.manager.createSession(bundle);

      const plaintext = 'live end to end proof';
      // Sealed sender is what the app actually sends. Mirror its exact
      // transport projection: the crypto envelope goes into `content` as a
      // JSON string, the outer carries the numeric type, the epoch and the
      // nine PreKey route fields lifted from the inner envelope.
      final sealed = await alice.manager.encryptSealedSender(
        bob.userId,
        bob.deviceId,
        await bob.manager.getIdentityPublicKey(),
        plaintext,
      );
      const routeFields = <String>[
        'kyberCiphertext',
        'recipientKeyId',
        'recipientSignedPreKeyId',
        'kemSuite',
        'kemStandard',
        'kemWireVersion',
        'bundleRevision',
        'opkGeneration',
        'opkSetDigest',
      ];
      final transport = <String, dynamic>{
        'type': 3,
        'content': jsonEncode(sealed),
        'cryptoProtocolEpoch': sealed['cryptoProtocolEpoch'],
        for (final field in routeFields)
          if (sealed.containsKey(field)) field: sealed[field],
      };

      // A conversation must exist before a message can be routed to it.
      final (convStatus, convPayload) = await alice.api.send(
        'POST',
        '/conversations/direct',
        body: <String, dynamic>{'recipientId': bob.userId},
      );
      expect(
        convStatus,
        anyOf(200, 201),
        reason: 'conversation create failed; keys ${convPayload.keys.toList()}',
      );
      final conversationId =
          (convPayload['conversationId'] ??
                  convPayload['id'] ??
                  (convPayload['conversation']
                      as Map<String, dynamic>?)?['conversationId'])
              as String?;
      expect(conversationId, isNotNull, reason: 'no conversation id returned');

      final (sendStatus, sendPayload) = await alice.api.send(
        'POST',
        '/messages',
        body: <String, dynamic>{
          'conversationId': conversationId,
          'envelope': transport,
          'contentType': 'text',
        },
      );
      expect(
        sendStatus,
        anyOf(200, 201),
        reason: 'send rejected by the live server: $sendPayload',
      );

      // Bob pulls it back and decrypts through the receive WAL.
      final (inboxStatus, inbox) = await bob.api.send(
        'GET',
        '/messages/undelivered',
      );
      expect(inboxStatus, 200, reason: 'inbox fetch failed: $inbox');

      final messages = (inbox['messages'] ?? inbox['data']) as List<dynamic>;
      expect(messages, isNotEmpty, reason: 'the server delivered nothing');

      final delivered = messages.first as Map<String, dynamic>;
      // The API serializes Mongo's `_id`; `id` is absent. Using the wrong key
      // silently produced `message:null` as the delivery id for every message,
      // which would have collided across deliveries.
      final deliveredId =
          (delivered['_id'] ?? delivered['id']) as String? ?? '';
      expect(deliveredId, isNotEmpty, reason: 'no message id in the listing');
      final storedEnvelope = delivered['envelope'] is String
          ? jsonDecode(delivered['envelope'] as String) as Map<String, dynamic>
          : Map<String, dynamic>.from(delivered['envelope'] as Map);

      final inner = storedEnvelope['content'] is String
          ? jsonDecode(storedEnvelope['content'] as String)
                as Map<String, dynamic>
          : storedEnvelope;
      final received = await bob.manager.prepareSealedReceive(
        deliveryId: 'message:$deliveredId',
        sealedEnvelope: inner,
      );
      expect(received.plaintext, plaintext);
      await bob.manager.acknowledgeReceive(received.receipt);

      // A redelivery of the same server message must be idempotent, never a
      // second ratchet advance.
      final replay = await bob.manager.prepareSealedReceive(
        deliveryId: 'message:$deliveredId',
        sealedEnvelope: inner,
      );
      expect(
        replay.alreadyAcknowledged,
        isTrue,
        reason: 'the server can redeliver; it must not decrypt twice',
      );

      // Reply on the established session, proving the ratchet advanced on both
      // sides against the live server rather than only in one direction.
      const replyText = 'live reply on the established session';
      final replySealed = await bob.manager.encryptSealedSender(
        alice.userId,
        alice.deviceId,
        await alice.manager.getIdentityPublicKey(),
        replyText,
      );
      final replyTransport = <String, dynamic>{
        'type': 3,
        'content': jsonEncode(replySealed),
        'cryptoProtocolEpoch': replySealed['cryptoProtocolEpoch'],
        for (final field in routeFields)
          if (replySealed.containsKey(field)) field: replySealed[field],
      };
      final (replyStatus, replyPayload) = await bob.api.send(
        'POST',
        '/messages',
        body: <String, dynamic>{
          'conversationId': conversationId,
          'envelope': replyTransport,
          'contentType': 'text',
        },
      );
      expect(
        replyStatus,
        anyOf(200, 201),
        reason: 'reply rejected; keys ${replyPayload.keys.toList()}',
      );

      // The conversation listing is authoritative; `undelivered` reflects
      // delivery bookkeeping and need not contain a just-sent reply.
      final (aliceInboxStatus, aliceInbox) = await alice.api.send(
        'GET',
        '/messages/$conversationId',
      );
      expect(aliceInboxStatus, 200);
      final aliceMessages =
          (aliceInbox['messages'] ?? aliceInbox['data']) as List<dynamic>;
      expect(aliceMessages, isNotEmpty, reason: 'the reply was not delivered');

      // The inbox can also carry Alice's own sent message; decrypting that
      // would fail the MAC. Take the one she did not send.
      final replyDelivered =
          aliceMessages
              .cast<Map<String, dynamic>>()
              .where((m) => (m['_id'] ?? m['id']) != deliveredId)
              .firstOrNull ??
          (throw StateError(
            'the reply is not in the listing; '
            'count=${aliceMessages.length} '
            'ids=${aliceMessages.cast<Map<String, dynamic>>().map((m) => m['id']).toList()} '
            'sent=${delivered['id']}',
          ));
      final replyStored = replyDelivered['envelope'] is String
          ? jsonDecode(replyDelivered['envelope'] as String)
                as Map<String, dynamic>
          : Map<String, dynamic>.from(replyDelivered['envelope'] as Map);
      final replyInner = replyStored['content'] is String
          ? jsonDecode(replyStored['content'] as String) as Map<String, dynamic>
          : replyStored;
      final replyReceived = await alice.manager.prepareSealedReceive(
        deliveryId:
            'message:${(replyDelivered['_id'] ?? replyDelivered['id'])}',
        sealedEnvelope: replyInner,
      );
      expect(replyReceived.plaintext, replyText);
      await alice.manager.acknowledgeReceive(replyReceived.receipt);
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: baseUrl == null
        ? 'set RISAAL_LIVE_API to run the live end-to-end proof'
        : null,
  );
}
