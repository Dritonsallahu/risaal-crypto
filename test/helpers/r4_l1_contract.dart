import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide KeyPair;
import 'package:risaal_crypto/src/double_ratchet.dart';
import 'package:risaal_crypto/src/models/session_state.dart';

/// An encoder for contracts/R4-L1-IDENTITY-BINDING.md §0 and §3, written from
/// the contract text and not from the implementation, so a test can build a
/// v3 envelope that a Part A receiver has never produced itself.
abstract final class R4L1Contract {
  static const aadDomainV1 = 'RISAAL_DR_HDRv1';
  static const aadDomainV2 = 'RISAAL_DR_HDRv2';
  static const transcriptDomainV1 = 'RISAAL_PQXDH_OPK_ROUTE_v1';
  static const transcriptDomainV2 = 'RISAAL_PQXDH_OPK_ROUTE_v2';

  static final _hmac = Hmac.sha256();
  static final _aesGcm = AesGcm.with256bits();

  static List<int> u32(int value) => <int>[
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ];

  static List<int> lengthPrefixed(List<int> bytes) => <int>[
    ...u32(bytes.length),
    ...bytes,
  ];

  /// `AD = IK_lo ‖ IK_hi`: the two raw identity keys, byte-lexicographic.
  static List<int> sortedAd(String identityA, String identityB) {
    final a = base64Decode(identityA);
    final b = base64Decode(identityB);
    var aFirst = true;
    for (var i = 0; i < a.length && i < b.length; i++) {
      if (a[i] != b[i]) {
        aFirst = a[i] < b[i];
        break;
      }
    }
    return aFirst ? <int>[...a, ...b] : <int>[...b, ...a];
  }

  /// The v2 header fields shared by both AAD layouts.
  static List<int> _headerFields({
    required int version,
    required String dhPublicKey,
    required int messageNumber,
    required int previousChainLength,
  }) => <int>[
    ...u32(version),
    ...lengthPrefixed(base64Decode(dhPublicKey)),
    ...u32(messageNumber),
    ...u32(previousChainLength),
  ];

  /// PR-SEC-004 v2 AAD: `u32 len ‖ "RISAAL_DR_HDRv1" ‖ <header fields>`.
  static List<int> aadV2({
    required int version,
    required String dhPublicKey,
    required int messageNumber,
    required int previousChainLength,
  }) => <int>[
    ...lengthPrefixed(utf8.encode(aadDomainV1)),
    ..._headerFields(
      version: version,
      dhPublicKey: dhPublicKey,
      messageNumber: messageNumber,
      previousChainLength: previousChainLength,
    ),
  ];

  /// R4-L1 v3 AAD:
  /// `u32 len ‖ "RISAAL_DR_HDRv2" ‖ u32 len(AD) ‖ AD ‖ <header fields>`.
  static List<int> aadV3({
    required int version,
    required String dhPublicKey,
    required int messageNumber,
    required int previousChainLength,
    required String identityA,
    required String identityB,
  }) => <int>[
    ...lengthPrefixed(utf8.encode(aadDomainV2)),
    ...lengthPrefixed(sortedAd(identityA, identityB)),
    ..._headerFields(
      version: version,
      dhPublicKey: dhPublicKey,
      messageNumber: messageNumber,
      previousChainLength: previousChainLength,
    ),
  ];

  /// The public half of the sender's current ratchet key.
  static String sendingPublicKey(RatchetState sender) =>
      (jsonDecode(utf8.decode(sender.dhSendingKeyPair))
              as Map<String, dynamic>)['publicKey']
          as String;

  /// Encrypt the next message on [sender]'s sending chain with [aad] and
  /// label it [version]; advances the chain exactly as the Double Ratchet
  /// does (`mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`).
  static Future<EncryptedMessage> encryptNext(
    RatchetState sender,
    List<int> plaintext, {
    required int version,
    required List<int> Function(String dhPublicKey, int n, int pn) aad,
  }) async {
    final chainKey = SecretKey(List<int>.from(sender.sendingChainKey));
    final messageKey = await _hmac.calculateMac([0x01], secretKey: chainKey);
    final nextChainKey = await _hmac.calculateMac([0x02], secretKey: chainKey);
    final dhPublicKey = sendingPublicKey(sender);
    final n = sender.sendMessageNumber;
    final pn = sender.previousChainLength;
    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: SecretKey(messageKey.bytes),
      aad: aad(dhPublicKey, n, pn),
    );
    sender.sendingChainKey = Uint8List.fromList(nextChainKey.bytes);
    sender.sendMessageNumber++;
    return EncryptedMessage(
      dhPublicKey: dhPublicKey,
      messageNumber: n,
      previousChainLength: pn,
      ciphertext: base64Encode(box.cipherText + box.mac.bytes),
      nonce: base64Encode(box.nonce),
      version: version,
    );
  }

  /// Decrypt [message] with the message key of chain key [chainKey] and the
  /// contract [aad]: an independent check of what a real sender produced.
  static Future<List<int>> decryptWithChainKey(
    List<int> chainKey,
    EncryptedMessage message,
    List<int> aad,
  ) async {
    final messageKey = await _hmac.calculateMac([
      0x01,
    ], secretKey: SecretKey(List<int>.from(chainKey)));
    final combined = base64Decode(message.ciphertext);
    return _aesGcm.decrypt(
      SecretBox(
        combined.sublist(0, combined.length - 16),
        nonce: base64Decode(message.nonce),
        mac: Mac(combined.sublist(combined.length - 16)),
      ),
      secretKey: SecretKey(messageKey.bytes),
      aad: aad,
    );
  }
}
