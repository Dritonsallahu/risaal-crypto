import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'key_helper.dart';
import 'sender_certificate.dart';

// GroupRoster v1 (R4-H10): an admin-signed, epoch-chained member list that the
// relay stores and serves verbatim. This file is a step-by-step port of
// `risaal-server/src/modules/conversations/group-roster.ts` (same rules, same
// check order, same stable error codes) plus the client-side chain and
// distribution policy. The signed bytes are the exact UTF-8 bytes of the
// roster string; nothing here re-serialises a received roster.

/// Wire version (`v`).
const int groupRosterVersion = 1;

/// Signature domain: `utf8('risaal-group-roster-v1') || 0x00`.
const String groupRosterDomain = 'risaal-group-roster-v1\u0000';

/// Largest accepted roster string, in UTF-8 bytes.
const int groupRosterMaxBytes = 65536;

/// Largest accepted member count.
const int groupRosterMaxMembers = 256;

const int _maxSafeInteger = 9007199254740991; // 2^53 - 1 (JS)
const int _deviceIdMax = 128;
final RegExp _uuidRe = RegExp(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
);
final RegExp _userIdRe = RegExp(r'^[0-9a-f]{24}$');
final RegExp _sha256HexRe = RegExp(r'^[0-9a-f]{64}$');
const List<String> _topKeys = [
  'v',
  'groupId',
  'epoch',
  'issuedAt',
  'signer',
  'members',
  'prev',
];
const List<String> _signerKeys = ['userId', 'deviceId', 'signingKey'];
const List<String> _memberKeys = ['userId', 'role', 'identityKey'];

/// Member role.
enum GroupRosterRole { admin, member }

/// A roster was rejected. [code] is one of the stable codes shared with the
/// server (`too_large`, `invalid_json`, `duplicate_key`, `not_object`,
/// `unknown_field`, `missing_field`, `unsupported_version`,
/// `invalid_group_id`, `invalid_epoch`, `invalid_issued_at`,
/// `invalid_signer`, `invalid_user_id`, `invalid_device_id`,
/// `invalid_signing_key`, `invalid_members`, `too_many_members`,
/// `invalid_member`, `invalid_role`, `invalid_identity_key`,
/// `members_unsorted`, `members_duplicate`, `invalid_prev`). The message
/// carries only the code, never roster contents.
final class GroupRosterError implements Exception {
  const GroupRosterError(this.code);

  final String code;

  @override
  String toString() => 'GroupRosterError: $code';
}

Never _fail(String code) => throw GroupRosterError(code);

/// The device that signed a roster.
final class GroupRosterSigner {
  const GroupRosterSigner({
    required this.userId,
    required this.deviceId,
    required this.signingKey,
  });

  /// Lowercase 24-hex user id.
  final String userId;

  /// Device id, 1..128 characters.
  final String deviceId;

  /// Canonical base64 of the 32-byte Ed25519 identity signing public key.
  final String signingKey;

  @override
  bool operator ==(Object other) =>
      other is GroupRosterSigner &&
      other.userId == userId &&
      other.deviceId == deviceId &&
      other.signingKey == signingKey;

  @override
  int get hashCode => Object.hash(userId, deviceId, signingKey);
}

/// One roster member.
final class GroupRosterMember {
  const GroupRosterMember({
    required this.userId,
    required this.role,
    required this.identityKey,
  });

  /// Lowercase 24-hex user id.
  final String userId;

  final GroupRosterRole role;

  /// The signer's pinned X25519 identity key for this member (canonical
  /// base64 of 32 bytes), or `null` when the signer has none pinned.
  final String? identityKey;
}

/// A parsed GroupRoster v1. [rosterJson] keeps the exact string that was
/// parsed (the signed bytes); [rosterHash] is its lowercase sha256 hex.
final class GroupRoster {
  GroupRoster._({
    required this.groupId,
    required this.epoch,
    required this.issuedAt,
    required this.signer,
    required List<GroupRosterMember> members,
    required this.prev,
    required this.rosterJson,
    required this.rosterHash,
  }) : members = List.unmodifiable(members),
       memberIds = Set.unmodifiable(members.map((m) => m.userId));

  final int v = groupRosterVersion;
  final String groupId;
  final int epoch;
  final int issuedAt;
  final GroupRosterSigner signer;

  /// Sorted by userId ascending, unique.
  final List<GroupRosterMember> members;

  /// sha256 hex of the previous roster string, `null` iff [epoch] is 1.
  final String? prev;
  final String rosterJson;
  final String rosterHash;

  /// Every member's user id.
  final Set<String> memberIds;

  bool isAdmin(String userId) =>
      members.any((m) => m.userId == userId && m.role == GroupRosterRole.admin);

  /// The signer's pinned identity key for [userId]; `null` when [userId] is
  /// not a member or no key was pinned.
  String? identityKeyFor(String userId) {
    for (final m in members) {
      if (m.userId == userId) return m.identityKey;
    }
    return null;
  }

  /// Strict whitelist parse, ported check-for-check from `parseGroupRoster`.
  /// Throws [GroupRosterError] with a stable code.
  static GroupRoster parse(String rosterJson) {
    final bytes = utf8.encode(rosterJson);
    if (bytes.length > groupRosterMaxBytes) _fail('too_large');

    final Object? doc;
    try {
      doc = jsonDecode(rosterJson);
    } on Object {
      _fail('invalid_json');
    }
    _assertNoDuplicateKeys(rosterJson);
    if (doc is! Map<String, dynamic>) _fail('not_object');
    _checkKeys(doc, _topKeys);

    final v = doc['v'];
    if (v is! num || v != groupRosterVersion) _fail('unsupported_version');

    final groupId = doc['groupId'];
    if (groupId is! String || !_uuidRe.hasMatch(groupId)) {
      _fail('invalid_group_id');
    }

    final epoch = _safeInteger(doc['epoch']);
    if (epoch == null || epoch < 1) _fail('invalid_epoch');

    final issuedAt = _safeInteger(doc['issuedAt']);
    if (issuedAt == null || issuedAt < 0) _fail('invalid_issued_at');

    final signer = _parseSigner(doc['signer']);

    final rawMembers = doc['members'];
    if (rawMembers is! List || rawMembers.isEmpty) _fail('invalid_members');
    if (rawMembers.length > groupRosterMaxMembers) _fail('too_many_members');
    final members = [for (final m in rawMembers) _parseMember(m)];
    for (var i = 1; i < members.length; i++) {
      final a = members[i - 1].userId;
      final b = members[i].userId;
      if (a == b) _fail('members_duplicate');
      if (a.compareTo(b) >= 0) _fail('members_unsorted');
    }

    final prev = doc['prev'];
    if (epoch == 1) {
      if (prev != null) _fail('invalid_prev');
    } else if (prev is! String || !_sha256HexRe.hasMatch(prev)) {
      _fail('invalid_prev');
    }

    return GroupRoster._(
      groupId: groupId,
      epoch: epoch,
      issuedAt: issuedAt,
      signer: signer,
      members: members,
      prev: prev as String?,
      rosterJson: rosterJson,
      rosterHash: crypto.sha256.convert(bytes).toString(),
    );
  }

  /// Producer: compact JSON with the fixed key order, members sorted by
  /// userId. Validates its own output with [parse] (throws
  /// [GroupRosterError]).
  static String encode({
    required String groupId,
    required int epoch,
    required int issuedAt,
    required GroupRosterSigner signer,
    required List<GroupRosterMember> members,
    required String? prev,
  }) {
    final sorted = [...members]..sort((a, b) => a.userId.compareTo(b.userId));
    final json = jsonEncode(<String, Object?>{
      'v': groupRosterVersion,
      'groupId': groupId,
      'epoch': epoch,
      'issuedAt': issuedAt,
      'signer': <String, Object?>{
        'userId': signer.userId,
        'deviceId': signer.deviceId,
        'signingKey': signer.signingKey,
      },
      'members': [
        for (final m in sorted)
          <String, Object?>{
            'userId': m.userId,
            'role': m.role.name,
            'identityKey': m.identityKey,
          },
      ],
      'prev': prev,
    });
    parse(json);
    return json;
  }

  /// Lowercase sha256 hex of the exact UTF-8 bytes of [rosterJson].
  static String rosterHashOf(String rosterJson) =>
      crypto.sha256.convert(utf8.encode(rosterJson)).toString();

  /// The signed message: `utf8(groupRosterDomain) || utf8(rosterJson)`.
  static Uint8List signingInput(String rosterJson) => Uint8List.fromList([
    ...utf8.encode(groupRosterDomain),
    ...utf8.encode(rosterJson),
  ]);

  /// Ed25519 verification over [signingInput]. Requires canonical base64
  /// (64-byte signature, 32-byte key) and the size limit. Never throws.
  static Future<bool> verifySignature(
    String rosterJson,
    String signatureB64,
    String signingKeyB64,
  ) async {
    try {
      if (utf8.encode(rosterJson).length > groupRosterMaxBytes) return false;
      if (!SenderCertificate.isCanonicalBase64(signatureB64, length: 64) ||
          !SenderCertificate.isCanonicalBase64(signingKeyB64, length: 32)) {
        return false;
      }
      return await SignalKeyHelper.verify(
        signingKeyB64,
        signingInput(rosterJson),
        signatureB64,
      );
    } on Object {
      return false;
    }
  }
}

/// JS parity: valid iff `Number.isSafeInteger(JSON.parse(text))`. Dart's
/// JSON decoder yields `int` for integer literals and `double` otherwise
/// (`1.0`, `1e0`), so an integral double within range is accepted too.
int? _safeInteger(Object? x) {
  if (x is int) {
    return x >= -_maxSafeInteger && x <= _maxSafeInteger ? x : null;
  }
  if (x is double) {
    if (!x.isFinite || x != x.truncateToDouble()) return null;
    if (x.abs() > _maxSafeInteger) return null;
    return x.toInt();
  }
  return null;
}

void _checkKeys(Map<String, dynamic> obj, List<String> allowed) {
  for (final k in obj.keys) {
    if (!allowed.contains(k)) _fail('unknown_field');
  }
  for (final k in allowed) {
    if (!obj.containsKey(k)) _fail('missing_field');
  }
}

/// Rejects duplicate keys within any JSON object. Runs only on text the
/// JSON decoder already accepted. Keys compare after string decoding.
void _assertNoDuplicateKeys(String json) {
  final stack = <Set<String>?>[];
  var expectKey = false;
  for (var i = 0; i < json.length; i++) {
    final c = json.codeUnitAt(i);
    if (c == 0x22) {
      var j = i + 1;
      while (json.codeUnitAt(j) != 0x22) {
        if (json.codeUnitAt(j) == 0x5c) j++;
        j++;
      }
      final top = stack.isEmpty ? null : stack.last;
      if (top != null && expectKey) {
        final key = jsonDecode(json.substring(i, j + 1)) as String;
        if (!top.add(key)) _fail('duplicate_key');
        expectKey = false;
      }
      i = j;
    } else if (c == 0x7b) {
      stack.add(<String>{});
      expectKey = true;
    } else if (c == 0x5b) {
      stack.add(null);
    } else if (c == 0x7d || c == 0x5d) {
      if (stack.isNotEmpty) stack.removeLast();
    } else if (c == 0x2c) {
      expectKey = stack.isNotEmpty && stack.last != null;
    }
  }
}

String _parseUserId(Object? x) {
  if (x is! String || !_userIdRe.hasMatch(x)) _fail('invalid_user_id');
  return x;
}

GroupRosterSigner _parseSigner(Object? x) {
  if (x is! Map<String, dynamic>) _fail('invalid_signer');
  _checkKeys(x, _signerKeys);
  final userId = _parseUserId(x['userId']);
  final deviceId = x['deviceId'];
  if (deviceId is! String ||
      deviceId.isEmpty ||
      deviceId.length > _deviceIdMax) {
    _fail('invalid_device_id');
  }
  final signingKey = x['signingKey'];
  if (!SenderCertificate.isCanonicalBase64(signingKey, length: 32)) {
    _fail('invalid_signing_key');
  }
  return GroupRosterSigner(
    userId: userId,
    deviceId: deviceId,
    signingKey: signingKey as String,
  );
}

GroupRosterMember _parseMember(Object? x) {
  if (x is! Map<String, dynamic>) _fail('invalid_member');
  _checkKeys(x, _memberKeys);
  final userId = _parseUserId(x['userId']);
  final role = switch (x['role']) {
    'admin' => GroupRosterRole.admin,
    'member' => GroupRosterRole.member,
    _ => _fail('invalid_role'),
  };
  final identityKey = x['identityKey'];
  if (identityKey != null &&
      !SenderCertificate.isCanonicalBase64(identityKey, length: 32)) {
    _fail('invalid_identity_key');
  }
  return GroupRosterMember(
    userId: userId,
    role: role,
    identityKey: identityKey as String?,
  );
}

// ── Chain policy ─────────────────────────────────────────────────────

/// Stable rejection codes produced by [GroupRosterChain.verifyNext] in
/// addition to the parse codes of [GroupRosterError].
abstract final class GroupRosterRejectCode {
  static const String groupMismatch = 'group_mismatch';
  static const String badSignature = 'bad_signature';
  static const String signerNotCreator = 'signer_not_creator';
  static const String signerNotAdmin = 'signer_not_admin';
  static const String epochFork = 'epoch_fork';
  static const String rollback = 'rollback';
  static const String prevMismatch = 'prev_mismatch';
  static const String signerUntrusted = 'signer_untrusted';
}

/// The host's verdict on the roster signer's key (pinned peer signing key,
/// or key bundle + key transparency, like first contact).
enum GroupRosterSignerTrust { trusted, untrusted, unavailable }

/// Result of [GroupRosterChain.verifyNext].
sealed class GroupRosterVerdict {
  const GroupRosterVerdict();
}

/// The roster is the new verified roster.
final class GroupRosterAccepted extends GroupRosterVerdict {
  const GroupRosterAccepted(
    this.roster, {
    this.bootstrap = false,
    this.gap = false,
  });

  final GroupRoster roster;

  /// First roster this device sees and its epoch is > 1: trust-on-first-use
  /// of the chain position (history is not served).
  final bool bootstrap;

  /// The epoch skipped past one or more rosters this device never saw; only
  /// accepted when the signer was an admin of the previous verified roster.
  final bool gap;
}

/// Byte-identical to the previous verified roster.
final class GroupRosterUnchanged extends GroupRosterVerdict {
  const GroupRosterUnchanged();
}

/// Rejected: keep the previous verified roster. [code] is a
/// [GroupRosterError] code or a [GroupRosterRejectCode].
final class GroupRosterRejected extends GroupRosterVerdict {
  const GroupRosterRejected(this.code);

  final String code;
}

/// Signer trust could not be decided now (e.g. offline); retry later.
final class GroupRosterDeferred extends GroupRosterVerdict {
  const GroupRosterDeferred();
}

abstract final class GroupRosterChain {
  /// Verifies [rosterJson] + [signature] as the successor of [previous] (the
  /// last roster this device accepted for the group, or `null`).
  ///
  /// Order: parse · groupId · signature · epoch rules · [signerTrust].
  /// [creatorUserId] is required to accept a genesis (epoch 1) roster.
  static Future<GroupRosterVerdict> verifyNext({
    GroupRoster? previous,
    required String rosterJson,
    required String signature,
    required String expectedGroupId,
    String? creatorUserId,
    required Future<GroupRosterSignerTrust> Function(GroupRosterSigner signer)
    signerTrust,
  }) async {
    final GroupRoster roster;
    try {
      roster = GroupRoster.parse(rosterJson);
    } on GroupRosterError catch (e) {
      return GroupRosterRejected(e.code);
    }
    if (roster.groupId != expectedGroupId ||
        (previous != null && previous.groupId != expectedGroupId)) {
      return const GroupRosterRejected(GroupRosterRejectCode.groupMismatch);
    }
    if (!await GroupRoster.verifySignature(
      rosterJson,
      signature,
      roster.signer.signingKey,
    )) {
      return const GroupRosterRejected(GroupRosterRejectCode.badSignature);
    }

    final signerId = roster.signer.userId;
    var bootstrap = false;
    var gap = false;
    if (previous == null) {
      if (roster.epoch == 1) {
        if (creatorUserId == null || signerId != creatorUserId) {
          return const GroupRosterRejected(
            GroupRosterRejectCode.signerNotCreator,
          );
        }
        if (!roster.isAdmin(signerId)) {
          return const GroupRosterRejected(
            GroupRosterRejectCode.signerNotAdmin,
          );
        }
      } else {
        if (!roster.isAdmin(signerId)) {
          return const GroupRosterRejected(
            GroupRosterRejectCode.signerNotAdmin,
          );
        }
        bootstrap = true;
      }
    } else if (roster.epoch == previous.epoch) {
      return roster.rosterHash == previous.rosterHash
          ? const GroupRosterUnchanged()
          : const GroupRosterRejected(GroupRosterRejectCode.epochFork);
    } else if (roster.epoch < previous.epoch) {
      return const GroupRosterRejected(GroupRosterRejectCode.rollback);
    } else if (roster.epoch == previous.epoch + 1) {
      if (roster.prev != previous.rosterHash) {
        return const GroupRosterRejected(GroupRosterRejectCode.prevMismatch);
      }
      if (!previous.isAdmin(signerId)) {
        return const GroupRosterRejected(GroupRosterRejectCode.signerNotAdmin);
      }
    } else {
      if (!previous.isAdmin(signerId)) {
        return const GroupRosterRejected(GroupRosterRejectCode.signerNotAdmin);
      }
      gap = true;
    }

    final GroupRosterSignerTrust trust;
    try {
      trust = await signerTrust(roster.signer);
    } on Object {
      return const GroupRosterDeferred();
    }
    return switch (trust) {
      GroupRosterSignerTrust.trusted => GroupRosterAccepted(
        roster,
        bootstrap: bootstrap,
        gap: gap,
      ),
      GroupRosterSignerTrust.untrusted => const GroupRosterRejected(
        GroupRosterRejectCode.signerUntrusted,
      ),
      GroupRosterSignerTrust.unavailable => const GroupRosterDeferred(),
    };
  }
}

// ── Distribution policy ──────────────────────────────────────────────

abstract final class GroupRosterPolicy {
  /// Who may receive this group's sender key. With a verified roster the
  /// relay can only shrink the set (`relay ∩ roster`), never add to it.
  /// Without one: nobody when [requireVerifiedRoster], else the relay's list
  /// (legacy behaviour).
  static Set<String> allowedRecipients({
    GroupRoster? verified,
    required Set<String> relayParticipants,
    required bool requireVerifiedRoster,
  }) {
    if (verified != null) {
      return relayParticipants.intersection(verified.memberIds);
    }
    return requireVerifiedRoster ? <String>{} : Set.of(relayParticipants);
  }

  /// Members of [previous] that are gone in [next]: rotate away from them.
  static Set<String> removedMembers(GroupRoster previous, GroupRoster next) =>
      previous.memberIds.difference(next.memberIds);
}
