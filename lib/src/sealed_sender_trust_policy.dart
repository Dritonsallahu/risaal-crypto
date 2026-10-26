/// Receive-side trust policy for Sender Certificate v1 (R4-C3).
///
/// See `docs/readiness/REMEDIATION_2026-10/contracts/R4-C3-sender-certificate-v1.md`.
library;

/// Host-configured policy the `SignalProtocolManager` applies to every
/// inbound first-contact and sealed-sender delivery, on the sealed AND the
/// direct (type-2) lane alike, so a relay cannot route around it by choosing
/// the envelope type.
///
/// [legacy] (the default) keeps the pre-R4-C3 accept-both behaviour.
final class SealedSenderTrustPolicy {
  const SealedSenderTrustPolicy({
    this.serverCertificateSigningKeys = const <String, String>{},
    this.requireCertified = false,
    this.requireVerifiedFirstContact = false,
    this.requireCertifiedSend = false,
  });

  /// keyId -> base64 Ed25519 public key of the server certificate signer
  /// (pinned by the host). Empty: carried certificates are not evaluated
  /// (`certificateIgnored`).
  final Map<String, String> serverCertificateSigningKeys;

  /// Enforcement phase: reject every sealed envelope without a verified
  /// certificate (`UncertifiedSealedSenderError`). Because a direct (type-2)
  /// envelope can never carry a certificate, this also implies
  /// [requireVerifiedFirstContact] on the direct lane; otherwise a relay could
  /// bypass enforcement by delivering a first contact unsealed.
  final bool requireCertified;

  /// Never seed a NEW identity pin from an uncertified PreKey envelope unless
  /// the host supplied a matching [FirstContactApproval]
  /// (`UnverifiedFirstContactError`). Applies to the sealed AND the direct
  /// lane.
  final bool requireVerifiedFirstContact;

  /// Send side: every sealed send must carry a Sender Certificate, either the
  /// explicit `senderCertificate:` argument or one returned by the manager's
  /// `senderCertificateProvider`. A missing certificate (no provider, the
  /// provider returned `null`, or it threw) raises
  /// `SenderCertificateRequiredError` before any ratchet or journal mutation.
  /// Default `false`: a missing certificate means a legacy uncertified send.
  final bool requireCertifiedSend;

  /// Today's behaviour: no pinned server key, nothing required.
  static const legacy = SealedSenderTrustPolicy();
}

/// Where the host's out-of-band evidence for a first contact came from.
enum FirstContactApprovalSource {
  /// The sender's published key bundle names this identity key.
  keyBundle,

  /// A key-transparency proof names this identity key.
  keyTransparency,

  /// The user verified the safety number out of band.
  userVerified,
}

/// Host-supplied evidence that [senderIdentityKey] really belongs to
/// [senderId]/[senderDeviceId]. It admits an uncertified first contact only
/// when all three fields equal the identity the envelope claims.
final class FirstContactApproval {
  const FirstContactApproval({
    required this.senderId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
    required this.source,
  });

  final String senderId;
  final String senderDeviceId;

  /// Standard base64 of the sender's 32-byte X25519 identity public key.
  final String senderIdentityKey;
  final FirstContactApprovalSource source;

  /// Whether this approval vouches for exactly the claimed identity.
  bool matches({
    required String senderId,
    required String senderDeviceId,
    required String senderIdentityKey,
  }) =>
      this.senderId == senderId &&
      this.senderDeviceId == senderDeviceId &&
      this.senderIdentityKey == senderIdentityKey;
}

/// What the receive path established about the sender of one delivered
/// message. The host decides how to present it (e.g. a "not verified" badge).
final class SenderAuthentication {
  const SenderAuthentication({
    required this.certified,
    this.certificateKeyId,
    this.certificateIgnored = false,
    this.firstContact = false,
    this.approvalSource,
  });

  /// A server-issued certificate was verified and bound to this envelope and
  /// this recipient. Always `false` on the direct lane.
  final bool certified;

  /// `keyId` of the verified certificate; `null` unless [certified].
  final String? certificateKeyId;

  /// A certificate was carried but not evaluated because the policy pins no
  /// server signing key.
  final bool certificateIgnored;

  /// This delivery established the FIRST identity pin for the contact (no
  /// device of the sender was pinned before).
  final bool firstContact;

  /// The host approval that admitted this first contact, if one matched.
  final FirstContactApprovalSource? approvalSource;
}

/// Read-only view of one sealed envelope, returned by
/// `SignalProtocolManager.peekSealedSender`. It says who CLAIMS to be sending
/// and what the receive path would establish, so the host can resolve a
/// [FirstContactApproval] outside the receive lock and retry the delivery.
///
/// It never contains the inner message. Nothing here is trusted unless
/// [certified] is true; the claimed identity must be checked against a key
/// bundle, key-transparency proof or the user before it is approved.
final class SealedSenderPeek {
  const SealedSenderPeek({
    required this.senderId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
    required this.certified,
    required this.certificateIgnored,
    required this.isFirstContact,
    required this.innerType,
    this.certificateKeyId,
  });

  /// Claimed sender user id (sealed, authenticated only if [certified]).
  final String senderId;

  /// Claimed sender device id.
  final String senderDeviceId;

  /// Claimed standard base64 X25519 identity public key of the sender.
  final String senderIdentityKey;

  /// A pinned server key verified the certificate. Contract v2: there is no
  /// per-recipient binding, so the envelope stays deniable (R4-C3-V2-PKG).
  final bool certified;

  /// A certificate was carried but no server key is pinned.
  final bool certificateIgnored;

  /// No device of the sender has an identity pin on this device yet.
  final bool isFirstContact;

  /// `keyId` of the verified certificate; `null` unless [certified].
  final String? certificateKeyId;

  /// Inner envelope type: `'prekey'` (session setup) or `'message'`.
  final String innerType;
}
