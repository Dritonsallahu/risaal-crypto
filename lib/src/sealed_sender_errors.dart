/// Typed rejection reasons for Sender Certificate v1 verification (R4-C3).
///
/// Order of evaluation on unseal is fixed by the contract
/// `docs/readiness/REMEDIATION_2026-10/contracts/R4-C3-sender-certificate-v1.md`
/// (§5 as amended by v2): [malformed] → [unknownKeyId] →
/// [badServerSignature] → [identityMismatch] → [notYetValid]/[expired].
enum SenderCertificateFailure {
  /// Bytes, JSON shape, field types/lengths or base64 are not exactly v1,
  /// only one of the two certificate fields is present, or the payload still
  /// carries the removed v1 `senderSignature` field.
  malformed,

  /// The certificate's `keyId` is not a pinned server signing key.
  unknownKeyId,

  /// The server signature does not verify over the exact certificate bytes.
  badServerSignature,

  /// The certificate names a different sender, device or identity key than
  /// the sealed payload.
  identityMismatch,

  /// The sealed timestamp is after `expiresAt` (+ clock skew).
  expired,

  /// The sealed timestamp is before `issuedAt` (− clock skew).
  notYetValid,
}

/// A sealed-sender envelope carried a sender certificate that failed
/// verification. The envelope is rejected before its nonce is recorded.
///
/// The message is deliberately sanitized: it names only the [reason], never
/// user ids, device ids, keys or certificate bytes.
class SealedSenderCertificateError extends StateError {
  SealedSenderCertificateError(this.reason)
    : super('Sealed sender certificate rejected: ${reason.name}');

  /// Why the certificate was rejected.
  final SenderCertificateFailure reason;
}

/// The `SealedSenderTrustPolicy` requires a verified sender certificate
/// (`requireCertified`) and this sealed envelope carried none, or carried one
/// that could not be evaluated. Rejected before the nonce is recorded and
/// before any session, pin or one-time-prekey state is planned.
///
/// Sanitized: names no sender, device or key.
class UncertifiedSealedSenderError extends StateError {
  UncertifiedSealedSenderError()
    : super(
        'Sealed sender rejected: a verified sender certificate is required',
      );
}

/// The `SealedSenderTrustPolicy` requires certified sends
/// (`requireCertifiedSend`) and no Sender Certificate was available: none was
/// passed, and the manager's `senderCertificateProvider` is absent, returned
/// `null` or threw. Raised before the send lock is taken, so no ratchet,
/// journal or pending-prekey state changed; the host may fetch a certificate
/// and retry.
///
/// Sanitized: names no sender, device or key, and never carries the
/// provider's own error.
class SenderCertificateRequiredError extends StateError {
  SenderCertificateRequiredError()
    : super('Sealed send refused: a sender certificate is required');
}

/// The `SealedSenderTrustPolicy` requires verified first contact
/// (`requireVerifiedFirstContact`) and this PreKey envelope would seed the
/// FIRST identity pin for a contact without a verified certificate or a
/// matching `FirstContactApproval`. Nothing was persisted: the host may
/// resolve an approval for exactly ([senderId], [senderDeviceId],
/// [senderIdentityKey]) outside the receive lock and retry the SAME delivery.
///
/// The fields are the sender's CLAIM, not verified facts. The message itself
/// is sanitized and names none of them.
class UnverifiedFirstContactError extends StateError {
  UnverifiedFirstContactError({
    required this.senderId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
  }) : super('First contact rejected: the sender identity is not verified');

  final String senderId;
  final String senderDeviceId;
  final String senderIdentityKey;
}
