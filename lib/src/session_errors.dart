/// Thrown when no Double Ratchet session exists for [peerId]:[deviceId]
/// (send, receive or session load).
///
/// A [StateError], so existing `on StateError` handlers keep working, and
/// [message] keeps its historical text. Callers that need the peer should
/// read the typed fields instead of parsing the message.
class NoSessionError extends StateError {
  NoSessionError(this.peerId, this.deviceId, String message) : super(message);

  /// The remote user id.
  final String peerId;

  /// The remote device id.
  final String deviceId;
}

/// Thrown when a session's recorded remote identity disagrees with the
/// identity currently pinned for [peerId]:[deviceId] (R4-PKG-SESSION-PIN-CHECK).
///
/// Raised before any ratchet state changes, on every encrypt and decrypt. The
/// session was built with a key this device no longer trusts (for example an
/// interrupted `acceptVerifiedPeerIdentity`); it must be re-established, not
/// used. A [StateError], so existing `on StateError` handlers keep working.
/// The message never carries key material.
class SessionIdentityMismatchError extends StateError {
  SessionIdentityMismatchError(this.peerId, this.deviceId)
    : super(
        'Session identity does not match the pinned identity for '
        '$peerId:$deviceId; the contact must be re-verified',
      );

  /// The remote user id.
  final String peerId;

  /// The remote device id.
  final String deviceId;
}
