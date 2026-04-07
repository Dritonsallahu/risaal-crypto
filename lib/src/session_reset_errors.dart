/// Thrown when a broken session was detected and auto-reset.
///
/// The message that triggered the error is unrecoverable (AES-GCM MAC
/// failed), but the session has been deleted. The next outgoing message
/// will auto-establish a fresh session via PreKey.
class SessionResetError implements Exception {
  final String senderId;
  final String senderDeviceId;
  final String originalError;

  const SessionResetError({
    required this.senderId,
    required this.senderDeviceId,
    required this.originalError,
  });

  @override
  String toString() =>
      'SessionResetError: Session with $senderId:$senderDeviceId was reset. '
      'Original: $originalError';
}

/// Thrown when a peer's security capabilities downgraded (e.g. PQXDH → classical).
///
/// This indicates a possible MITM stripping the post-quantum layer. The caller
/// should present the user with a warning and only proceed if they explicitly
/// confirm via [PqxdhPolicy.classicalOnly].
class PqxdhDowngradeError implements Exception {
  final String userId;
  final String deviceId;

  const PqxdhDowngradeError({
    required this.userId,
    required this.deviceId,
  });

  @override
  String toString() =>
      'PqxdhDowngradeError: Peer $userId:$deviceId previously supported PQXDH '
      'but new bundle lacks Kyber key. Possible downgrade attack.';
}

/// Thrown when a session has been flagged as unstable (too many resets).
///
/// Auto-reset is disabled for this session pair. The user should update
/// their app or manually reset encryption from the chat info screen.
class SessionUnstableError implements Exception {
  final String senderId;
  final String senderDeviceId;
  final int resetCount;

  const SessionUnstableError({
    required this.senderId,
    required this.senderDeviceId,
    required this.resetCount,
  });

  @override
  String toString() =>
      'SessionUnstableError: Session with $senderId:$senderDeviceId is unstable '
      '($resetCount resets). Auto-reset disabled.';
}
