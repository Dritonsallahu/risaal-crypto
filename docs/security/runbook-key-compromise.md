# Runbook: Key Compromise Response

**Severity:** P0 — Critical
**Response time:** 15 minutes to acknowledge, 1 hour to contain
**Owner:** Security lead + on-call engineer

---

## Detection Signals

| Signal | Source | Severity |
|--------|--------|----------|
| MAC verification failure spike (> 5 in 5 min) | SecurityEventBus: `macVerificationFailed` | Critical |
| Signature verification failure spike | SecurityEventBus: `signatureVerificationFailed` | Critical |
| PQ downgrade attempt detected | SecurityEventBus: `pqDowngradeBlocked` | Critical |
| User-reported "safety number changed" without re-registration | User report | High |
| Unusual session reset pattern (same user, multiple peers) | SecurityEventBus: `sessionReset` | High |

## Triage Checklist

- [ ] **1. Classify the compromise scope**
  - Single session (one user pair)?
  - Single device (all sessions for one user)?
  - Server-side (pre-key bundle tampering)?
  - Protocol-level (algorithmic flaw)?

- [ ] **2. Identify affected users**
  - Query telemetry for which sessions are emitting MAC/sig failures
  - Cross-reference with session reset events
  - Identify the common factor (single user, single server endpoint, etc.)

- [ ] **3. Determine the attack vector**
  - Is the server returning tampered pre-key bundles?
  - Are messages being modified in transit (MITM)?
  - Is a device compromised (key extraction)?
  - Is this a replay attack (check `replayDetected` events)?

## Containment Actions

### Scenario A: Single Session Compromise

1. **Immediate:** Force session reset for the affected pair
   ```dart
   await signalProtocolManager.resetSession(affectedUserId);
   ```
2. Trigger new X3DH handshake with fresh pre-key bundle
3. Notify both users: "Your safety number has changed. Verify with your contact."
4. Preserve telemetry logs for forensic analysis

### Scenario B: Device Compromise

1. **Immediate:** Revoke all sessions for the compromised device
   ```dart
   await cryptoStorage.wipeAllSessions();
   await signalProtocolManager.clearAllSessions();
   ```
2. Rotate identity key pair (requires re-registration)
3. Revoke all one-time pre-keys on server
4. Upload fresh pre-key bundle with new signed pre-key
5. Notify all contacts: "This user has re-registered. Verify safety numbers."

### Scenario C: Server-Side Pre-Key Tampering

1. **Immediate:** Disable pre-key distribution endpoint
2. Audit pre-key storage for unauthorized modifications
3. Compare pre-key fingerprints with client-side records
4. If tampering confirmed:
   - Rotate server TLS certificate
   - Rotate admin credentials
   - Force all users to re-upload pre-key bundles
   - Enable key transparency verification for all subsequent fetches

### Scenario D: Protocol-Level Flaw

1. **Immediate:** Assess if the flaw is exploitable remotely
2. If remotely exploitable:
   - Prepare emergency patch
   - Follow canary deployment (expedited: 4-hour Stage 1)
   - Coordinate disclosure per `INCIDENT_RESPONSE.md`
3. If only locally exploitable:
   - Prepare patch for next release cycle
   - Document in SECURITY.md "Known Limitations"

## Recovery Steps

1. Verify all affected sessions are re-established with fresh keys
2. Verify safety numbers have changed (confirming new key material)
3. Monitor SLOs for 24 hours post-recovery:
   - Decrypt failure rate should return to < 0.1%
   - Session reset rate should return to < 0.5%
   - MAC failure rate should be 0%
4. Conduct post-incident review within 48 hours

## Communication Template

```
Subject: [SECURITY] Key compromise incident — [DATE]

Summary: [1 sentence describing what happened]

Impact: [Number of affected users/sessions]

Timeline:
- [TIME] Detection
- [TIME] Triage completed
- [TIME] Containment actions taken
- [TIME] Recovery confirmed

Root cause: [Brief description]

Actions taken: [List]

Follow-up: [List of preventive measures]
```

## Post-Incident

- [ ] Update threat model if new attack vector identified
- [ ] Add detection rule if the compromise was initially missed
- [ ] Update this runbook with lessons learned
- [ ] Schedule follow-up review in 2 weeks
