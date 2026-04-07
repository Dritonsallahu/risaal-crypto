# Runbook: Session Reset Storm

**Severity:** P2 — Medium (escalate to P1 if > 5% of sessions affected)
**Response time:** 4 hours to acknowledge, 24 hours to resolve
**Owner:** On-call engineer

---

## Detection Signals

| Signal | Source | Threshold |
|--------|--------|-----------|
| Session reset rate spike | SecurityEventBus: `sessionReset` | > 0.5% of active sessions in 1 hour |
| Decrypt failure rate spike | SecurityEventBus: `decryptionFailed` | > 0.1% of decrypt attempts |
| Multiple users reporting "messages not delivered" | User reports | 3+ reports in 1 hour |
| OTP exhaustion spike | SecurityEventBus: `otpExhausted` | > 1% of sessions |

## Triage Checklist

- [ ] **1. Determine the trigger**
  - Client update deployed? (Protocol version mismatch)
  - Server update deployed? (Message routing change)
  - Mass re-registration event? (Server outage recovery)
  - Key storage corruption? (Platform update breaking Keychain/Keystore)

- [ ] **2. Identify the scope**
  - How many sessions are resetting?
  - Is it concentrated on one platform (iOS/Android)?
  - Is it concentrated on one client version?
  - Is it concentrated on sessions older than N days?

- [ ] **3. Check for cascading effects**
  - Are resets causing OTP exhaustion? (Each reset consumes a pre-key)
  - Are resets succeeding or failing? (Failed resets = no recovery)
  - Is the pre-key server under pressure? (Spike in pre-key bundle fetches)

## Diagnosis

### Client Update Mismatch

**Cause:** New client version changes protocol behavior in a way that's incompatible with older sessions.

**Evidence:**
- Resets concentrated on sessions between updated and non-updated clients
- Decrypt failures show `SecretBoxAuthenticationError`
- Reset attempts succeed (new sessions establish correctly)

**Resolution:**
1. If backward-compatible fix possible, deploy patch via expedited canary
2. If not, the resets are expected — monitor that new sessions establish correctly
3. Communicate to users: "Sessions are being refreshed for improved security"
4. Monitor OTP levels — ensure pre-key server keeps up with demand

### Server Message Routing Issue

**Cause:** Server delivering messages to wrong sessions or in wrong order.

**Evidence:**
- Resets across all client versions
- Server logs show message routing errors
- Messages delivered to wrong user or wrong device

**Resolution:**
1. **Immediate:** Check server message routing logic
2. Verify conversation membership is correct in database
3. Check for race conditions in multi-device message fanout
4. Fix routing issue and monitor recovery

### Key Storage Corruption

**Cause:** Platform OS update or migration corrupted Keychain/Keystore entries.

**Evidence:**
- Resets concentrated on one platform (e.g., all iOS after iOS update)
- `CryptoStorage` read failures in client logs
- Identity key or signed pre-key cannot be loaded

**Resolution:**
1. Check if Keychain/Keystore access patterns changed in the OS update
2. If keys are irrecoverable, users must re-register (new identity key)
3. Deploy client update with improved key storage resilience
4. Consider adding key backup mechanism (encrypted cloud backup)

### Mass Re-Registration

**Cause:** Server outage caused users to re-register, invalidating all existing sessions.

**Evidence:**
- Burst of new registrations in server logs
- All sessions with re-registered users are resetting
- Pre-key server under heavy load

**Resolution:**
1. Ensure pre-key server can handle the spike (scale if needed)
2. Session resets are expected behavior — monitor that they succeed
3. Monitor OTP levels closely — upload more pre-keys if exhausting
4. Communicate ETA for full recovery

## Containment Actions

### If resets are failing (sessions not recovering):

1. Check pre-key server availability
2. Verify pre-key bundle format is correct
3. Check X3DH handshake success rate (SLO S-005)
4. If pre-key server is down, bring it back online immediately
5. If pre-keys are exhausted, trigger emergency pre-key upload for all affected users

### If resets are succeeding but overwhelming the system:

1. Rate-limit session reset attempts (max 1 per peer per 5 minutes)
2. Stagger resets using exponential backoff on the client
3. Monitor server resource usage (CPU, memory, database connections)
4. Scale server resources if needed

## Recovery Steps

1. Verify session reset rate returns to baseline (< 0.5% per day)
2. Verify decrypt failure rate returns to baseline (< 0.1%)
3. Verify OTP levels are healthy across all users
4. Check that all affected sessions have been re-established
5. Monitor for 48 hours post-recovery

## Escalation Criteria

Escalate from P2 to P1 if:
- > 5% of active sessions affected
- Session resets are failing (not recovering)
- Pre-key exhaustion is spreading
- User reports exceed 10 in 1 hour

Escalate from P1 to P0 if:
- MAC failures accompany the resets (indicates active attack, not just instability)
- > 25% of active sessions affected
- Recovery is not possible without user action (re-registration)

## Post-Incident

- [ ] Quantify total sessions affected and time to recovery
- [ ] Identify root cause and whether it was preventable
- [ ] Add regression test if caused by a code change
- [ ] Update session reset rate-limiting if current limits were insufficient
- [ ] Review OTP replenishment strategy
- [ ] Update this runbook with lessons learned
