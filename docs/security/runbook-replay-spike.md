# Runbook: Replay Attack Spike

**Severity:** P1 — High
**Response time:** 1 hour to acknowledge, 4 hours to resolve
**Owner:** On-call engineer + security lead

---

## Detection Signals

| Signal | Source | Threshold |
|--------|--------|-----------|
| Replay rejection rate spike | SecurityEventBus: `replayDetected` | > 10 rejections in 15 minutes |
| Sealed Sender replay rejection | SecurityEventBus: `sealedSenderReplayRejected` | Any occurrence |
| Unusual inbound message volume | Server metrics | > 3x normal rate for a user |

## Triage Checklist

- [ ] **1. Classify the replay source**
  - Network replay (same encrypted envelope sent multiple times)?
  - Application replay (sender retrying with same message number)?
  - Server replay (server re-delivering old messages)?
  - Malicious replay (attacker capturing and replaying envelopes)?

- [ ] **2. Identify the scope**
  - Single conversation?
  - Single user (all conversations)?
  - Multiple users (systemic issue)?

- [ ] **3. Check for correlating signals**
  - Are MAC failures also occurring? (Indicates tampering, not just replay)
  - Are session resets spiking? (Indicates corrupted state)
  - Is the server under unusual load? (Indicates DDoS/abuse)

## Diagnosis

### Network Replay (Most Common)

**Cause:** Unreliable network causing the transport layer to re-deliver messages.

**Evidence:**
- Replay rejections from a single conversation
- No MAC failures
- Messages have valid timestamps (within 5-minute window for Sealed Sender)
- Network error logs show TCP retransmissions

**Resolution:**
1. No action needed — anti-replay protection is working correctly
2. Verify rejection count returns to baseline after network stabilizes
3. If persistent, investigate client-side message deduplication

### Application Replay (Bug)

**Cause:** Client bug causing the same message to be sent with the same message number.

**Evidence:**
- Replay rejections from a single sender across multiple conversations
- Sender's message counter may be stuck or resetting
- No corresponding encrypt events for the replayed messages

**Resolution:**
1. Identify the bug in the sender's client
2. Check if `RatchetState.sendingChainMessageNumber` is being persisted correctly
3. Verify message number monotonicity enforcement
4. Deploy fix via canary process

### Server Replay (Infrastructure Bug)

**Cause:** Message queue or WebSocket layer re-delivering previously delivered messages.

**Evidence:**
- Replay rejections across multiple conversations
- Server logs show duplicate message deliveries
- Messages have old timestamps

**Resolution:**
1. Check message queue for duplicate delivery issues
2. Verify server-side message deduplication
3. Check Redis message ID tracking
4. If systematic, pause message delivery until root cause fixed

### Malicious Replay (Attack)

**Cause:** Attacker capturing encrypted envelopes and replaying them.

**Evidence:**
- Replay rejections with anomalous source patterns
- Messages from unexpected IP ranges (if server logs source)
- Sealed Sender replays outside normal delivery patterns
- Possible correlation with other suspicious activity

**Resolution:**
1. **Immediate:** Rate-limit message delivery for affected users
2. Check if replayed messages are exact copies (same ciphertext)
3. If from a single source IP, block at firewall level
4. If distributed, escalate to P0 and follow `runbook-key-compromise.md`
5. Consider enabling additional server-side envelope deduplication

## Recovery Steps

1. Verify replay rejection rate returns to baseline (< 0.01% of messages)
2. Check `receivedMessages` set sizes — ensure they're not growing unboundedly
3. Verify anti-replay state persistence is working (sets survive app restart)
4. Monitor for 24 hours post-resolution

## Anti-Replay Mechanism Reference

The anti-replay system works at two levels:

**Double Ratchet level:**
- `RatchetState.receivedMessages` tracks up to 2000 message numbers
- Duplicate message numbers are rejected before decryption
- Message numbers must strictly increase within a chain

**Sealed Sender level:**
- Envelope timestamps validated within 5-minute window
- Envelope hashes tracked in short-term replay cache
- Expired envelopes rejected

## Post-Incident

- [ ] Verify anti-replay state was not corrupted during the incident
- [ ] Check if `receivedMessages` cap (2000) needs adjustment
- [ ] Update monitoring thresholds if baseline has shifted
- [ ] Update this runbook with lessons learned
