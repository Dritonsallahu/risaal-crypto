# RISAAL-CRYPTO-2026-001 — Non-Transactional Decrypt and Session Deletion on MAC Failure

**Fixed in 0.4.0.**

## Advisory Fields

| Field | Value |
|-------|-------|
| **ID** | RISAAL-CRYPTO-2026-001 |
| **Title** | Non-transactional decrypt and session deletion on MAC failure |
| **Package** | `risaal_crypto` — pub.dev / GitHub [Dritonsallahu/risaal-crypto](https://github.com/Dritonsallahu/risaal-crypto) |
| **Affected versions** | 0.1.0 – 0.3.0 (all versions before 0.4.0) |
| **Patched version** | 0.4.0 |
| **Severity** | High |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` |

## Summary

A relay-position attacker who can flip one byte in transit could destroy an established Double Ratchet session. Three defects in the decrypt path combined to allow it:

1. **Non-atomic ratchet advancement.** `DoubleRatchet._decryptInner` advanced the anti-replay set, the skipped-key map, the receiving chain, and the DH ratchet against live state _before_ AES-256-GCM authentication. A message whose tag fails authentication after partial ratchet advancement left the session in a corrupted intermediate state.

2. **Unauthenticated message header.** The fields `dhPublicKey`, `messageNumber`, and `previousChainLength` were not bound into the AEAD additional authenticated data (AAD). A relay could inflate `previousChainLength`, causing the receiver to derive and store hundreds of skipped keys while the GCM tag still verified for a different message.

3. **Session deleted on MAC failure.** `_shouldTriggerReset` treated any `SecretBoxAuthenticationError` as grounds for calling `removeSession()`. With the three-per-hour limiter, three forged messages could wedge automatic recovery for 24 hours, each cycle burning a one-time pre-key.

## Impact

- A relay-position attacker (including a compromised server) could destroy an established E2EE session by injecting a single forged message.
- With three injected messages per hour, automated recovery was blocked for up to 24 hours because each reset cycle consumed a one-time pre-key.
- No confidentiality impact: the attacker cannot read message content using this technique.

## CVSS 3.1 Metric Justification

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Attacker acts as a relay; no local access needed |
| Attack Complexity | Low | Single byte flip suffices; no pre-conditions |
| Privileges Required | None | Any relay can inject a forged message |
| User Interaction | None | Victim need not take any action |
| Scope | Unchanged | Impact is confined to the affected session |
| Confidentiality Impact | None | Attacker cannot read plaintext via this bug |
| Integrity Impact | High | Session is destroyed; no further messages can be sent or received |
| Availability Impact | High | Recovery is blocked for up to 24 hours per injected message set |

## Workarounds

None. Upgrade to `risaal_crypto` 0.4.0 or later.

## Fix Description

In 0.4.0:

- Ratchet advancement runs against a deep-cloned _candidate_ state; the candidate is committed to live state only after AES-256-GCM authentication succeeds. A rejected message leaves the session byte-identical to its pre-receive state.
- The canonical message header (`version`, `dhPublicKey`, `messageNumber`, `previousChainLength`) is bound as AES-GCM additional authenticated data. This is a **breaking wire-format change** (wire version 2).
- A MAC failure raises a typed `MessageAuthenticationError` and the session is preserved. The `_shouldTriggerReset` path and its rate limiter are removed.
- The message key is wiped from memory on the rejection path.
- `onPreKeyReplenishmentNeeded` now fires where a one-time pre-key is actually spent.

## References

- Fix commit: `d09c716` (`security(crypto): close 8 P0 defects in the successful-receive WAL`) in the Risaal monorepo, 2026-08-10
- Internal branch: `security/0.4.0-transactional-decrypt`

## Credit

Reported privately through the disclosure program. Reporter credit will be added with the reporter's consent.

## Timeline

| Date | Event |
|------|-------|
| 2026-10-09 | Report received |
| 2026-08-10 | Fix committed to internal monorepo (`d09c716`) |
| 2026-10-11 | Advisory draft prepared |
| TBD | GHSA published and 0.4.0 released to pub.dev |

---


