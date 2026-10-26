# Vulnerability Disclosure Policy

`risaal_crypto` welcomes responsible vulnerability reports. **There is currently no paid bug bounty**; see Program Status below.

## Scope

In scope:
- `lib/src/` cryptographic logic
- Protocol correctness vulnerabilities
- Replay/downgrade/session compromise vectors
- Key management and memory hygiene flaws

Out of scope:
- Social engineering and phishing
- Denial-of-service requiring unrealistic resources
- Issues only affecting unsupported versions

## Disclosure Process

- Report privately to `security@risaal.org`.
- Follow `SECURITY.md` response expectations and coordinated disclosure policy.
- Do not publish exploit details before coordinated release.

## Program Status

**No monetary rewards are offered at this time.** Risaal is in pre-release
hardening, and rewards will only begin once the Risaal application reaches
stable, live production. Terms will be published at https://risaal.org/security
when that happens.

Until then, every report is:

- acknowledged within 72 hours,
- triaged against the current source (reports against an older published version
  are checked for whether the current code is still affected), and
- credited in the resulting advisory and changelog, with the reporter's consent.

## Safe Harbor

Good-faith research conducted within this policy will be considered authorized and welcomed.
