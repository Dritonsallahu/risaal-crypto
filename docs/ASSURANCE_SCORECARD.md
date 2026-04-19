# Assurance Scorecard

This scorecard tracks objective maturity across fixed security criteria.

## Criteria

- Forward secrecy
- Post-compromise security
- Metadata resistance
- Group security guarantees
- PQ readiness
- Audit depth
- Exploit response maturity

## Baseline Snapshot (Internal, 2026-04)

| Criterion | risaal_crypto | Evidence Source |
|---|---:|---|
| Forward secrecy | 8.5/10 | Double Ratchet tests + protocol spec |
| Post-compromise security | 8.0/10 | Ratchet adversarial tests |
| Metadata resistance | 7.0/10 | Sealed sender + padding, timing limitations documented |
| Group security | 8.0/10 | Sender Key auth tests + docs |
| PQ readiness | 6.5/10 | Hybrid PQXDH with research-grade binding caveat |
| Audit depth | 4.0/10 | No completed third-party formal audit yet |
| Exploit response maturity | 8.0/10 | Incident runbooks, SLOs, CI gates |

## External Comparison Template

Use this fixed matrix to compare with WhatsApp, Signal, Session, Telegram, and Viber after each milestone.

| Product | FS | PCS | Metadata | Group Sec | PQ Ready | Audit Depth | Exploit Response | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| risaal_crypto | - | - | - | - | - | - | - | |
| Signal | - | - | - | - | - | - | - | |
| WhatsApp | - | - | - | - | - | - | - | |
| Session | - | - | - | - | - | - | - | |
| Telegram | - | - | - | - | - | - | - | |
| Viber | - | - | - | - | - | - | - | |

## Update Cadence

- Re-score after every major security milestone.
- Re-score immediately after formal audit completion and remediation.
