# Security Goals & Acceptance Criteria

This document defines measurable security goals for `risaal_crypto` and maps them to verification evidence.

## Goal 1 — Protocol Correctness

- Maintain conformance with the versioned protocol specification in `PROTOCOL.md`.
- Any cryptographic behavior change requires updated test vectors and changelog entries.
- Acceptance criteria:
  - CI test suite passes, including adversarial and fuzz tests.
  - Protocol-impacting PRs include rationale and spec references.

## Goal 2 — Confidentiality & Integrity

- Message content confidentiality and integrity must be preserved for 1:1 and group messaging.
- Acceptance criteria:
  - Encryption/decryption and tamper-detection tests pass.
  - No downgrade in authenticated encryption guarantees.

## Goal 3 — Forward Secrecy & Post-Compromise Security

- Session ratchets must preserve forward secrecy and post-compromise healing properties.
- Acceptance criteria:
  - Ratchet state transition and replay protections are continuously tested.
  - Regression tests are mandatory for any ratchet bug fix.

## Goal 4 — Metadata Minimization

- Minimize metadata exposed to servers by default, and explicitly document residual leakage.
- Acceptance criteria:
  - Sealed sender and padding behavior tested and documented.
  - Metadata guarantees and non-goals are kept current in `docs/METADATA_PRIVACY_MODEL.md`.

## Goal 5 — Implementation Hardening

- Resist malformed input, replay, downgrade, and state-desynchronization attacks.
- Acceptance criteria:
  - Fuzz/adversarial test suites pass in CI.
  - High-severity findings are tracked through incident and patch workflows.

## Goal 6 — Supply Chain & Release Integrity

- Keep dependency risk and release artifacts auditable.
- Acceptance criteria:
  - Dependency vulnerability scanning passes in CI.
  - Releases include checksums, provenance attestation, and SBOM.

## Goal 7 — Independent Assurance

- Progress from internal verification to external, independent validation.
- Acceptance criteria:
  - Audit scope and cadence maintained in `docs/AUDIT_SCOPE.md`.
  - Public publication of audit reports and remediation status.

## Goal 8 — Operational Transparency

- Publish objective security posture updates over time.
- Acceptance criteria:
  - Maintain benchmark scorecards in `docs/ASSURANCE_SCORECARD.md`.
  - Publish periodic transparency updates using `docs/TRANSPARENCY_REPORT_TEMPLATE.md`.
