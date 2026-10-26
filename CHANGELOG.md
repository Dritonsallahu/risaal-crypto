# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-26

> Each bullet below cites at least one monorepo commit hash from `git log -- packages/risaal_crypto/lib`.

### Breaking

- **Removed `StegoService`**: the LSB embedding with a plaintext length header was detectable; a future design will need keyed embedding and an encrypted header (`198e435`, R4-L7).
- **ML-KEM-768 FIPS 203 (pqcrypto 0.4.0) cutover** — `pqcrypto` upgraded from 0.1.0 (pre-release FFI) to 0.4.0 (pure-Dart FIPS 203). Key bytes are incompatible; new key bundles required on first contact after upgrade. `PqxdhPolicy.classicalOnly` downgrade path removed — callers that set this policy must update to `preferPq`. (`285ebaf`, `73eb5e6`)
- **`RatchetState` storage format v2** — storage key namespace now validated; sessions written by 0.3.x are auto-migrated on first load. (`65d2314`)
- **`seenNonces` / `securityLevel` API stable** — previously marked experimental in 0.3.0; both are now required fields with no fallback.

### Security

- **Sender Key distributions can no longer roll a chain back** — re-processing a distribution at the same epoch rewound the stored iteration, so group messages already read (and rejected as replays) decrypted again, and dropped retained skipped keys. A redelivered chain is now an idempotent no-op, a conflicting chain at the same epoch, signer and iteration is refused, and a distribution naming the local user is refused (it overwrote the private signing key and broke group sending). A same-epoch distribution from a different signer still replaces the chain, since old messages cannot verify under the new key.
- **All-zero X25519 outputs are rejected (RFC 7748 §6.1)** — `SignalKeyHelper.requireContributoryX25519` is applied at every DH call site (X3DH/PQXDH, Double Ratchet, Sealed Sender), so a low-order public key cannot force a DH term to a public constant. Mandatory PQXDH already prevented a publicly known session key; this closes the classical term as well.
- **0xFF F-prefix added to X3DH/PQXDH KDF info string** for spec-compliant domain separation (A2-4). Prevents cross-context key confusion when the KDF info labels share a prefix. (`73eb5e6`)
- **Signed ML-KEM pre-key transcript bound into HKDF info** — prevents a relay from substituting a different ML-KEM ciphertext in the PQXDH handshake. (`285ebaf`)
- **Authenticated OPK generation routing** — one-time pre-key assignment is bound into the HKDF transcript, preventing silent OPK substitution. (`65d2314`)
- **Sealed Sender outer/inner identity binding and pinned-identity checks** on every receive lane — prevents a compromised relay from resigning an envelope with a different sender identity. (`6835587`, `a16d839`)
- **Pre-key handshake tombstones** against replay — each one-time pre-key may be consumed at most once; replayed handshakes are rejected before any ratchet state is advanced. (`d09c716`)
- **Storage-key namespace validation** — storage keys containing path-traversal sequences or unexpected prefixes are rejected before any read or write. (`1c0190b`)
- **Receive WAL** — the successful-receive write-ahead log closes eight P0 defects found by frozen-hash review: atomic commit, nonce-first ordering, rollback on partial write, replay protection across crashes, durable nonce set written before message delivery, candidate isolation, epoch-ordering guard, and skipped-key eviction ordering. (`d09c716`)
- **Send WAL** — write-ahead log for the outbound path mirrors the receive-WAL invariants. (`cfe2d28`)
- **Key-bundle replacement journal and generation retirement** — a device could previously never rotate its signing keys again after eight rotations; generation retirement closes this. (`f462646`, `31a8be7`)
- **Sender Key v3 AES-256-GCM with epoch in AAD and signature-first admission** — the epoch counter is bound into AES-GCM AAD; the sender signature is verified before the GCM tag is checked, preventing AEAD oracles. (`5063c36`, `dbab7e7`)
- **Skipped sender-key TTL 14 days** — skipped sender-key entries that have not been used within 14 days are evicted to bound the memory cost of long-offline group members. (`f9fb960`)
- **Persistent sealed nonce set with rollback and 30-day window** — the nonce deduplication set is persisted across restarts and trimmed to the newest 10,000 entries; the timestamp window is 30 days to cover realistic offline gaps (closes audit 2026-06 showstopper #4). (`ade3edf`, `890b462`)
- **Typed `MessageAuthenticationError`** — MAC failures now surface a dedicated exception type so callers can distinguish authentication failures from protocol errors. (`65d2314`)
- **Adopted-account device re-attachment is fail-closed** — an adopted device that re-attaches to its own account now re-uses the pre-journal install path rather than demanding a full wipe that destroyed the existing identity. (`45b8d75`, `d808e08`)
- **Sender Certificate v1 for sealed sender (R4-C3)** — sealed-sender envelopes can carry a server-signed sender certificate (v1) with a per-recipient sender binding signature; verified fail-closed when a server signing key is pinned (R4-C3). (`198e435`)
- **SealedSenderTrustPolicy (R4-C3)** — verified-first-contact and require-certified switches; peer signing-key pin; typed rejections and security events (R4-C3). Default `SealedSenderTrustPolicy.legacy` keeps accept-both behaviour; the policy applies to the sealed and the direct lane. (`198e435`)
- **Certified sealed sends + `peekSealedSender` (R4-C3)** — Manager accepts an issued sender certificate on sealed sends (`encryptSealedSender`/`encryptSealedSenderFull`/`prepareSealedSend`, optional `senderCertificate:`) and exposes `peekSealedSender` for host-side first-contact verification (R4-C3). A certificate that does not name this device's ids and keys, or is not usable now, throws `StateError('Sender certificate does not describe this device')` before any ratchet or journal mutation — hosts renew on that error. Sends without a certificate are unchanged. (`198e435`)
- **`senderCertificateProvider` + `requireCertifiedSend` (R4-C3)** — `SignalProtocolManager(senderCertificateProvider: ...)` supplies the device certificate for every sealed send that is not given one explicitly (explicit `senderCertificate:` still wins). The provider runs before the send lock and any ratchet/journal mutation; `null` or a throw (event `senderCertificateProviderFailed`, sanitized) means a legacy uncertified send unless `SealedSenderTrustPolicy.requireCertifiedSend` is set, which throws `SenderCertificateRequiredError` before any mutation (also when no provider is configured). New getters `hasSenderCertificateProvider`, `sealedSenderTrustPolicy` (R4-C3). (`198e435`)
- **Real zeroing of package-owned DH/HKDF outputs (R4-M1)** — DH/HKDF outputs are now copied into package-owned buffers (`SecureMemory.ownedCopy`) and really zeroed; previously `zeroBytes` on `cryptography` `extractBytes()` output silently did nothing. `SecureMemory.zeroBytes` / `zeroUint8List` now return whether they could zero; removed the no-op native wipe of a freshly allocated buffer. Memory-safety claims corrected: the `cryptography`/`pqcrypto` internal copies, GC copies and `String` keys are not wiped (R4-M1). (`198e435`)
- **Skipped message keys expire after 30 days (R4-L2)** — `RatchetState` gains `skippedKeyAges` (Unix ms per skipped key, local storage only; legacy state loads with every key stamped at load time, none dropped). `DoubleRatchet` stamps keys on store, drops the age on consume, and at the start of every decrypt (under the state lock) zeroes and removes keys older than `DoubleRatchet.skippedKeyTtl` (30 days, the relay's retention). The 2000-key cap is unchanged; no wire-format change. (`198e435`)
- **GroupRoster v1: signed, epoch-chained group membership (R4-H10)** — new `group_roster.dart`: byte-compatible port of the server parser (`GroupRoster.parse`, same check order and stable `GroupRosterError` codes, duplicate-key rejection, JS safe-integer number semantics), producer `GroupRoster.encode`, `rosterHashOf`, `verifySignature` (Ed25519 over `risaal-group-roster-v1\0 || roster bytes`, never throws); chain policy `GroupRosterChain.verifyNext` (genesis by creator, +1 with `prev` hash and previous-admin signer, `epoch_fork`/`rollback`/`prev_mismatch`, bootstrap/gap flags, host signer trust); distribution policy `GroupRosterPolicy.allowedRecipients` (relay can only shrink a verified roster) and `removedMembers`. Manager: `localGroupRosterSigner()`, `signGroupRoster()` (refuses rosters naming another signer). Shared Node↔Dart vector `test/fixtures/group_roster/v1_vectors.json` (R4-H10). (`198e435`)
- **Sender Certificate contract v2: per-recipient sender binding removed (R4-C3-V2)** — the v1 `senderSignature` (Ed25519 by the sender's long-term signing key over the certificate and the recipient's identity key) was a transferable, non-deniable proof of contact and is gone: a certified sealed payload now carries exactly `senderCertificate` + `serverSignature` (all-or-nothing), and a payload that still carries `senderSignature` is rejected as `malformed`. Removed `SenderCertificateVerifier.signSenderBinding`/`verifySenderBinding`, `SenderCertificateDomains.senderBinding`, `SenderCertificateFailure.badSenderBinding`; `SealedSenderEnvelope.seal` no longer takes `senderSigningPrivateKey` (**breaking** for direct callers); `verifyForEnvelope` drops `senderSignature`/`recipientIdentityKey`. Impersonation resistance still comes from cert identity == payload identity == inner identity key plus the deniable inner-message authentication. Certified receives **no longer seed the peer signing-key pin** (the certificate's signing key is only server-attested); the pin storage API and the pinned-key mismatch check stay for a future KT-backed source. Shared fixture regenerated without binding material (certificate bytes and server signatures unchanged). No v1 sender ever shipped (app attach flag off, endpoint undeployed). (`198e435`)
- **A session can no longer outlive the identity it was made with (R4-PKG-SESSION-PIN-CHECK)** — `RatchetState` records the remote identity key it was established with (`remoteIdentityKey`, local storage only, optional: older records load without it and are stamped with the current pin on first load). Every encrypt and decrypt of an established session (direct and sealed, legacy and prepared/WAL lanes, batch decrypt) compares it with the pinned identity and throws the new typed `SessionIdentityMismatchError` (`extends StateError`, `peerId` / `deviceId`, no key material) before any ratchet change. `acceptVerifiedPeerIdentity` first stamps such older records with the OLD pin (a record without any pin is removed), so an interrupted accept now leaves the old session refused on every path instead of only on sealed and PreKey receives. No wire-format change. (`198e435`, R4-PKG-SESSION-PIN-CHECK)

### Added

- New `SecurityEventType` values: `sealedNonceReplay`, `senderKeyEpochMismatch`, `keyBundleReplacementRejected`, `generationRetired` (from the commits above).
- ACVP ML-KEM-768 known-answer-test fixture and cross-device robustness tests. (`0a8fa22`, `4bf78cb`)
- Security assurance artifacts: `docs/SECURITY_GOALS.md`, `docs/PROTOCOL_COMPATIBILITY.md`, `docs/METADATA_PRIVACY_MODEL.md`
- Operational trust artifacts: `docs/BUG_BOUNTY.md`, `docs/ASSURANCE_SCORECARD.md`, `docs/TRANSPARENCY_REPORT_TEMPLATE.md`
- Third-party audit lifecycle hardening: report publication and re-audit trigger policy in `docs/AUDIT_SCOPE.md`
- `SignalProtocolManager.acceptVerifiedPeerIdentity(userId, deviceId, identityKey)`: after a contact's identity changes, pin exactly the key the user verified instead of trusting whatever the next handshake presents; the pin is written before the old sessions, pins and device list are removed, and invalid input throws `ArgumentError` with nothing changed. (`198e435`, R4-VERIFY-NEW-KEY-PKG)

### Changed

- Documentation index updates in `README.md` and `SECURITY.md` to surface assurance and transparency materials.

### Fixed

- DoubleRatchet.encrypt and decrypt now share one mutex; an encrypt racing a transactional decrypt could lose its chain advance (R4-M5). Test retries removed. (`198e435`)
- **Tampered direct messages now fail as `MessageAuthenticationError` and emit `messageAuthenticationRejected`.** The authentication handler on the direct receive path wrapped non-awaited futures, so an async MAC failure escaped as a raw `SecretBoxAuthenticationError` and the tamper event was never raised. (`198e435`, R4-PKG-AUTH-AWAIT)
- **Typed `NoSessionError`** (`extends StateError`, with `peerId` / `deviceId`; message text unchanged) is thrown wherever no session exists, so callers no longer parse error text. (`198e435`, R4-PKG-NOSESSION)

### Security: advisory RISAAL-CRYPTO-2026-001

> **Advisory: RISAAL-CRYPTO-2026-001** — Non-transactional decrypt and session deletion on MAC failure.
> A relay-position attacker who can flip one byte in transit could destroy an established session and,
> with three messages per hour, block automatic recovery for 24 hours.
> Reported privately through the disclosure program.
> All 0.1.0–0.3.0 users should upgrade immediately.

- **[BREAKING] Ratchet advancement is now atomic (transactional decrypt)** — `DoubleRatchet._decryptInner` previously advanced the anti-replay set, skipped-key map, receiving chain, and DH ratchet against live state before AES-256-GCM authentication. All ratchet advancement now runs against a deep-cloned candidate; the candidate is committed only after authentication succeeds. A rejected message leaves the session byte-identical to its pre-receive state.
- **[BREAKING] Message header bound as additional authenticated data (AAD)** — `version`, `dhPublicKey`, `messageNumber`, and `previousChainLength` are now bound into AES-GCM AAD. A relay can no longer modify these fields and have the GCM tag verify against a different ciphertext. This changes the wire format (wire version 2) and is not backward-compatible with 0.3.x sessions.
- **MAC failure no longer deletes the session** — previously, `_shouldTriggerReset` treated any `SecretBoxAuthenticationError` as grounds for `removeSession()`; with the three-per-hour limiter this wedged recovery for 24 hours and burned one-time pre-keys on each cycle. A failed MAC now raises the typed `MessageAuthenticationError` and the session is kept intact. The reset path and its rate limiter are removed.
- **Message key wiped on rejection path** — the message key is now zeroed from memory when authentication fails, closing the key-retention window on the common rejection path.
- **`onPreKeyReplenishmentNeeded` fires on actual OPK spend** — previously fired only on auto-reset (which is removed); now fires at the point where a one-time pre-key is actually consumed.

## [0.3.0] - 2026-04-18

### Security Fixes (from external security analysis)

- **[BREAKING] AES-256-CBC → AES-256-GCM** for Sender Key group encryption. Old CBC messages (v1) can still be decrypted for backward compatibility. New messages always use GCM (v2). Eliminates unauthenticated CBC and non-constant-time PKCS7 padding.
- **[BREAKING] `seenNonces` now required** in `SealedSenderEnvelope.unseal()`. Prevents nonce replay attacks. Callers must supply a persistent `Set<String>`.
- **[BREAKING] `RatchetState` keys migrated from `String` to `Uint8List`**. Enables genuine memory zeroing via `SecureMemory.zeroBytes()`. Stored sessions auto-migrate on first load.
- **[BREAKING] `CryptoSecureStorage` now requires `securityLevel` getter**. Implementations must declare `StorageSecurityLevel.hardwareBacked`, `.softwareEncrypted`, or `.insecure`.
- **Pinned `pqcrypto`** to exact version (pre-release, unaudited FFI binding).
- **First-session Kyber downgrade protection**: `requirePq` policy now blocks first-contact sessions without Kyber; `preferPq` emits `firstSessionNoPqxdh` warning.
- **Message number cap**: `messageNumber` and `previousChainLength` reject values > 100,000.

### Documentation

- Corrected deniability claims: group messages are non-deniable by design (Ed25519 signatures). 1-to-1 remains deniable.
- Updated crypto primitives: group encryption is AES-256-GCM (not CBC).

### Added

- `SecurityEventType.firstSessionNoPqxdh` event type
- `SecurityEventType.insecureStorageWarning` event type
- `StorageSecurityLevel` enum
- `CryptoStorage.saveSeenNonces()` / `loadSeenNonces()` for nonce persistence
- Negative test vectors (malformed keys, truncated ciphertext, invalid nonces)

## [0.2.1] - 2026-04-07

### Fixed
- [SECURITY] PQXDH anti-downgrade now **refuses** session establishment when a peer's bundle loses its Kyber key (previously only logged a warning). Prevents MITM from silently stripping the post-quantum layer. `PqxdhPolicy.classicalOnly` override preserved for explicit user confirmation.

### Added
- `PqxdhDowngradeError` exception for anti-downgrade enforcement
- 8 new tests: anti-downgrade blocking, override bypass, event emission, edge cases (392 total)
- Dependency patching policy (72h SLA) documented in `SECURITY.md`
- GPG-signed tag release procedure documented in `BRANCH_PROTECTION.md`

## [0.2.0] - 2026-04-07

### Added
- **CI: Per-file coverage enforcement** — 85% global threshold, 95% for critical crypto files (x3dh, double_ratchet, sender_key, sealed_sender), 90% for protocol orchestration files. Enforced via `scripts/check_coverage.sh`
- **CI: OSV-Scanner vulnerability scanning** — scans `pubspec.lock` against OSV database, blocks merge on unexcepted vulnerabilities
- **CI: Dependabot configuration** — weekly scans for both `pub` and `github-actions` ecosystems
- **CI: Known vulnerability exception file** — `security/known-vulns.yaml` with mandatory expiry dates (max 90 days), automated expiry enforcement in CI
- **CI: Semgrep SAST** — 9 custom crypto-focused rules (insecure RNG, MD5, SHA-1, ECB, CBC without auth, static IV, hardcoded secrets, print in production, unsafe deserialization) with SARIF upload to GitHub Security tab
- **CI: Signed release workflow** — `release.yml` with version verification, changelog extraction, source archives, SHA256SUMS checksums, GitHub Attestations build provenance, pub.dev publish
- **CI: CODEOWNERS** — all `lib/src/` crypto files require explicit review from @Dritonsallahu
- **Ops: SLO definitions** — 6 stability SLOs (decrypt failure < 0.1%, session reset < 0.5%, replay rejection < 0.01%, OTP exhaustion < 1%, X3DH success > 99.5%, Sender Key success > 99%) and 6 security SLOs (MAC failure < 0.01%, signature failure < 0.01%, PQ downgrade block 100%, replay rejection 100%, key cap enforcement 100%, key rotation compliance 100%)
- **Ops: Telemetry integration guide** — privacy-safe counter architecture, client collection, server aggregation, Prometheus-style alert rules, Grafana dashboard panels
- **Ops: Canary deployment strategy** — 4-stage rollout (1% internal → 5% beta → 25% progressive → 100%), statistical significance methodology, rollback triggers, version-specific requirements
- **Ops: 4 security runbooks** — `runbook-key-compromise.md`, `runbook-replay-spike.md`, `runbook-session-reset-storm.md`, `runbook-critical-dependency-cve.md` with triage checklists, containment actions, recovery steps, and communication templates
- **Ops: Incident drill procedures** — monthly tabletop exercises (12-scenario annual rotation), quarterly live simulations with event injection, annual full simulations with scoring criteria
- **Docs: Branch protection policy** — required CI checks, CODEOWNERS, signed commits, linear history, emergency bypass procedure

### Changed
- [SECURITY] CI coverage threshold raised from 80% to 85% global, with per-file enforcement
- CI pipeline expanded from 7 to 8 jobs (added Semgrep SAST)
- CI dependency audit now includes OSV-Scanner and known-vulns expiry enforcement

## [0.1.1] - 2026-04-07

### Added
- SecurityEventBus: stream-based pub/sub for 13 security event types
- Anti-replay state persistence: `receivedMessages` in RatchetState (cap 2000, persisted via JSON)
- Anti-downgrade enforcement: tracks peer PQXDH capability, detects classical-only regression
- Kyber key rotation: periodic ML-KEM-768 rotation (default 7 days)
- `rotateKyberKeyIfNeeded()` and `rotateKeysIfNeeded()` convenience methods
- OTP low-watermark raised to 25 with event bus emissions
- Production telemetry integration guide (`docs/OPERATIONAL_RUNBOOK.md`)
- Release signing controls and semver policy for crypto libraries
- Incident drill procedures (quarterly schedule with pass criteria)
- Memory safety model documentation (`docs/MEMORY_SAFETY.md`)

### Changed
- [SECURITY] Skipped message key cap raised from 100 to 2000 for realistic offline gaps
- [SECURITY] OTP exhaustion threshold raised from 10 to 25 (earlier warnings)
- CI pipeline: enforced 80% coverage threshold, SAST scan, dependency vulnerability audit, changelog gate

### Fixed
- [SECURITY] `SecretKey` by-reference corruption from `SecureMemory.zeroBytes()` — defensive `List<int>.from()` copies
- SECURITY.md: corrected skipped key cap documentation (was 100, now 2000)

## [0.1.0] - 2026-04-07

### Added
- X3DH key agreement with mandatory signed pre-key verification
- Double Ratchet with forward secrecy and post-compromise security
- Sealed Sender for metadata protection (sender anonymity)
- Sender Keys for efficient group E2EE with Ed25519 authentication
- PQXDH hybrid key agreement (X25519 + Kyber-768) with policy modes
- Safety Number generation (60-digit numeric fingerprint)
- Message padding (fixed bucket sizes for traffic analysis resistance)
- LSB steganography for covert communication
- Session auto-reset with rate limiting
- FFI-based secure memory zeroing (Android/iOS)
- 357+ tests covering protocol correctness, adversarial, fuzz, and memory hygiene scenarios

### Security
- Ed25519 asymmetric signatures for Sender Key authentication (prevents recipient forgery)
- Mandatory signed pre-key verification (no downgrade path)
- PQXDH policy enforcement (require_pq, prefer_pq, classical_only)
- Constant-time HMAC comparison for chain key operations
