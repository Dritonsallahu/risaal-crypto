# Runbook: Critical Dependency CVE

**Severity:** P1 — High (P0 if actively exploited in the wild)
**Response time:** 4 hours to assess, 24 hours to patch or mitigate
**Owner:** Security lead + maintainer

---

## Detection Signals

| Signal | Source |
|--------|--------|
| Dependabot security alert | GitHub Security tab |
| OSV-Scanner CI failure | CI pipeline: `dependency-audit` job |
| Security advisory notification | pub.dev advisory, NVD, GitHub Advisory DB |
| Community report | GitHub issue, security mailing list |

## Triage Checklist

- [ ] **1. Identify the vulnerability**
  - CVE/GHSA/OSV identifier
  - Affected package and version range
  - CVSS score and attack vector
  - Is there a public exploit?

- [ ] **2. Assess impact on risaal_crypto**
  - Do we use the affected function/API?
  - Is the vulnerability reachable from our code paths?
  - What's the worst-case impact? (key exposure, data leak, DoS, RCE)

- [ ] **3. Check fix availability**
  - Is a patched version available?
  - Is the patch backward-compatible?
  - Are there known issues with the patch?

## Severity Classification

| CVSS | Exploitable in our context? | Classification |
|------|----------------------------|----------------|
| Critical (9.0-10.0) | Yes | P0 — Immediate |
| Critical (9.0-10.0) | No | P1 — Assess within 4h |
| High (7.0-8.9) | Yes | P1 — Patch within 24h |
| High (7.0-8.9) | No | P2 — Patch within 7 days |
| Medium (4.0-6.9) | Yes | P2 — Patch within 7 days |
| Medium (4.0-6.9) | No | P3 — Next release cycle |
| Low (0.1-3.9) | Any | P3 — Next release cycle |

### Special Rules for Crypto Dependencies

The following packages have elevated severity regardless of CVSS:

| Package | Policy |
|---------|--------|
| `cryptography` | Any vulnerability = P1 minimum. Provides X25519, Ed25519, AES-GCM, HKDF |
| `crypto` | Any vulnerability = P1 minimum. Provides SHA-256, SHA-512, HMAC |
| `pqcrypto` | Any vulnerability = P1 minimum. Provides Kyber-768 (ML-KEM) |

## Response Actions

### If Patch Available

1. **Update dependency**
   ```yaml
   # pubspec.yaml — update version constraint
   dependencies:
     cryptography: ^2.7.1  # Patched version
   ```

2. **Run full CI locally**
   ```bash
   flutter pub get
   flutter analyze --fatal-warnings
   flutter test --coverage
   flutter test test/adversarial_crypto_test.dart -r expanded
   flutter test test/fuzz_test.dart -r expanded
   flutter test test/memory_hygiene_test.dart -r expanded
   flutter test test/test_vectors_test.dart -r expanded
   bash scripts/check_coverage.sh coverage/lcov.info
   ```

3. **Verify no behavioral changes**
   - Run test vectors to confirm cryptographic output is unchanged
   - Run adversarial tests to confirm security properties hold
   - Run memory hygiene tests to confirm zeroing still works

4. **Release**
   - Bump patch version in `pubspec.yaml`
   - Update `CHANGELOG.md` with `[SECURITY]` prefix
   - Follow canary deployment (expedited for security fixes)
   - Tag and release

### If No Patch Available

1. **Assess workaround feasibility**
   - Can we avoid the affected code path?
   - Can we add a wrapper that sanitizes input?
   - Can we fork the dependency temporarily?

2. **If workaround exists:**
   - Implement and test the workaround
   - Add a comment: `// SECURITY WORKAROUND: [CVE-XXXX] — remove when [package] >= [version]`
   - Add to `security/known-vulns.yaml` with 30-day expiry
   - Monitor upstream for patch

3. **If no workaround:**
   - Evaluate alternative packages
   - If the vulnerability is critical and actively exploited, consider:
     - Disabling the affected feature
     - Forking the dependency and applying a fix
     - Coordinating with upstream maintainers

### If False Positive

1. Verify the vulnerability doesn't affect our usage
2. Document the reasoning in `security/known-vulns.yaml`:
   ```yaml
   exceptions:
     - id: "GHSA-xxxx-xxxx-xxxx"
       package: "example_package"
       reason: "Vulnerability is in HTTP client module; we only use the crypto module"
       expires: "2026-07-07"
       reviewer: "Dritonsallahu"
   ```
3. Exception expires in 90 days — re-review at expiry

## Communication

### Internal

```
Subject: [CVE-XXXX] [Package] vulnerability — Impact assessment

Vulnerability: [CVE ID] in [package] [version range]
CVSS: [score] ([severity])
Impact on risaal_crypto: [assessment]
Action: [patching / workaround / monitoring]
ETA: [timeline]
```

### External (if user-facing impact)

Follow coordinated disclosure process in `INCIDENT_RESPONSE.md`.

## Dependency Monitoring Configuration

### Dependabot (`.github/dependabot.yml`)

Configured for weekly checks of both `pub` and `github-actions` ecosystems. Security updates are auto-opened as PRs.

### OSV-Scanner (CI)

Runs on every push and PR. Scans `pubspec.lock` against the OSV database. Failures block merge.

### Manual Monitoring

| Source | Check Frequency |
|--------|----------------|
| [pub.dev advisories](https://pub.dev/advisories) | Weekly |
| [GitHub Advisory Database](https://github.com/advisories) | Weekly |
| [NVD](https://nvd.nist.gov/) | Weekly |
| `cryptography` package releases | Every release |
| `pqcrypto` package releases | Every release |

## Post-Incident

- [ ] Verify patched version is deployed to all stages
- [ ] Remove `known-vulns.yaml` exception if no longer needed
- [ ] Update dependency pinning strategy if needed
- [ ] Add specific test case if the vulnerability was in a code path we use
- [ ] Update this runbook with lessons learned
