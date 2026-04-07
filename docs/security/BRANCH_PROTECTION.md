# Branch Protection Policy — risaal_crypto

This document defines the required branch protection rules for the `main` branch. These rules are enforced via GitHub repository settings.

---

## Required Branch Protection Rules

### 1. Status Checks

All of the following CI jobs MUST pass before a PR can be merged to `main`:

| CI Job | What It Enforces |
|--------|-----------------|
| Static Analysis | `flutter analyze --fatal-warnings` — zero warnings |
| Format Check | All files formatted with `dart format` |
| Tests + Coverage Enforcement | All tests pass, 85% global coverage, 95% critical file coverage |
| Adversarial & Fuzz Tests | Adversarial, fuzz, memory hygiene, and test vector suites pass |
| Dependency Vulnerability Scan | OSV-Scanner clean, no expired exceptions, no git deps |
| Security Static Analysis (SAST) | No hardcoded secrets, no unsafe crypto patterns |
| Semgrep SAST | No Semgrep rule violations in lib/ |
| Changelog Updated | CHANGELOG.md updated in every PR |

**Configuration:** Repository Settings → Branches → Branch protection rules → `main`
- Require status checks to pass before merging: **Yes**
- Require branches to be up to date before merging: **Yes**
- Status checks that are required: All jobs listed above

### 2. Code Review Requirements

| Path Pattern | Minimum Reviewers | Rationale |
|-------------|-------------------|-----------|
| `lib/src/x3dh.dart` | 1 | Core key agreement — errors break all sessions |
| `lib/src/double_ratchet.dart` | 1 | Core ratchet — errors break forward secrecy |
| `lib/src/sender_key.dart` | 1 | Group encryption — errors break group E2EE |
| `lib/src/sealed_sender.dart` | 1 | Metadata protection — errors expose sender identity |
| `lib/src/signal_protocol_manager.dart` | 1 | Protocol orchestrator — errors break all messaging |
| `lib/src/secure_memory.dart` | 1 | Memory safety — errors leave keys in RAM |
| `lib/src/key_helper.dart` | 1 | Key generation — errors produce weak keys |
| All other `lib/src/*.dart` | 1 | Standard review |
| `test/**` | 1 | Standard review |
| `.github/workflows/**` | 1 | CI changes need review |
| `scripts/**` | 1 | Build scripts need review |

**Configuration:** Repository Settings → Branches → Branch protection rules → `main`
- Require a pull request before merging: **Yes**
- Required number of approvals: **1** (minimum)
- Dismiss stale pull request approvals when new commits are pushed: **Yes**

**CODEOWNERS file** (`.github/CODEOWNERS`):
```
# Default owner
* @Dritonsallahu

# Critical crypto files — require explicit review
lib/src/x3dh.dart @Dritonsallahu
lib/src/double_ratchet.dart @Dritonsallahu
lib/src/sender_key.dart @Dritonsallahu
lib/src/sealed_sender.dart @Dritonsallahu
lib/src/signal_protocol_manager.dart @Dritonsallahu
lib/src/secure_memory.dart @Dritonsallahu
lib/src/key_helper.dart @Dritonsallahu
```

### 3. Direct Push Protection

- **Do not allow bypassing the above settings:** Yes
- **Restrict who can push to matching branches:** Only repository administrators
- **Allow force pushes:** **No** (never)
- **Allow deletions:** **No** (never)

### 4. Signed Commits

- **Require signed commits:** Recommended but not enforced (GPG signing requires local setup)
- **Require linear history:** **Yes** (no merge commits, rebase-only)

---

## Setup Instructions

### GitHub UI Configuration

1. Go to repository **Settings** → **Branches**
2. Click **Add branch protection rule**
3. Branch name pattern: `main`
4. Enable:
   - [x] Require a pull request before merging
     - [x] Required number of approvals: 1
     - [x] Dismiss stale pull request approvals when new commits are pushed
   - [x] Require status checks to pass before merging
     - [x] Require branches to be up to date before merging
     - Add all 8 CI jobs as required checks
   - [x] Require linear history
   - [x] Do not allow bypassing the above settings
   - [ ] Allow force pushes (UNCHECKED)
   - [ ] Allow deletions (UNCHECKED)
5. Click **Create**

### CODEOWNERS File

Create `.github/CODEOWNERS` with the content shown above. GitHub will automatically require review from the listed owners when those files are modified.

---

## Emergency Bypass

In the event of a critical security patch that cannot wait for CI:

1. A repository administrator may temporarily disable branch protection
2. Push the fix directly
3. **Immediately** re-enable branch protection
4. Open a follow-up PR with tests to validate the emergency fix
5. Document the bypass in `CHANGELOG.md` with `[EMERGENCY]` prefix

Emergency bypasses must be logged in the incident response tracker.
