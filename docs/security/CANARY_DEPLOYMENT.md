# Canary Deployment Strategy — risaal_crypto

This document defines the canary deployment process for releasing new versions of the cryptographic library. Canary deployments reduce blast radius by gradually rolling out changes while monitoring for regressions.

---

## Overview

Every non-patch release of `risaal_crypto` follows a canary deployment process before full rollout:

```
v0.2.0 tagged
    │
    ▼
┌──────────────┐
│ Stage 1:     │ 1% of sessions (internal testers)
│ Internal     │ Duration: 24 hours
│ Canary       │ Monitoring: All SLOs
└──────┬───────┘
       │ Pass?
       ▼
┌──────────────┐
│ Stage 2:     │ 5% of sessions (opt-in beta users)
│ Beta         │ Duration: 48 hours
│ Canary       │ Monitoring: All SLOs
└──────┬───────┘
       │ Pass?
       ▼
┌──────────────┐
│ Stage 3:     │ 25% of sessions
│ Progressive  │ Duration: 24 hours
│ Rollout      │ Monitoring: All SLOs
└──────┬───────┘
       │ Pass?
       ▼
┌──────────────┐
│ Stage 4:     │ 100% of sessions
│ Full         │ Duration: Ongoing
│ Rollout      │ Monitoring: SLO dashboard
└──────────────┘
```

## Stage Definitions

### Stage 1: Internal Canary (24 hours)

**Target:** 1% of sessions — internal team devices only

**Entry criteria:**
- All CI gates pass (analyze, format, test, adversarial, SAST, dependency audit, Semgrep)
- Coverage thresholds met (85% global, 95% critical)
- Release signed with attestation
- CHANGELOG updated

**Monitoring:**
- All SLO metrics compared to 7-day baseline
- Manual testing of critical flows: 1:1 chat, group chat, session recovery, key rotation

**Exit criteria:**
- Zero P0/P1 alerts for 24 hours
- All SLOs within baseline (no metric > 10% worse)
- No crash reports related to crypto operations
- Manual test checklist completed

**Rollback trigger:** Any P0 alert or SLO breach

### Stage 2: Beta Canary (48 hours)

**Target:** 5% of sessions — opt-in beta users

**Entry criteria:**
- Stage 1 passed
- No regression bugs reported

**Monitoring:**
- Automated SLO dashboard with canary vs stable comparison
- Client error rate tracking (segmented by version)
- Session establishment success rate

**Exit criteria:**
- Zero P0/P1 alerts for 48 hours
- All SLOs within 5% of stable baseline
- Beta user feedback reviewed (no negative reports)

**Rollback trigger:** Any P0 alert, any SLO > 10% worse than stable, or 3+ user reports of crypto issues

### Stage 3: Progressive Rollout (24 hours)

**Target:** 25% of sessions

**Entry criteria:**
- Stage 2 passed
- 72 hours total canary time elapsed

**Monitoring:**
- Same as Stage 2, with higher traffic providing more statistical confidence

**Exit criteria:**
- All SLOs within 2% of stable baseline
- No anomalies in security event stream

**Rollback trigger:** Any SLO breach or security anomaly

### Stage 4: Full Rollout

**Target:** 100% of sessions

**Entry criteria:**
- Stage 3 passed
- Total canary period: minimum 96 hours (4 days)

**Monitoring:**
- Standard SLO dashboard (ongoing)
- 30/60/90 day trend analysis begins

---

## Canary Comparison Methodology

### Statistical Significance

To avoid false positives from low-traffic canary groups:

| Metric | Minimum sample size for comparison |
|--------|------------------------------------|
| Decrypt failure rate | 10,000 decrypt operations |
| Session reset rate | 1,000 active sessions |
| Replay rejection rate | 10,000 inbound messages |

If the canary group hasn't reached minimum sample size, extend the stage duration.

### Comparison Formula

```
degradation = (canary_rate - stable_rate) / stable_rate × 100%
```

| Degradation | Action |
|------------|--------|
| < 5% | Pass — within normal variance |
| 5-10% | Warning — extend stage by 24h, investigate |
| > 10% | Fail — rollback immediately |

### Baseline Computation

The "stable baseline" is the 7-day rolling average of each SLO metric from the current production version. Baselines are recomputed daily.

---

## Rollback Procedure

### Automatic Rollback Triggers

The following conditions trigger automatic rollback:

1. **P0 security alert:** MAC failure spike, PQ downgrade unblocked, sealed sender replay accepted
2. **Crash rate > 0.1%** in canary group (any crash in crypto code path)
3. **Decrypt failure rate > 0.5%** (5x the SLO target)

### Manual Rollback Steps

1. **Client-side:** Push config update to disable canary flag → clients fall back to stable version
2. **Verify:** Check that canary sessions re-establish with stable version
3. **Investigate:** Collect telemetry from canary period for root cause analysis
4. **Report:** File incident report with findings

### Post-Rollback

1. Root cause analysis within 48 hours
2. Fix validated with additional test coverage
3. New canary cycle starts from Stage 1

---

## Version-Specific Canary Requirements

| Change Type | Minimum Canary Duration | Stages Required |
|------------|------------------------|-----------------|
| Patch (bug fix, no protocol change) | 24 hours | Stage 1 only |
| Minor (new feature, backward compatible) | 96 hours | All 4 stages |
| Major (protocol change, breaking) | 168 hours (7 days) | All 4 stages + extended Stage 2 |
| Security fix (critical) | 4 hours | Stage 1 (expedited) |

---

## 30/60/90 Day Trend Dashboard

After full rollout, monitor long-term trends:

| Window | What to Watch |
|--------|---------------|
| 30 days | Short-term stability — are SLOs holding? |
| 60 days | Medium-term — any gradual degradation? |
| 90 days | Long-term — seasonal patterns, growth impact? |

**Dashboard panels:**
- Rolling average for each SLO metric
- Version-segmented view (if multiple versions in production)
- Anomaly detection band (2σ from rolling mean)
- Comparison to previous release cycle

**Review cadence:** Monthly SLO review meeting examines 30/60/90 day trends and adjusts thresholds if the baseline has shifted.
