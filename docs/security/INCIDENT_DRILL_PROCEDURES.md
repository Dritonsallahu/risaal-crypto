# Incident Drill Procedures — risaal_crypto

This document defines the schedule, format, and evaluation criteria for security incident drills. Regular drills ensure the team can respond effectively to real incidents.

---

## Drill Schedule

| Frequency | Type | Duration | Participants |
|-----------|------|----------|-------------|
| Monthly | Tabletop exercise | 1 hour | All team members |
| Quarterly | Live simulation | 2-4 hours | On-call engineers + security lead |
| Annually | Full incident simulation | Half day | All team members + stakeholders |

## Tabletop Exercises (Monthly)

### Format

1. **Facilitator** presents a scenario (see scenarios below)
2. Team walks through the response using the relevant runbook
3. Each step is discussed: who does what, in what order, with what tools
4. Identify gaps in runbooks, tooling, or knowledge
5. Document findings and action items

### Scenarios

Rotate through these scenarios over a 12-month cycle:

| Month | Scenario | Runbook |
|-------|----------|---------|
| 1 | Single session MAC failure spike | runbook-key-compromise.md |
| 2 | Replay attack from a single IP | runbook-replay-spike.md |
| 3 | 10% of sessions resetting after client update | runbook-session-reset-storm.md |
| 4 | Critical CVE in `cryptography` package | runbook-critical-dependency-cve.md |
| 5 | PQ downgrade attempt detected | runbook-key-compromise.md |
| 6 | Server delivering messages to wrong users | runbook-session-reset-storm.md |
| 7 | Pre-key exhaustion cascade | runbook-session-reset-storm.md |
| 8 | Sealed Sender replay from distributed sources | runbook-replay-spike.md |
| 9 | Key storage corruption after iOS update | runbook-session-reset-storm.md |
| 10 | Zero-day in `pqcrypto` FFI bindings | runbook-critical-dependency-cve.md |
| 11 | Mass re-registration after server outage | runbook-session-reset-storm.md |
| 12 | Coordinated attack: replay + MAC failures | runbook-key-compromise.md |

### Evaluation Criteria

| Criterion | Pass | Fail |
|-----------|------|------|
| Correct runbook identified within 5 minutes | The right runbook was opened | Wrong runbook or no runbook consulted |
| Triage completed within 15 minutes | All triage checklist items addressed | Triage items skipped or incomplete |
| Containment actions identified | Correct containment for the scenario | Wrong containment or no containment proposed |
| Communication template used | Incident communication drafted | No communication plan |
| Recovery steps defined | Clear recovery plan with verification | Vague or missing recovery plan |
| Time to theoretical resolution | < 4 hours for P1, < 1 hour for P0 | Exceeds target response time |

## Live Simulations (Quarterly)

### Format

1. **Facilitator** injects simulated events into a staging environment
2. Team responds as if it were a real incident
3. Clock runs — response time is measured
4. No advance notice of the specific scenario (team knows a drill is scheduled)
5. Full post-mortem after the drill

### Simulation Setup

#### Prerequisites
- Staging environment with telemetry enabled
- Simulated `SecurityEventBus` event injector
- Dashboard access for monitoring
- Communication channels (Slack/email) for incident coordination

#### Event Injection

```dart
/// Inject simulated security events for drill purposes
class DrillEventInjector {
  final SecurityEventBus _bus;

  DrillEventInjector(this._bus);

  /// Simulate a MAC failure spike
  void simulateMacFailureSpike({int count = 10, Duration interval = const Duration(seconds: 30)}) {
    for (var i = 0; i < count; i++) {
      Future.delayed(interval * i, () {
        _bus.emit(SecurityEvent(
          type: SecurityEventType.macVerificationFailed,
          timestamp: DateTime.now(),
          metadata: {'drill': true, 'simulated': true},
        ));
      });
    }
  }

  /// Simulate a replay spike
  void simulateReplaySpike({int count = 20}) {
    for (var i = 0; i < count; i++) {
      _bus.emit(SecurityEvent(
        type: SecurityEventType.replayDetected,
        timestamp: DateTime.now(),
        metadata: {'drill': true},
      ));
    }
  }

  /// Simulate session reset storm
  void simulateSessionResetStorm({int count = 50}) {
    for (var i = 0; i < count; i++) {
      _bus.emit(SecurityEvent(
        type: SecurityEventType.sessionReset,
        timestamp: DateTime.now(),
        metadata: {'drill': true},
      ));
    }
  }
}
```

### Quarterly Scenarios

| Quarter | Scenario | Complexity |
|---------|----------|------------|
| Q1 | MAC failure spike from single user | Medium — clear source, follow runbook |
| Q2 | Critical CVE in crypto dependency (simulated advisory) | High — assess, patch, deploy |
| Q3 | Session reset storm after simulated client update | High — diagnosis + containment |
| Q4 | Coordinated attack: replay + PQ downgrade + MAC failures | Very High — multi-runbook response |

### Pass Criteria

| Criterion | Target |
|-----------|--------|
| Detection time (from event injection to first acknowledgment) | < 15 minutes |
| Correct incident classification | Correct severity and category |
| Containment initiated | Within target response time for severity |
| Communication sent | Within 30 minutes of detection |
| Recovery plan defined | Within 1 hour |
| Root cause identified | Within 2 hours (for simulated scenarios) |
| Post-mortem completed | Within 48 hours of drill |

## Annual Full Simulation

### Format

The annual simulation tests the complete incident lifecycle:

1. **Detection:** Simulated events injected without advance notice
2. **Triage:** Team classifies and assigns severity
3. **Containment:** Real containment actions on staging environment
4. **Communication:** Full incident communication flow
5. **Recovery:** Restore normal operation
6. **Post-mortem:** Complete post-incident review
7. **Improvement:** Actionable improvements documented

### Evaluation

| Area | Weight | Scoring |
|------|--------|---------|
| Detection & Triage | 25% | Time, accuracy, completeness |
| Containment | 25% | Speed, correctness, minimal collateral |
| Communication | 20% | Timeliness, clarity, appropriate audience |
| Recovery | 20% | Completeness, verification, monitoring |
| Documentation | 10% | Post-mortem quality, action items |

**Overall score:** Each area scored 1-5. Minimum passing score: 3.5 average.

---

## Post-Drill Actions

After every drill (tabletop, live, or annual):

1. **Document findings**
   - What worked well?
   - What didn't work?
   - What was missing from the runbook?
   - What tools were needed but not available?

2. **Create action items**
   - Runbook updates (with specific sections to change)
   - Tooling improvements (with priority)
   - Training needs (with specific topics)

3. **Track completion**
   - All action items must be completed before the next drill
   - Unresolved items from previous drills are flagged

4. **Update this document**
   - Record drill date, scenario, and outcome
   - Track improvement trends over time

## Drill History

| Date | Type | Scenario | Result | Action Items |
|------|------|----------|--------|-------------|
| — | — | — | — | No drills conducted yet |

*This table is updated after each drill.*
