### Measuring Success Metrics in Production

These are the measurements needed to validate SOCrates against real SOC data.
Each requires instrumenting the pipeline with analyst feedback.

**MTTD (Mean Time to Detect)**
```
How to measure:
1. Record timestamp when attack actually started (from forensics / IR report)
2. Record timestamp when SOCrates first flagged the threat
3. MTTD = timestamp_flagged - timestamp_attack_started

Baseline: Compare against avg MTTD before SOCrates was deployed
Target:   Reduce MTTD by >50% vs manual triage baseline
```

**MTTR (Mean Time to Respond)**
```
How to measure:
1. Record timestamp when alert appeared in SOCrates queue
2. Record timestamp when analyst took containment action
3. MTTR = timestamp_action - timestamp_flagged

Baseline: Interview analysts — how long does triage take today?
Target:   <60 seconds per alert for Tier 1 triage decision
```

**Alert Fatigue Index (Precision in production)**
```
How to measure:
1. Add analyst feedback buttons to each alert (True Positive / False Positive)
2. Precision = analyst_confirmed_TP / total_alerts_shown
3. Track weekly — should improve as model is retrained on feedback

Baseline: Current false positive rate from existing SIEM rules
Target:   >80% precision on Tier 1, >60% on Tier 2
```

**Analyst Ramp Time**
```
How to measure:
1. Track time-to-first-correct-escalation for new analysts
2. Compare cohort using SOCrates vs cohort without
3. Survey analysts monthly on confidence level (1-5 scale)

Baseline: Manager estimate of current ramp time (typically 6-12 months)
Target:   Junior analyst triage confidence matches senior within 90 days
```

> **TODO:** Add analyst feedback endpoint to backend (`POST /analysis/{job_id}/feedback`)
> and build a metrics dashboard to track these values over time.

---