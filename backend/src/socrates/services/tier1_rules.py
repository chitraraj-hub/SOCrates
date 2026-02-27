# backend/src/socrates/services/tier1_rules.py
#
# NOTE: Prototype — three beaconing detection methods combined per
# (ip, domain) pair. Production would add configurable thresholds,
# domain whitelist, persistence to DB.

from dataclasses import dataclass, field
from collections import defaultdict
from typing import List, Dict
import numpy as np

from socrates.data_generator.normal_traffic import LogEntry

# Thresholds
ZSCORE_THRESHOLD      = 3.0
INTERVAL_MAX_AVG_S    = 360
INTERVAL_MAX_JITTER_S = 10
IQR_MAX               = 15
MIN_REQUESTS          = 10


@dataclass
class Tier1Result:
    src_ip:         str
    domain:         str
    username:       str
    methods_fired:  List[str]
    descriptions:   List[str]
    severity:       str
    request_count:  int
    evidence:       Dict
    sample_entry:   LogEntry


def run_tier1(logs: List[LogEntry]) -> List[Tier1Result]:
    """
    Run all three beaconing detection methods.
    Results are grouped per (ip, domain) pair — one result per pair
    with a list of which methods fired and their evidence combined.
    """

    # Single pass — build shared state
    counts     = defaultdict(int)
    timestamps = defaultdict(list)
    samples    = {}

    for entry in logs:
        domain = entry.url.split("/")[0]
        key    = (entry.src_ip, domain)
        counts[key] += 1
        timestamps[key].append(entry.timestamp)
        if key not in samples:
            samples[key] = entry

    print(f"[tier1] {len(counts):,} (ip, domain) pairs evaluated")

    # Precompute z-scores across all pairs
    keys    = list(counts.keys())
    values  = np.array([counts[k] for k in keys], dtype=float)
    mean    = float(np.mean(values))
    std     = float(np.std(values))
    zscores = (values - mean) / std if std > 0 else np.zeros(len(values))
    zscore_map = {k: float(zscores[i]) for i, k in enumerate(keys)}

    # Evaluate each pair across all three methods
    results: List[Tier1Result] = []

    for key in keys:
        ip, domain     = key
        count          = counts[key]
        ts_list        = sorted(timestamps[key])
        sample         = samples[key]
        methods_fired  = []
        descriptions   = []
        evidence       = {"request_count": count}

        # --- Method 1: Z-score ---
        z = zscore_map[key]
        if z >= ZSCORE_THRESHOLD:
            methods_fired.append("zscore")
            descriptions.append(
                f"Request count {count} is {z:.1f}σ above mean ({mean:.1f})"
            )
            evidence["zscore"]    = round(z, 2)
            evidence["pop_mean"]  = round(mean, 2)
            evidence["pop_std"]   = round(std, 2)

        # --- Method 2: Interval threshold ---
        if count >= MIN_REQUESTS:
            intervals    = np.diff([t.timestamp() for t in ts_list])
            avg_interval = float(np.mean(intervals))
            jitter       = float(np.std(intervals))
            evidence["avg_interval_s"] = round(avg_interval, 2)
            evidence["jitter_s"]       = round(jitter, 2)

            if avg_interval <= INTERVAL_MAX_AVG_S and jitter <= INTERVAL_MAX_JITTER_S:
                methods_fired.append("interval_threshold")
                descriptions.append(
                    f"Avg interval {avg_interval:.1f}s with jitter {jitter:.1f}s — too regular for human browsing"
                )

            # --- Method 3: IQR ---
            q1  = float(np.percentile(intervals, 25))
            q3  = float(np.percentile(intervals, 75))
            iqr = q3 - q1
            evidence["iqr_s"] = round(iqr, 2)
            evidence["q1_s"]  = round(q1, 2)
            evidence["q3_s"]  = round(q3, 2)

            if iqr <= IQR_MAX:
                methods_fired.append("iqr")
                descriptions.append(
                    f"Interval IQR {iqr:.1f}s (Q1={q1:.1f}s Q3={q3:.1f}s) — abnormally consistent timing"
                )

        if len(methods_fired) < 2:
            continue

        # Severity scales with how many methods fired
        severity = {1: "low", 2: "high", 3: "critical"}.get(len(methods_fired), "critical")

        results.append(Tier1Result(
            src_ip=        ip,
            domain=        domain,
            username=      sample.username,
            methods_fired= methods_fired,
            descriptions=  descriptions,
            severity=      severity,
            request_count= count,
            evidence=      evidence,
            sample_entry=  sample,
        ))

    results.sort(key=lambda r: len(r.methods_fired), reverse=True)

    print(f"[tier1] Flagged {len(results)} (ip, domain) pairs")
    for r in results:
        print(f"  [{r.severity:<8}] {r.src_ip} → {r.domain} | methods: {r.methods_fired}")

    return results