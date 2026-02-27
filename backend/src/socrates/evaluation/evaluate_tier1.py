# backend/src/socrates/services/evaluate_tier1.py
#
# Evaluates Tier 1 detection against ground truth labels.
# Run from backend/ directory:
#   python -m socrates.services.evaluate_tier1
#
# NOTE: Prototype — evaluates at IP level only.
# Production would evaluate at individual log entry level
# and track metrics over time as thresholds are tuned.

import csv
from pathlib import Path
from collections import defaultdict

from socrates.services.parser import parse_log_file
from socrates.services.tier1_rules import run_tier1, ZSCORE_THRESHOLD, INTERVAL_MAX_AVG_S, INTERVAL_MAX_JITTER_S, IQR_MAX

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT     = Path(__file__).parents[4]
LOG_FILE         = PROJECT_ROOT / "data" / "synthetic_logs.csv"
GROUND_TRUTH     = PROJECT_ROOT / "data" / "ground_truth.csv"


# ---------------------------------------------------------------------------
# Load ground truth
# ---------------------------------------------------------------------------

def load_ground_truth(filepath: Path) -> dict:
    """
    Returns a dict of src_ip → anomaly_type for all beaconing entries.
    We evaluate at IP level — if the IP is flagged that counts as a hit.
    """
    beaconing_ips = set()
    all_anomaly_types = defaultdict(set)

    with open(filepath) as f:
        for row in csv.DictReader(f):
            all_anomaly_types[row["anomaly_type"]].add(row["src_ip"])
            if row["anomaly_type"].startswith("beaconing"):
                beaconing_ips.add(row["src_ip"])

    print(f"[eval] Ground truth anomaly types found:")
    for atype, ips in all_anomaly_types.items():
        print(f"  {atype:<25} {len(ips)} unique IPs")

    return beaconing_ips


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(
    flagged_ips:      set,
    ground_truth_ips: set,
) -> dict:
    tp = len(flagged_ips & ground_truth_ips)
    fp = len(flagged_ips - ground_truth_ips)
    fn = len(ground_truth_ips - flagged_ips)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )

    return {
        "tp":        tp,
        "fp":        fp,
        "fn":        fn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(
    metrics:          dict,
    flagged_ips:      set,
    ground_truth_ips: set,
    results:          list,
):
    print()
    print("=" * 50)
    print("  SOCrates — Tier 1 Evaluation Report")
    print("=" * 50)

    print(f"\n  Thresholds used:")
    print(f"    ZSCORE_THRESHOLD      : {ZSCORE_THRESHOLD}")
    print(f"    INTERVAL_MAX_AVG_S    : {INTERVAL_MAX_AVG_S}")
    print(f"    INTERVAL_MAX_JITTER_S : {INTERVAL_MAX_JITTER_S}")
    print(f"    IQR_MAX               : {IQR_MAX}")

    print(f"\n  Ground truth beaconing IPs : {ground_truth_ips}")
    print(f"  Tier 1 flagged IPs         : {flagged_ips}")

    print(f"\n  Results:")
    print(f"    True Positives  : {metrics['tp']}")
    print(f"    False Positives : {metrics['fp']}")
    print(f"    False Negatives : {metrics['fn']}")

    print(f"\n  Metrics:")
    print(f"    Precision : {metrics['precision']:.2%}")
    print(f"    Recall    : {metrics['recall']:.2%}")
    print(f"    F1 Score  : {metrics['f1']:.2%}")

    print(f"\n  Flagged detail:")
    for r in results:
        label = "✓ TP" if r.src_ip in ground_truth_ips else "✗ FP"
        print(f"    [{label}] {r.username:<30} {r.domain:<25} methods: {r.methods_fired}")

    # Missed beacons
    missed = ground_truth_ips - flagged_ips
    if missed:
        print(f"\n  Missed beacons (FN):")
        for ip in missed:
            print(f"    {ip}")
    else:
        print(f"\n  No missed beacons.")

    print("=" * 50)

    # Verdict
    f1 = metrics["f1"]
    if f1 == 1.0:
        verdict = "PERFECT — all beacons caught, no false positives"
    elif f1 >= 0.8:
        verdict = "GOOD — consider tuning thresholds to reduce FP/FN"
    elif f1 >= 0.5:
        verdict = "MODERATE — thresholds need adjustment"
    else:
        verdict = "POOR — significant tuning required"

    print(f"\n  Verdict: {verdict}")
    print("=" * 50 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n[eval] Loading ground truth...")
    ground_truth_ips = load_ground_truth(GROUND_TRUTH)

    print("\n[eval] Parsing logs and running Tier 1...")
    logs    = parse_log_file(str(LOG_FILE))
    results = run_tier1(logs)

    flagged_ips = set(r.src_ip for r in results)
    metrics     = compute_metrics(flagged_ips, ground_truth_ips)

    print_report(metrics, flagged_ips, ground_truth_ips, results)


if __name__ == "__main__":
    main()