# backend/src/socrates/evaluation/evaluate_tier2.py
#
# Evaluates Tier 2 ML detection against ground truth labels.
# Also shows combined Tier 1 + Tier 2 pipeline metrics.
#
# Run from backend/:
#   python -m socrates.evaluation.evaluate_tier2
#
# NOTE: Prototype — evaluates at IP level only.
# Production would evaluate at log entry level and track
# metrics over time as the model is retrained on analyst feedback.

import csv
from pathlib import Path
from collections import defaultdict

from socrates.services.parser      import parse_log_file
from socrates.services.tier1_rules import run_tier1, ZSCORE_THRESHOLD, INTERVAL_MAX_AVG_S, INTERVAL_MAX_JITTER_S, IQR_MAX
from socrates.services.tier2_ml    import run_tier2, CONFIDENCE_THRESHOLD

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT  = Path(__file__).parents[4]
LOG_FILE      = PROJECT_ROOT / "data" / "synthetic_logs.csv"
GROUND_TRUTH  = PROJECT_ROOT / "data" / "ground_truth.csv"


# ---------------------------------------------------------------------------
# Load ground truth
# ---------------------------------------------------------------------------

def load_ground_truth(filepath: Path) -> set:
    beaconing_ips     = set()
    anomaly_breakdown = defaultdict(set)

    with open(filepath) as f:
        for row in csv.DictReader(f):
            anomaly_breakdown[row["anomaly_type"]].add(row["src_ip"])
            if row["anomaly_type"].startswith("beaconing"):
                beaconing_ips.add(row["src_ip"])

    print(f"[eval] Ground truth anomaly breakdown:")
    for atype, ips in anomaly_breakdown.items():
        print(f"  {atype:<30} {len(ips)} unique IPs: {ips}")

    return beaconing_ips


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(flagged: set, ground_truth: set) -> dict:
    tp = len(flagged & ground_truth)
    fp = len(flagged - ground_truth)
    fn = len(ground_truth - flagged)

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
    gt_ips:       set,
    tier1_ips:    set,
    tier2_ips:    set,
    combined_ips: set,
    tier2_results: list,
):
    t1_metrics = compute_metrics(tier1_ips,    gt_ips)
    t2_metrics = compute_metrics(tier2_ips,    gt_ips)
    co_metrics = compute_metrics(combined_ips, gt_ips)

    print()
    print("=" * 60)
    print("  SOCrates — Tier 2 Evaluation Report")
    print("=" * 60)

    print(f"\n  Configuration:")
    print(f"    CONFIDENCE_THRESHOLD  : {CONFIDENCE_THRESHOLD}")
    print(f"    ZSCORE_THRESHOLD      : {ZSCORE_THRESHOLD}")
    print(f"    INTERVAL_MAX_AVG_S    : {INTERVAL_MAX_AVG_S}")
    print(f"    INTERVAL_MAX_JITTER_S : {INTERVAL_MAX_JITTER_S}")
    print(f"    IQR_MAX               : {IQR_MAX}")

    print(f"\n  Ground truth IPs  : {gt_ips}")
    print(f"  Tier 1 flagged    : {tier1_ips}")
    print(f"  Tier 2 flagged    : {tier2_ips}")
    print(f"  Combined flagged  : {combined_ips}")

    # Per tier metrics table
    print(f"\n  {'':25} {'Tier 1':<12} {'Tier 2':<12} {'Combined':<12}")
    print(f"  {'-'*60}")
    print(f"  {'True Positives':<25} {t1_metrics['tp']:<12} {t2_metrics['tp']:<12} {co_metrics['tp']:<12}")
    print(f"  {'False Positives':<25} {t1_metrics['fp']:<12} {t2_metrics['fp']:<12} {co_metrics['fp']:<12}")
    print(f"  {'False Negatives':<25} {t1_metrics['fn']:<12} {t2_metrics['fn']:<12} {co_metrics['fn']:<12}")
    print(f"  {'Precision':<25} {t1_metrics['precision']:.2%}      {t2_metrics['precision']:.2%}      {co_metrics['precision']:.2%}")
    print(f"  {'Recall':<25} {t1_metrics['recall']:.2%}      {t2_metrics['recall']:.2%}      {co_metrics['recall']:.2%}")
    print(f"  {'F1 Score':<25} {t1_metrics['f1']:.2%}      {t2_metrics['f1']:.2%}      {co_metrics['f1']:.2%}")

    # What Tier 2 added over Tier 1
    tier2_new    = tier2_ips - tier1_ips
    tier2_new_tp = tier2_new & gt_ips
    tier2_new_fp = tier2_new - gt_ips

    print(f"\n  What Tier 2 added over Tier 1:")
    print(f"    New detections total : {len(tier2_new)}")
    print(f"    New true positives   : {len(tier2_new_tp)}  {tier2_new_tp}")
    print(f"    New false positives  : {len(tier2_new_fp)}  {tier2_new_fp}")

    # Per beacon breakdown
    print(f"\n  Per beacon:")
    for ip in gt_ips:
        t1 = "✓ Tier1" if ip in tier1_ips else "✗ Tier1"
        t2 = "✓ Tier2" if ip in tier2_ips else "✗ Tier2"
        print(f"    {ip:<20} {t1}  {t2}")

    # Tier 2 flagged detail
    print(f"\n  Tier 2 flagged detail (sorted by confidence):")
    for r in sorted(tier2_results, key=lambda x: x.confidence, reverse=True):
        label = "✓ TP" if r.src_ip in gt_ips else "✗ FP"
        print(
            f"    [{label}] {r.confidence:.0%}  "
            f"{r.username:<35} {r.domain:<25} "
            f"top: {r.top_features}"
        )

    # Verdict
    print(f"\n  Verdict:")
    if co_metrics["recall"] == 1.0 and co_metrics["fp"] == 0:
        print(f"    PERFECT — combined pipeline catches all beacons, zero false positives")
    elif co_metrics["recall"] == 1.0:
        print(f"    GOOD RECALL — all beacons caught. {co_metrics['fp']} FP(s) need threshold tuning.")
    elif t2_metrics["recall"] > t1_metrics["recall"]:
        print(f"    TIER 2 ADDS VALUE — recall improved from {t1_metrics['recall']:.0%} to {t2_metrics['recall']:.0%}")
    else:
        print(f"    NEEDS TUNING — Tier 2 not improving on Tier 1")

    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n[eval] Loading ground truth...")
    gt_ips = load_ground_truth(GROUND_TRUTH)

    print("\n[eval] Parsing logs and running pipeline...")
    logs          = parse_log_file(str(LOG_FILE))
    tier1_results = run_tier1(logs)
    tier2_results = run_tier2(logs)

    tier1_ips    = set(r.src_ip for r in tier1_results)
    tier2_ips    = set(r.src_ip for r in tier2_results)
    combined_ips = tier1_ips | tier2_ips

    print_report(gt_ips, tier1_ips, tier2_ips, combined_ips, tier2_results)


if __name__ == "__main__":
    main()