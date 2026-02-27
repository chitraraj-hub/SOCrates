# backend/src/socrates/data_generator/generate.py

import yaml
import os
from pathlib import Path
from collections import Counter

from socrates.data_generator.company_profile import build_company
from socrates.data_generator.normal_traffic import generate_traffic
from socrates.data_generator.anomaly_injector import inject_anomalies
from socrates.data_generator.exporter import export_logs, export_ground_truth


def load_config() -> dict:
    config_path = Path(__file__).parent / "config.yaml"
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    # Resolve output paths relative to project root (SOCrates/)
    project_root = Path(__file__).parents[4]
    config["output"]["log_file"] = str(
        project_root / config["output"]["log_file"]
    )
    config["output"]["ground_truth_file"] = str(
        project_root / config["output"]["ground_truth_file"]
    )
    return config

def print_summary(logs):
    total = len(logs)
    anomalies = [l for l in logs if l.is_anomaly]
    normal = total - len(anomalies)

    print("\n" + "=" * 50)
    print("  SOCrates — Data Generation Summary")
    print("=" * 50)
    print(f"  Total log entries   : {total:,}")
    print(f"  Normal entries      : {normal:,} ({normal/total*100:.1f}%)")
    print(f"  Anomalous entries   : {len(anomalies):,} ({len(anomalies)/total*100:.1f}%)")
    print()
    print("  Anomaly breakdown:")
    for anomaly_type, count in Counter(l.anomaly_type for l in anomalies).items():
        print(f"    {anomaly_type:<25} {count:>6} entries")
    print()
    print("  Severity breakdown:")
    for severity, count in Counter(l.anomaly_severity for l in anomalies).items():
        if severity:
            print(f"    {severity:<25} {count:>6} entries")
    print("=" * 50 + "\n")


def main():
    print("\n[SOCrates] Starting data generation...\n")

    config  = load_config()
    seed    = config.get("seed", 42)

    users   = build_company(config, seed=seed)
    print(f"[SOCrates] Built company: {len(users)} users\n")

    logs    = generate_traffic(users, config, seed=seed)
    logs    = inject_anomalies(logs, users, config, seed=seed)

    export_logs(logs, config)
    export_ground_truth(logs, config)

    print_summary(logs)
    print("[SOCrates] Data generation complete.")


if __name__ == "__main__":
    main()