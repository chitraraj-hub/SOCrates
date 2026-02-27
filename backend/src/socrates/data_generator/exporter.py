# backend/src/socrates/data_generator/exporter.py

import os
import csv
from typing import List
from datetime import datetime
from socrates.data_generator.normal_traffic import LogEntry


# ZScaler-inspired column order
LOG_FIELDS = [
    "timestamp", "username", "department", "src_ip", "dst_ip",
    "protocol", "http_method", "url", "status_code",
    "bytes_sent", "bytes_received", "action", "url_category",
    "threat_category", "risk_score", "user_agent",
]

GROUND_TRUTH_FIELDS = [
    "timestamp", "username", "src_ip", "url",
    "is_anomaly", "anomaly_type", "anomaly_severity", "tier_detection",
]


def _ensure_dir(filepath: str):
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)


def export_logs(logs: List[LogEntry], config: dict):
    """Export all log entries to CSV — anomaly metadata stripped out."""
    filepath = config["output"]["log_file"]
    _ensure_dir(filepath)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        writer.writeheader()
        for entry in logs:
            writer.writerow({
                "timestamp":       entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "username":        entry.username,
                "department":      entry.department,
                "src_ip":          entry.src_ip,
                "dst_ip":          entry.dst_ip,
                "protocol":        entry.protocol,
                "http_method":     entry.http_method,
                "url":             entry.url,
                "status_code":     entry.status_code,
                "bytes_sent":      entry.bytes_sent,
                "bytes_received":  entry.bytes_received,
                "action":          entry.action,
                "url_category":    entry.url_category,
                "threat_category": entry.threat_category,
                "risk_score":      entry.risk_score,
                "user_agent":      entry.user_agent,
            })

    size_mb = os.path.getsize(filepath) / 1024 / 1024
    print(f"[exporter] Logs → {filepath} ({len(logs):,} rows, {size_mb:.1f} MB)")


def export_ground_truth(logs: List[LogEntry], config: dict):
    """Export only anomalous entries with labels — used for ML evaluation."""
    filepath = config["output"]["ground_truth_file"]
    _ensure_dir(filepath)

    anomalies = [l for l in logs if l.is_anomaly]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        for entry in anomalies:
            writer.writerow({
                "timestamp":       entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "username":        entry.username,
                "src_ip":          entry.src_ip,
                "url":             entry.url,
                "is_anomaly":      entry.is_anomaly,
                "anomaly_type":    entry.anomaly_type,
                "anomaly_severity": entry.anomaly_severity,
                "tier_detection":  entry.tier_detection,
            })

    print(f"[exporter] Ground truth → {filepath} ({len(anomalies):,} anomaly rows)")