# backend/src/socrates/ml/feature_engineering.py
#
# Builds a feature vector per (src_ip, domain) pair from log entries.
# These features are used to train the Isolation Forest in train.py
# and for inference in tier2_ml.py.
#
# NOTE: Prototype — 6 features focused on beaconing detection.
# Production would add: user-level baseline features, geo features,
# content-based features, cross-session aggregations.

from dataclasses import dataclass
from collections import defaultdict
from typing import List, Tuple, Dict
import numpy as np

from socrates.data_generator.normal_traffic import LogEntry


# ---------------------------------------------------------------------------
# FeatureVector — one row in the feature matrix
# ---------------------------------------------------------------------------

@dataclass
class FeatureVector:
    # Identity — not used in ML, kept for traceability
    src_ip:   str
    domain:   str
    username: str

    # Features fed to Isolation Forest
    avg_interval_s:     float   # how often requests are made
    cv:                 float   # coefficient of variation = std/mean (regularity)
    bytes_sent_cv:      float   # payload size consistency
    unique_paths_ratio: float   # path diversity (machines hit same path)
    night_ratio:        float   # fraction of requests outside 8am-8pm
    request_count:      int     # total volume

    # Reference to first log entry for downstream context
    sample_entry: LogEntry


FEATURE_NAMES = [
    "avg_interval_s",
    "cv",
    "bytes_sent_cv",
    "unique_paths_ratio",
    "night_ratio",
    "request_count",
]


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(logs: List[LogEntry]) -> List[FeatureVector]:
    """
    Group logs by (src_ip, domain) and extract a feature vector per pair.
    Pairs with fewer than 5 requests are skipped — too little data to score.
    """

    # Group logs by (src_ip, domain)
    groups:  Dict[Tuple, List[LogEntry]] = defaultdict(list)
    samples: Dict[Tuple, LogEntry]       = {}

    for entry in logs:
        domain = entry.url.split("/")[0]
        key    = (entry.src_ip, domain)
        groups[key].append(entry)
        if key not in samples:
            samples[key] = entry

    feature_vectors: List[FeatureVector] = []

    for key, entries in groups.items():
        if len(entries) < 30:
            continue

        ip, domain = key
        entries.sort(key=lambda e: e.timestamp)

        # --- avg_interval_s and cv ---
        timestamps   = [e.timestamp.timestamp() for e in entries]
        intervals    = np.diff(timestamps)

        if len(intervals) == 0 or np.mean(intervals) == 0:
            continue

        avg_interval = float(np.mean(intervals))
        std_interval = float(np.std(intervals))
        cv           = std_interval / avg_interval   # near 0 = machine, near 1 = human

        # --- bytes_sent_cv ---
        bytes_sent       = np.array([e.bytes_sent for e in entries], dtype=float)
        mean_bytes       = float(np.mean(bytes_sent))
        bytes_sent_cv    = (
            float(np.std(bytes_sent)) / mean_bytes
            if mean_bytes > 0 else 0.0
        )

        # --- unique_paths_ratio ---
        paths               = [e.url.split("/", 1)[-1] for e in entries]
        unique_paths_ratio  = len(set(paths)) / len(paths)

        # --- night_ratio ---
        # Fraction of requests outside business hours (8am - 8pm)
        night_count  = sum(
            1 for e in entries
            if e.timestamp.hour < 8 or e.timestamp.hour >= 20
        )
        night_ratio  = night_count / len(entries)

        feature_vectors.append(FeatureVector(
            src_ip=             ip,
            domain=             domain,
            username=           samples[key].username,
            avg_interval_s=     round(avg_interval, 4),
            cv=                 round(cv, 4),
            bytes_sent_cv=      round(bytes_sent_cv, 4),
            unique_paths_ratio= round(unique_paths_ratio, 4),
            night_ratio=        round(night_ratio, 4),
            request_count=      len(entries),
            sample_entry=       samples[key],
        ))

    print(f"[feature_engineering] Extracted {len(feature_vectors):,} feature vectors")
    return feature_vectors


def to_matrix(vectors: List[FeatureVector]) -> np.ndarray:
    """
    Convert list of FeatureVectors to a numpy matrix for sklearn.
    Column order matches FEATURE_NAMES.
    """
    return np.array([
        [
            v.avg_interval_s,
            v.cv,
            v.bytes_sent_cv,
            v.unique_paths_ratio,
            v.night_ratio,
            v.request_count,
        ]
        for v in vectors
    ], dtype=float)