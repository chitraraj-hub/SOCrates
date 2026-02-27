# backend/src/socrates/services/tier2_ml.py
#
# Loads trained Isolation Forest and scores all (ip, domain) pairs.
# Returns anomaly confidence scores for each flagged vector.
#
# NOTE: Prototype — scores all vectors independently.
# Production would: only score vectors flagged by Tier 1,
# version model loading, handle model drift detection.

import joblib
import numpy as np
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from socrates.ml.feature_engineering import (
    FeatureVector,
    extract_features,
    to_matrix,
    FEATURE_NAMES,
)
from socrates.data_generator.normal_traffic import LogEntry

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

MODEL_PATH  = Path(__file__).parents[1] / "ml" / "models" / "isolation_forest.pkl"
SCALER_PATH = Path(__file__).parents[1] / "ml" / "models" / "scaler.pkl"

# Confidence threshold — below this score we don't flag
CONFIDENCE_THRESHOLD = 0.70


# ---------------------------------------------------------------------------
# Tier2Result
# ---------------------------------------------------------------------------

@dataclass
class Tier2Result:
    src_ip:        str
    domain:        str
    username:      str
    confidence:    float        # 0.0 - 1.0, higher = more anomalous
    anomaly_score: float        # raw isolation forest score (negative)
    feature_vector: FeatureVector
    top_features:  List[str]    # which features drove the anomaly score
    description:   str
    sample_entry:  LogEntry


# ---------------------------------------------------------------------------
# Score normalization
# Isolation Forest returns negative scores — more negative = more anomalous
# We normalize to 0-1 where 1.0 = most anomalous
# ---------------------------------------------------------------------------

def normalize_scores(scores: np.ndarray) -> np.ndarray:
    """Normalize raw IF scores to [0, 1] confidence values."""
    # Scores are negative — flip so higher = more anomalous
    flipped = -scores
    min_s   = flipped.min()
    max_s   = flipped.max()
    if max_s == min_s:
        return np.zeros(len(scores))
    return (flipped - min_s) / (max_s - min_s)


# ---------------------------------------------------------------------------
# Feature importance — which features deviate most from normal
# ---------------------------------------------------------------------------

def get_top_features(
    vector:  FeatureVector,
    scaler,
    n: int = 3,
) -> List[str]:
    """
    Return the top N features that deviate most from the training mean.
    Used to explain why this vector was flagged.
    """
    raw = np.array([[
        vector.avg_interval_s,
        vector.cv,
        vector.bytes_sent_cv,
        vector.unique_paths_ratio,
        vector.night_ratio,
        vector.request_count,
    ]])
    scaled     = scaler.transform(raw)[0]
    deviations = np.abs(scaled)  # distance from mean (0 after scaling)
    top_idx    = np.argsort(deviations)[::-1][:n]
    return [FEATURE_NAMES[i] for i in top_idx]


# ---------------------------------------------------------------------------
# Main inference function
# ---------------------------------------------------------------------------

def run_tier2(
    logs:      List[LogEntry],
    skip_keys: set = None,    # (src_ip, domain) pairs already handled by Tier 1 at critical confidence
) -> List[Tier2Result]:
    """
    Extract features, score with Isolation Forest,
    return results above confidence threshold sorted by confidence.
    Skips pairs already flagged as critical by Tier 1 — no need to re-score.
    """

    # Load model and scaler
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. "
            f"Run: python -m socrates.ml.train"
        )

    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"[tier2] Model loaded from {MODEL_PATH}")

    # Extract features
    vectors = extract_features(logs)
    if not vectors:
        print("[tier2] No feature vectors extracted")
        return []

    # Filter out keys already handled by Tier 1 at critical confidence
    if skip_keys:
        before = len(vectors)
        vectors = [
            v for v in vectors
            if (v.src_ip, v.domain) not in skip_keys
        ]
        print(f"[tier2] Skipped {before - len(vectors)} pairs already flagged critical by Tier 1")

    if not vectors:
        print("[tier2] No vectors remaining after skip filter")
        return []

    # Build and scale feature matrix
    X        = to_matrix(vectors)
    X_scaled = scaler.transform(X)

    # Score
    raw_scores  = model.score_samples(X_scaled)
    confidences = normalize_scores(raw_scores)

    print(f"[tier2] Scored {len(vectors):,} feature vectors")
    print(f"[tier2] Score range: [{raw_scores.min():.3f}, {raw_scores.max():.3f}]")
    print(f"[tier2] Confidence range: [{confidences.min():.3f}, {confidences.max():.3f}]")

    # Build results above threshold
    results: List[Tier2Result] = []

    for i, vector in enumerate(vectors):
        confidence = float(confidences[i])
        if confidence < CONFIDENCE_THRESHOLD:
            continue

        top_feats = get_top_features(vector, scaler)

        feature_explanations = {
            "cv":                 f"request interval CV={vector.cv:.3f} (machines are unnaturally regular)",
            "avg_interval_s":     f"avg interval {vector.avg_interval_s:.1f}s (consistent periodic pattern)",
            "bytes_sent_cv":      f"payload size CV={vector.bytes_sent_cv:.3f} (identical payloads per request)",
            "unique_paths_ratio": f"path diversity={vector.unique_paths_ratio:.3f} (hitting same endpoint repeatedly)",
            "night_ratio":        f"night ratio={vector.night_ratio:.2f} ({'active 24/7' if vector.night_ratio > 0.3 else 'unusually low night activity'})",
            "request_count":      f"request count={vector.request_count} (unusually high volume)",
        }
        top_explanations = [
            feature_explanations[f] for f in top_feats
            if f in feature_explanations
        ]

        description = (
            f"{vector.src_ip} → {vector.domain} flagged with "
            f"{confidence*100:.1f}% confidence. "
            f"Top signals: {'; '.join(top_explanations)}"
        )

        results.append(Tier2Result(
            src_ip=         vector.src_ip,
            domain=         vector.domain,
            username=       vector.username,
            confidence=     round(confidence, 4),
            anomaly_score=  round(float(raw_scores[i]), 4),
            feature_vector= vector,
            top_features=   top_feats,
            description=    description,
            sample_entry=   vector.sample_entry,
        ))

    results.sort(key=lambda r: r.confidence, reverse=True)
    print(f"[tier2] Flagged {len(results)} vectors above threshold {CONFIDENCE_THRESHOLD}")
    return results