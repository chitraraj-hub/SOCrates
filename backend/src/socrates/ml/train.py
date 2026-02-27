# backend/src/socrates/ml/train.py
#
# Trains an Isolation Forest on NORMAL traffic only.
# The model learns what "normal" looks like and scores
# anything that deviates as anomalous.
#
# Run from backend/:
#   python -m socrates.ml.train
#
# NOTE: Prototype — trains on full dataset minus known beacon domains.
# Production would: use a dedicated clean training window,
# retrain periodically as new normal traffic is observed,
# version and store models with metadata.

import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from socrates.services.parser import parse_log_file
from socrates.ml.feature_engineering import extract_features, to_matrix, FEATURE_NAMES

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parents[4]
LOG_FILE     = PROJECT_ROOT / "data" / "synthetic_logs.csv"
MODEL_DIR    = Path(__file__).parent / "models"
MODEL_PATH   = MODEL_DIR / "isolation_forest.pkl"
SCALER_PATH  = MODEL_DIR / "scaler.pkl"

# ---------------------------------------------------------------------------
# Known malicious domains — excluded from training
# We never want the model to learn beaconing as "normal"
# ---------------------------------------------------------------------------

KNOWN_BAD_DOMAINS = {
    "malware-c2.ru", "botnet-cmd.cn", "evil-update.net",
    "payload-drop.xyz", "c2-handler.io",
}

# ---------------------------------------------------------------------------
# Isolation Forest hyperparameters
# ---------------------------------------------------------------------------

CONTAMINATION = 0.01   # expected fraction of anomalies in training data
                        # low because we filtered known bad domains
N_ESTIMATORS  = 100    # number of trees
RANDOM_STATE  = 42


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train():
    print("\n[train] Starting Isolation Forest training...\n")

    # Step 1 — Load and parse logs
    logs = parse_log_file(str(LOG_FILE))

    # Step 2 — Extract features
    all_vectors = extract_features(logs)
    print(f"[train] Total feature vectors: {len(all_vectors):,}")

    # Step 3 — Filter out known bad domains for clean training
    train_vectors = [
        v for v in all_vectors
        if v.domain not in KNOWN_BAD_DOMAINS
    ]
    print(f"[train] Training vectors (bad domains removed): {len(train_vectors):,}")
    print(f"[train] Removed {len(all_vectors) - len(train_vectors)} known bad domain vectors")

    # Step 4 — Build feature matrix
    X_train = to_matrix(train_vectors)
    print(f"[train] Feature matrix shape: {X_train.shape}")
    print(f"[train] Features: {FEATURE_NAMES}")

    # Step 5 — Scale features
    # Important: Isolation Forest works better with scaled features
    # since avg_interval_s (300-2000) would dominate cv (0.01-6) otherwise
    scaler  = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    print(f"\n[train] Feature statistics after scaling:")
    for i, name in enumerate(FEATURE_NAMES):
        print(f"  {name:<25} mean={X_scaled[:,i].mean():.3f}  std={X_scaled[:,i].std():.3f}")

    # Step 6 — Train Isolation Forest
    print(f"\n[train] Training Isolation Forest...")
    print(f"  n_estimators  : {N_ESTIMATORS}")
    print(f"  contamination : {CONTAMINATION}")
    print(f"  random_state  : {RANDOM_STATE}")

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
    )
    model.fit(X_scaled)

    # Step 7 — Quick sanity check on training data
    train_preds  = model.predict(X_scaled)
    train_scores = model.score_samples(X_scaled)
    n_flagged    = int(np.sum(train_preds == -1))

    print(f"\n[train] Sanity check on training data:")
    print(f"  Flagged as anomaly : {n_flagged} / {len(train_vectors)} vectors ({n_flagged/len(train_vectors)*100:.1f}%)")
    print(f"  Score range        : [{train_scores.min():.3f}, {train_scores.max():.3f}]")

    # Step 8 — Save model and scaler
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\n[train] Model  saved → {MODEL_PATH}")
    print(f"[train] Scaler saved → {SCALER_PATH}")
    print(f"\n[train] Training complete.\n")


if __name__ == "__main__":
    train()