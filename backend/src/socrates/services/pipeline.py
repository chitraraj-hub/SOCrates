# backend/src/socrates/services/pipeline.py
#
# Orchestrates the full three-tier detection pipeline.
# Input:  path to uploaded log CSV
# Output: list of Tier3Results ranked by confidence
#
# NOTE: Prototype — runs tiers sequentially in-process.
# Production would: run async, persist results to PostgreSQL,
# track job status, handle timeouts per tier.

from dataclasses import dataclass
from typing import List
from pathlib import Path
import time

from socrates.services.parser       import parse_log_file
from socrates.services.tier1_rules  import run_tier1
from socrates.services.tier2_ml     import run_tier2
from socrates.services.tier3_agent  import run_tier3, Tier3Result


@dataclass
class PipelineResult:
    total_logs:      int
    parse_time_ms:   float
    tier1_flagged:   int
    tier2_flagged:   int
    tier3_explained: int
    total_time_ms:   float
    anomalies:       List[Tier3Result]


def run_pipeline(filepath: str) -> PipelineResult:
    """
    Run the full SOCrates detection pipeline on a log file.
    Returns a PipelineResult with all anomalies explained.
    """
    start = time.monotonic()
    print(f"\n[pipeline] Starting SOCrates pipeline on {Path(filepath).name}")
    print("[pipeline] " + "=" * 45)

    # --- Parse ---
    t0   = time.monotonic()
    logs = parse_log_file(filepath)
    parse_time_ms = (time.monotonic() - t0) * 1000
    print(f"[pipeline] Step 1 — Parsed {len(logs):,} log entries in {parse_time_ms:.0f}ms")

    # --- Tier 1 ---
    t0            = time.monotonic()
    tier1_results = run_tier1(logs)
    tier1_time_ms = (time.monotonic() - t0) * 1000
    print(f"[pipeline] Step 2 — Tier 1 flagged {len(tier1_results)} anomalies in {tier1_time_ms:.0f}ms")

    # --- Tier 2 ---
    t0            = time.monotonic()
    tier2_results = run_tier2(logs)
    tier2_time_ms = (time.monotonic() - t0) * 1000
    print(f"[pipeline] Step 3 — Tier 2 flagged {len(tier2_results)} anomalies in {tier2_time_ms:.0f}ms")

    # --- Tier 3 ---
    t0            = time.monotonic()
    tier3_results = run_tier3(tier1_results, tier2_results)
    tier3_time_ms = (time.monotonic() - t0) * 1000
    print(f"[pipeline] Step 4 — Tier 3 explained {len(tier3_results)} anomalies in {tier3_time_ms:.0f}ms")

    total_time_ms = (time.monotonic() - start) * 1000
    print(f"[pipeline] " + "=" * 45)
    print(f"[pipeline] Complete in {total_time_ms:.0f}ms\n")

    return PipelineResult(
        total_logs=      len(logs),
        parse_time_ms=   round(parse_time_ms, 2),
        tier1_flagged=   len(tier1_results),
        tier2_flagged=   len(tier2_results),
        tier3_explained= len(tier3_results),
        total_time_ms=   round(total_time_ms, 2),
        anomalies=       tier3_results,
    )