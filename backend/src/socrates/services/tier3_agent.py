# backend/src/socrates/services/tier3_agent.py
#
# Generates plain-English SOC analyst explanations for flagged anomalies.
#
# AI USAGE NOTE: This module is designed to use the Anthropic Claude API
# to synthesize Tier 1 and Tier 2 evidence into analyst-friendly narratives.
# Currently using a rule-based mock for development — swap in real Claude
# call by setting ANTHROPIC_API_KEY and setting USE_MOCK = False.
#
# NOTE: Prototype — mock implementation for development.
# Production would: use Claude API, batch calls, stream responses,
# handle rate limiting, cache explanations.

import os
from dataclasses import dataclass
from typing import List, Optional

from socrates.services.tier1_rules import Tier1Result
from socrates.services.tier2_ml import Tier2Result

USE_MOCK = True   # Set False when ANTHROPIC_API_KEY is available


# ---------------------------------------------------------------------------
# Tier3Result
# ---------------------------------------------------------------------------

@dataclass
class Tier3Result:
    src_ip:             str
    domain:             str
    username:           str
    threat_summary:     str
    what_happened:      str
    why_suspicious:     str
    recommended_action: str
    confidence:         float
    severity:           str
    tier1_fired:        bool
    tier2_fired:        bool


# ---------------------------------------------------------------------------
# Mock explanation generator
# Builds realistic explanations from evidence without API call
# ---------------------------------------------------------------------------

def _mock_explanation(
    tier1: Optional[Tier1Result],
    tier2: Optional[Tier2Result],
) -> dict:
    src_ip   = (tier1 or tier2).src_ip
    domain   = (tier1 or tier2).domain
    username = (tier1 or tier2).username
    confidence = tier2.confidence if tier2 else 1.0
    count = (
        tier1.request_count if tier1
        else tier2.feature_vector.request_count
    )

    # Build what_happened from available evidence
    if tier1 and tier2:
        fv = tier2.feature_vector
        what_happened = (
            f"Host {src_ip} (user: {username}) made {count:,} requests "
            f"to {domain} over the observation window. "
            f"Requests occurred every {fv.avg_interval_s:.0f} seconds on average "
            f"with {fv.night_ratio*100:.0f}% of activity outside business hours. "
            f"The same endpoint was contacted repeatedly with nearly identical "
            f"{fv.bytes_sent_cv:.3f} payload variance."
        )
        why_suspicious = (
            f"The request interval coefficient of variation (CV={fv.cv:.3f}) "
            f"is near zero — human browsing typically has CV above 1.0. "
            f"This level of timing precision indicates automated software, "
            f"not human activity. Combined with {fv.night_ratio*100:.0f}% "
            f"off-hours activity and path diversity of only {fv.unique_paths_ratio:.4f}, "
            f"this pattern is consistent with C2 beaconing malware."
        )
    elif tier1 is not None:
        what_happened = (
            f"Host {src_ip} (user: {username}) made {count:,} requests "
            f"to {domain}. Rule-based detection fired on: "
            f"{', '.join(tier1.methods_fired)}."
        )
        why_suspicious = (
            f"Multiple detection rules fired simultaneously: "
            f"{'; '.join(tier1.descriptions[:2])}. "
            f"This volume and regularity is inconsistent with normal user behavior."
        )
    else:
        fv = tier2.feature_vector
        what_happened = (
            f"Host {src_ip} (user: {username}) made {count:,} requests "
            f"to {domain} with unusual statistical properties. "
            f"ML anomaly detection scored this {confidence:.0%} confidence."
        )
        why_suspicious = (
            f"Isolation Forest detected deviation from normal baseline. "
            f"Key signals: {', '.join(tier2.top_features)}. "
            f"Request timing CV={fv.cv:.3f} and path diversity "
            f"{fv.unique_paths_ratio:.4f} are atypical for legitimate traffic."
        )

    # Severity-based recommended action
    if confidence >= 0.9:
        action = (
            f"1. Immediately isolate host {src_ip} from the network. "
            f"2. Block domain {domain} at the firewall. "
            f"3. Suspend account {username} pending investigation. "
            f"4. Escalate to Tier 2 for forensic analysis."
        )
    elif confidence >= 0.7:
        action = (
            f"1. Block outbound traffic to {domain} at the proxy. "
            f"2. Review recent activity for {username} in the last 24 hours. "
            f"3. Run endpoint scan on {src_ip}. "
            f"4. Monitor for continued beaconing attempts."
        )
    else:
        action = (
            f"1. Add {domain} to watchlist for continued monitoring. "
            f"2. Review {username} recent activity for other anomalies. "
            f"3. Flag for Tier 2 review if pattern persists."
        )

    return {
        "threat_summary": (
            f"Suspected C2 beaconing from {src_ip} to {domain} "
            f"— {confidence:.0%} confidence"
        ),
        "what_happened":      what_happened,
        "why_suspicious":     why_suspicious,
        "recommended_action": action,
    }


# ---------------------------------------------------------------------------
# Real Claude explanation (stubbed — enable when API key available)
# ---------------------------------------------------------------------------

def _claude_explanation(
    tier1: Optional[Tier1Result],
    tier2: Optional[Tier2Result],
) -> dict:
    """
    Real Claude API call — uncomment and set USE_MOCK=False when ready.
    Requires: pip install anthropic and ANTHROPIC_API_KEY in .env
    """
    raise NotImplementedError(
        "Set USE_MOCK=False and provide ANTHROPIC_API_KEY to enable"
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_tier3(
    tier1_results: List[Tier1Result],
    tier2_results: List[Tier2Result],
) -> List[Tier3Result]:
    """
    Match Tier 1 and Tier 2 results by (src_ip, domain),
    generate explanation for each unique anomaly.
    """
    # Index by (src_ip, domain)
    tier1_map = {(r.src_ip, r.domain): r for r in tier1_results}
    tier2_map = {(r.src_ip, r.domain): r for r in tier2_results}

    all_keys = set(tier1_map.keys()) | set(tier2_map.keys())
    print(f"[tier3] Explaining {len(all_keys)} unique anomalies...")

    results: List[Tier3Result] = []

    for key in all_keys:
        t1 = tier1_map.get(key)
        t2 = tier2_map.get(key)

        src_ip     = (t1 or t2).src_ip
        domain     = (t1 or t2).domain
        username   = (t1 or t2).username
        confidence = t2.confidence if t2 else 1.0
        severity   = t1.severity if t1 else (
            "critical" if confidence >= 0.9 else
            "high"     if confidence >= 0.7 else "medium"
        )

        explain_fn = _mock_explanation if USE_MOCK else _claude_explanation

        try:
            explanation = explain_fn(t1, t2)
            results.append(Tier3Result(
                src_ip=             src_ip,
                domain=             domain,
                username=           username,
                threat_summary=     explanation["threat_summary"],
                what_happened=      explanation["what_happened"],
                why_suspicious=     explanation["why_suspicious"],
                recommended_action= explanation["recommended_action"],
                confidence=         confidence,
                severity=           severity,
                tier1_fired=        t1 is not None,
                tier2_fired=        t2 is not None,
            ))
            print(f"[tier3] ✓ {domain} — {explanation['threat_summary'][:70]}")

        except Exception as e:
            print(f"[tier3] ✗ Failed for {src_ip} → {domain}: {e}")

    results.sort(key=lambda r: r.confidence, reverse=True)
    print(f"[tier3] Explained {len(results)} anomalies")
    return results