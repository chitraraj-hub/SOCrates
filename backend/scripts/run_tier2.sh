cat > scripts/run_tier2.sh << 'EOF'
#!/bin/bash
# Run Tier 1 + Tier 2 detection and evaluation
# Usage: ./scripts/run_tier2.sh

set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate

echo ""
echo "════════════════════════════════════════"
echo "  SOCrates — Tier 2 Detection"
echo "════════════════════════════════════════"

python -c "
from socrates.services.parser import parse_log_file
from socrates.services.tier1_rules import run_tier1
from socrates.services.tier2_ml import run_tier2

logs = parse_log_file('../data/synthetic_logs.csv')

# Tier 1 first
tier1_results = run_tier1(logs)
tier1_critical_keys = {
    (r.src_ip, r.domain)
    for r in tier1_results
    if len(r.methods_fired) == 3
}

print(f'Tier 1 critical pairs (skipped in Tier 2): {len(tier1_critical_keys)}')
print()

# Tier 2 on remaining
tier2_results = run_tier2(logs, skip_keys=tier1_critical_keys)

print()
print(f'Tier 2 Results ({len(tier2_results)} flagged):')
print()
for r in tier2_results:
    fv = r.feature_vector
    print(f'  Confidence : {r.confidence:.0%}')
    print(f'  IP         : {r.src_ip}')
    print(f'  Domain     : {r.domain}')
    print(f'  User       : {r.username}')
    print(f'  Top signals: {r.top_features}')
    print(f'  cv         : {fv.cv}')
    print(f'  night_ratio: {fv.night_ratio}')
    print(f'  uniq_paths : {fv.unique_paths_ratio}')
    print(f'  requests   : {fv.request_count}')
    print()
    print('  ' + '-'*50)
    print()
"

echo ""
echo "════════════════════════════════════════"
echo "  SOCrates — Tier 2 Evaluation"
echo "════════════════════════════════════════"
python -m socrates.evaluation.evaluate_tier2
EOF

