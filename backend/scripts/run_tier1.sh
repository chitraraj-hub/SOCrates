#!/bin/bash
# Run Tier 1 detection and evaluation
# Usage: ./scripts/run_tier1.sh

set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate

echo ""
echo "════════════════════════════════════════"
echo "  SOCrates — Tier 1 Detection"
echo "════════════════════════════════════════"

python -c "
from socrates.services.parser import parse_log_file
from socrates.services.tier1_rules import run_tier1

logs    = parse_log_file('../data/synthetic_logs.csv')
results = run_tier1(logs)

print()
print(f'Results ({len(results)} flagged):')
print()
for r in results:
    print(f'  Severity : {r.severity.upper()}')
    print(f'  IP       : {r.src_ip}')
    print(f'  Domain   : {r.domain}')
    print(f'  User     : {r.username}')
    print(f'  Methods  : {r.methods_fired}')
    print(f'  Requests : {r.request_count}')
    print(f'  Evidence : {r.evidence}')
    print()
    for d in r.descriptions:
        print(f'    → {d}')
    print()
    print('  ' + '-'*50)
    print()
"

echo ""
echo "════════════════════════════════════════"
echo "  SOCrates — Tier 1 Evaluation"
echo "════════════════════════════════════════"
python -m socrates.evaluation.evaluate_tier1
