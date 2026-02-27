cat > scripts/run_pipeline.sh << 'EOF'
#!/bin/bash
# Run full SOCrates pipeline end to end
# Usage: ./scripts/run_pipeline.sh [path/to/logfile.csv]

set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate

LOG_FILE="${1:-../data/synthetic_logs.csv}"

echo ""
echo "════════════════════════════════════════"
echo "  SOCrates — Full Pipeline"
echo "  File: $LOG_FILE"
echo "════════════════════════════════════════"

python -c "
from socrates.services.pipeline import run_pipeline

result = run_pipeline('$LOG_FILE')

print()
print('Pipeline Summary')
print('=' * 50)
print(f'  Total logs      : {result.total_logs:,}')
print(f'  Tier 1 flagged  : {result.tier1_flagged}')
print(f'  Tier 2 flagged  : {result.tier2_flagged}')
print(f'  Tier 3 explained: {result.tier3_explained}')
print(f'  Total time      : {result.total_time_ms:.0f}ms')
print('=' * 50)

print()
print('Alert Queue (ranked by confidence):')
print()

for a in result.anomalies:
    tier = 'T1+T2' if a.tier1_fired and a.tier2_fired else 'T1' if a.tier1_fired else 'T2 '
    print(f'  [{a.severity.upper():<8}] {tier}  {a.confidence:.0%}  {a.src_ip:<18} → {a.domain}')
    print(f'  {a.threat_summary}')
    print()
    print(f'  WHAT HAPPENED:')
    print(f'  {a.what_happened}')
    print()
    print(f'  WHY SUSPICIOUS:')
    print(f'  {a.why_suspicious}')
    print()
    print(f'  ACTION:')
    print(f'  {a.recommended_action}')
    print()
    print('  ' + '─'*60)
    print()
"
EOF

