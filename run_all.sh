#!/usr/bin/env bash
# run pi on every case -> aggregate.
#   ./run_all.sh <run-name> [extra run_pi.py args...]
set -euo pipefail
cd "$(dirname "$0")"
RUN="${1:-glm53_$(date +%Y%m%d_%H%M)}"; shift || true
python3 run_pi.py --run-name "$RUN" "$@"
python3 aggregate.py "$RUN"
