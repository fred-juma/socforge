#!/usr/bin/env bash
set -euo pipefail

echo "→ core /health"
curl -fsS localhost:8000/health | grep -q '"status":"ok"'

echo "→ postgres tables"
docker exec socforge-postgres psql -U socforge -d socforge -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" \
  | grep -q '^7$'

echo "→ tenant org_aa present"
docker exec socforge-postgres psql -U socforge -d socforge -tAc \
  "SELECT 1 FROM tenants WHERE id='org_aa';" | grep -q 1

echo "✅ day 2 stack OK"