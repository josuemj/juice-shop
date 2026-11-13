#!/usr/bin/env bash
# V-06 · Fuerza bruta sin rate-limit en el login (routes/login.ts): N intentos desde la misma IP, ningún 429
set -uo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="${EVID:-$HERE/../../evidencias/h2-V-06-brute-force-login}"; mkdir -p "$EVID"
N="${N:-30}"; TARGET="${TARGET:-admin@juice-sh.op}"
echo "[$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')] V-06 brute force ($N intentos) -> $BASE_URL"
: > "$EVID/codigos.txt"
for i in $(seq 1 "$N"); do
  c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$TARGET\",\"password\":\"wrong$i\"}")
  echo "$i $c" >> "$EVID/codigos.txt"
done
R429=$(awk '$2==429' "$EVID/codigos.txt" | wc -l | tr -d ' ')
R401=$(awk '$2==401' "$EVID/codigos.txt" | wc -l | tr -d ' ')
echo "intentos=$N  401=$R401  429=$R429"
echo "401=$R401 429=$R429 de $N" > "$EVID/resumen.txt"
[ "$R429" -eq 0 ] && echo "VULN CONFIRMADA (V-06): $N intentos fallidos desde la misma IP, 0 respuestas 429 (sin rate-limit)"
