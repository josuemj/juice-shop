#!/usr/bin/env bash
# Verifica que el entorno Blue Team funciona de punta a punta.
# Uso (desde entorno-blue-team/):  ./verificar.sh
# En Windows: correrlo desde Git Bash o WSL.

set -u
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "Falta .env. Copiar .env.example como .env y cambiar las contrasenas."
  exit 1
fi
set -a; . ./.env; set +a

WAF="http://localhost:8080"
ES="http://localhost:9200"
KIBANA="http://localhost:5601"
MARCA="blue-team-verificacion-$(date +%s)"
fallos=0

ok()   { echo "  [OK]    $1"; }
fail() { echo "  [FALLA] $1"; fallos=$((fallos+1)); }

echo "1. Juice Shop responde a traves del WAF ($WAF)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$WAF/")
[ "$code" = "200" ] && ok "HTTP $code" || fail "HTTP $code (esperado 200)"

echo "2. Juice Shop NO es accesible directamente en :3000 (todo pasa por el WAF)"
if curl -s -o /dev/null -m 3 "http://localhost:3000/"; then
  fail "localhost:3000 responde: hay otra instancia de Juice Shop corriendo fuera del WAF"
else
  ok "localhost:3000 no responde"
fi

echo "3. Peticion de prueba con SQLi (modo del WAF: ${MODSEC_RULE_ENGINE:-DetectionOnly})"
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$MARCA" \
  "$WAF/rest/products/search?q=%27%20OR%201%3D1--")
if [ "${MODSEC_RULE_ENGINE:-DetectionOnly}" = "On" ]; then
  [ "$code" = "403" ] && ok "bloqueada con HTTP 403" || fail "HTTP $code (en modo On se esperaba 403)"
else
  [ "$code" != "403" ] && ok "dejada pasar (HTTP $code), como corresponde a DetectionOnly" \
                       || fail "HTTP 403 en DetectionOnly: revisar MODSEC_RULE_ENGINE"
fi

echo "4. El evento llega a Elasticsearch (puede tardar unos segundos)"
encontrado=0
for _ in $(seq 1 12); do
  n=$(curl -s -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' \
      "$ES/filebeat-*/_count" \
      -d "{\"query\":{\"term\":{\"user_agent.original\":\"$MARCA\"}}}" \
      | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
  if [ "${n:-0}" -gt 0 ]; then encontrado=1; break; fi
  sleep 5
done
[ $encontrado = 1 ] && ok "evento encontrado en filebeat-* (user_agent = $MARCA)" \
                    || fail "no aparecio en 60 s. Revisar: docker compose logs filebeat waf"

echo "5. Kibana responde ($KIBANA)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$KIBANA/api/status")
case "$code" in
  200|401) ok "HTTP $code" ;;
  *) fail "HTTP $code (si acaba de arrancar, esperar 1-2 minutos)" ;;
esac

echo
if [ $fallos = 0 ]; then
  echo "Entorno OK. Juice Shop: $WAF   Kibana: $KIBANA (usuario elastic)"
else
  echo "$fallos verificacion(es) fallaron."
  exit 1
fi