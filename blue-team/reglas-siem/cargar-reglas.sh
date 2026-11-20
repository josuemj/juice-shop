#!/usr/bin/env bash
# Carga (o actualiza) en Kibana las reglas de detección del H3.
# Uso (desde la raíz del repo, con el entorno levantado):
#   ./blue-team/reglas-siem/cargar-reglas.sh
# En Windows: correrlo desde Git Bash o WSL.

set -u
cd "$(dirname "$0")"

ENV_FILE=../../entorno-blue-team/.env
if [ ! -f "$ENV_FILE" ]; then
  echo "Falta $ENV_FILE. Levantar primero el entorno (ver entorno-blue-team/)."
  exit 1
fi
ELASTIC_PASSWORD=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
KIBANA="http://localhost:5601"
API="$KIBANA/api/detection_engine/rules"
fallos=0

for regla in h3-*.json; do
  rule_id=$(sed -n 's/.*"rule_id": *"\([^"]*\)".*/\1/p' "$regla")
  code=$(curl -s -o /tmp/respuesta-regla.json -w '%{http_code}' -u "elastic:$ELASTIC_PASSWORD" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -X POST "$API" --data-binary @"$regla")
  if [ "$code" = "409" ]; then
    code=$(curl -s -o /tmp/respuesta-regla.json -w '%{http_code}' -u "elastic:$ELASTIC_PASSWORD" \
      -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -X PUT "$API" --data-binary @"$regla")
    accion="actualizada"
  else
    accion="creada"
  fi
  if [ "$code" = "200" ]; then
    echo "  [OK]    $rule_id $accion"
  else
    echo "  [FALLA] $rule_id (HTTP $code): $(head -c 300 /tmp/respuesta-regla.json)"
    fallos=$((fallos + 1))
  fi
done

[ $fallos = 0 ] && echo "Reglas cargadas. Ver en Kibana: Security > Rules > Detection rules (SIEM)." || exit 1
