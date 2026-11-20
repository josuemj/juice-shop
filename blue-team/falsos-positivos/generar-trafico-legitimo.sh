#!/usr/bin/env bash
# Genera tráfico LEGÍTIMO de un cliente normal a través del WAF, para cazar
# falsos positivos del CRS (H3, fase DetectionOnly). NO contiene payloads de
# ataque: todo lo que aquí dispare una regla del WAF es un falso positivo.
#
# Marca cada petición con un User-Agent único para filtrarlo en Kibana:
#   user_agent.original : cliente-legitimo-*
#
# Uso (desde la raíz del repo, con el entorno levantado):
#   bash blue-team/falsos-positivos/generar-trafico-legitimo.sh
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
RUN="cliente-legitimo-$(date '+%Y%m%dT%H%M%S')"
UA=(-A "$RUN")
JSON=(-H 'Content-Type: application/json')
em="cliente.$(date +%s)@juice-sh.op"
pw="Cliente.Seguro1"
echo "Marcador para Kibana: user_agent.original : $RUN"

req() { # método url [datos]
  local m="$1" u="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s -o /dev/null -w "  %{http_code}  $m $u\n" "${UA[@]}" "${JSON[@]}" -X "$m" --data "$d" "$BASE_URL$u"
  else
    curl -s -o /dev/null -w "  %{http_code}  $m $u\n" "${UA[@]}" "$BASE_URL$u"
  fi
}

echo "== Navegación anónima =="
req GET "/"
req GET "/rest/products/search?q="
req GET "/rest/products/search?q=apple"
req GET "/rest/products/search?q=banana juice"
req GET "/api/Products"
req GET "/api/Quantitys"

echo "== Registro e inicio de sesión =="
req POST "/api/Users/" "{\"email\":\"$em\",\"password\":\"$pw\",\"passwordRepeat\":\"$pw\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"Perro\"}"
tok=$(curl -s "${UA[@]}" "${JSON[@]}" -X POST "$BASE_URL/rest/user/login" \
  --data "{\"email\":\"$em\",\"password\":\"$pw\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
AUTH=(-H "Authorization: Bearer $tok")
[ -n "$tok" ] && echo "  (sesión iniciada)" || echo "  (no se obtuvo token; se omiten pasos autenticados)"

echo "== Carrito y compra =="
req GET "/rest/basket/1"
curl -s -o /dev/null -w "  %{http_code}  POST /api/BasketItems\n" "${UA[@]}" "${JSON[@]}" "${AUTH[@]}" \
  -X POST --data '{"ProductId":1,"BasketId":"1","quantity":1}' "$BASE_URL/api/BasketItems"

echo "== Reseñas y feedback (texto natural que suele parecer sospechoso) =="
# Apóstrofes, comillas, signos < > y palabras como "or"/"select" en lenguaje normal:
# son legítimos, pero el CRS los puede confundir con SQLi/XSS.
curl -s -o /dev/null -w "  %{http_code}  PUT /rest/products/1/reviews\n" "${UA[@]}" "${JSON[@]}" "${AUTH[@]}" \
  -X PUT --data "{\"message\":\"It's the best juice, I'd buy it again! 5/5 <3\",\"author\":\"$em\"}" \
  "$BASE_URL/rest/products/1/reviews"
req GET "/rest/products/1/reviews"
curl -s -o /dev/null -w "  %{http_code}  POST /api/Feedbacks\n" "${UA[@]}" "${JSON[@]}" "${AUTH[@]}" \
  -X POST --data '{"comment":"Great shop. Should I order apple or banana next? Love it!","rating":5}' \
  "$BASE_URL/api/Feedbacks"

echo "== Perfil e idioma =="
req GET "/rest/user/whoami"
req GET "/api/Addresss"
req GET "/rest/admin/application-configuration"

echo
echo "Listo. En Kibana (Discover, filebeat-*) filtrar:"
echo "  user_agent.original : $RUN and modsec.transaction.messages.details.ruleId : *"
echo "Cada regla que aparezca sobre este tráfico es un FALSO POSITIVO a documentar y ajustar."
