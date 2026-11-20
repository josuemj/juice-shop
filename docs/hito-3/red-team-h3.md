# Hito 3 · Detección y respuesta - Red Team

## 1. Resumen

El Red Team repite las 6 PoC explotadas en H2 (`red-team/poc/V-01..V-06`) a través del WAF
(`localhost:8080`, no `:3000`), usando el script `red-team/poc/h3-waf/run-h3.sh`. El objetivo es
demostrar, con evidencia real, qué parte del tráfico ofensivo el WAF puede ver y bloquear en el
perímetro (TB1 del modelado de amenazas, `docs/hito-1/blue-team-h1.md` §4) y cuál pasa siempre
porque no es visible a nivel HTTP (lógica de negocio, firma válida, ráfaga sin payload).

Las reglas de detección del SIEM, el dashboard y el análisis de falsos positivos sobre tráfico
legítimo son responsabilidad y entregable del Blue Team: ver
[`docs/hito-3/blue-team-h3.md`](blue-team-h3.md) y
[`blue-team/falsos-positivos/generar-trafico-legitimo.sh`](../../blue-team/falsos-positivos/generar-trafico-legitimo.sh).
Este documento no los repite; en la sección 4 los usa para verificar, con las PoC del Red Team,
que las exclusiones que Blue aplicó para corregirlos no abren hueco a los ataques.

## 2. Resultado, DetectionOnly vs On

Corridas reales contra el entorno local levantado con `docker compose up -d log-init juice-shop waf`
(ver comando completo en [`red-team/poc/h3-waf/README.md`](../../red-team/poc/h3-waf/README.md)),
el 19-nov-2026 a las 22:15 CST, con las exclusiones de Blue (`entorno-blue-team/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`)
ya montadas en el WAF en ambas corridas.

| ID | Vector | ¿WAF lo ve? | DetectionOnly | On |
|---|---|---|---|---|
| V-01 | SQLi login | Sí · CRS 942xxx | 200 (pasa, queda en audit.log) | **403 bloqueado** |
| V-02 | SQLi UNION exfiltración | Sí · CRS 942xxx | 200 (pasa, queda en audit.log) | **403 bloqueado** |
| V-03 | XSS reflejado (track-order) | Sí · CRS 941xxx | 200 (pasa, queda en audit.log) | **403 bloqueado** |
| V-04 | IDOR carrito | No (petición legítima) | 200 | 200 (sin cambio) |
| V-05 | JWT forjado -> admin | No (firma válida) | 200 | 200 (sin cambio) |
| V-06 | Fuerza bruta login (30 intentos) | No por firma | 401=30/403=0/429=0 | 401=30/403=0/429=0 (sin cambio) |

Evidencia completa (payload, request/response, código HTTP) por PoC:

- Pasada 1 (`DetectionOnly`): [`red-team/evidencias/h3-detectiononly-redteam-h3-20261119T221524/`](../../red-team/evidencias/h3-detectiononly-redteam-h3-20261119T221524/)
- Pasada 2 (`On`): [`red-team/evidencias/h3-on-redteam-h3-20261119T221546/`](../../red-team/evidencias/h3-on-redteam-h3-20261119T221546/)

La lección central de H3 confirmada con datos: el WAF defiende el perímetro (V-01/02/03), pero
**no sustituye la autorización ni la lógica en el código** (V-04/05/06): esos tres pasan igual en
`On` que en `DetectionOnly`.

## 3. Bug corregido en el script antes de esta corrida

Una corrida anterior (commit `5d5b92fb7`, reemplazada por las de la sección 2) reportaba V-04 como
`n/d`: el registro y login del customer de prueba sí generaban un JWT válido, pero la extracción
del token con `python3 -c "...json.load..."` fallaba sin indicar por qué (su `stderr` se
descartaba con `2>/dev/null`). Se corrigió `run-h3.sh`:

- Los `curl` de registro y login ahora capturan y muestran su propio código HTTP.
- Se exige explícitamente `login_code = 200` **y** token no vacío antes de intentar leer el
  carrito ajeno, en vez de confiar solo en que el token no esté vacío.
- Si la extracción falla de verdad, el `stderr` de `python3` queda en
  `token-extraction.err` dentro de la carpeta de evidencia de V-04, en vez de perderse.

Con la corrección, V-04 funcionó en ambas corridas de la sección 2 (HTTP 200, lee el carrito de
otro usuario autenticado como dueño `UserId=1`).

## 4. Verificación: las exclusiones de Blue no abren hueco a los ataques del Red Team

`docs/hito-3/blue-team-h3.md` §4 afirma que, tras aplicar las 3 exclusiones (FP-1 métodos
HTTP, FP-2 `/rest/user/whoami`, FP-3 `/socket.io/`), probó un ataque de control de SQLi y uno de
XSS y ambos seguían bloqueados. Esta sección repite esa verificación con el conjunto completo de
vectores del Red Team, no solo dos de control:

- Las corridas de la sección 2 se ejecutaron con el archivo de exclusiones **ya montado** en el
  contenedor `waf` (está declarado como volumen fijo en `entorno-blue-team/docker-compose.yml`,
  no es opcional).
- Revisado el contenido de las 3 exclusiones (`entorno-blue-team/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`,
  IDs 1001-1003): ninguna toca `/rest/user/login`, `/rest/products/search` ni
  `/rest/track-order/`, que son las rutas de V-01/V-02/V-03. FP-1 solo amplía los métodos HTTP
  permitidos (las PoC usan GET/POST, ya permitidos por defecto); FP-2 y FP-3 quitan una regla
  puntual solo en `/rest/user/whoami` y `/socket.io/`, por donde ninguna PoC pasa.
- Resultado observado: V-01, V-02 y V-03 siguieron devolviendo **403** en modo `On` (sección 2),
  exactamente igual que sin las exclusiones. No hay regresión de detección atribuible a los
  ajustes de falsos positivos del Blue Team.

## 5. Cómo reproducir

Ver [`red-team/poc/h3-waf/README.md`](../../red-team/poc/h3-waf/README.md) (comando completo,
desde levantar el entorno hasta las dos pasadas).
