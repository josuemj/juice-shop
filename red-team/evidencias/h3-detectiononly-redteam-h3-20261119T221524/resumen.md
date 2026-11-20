# H3 · PoC a través del WAF — 2026-11-19 22:15:24 CST

- Objetivo: `http://localhost:8080` (WAF ModSecurity + CRS)
- Modo WAF observado: **detectiononly** (sondeo HTTP 500) · .env declara: `DetectionOnly`
- Marcador para el SIEM: `redteam-h3-20261119T221524` → en Kibana filtrar `user_agent.original: redteam-h3-20261119T221524*`
  - Cubre V-01/02/03/06 (el WAF registra estas peticiones en su audit log).
  - V-04 y V-05 son peticiones legítimas (200 OK) que no disparan regla CRS: NO se
    correlacionan por UA. Para esas dos, el dato de correlación es endpoint + la hora de
    esta corrida + el token/carrito guardado en su carpeta de evidencia (lo detecta Blue
    a nivel de aplicación, no el WAF).

| ID | Vector | ¿WAF lo ve? | Observado | Esperado (detectiononly) | Veredicto |
|---|---|---|---|---|---|
| V-01 | SQLi login | Sí (942xxx) | 200 | pasa + queda en audit.log | OK · pasa; Blue debe verla en Kibana |
| V-02 | SQLi UNION exfiltración | Sí (942xxx) | 200 | pasa + queda en audit.log | OK · pasa; Blue debe verla en Kibana |
| V-03 | XSS reflejado (track-order) | Sí (941xxx) | 200 | pasa + queda en audit.log | OK · pasa; Blue debe verla en Kibana |
| V-04 | IDOR carrito | No (petición legítima) | 200 | pasa (el WAF no la ve) | OK · no bloqueada (solo SIEM la detecta) |
| V-05 | JWT forjado -> admin | No (firma válida) | 200 | pasa (el WAF no la ve) | OK · no bloqueada (solo SIEM la detecta) |
| V-06 | Fuerza bruta login | No por firma (sí por ráfaga en SIEM) | 401=30/403=0/429=0 | pasa; 0× 429 (CRS no limita ráfaga) | OK · sin rate-limit; regla de ráfaga del SIEM debe alertar |
