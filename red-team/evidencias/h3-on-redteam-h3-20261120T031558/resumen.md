# H3 · PoC a través del WAF — blue team / read team

- Objetivo: `http://localhost:8080` (WAF ModSecurity + CRS)
- Modo WAF observado: **on** (sondeo HTTP 403) · .env declara: `On`
- Marcador para el SIEM: `redteam-h3-20261120T031558`

Kibana filtrar `user_agent.original: redteam-h3-20261120T031558*`

| ID | Vector | ¿WAF lo ve? | Observado | Esperado (on) | Veredicto |
|---|---|---|---|---|---|
| V-01 | SQLi login | Sí (942xxx) | 403 | 403 bloqueado | OK · bloqueado |
| V-02 | SQLi UNION exfiltración | Sí (942xxx) | 403 | 403 bloqueado | OK · bloqueado |
| V-03 | DOM XSS (vía API) | Sí en la API (941xxx) | 403 | 403 bloqueado | OK · bloqueado |
| V-04 | IDOR carrito | No (petición legítima) | n/d | pasa (el WAF no la ve) | OK · no bloqueada (solo SIEM la detecta) |
| V-05 | JWT forjado -> admin | No (firma válida) | 200 | pasa (el WAF no la ve) | OK · no bloqueada (solo SIEM la detecta) |
| V-06 | Fuerza bruta login | No por firma (sí por ráfaga en SIEM) | 401=30/403=0/429=0 | pasa; 0× 429 (CRS no limita ráfaga) | OK · sin rate-limit; regla de ráfaga del SIEM debe alertar |
