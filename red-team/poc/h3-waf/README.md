# PoC H3 · Red Team a través del WAF

En H2 las PoC atacan la app directa (`:3000`). En **H3** se repiten **a través del WAF**
(`localhost:8080`) para que el Blue Team demuestre **detección** (SIEM) y **bloqueo** (WAF en
modo `On`). Mismo payload, distinto punto de entrada: el perímetro.

Data flow (del modelado de amenazas, `docs/hito-1/blue-team-h1.md` §4): el tráfico entra por
`F1/F2 → P1 (WAF) → F3 → P2 (API)`. El WAF solo puede inspeccionar lo que viaja por ese borde
(límite de confianza **TB1**). De ahí la división que H3 demuestra en vivo:

| ID | Vector | Objetivo que amenaza | Data flow | Límite | ¿El WAF lo ve? | On (bloqueo) |
|---|---|---|---|---|---|---|
| V-01 | SQLi login | BO-2 / SO-5 | F1→F3 (cuerpo JSON) | TB1 | **Sí** · CRS 942xxx | **403** |
| V-02 | SQLi UNION | BO-2 / SO-5 | F1→F3 (query string) | TB1 | **Sí** · CRS 942xxx | **403** |
| V-03 | XSS reflejado (track-order) | BO-5 / SO-5 | F1→F3 (path `/rest/track-order/<payload>`) | TB1 | **Sí** · CRS 941xxx | **403** |
| V-04 | IDOR carrito | BO-3 / SO-1 | F3 petición legítima (sin payload) | TB2/TB3 | **No** | pasa (solo SIEM con log de app) |
| V-05 | JWT forjado | BO-2 / SO-3 | F3 con firma válida de clave filtrada | TB1 | **No** (firma válida) | pasa (solo anomalía de uso) |
| V-06 | Fuerza bruta | BO-2 / SO-6 | F3 N× 401 sin payload | TB1 | **No** por firma | pasa (regla de ráfaga del SIEM) |

> La lección central de H3: el WAF defiende el **perímetro** (V-01/02/03), pero **no sustituye la
> autorización ni la lógica en el código** (V-04/05/06). Esos tres pasan aunque el WAF esté en `On`.

## Requisitos

Entorno Blue Team levantado (desde `entorno-blue-team/`, con `.env` configurado):

```bash
cd entorno-blue-team
cp .env.example .env     # y rellenar ELASTIC_PASSWORD, KIBANA_PASSWORD, KIBANA_ENCRYPTION_KEY
docker compose up -d
./verificar.sh           # debe pasar las 5 verificaciones
```

Dependencias del runner: `curl`, `python3` (parseo de JWT/JSON) y `node` (V-05, forja el token).

## Cómo correr las PoC H3

Se corre **dos veces**: primero con el WAF en `DetectionOnly` (registra, no bloquea) y luego en
`On` (bloquea). El script **detecta solo** en qué modo está y clasifica cada PoC.

```bash
# --- Pasada 1: DetectionOnly (modo por defecto del .env) ---
bash red-team/poc/h3-waf/run-h3.sh

# --- Pasada 2: modo bloqueo On ---
cd entorno-blue-team
sed -i '' 's/^MODSEC_RULE_ENGINE=.*/MODSEC_RULE_ENGINE=On/' .env   # macOS; en Linux: sed -i 's/.../.../'
docker compose up -d --force-recreate waf
cd ..
bash red-team/poc/h3-waf/run-h3.sh
```

Variables opcionales: `BASE_URL` (def `http://localhost:8080`), `N` (intentos de V-06, def 30),
`TARGET_BASKET` (carrito ajeno a leer en V-04, def 1).

## Qué produce

- Imprime una tabla **observado vs esperado** con veredicto por PoC (`OK` o `⚠` si hay evasión /
  comportamiento inesperado — p. ej. una inyección que el WAF debió bloquear y pasó).
- Evidencia en `red-team/evidencias/h3-<modo>-redteam-h3-<fecha>/`, con un `resumen.md` y, por PoC,
  el código HTTP, el payload y la respuesta.
- Un **marcador único** por corrida (`redteam-h3-<fecha>`) puesto en el `User-Agent` de cada
  petición. El Blue Team filtra en Kibana con `user_agent.original: redteam-h3-*` para correlacionar
  exactamente estos eventos con sus reglas (SQLi, XSS, ráfaga por IP) — con la hora que imprime el
  script.

## Reglas de enfrentamiento

El script **aborta** si `BASE_URL` no es loopback (`localhost` / `127.0.0.1`). Solo se ataca la
instancia local del grupo. La evidencia se genera únicamente al ejecutar: nada está pre-rellenado.
