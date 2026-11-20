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

Comando completo, de cero, desde la raíz del repo:
```bash
# 0) Entorno (solo lo que el Red Team necesita: WAF + Juice Shop; sin SIEM)
cd entorno-blue-team
cp .env.example .env   # si no existe; rellenar ELASTIC_PASSWORD/KIBANA_PASSWORD/KIBANA_ENCRYPTION_KEY
docker compose up -d log-init juice-shop waf
cd ..

# --- Pasada 1: DetectionOnly (modo por defecto del .env) ---
bash red-team/poc/h3-waf/run-h3.sh
```

**Pasada 2: modo bloqueo On.** Abrir `entorno-blue-team/.env` en cualquier editor y cambiar la línea
`MODSEC_RULE_ENGINE=DetectionOnly` por `MODSEC_RULE_ENGINE=On`. Desde la terminal también se puede:

```bash
# Linux
sed -i 's/^MODSEC_RULE_ENGINE=.*/MODSEC_RULE_ENGINE=On/' entorno-blue-team/.env
# macOS
sed -i '' 's/^MODSEC_RULE_ENGINE=.*/MODSEC_RULE_ENGINE=On/' entorno-blue-team/.env
```

```powershell
# Windows (PowerShell)
(Get-Content entorno-blue-team\.env) -replace '^MODSEC_RULE_ENGINE=.*', 'MODSEC_RULE_ENGINE=On' | Set-Content entorno-blue-team\.env
```

Luego recrear el WAF y volver a correr las PoC:

```bash
cd entorno-blue-team
docker compose up -d --force-recreate waf
cd ..
bash red-team/poc/h3-waf/run-h3.sh
```

En Windows, `run-h3.sh` se ejecuta desde **Git Bash** y necesita `python3` y `node` instalados.
Como el script solo ataca `localhost`, debe correr en la misma máquina donde está levantado el entorno.

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

## Evidencia ejecutada (19-nov-2026)

Corridas reales contra el entorno local, con el script ya corregido (ver bug abajo):

- `red-team/evidencias/h3-detectiononly-redteam-h3-20261119T221524/` — pasada 1, `DetectionOnly`.
- `red-team/evidencias/h3-on-redteam-h3-20261119T221546/` — pasada 2, `On`.

Las 6 PoC dieron resultado en ambas pasadas, sin `n/d`. Resumen (`On`, el que importa para el
bloqueo): V-01/02/03 → `403` bloqueadas por CRS 942xxx/941xxx. V-04/05/06 → pasan con `200`/`401`
tal como se esperaba (el WAF no puede verlas: son petición legítima, firma válida o sin payload).

**Bug corregido:** en una corrida anterior (commit `5d5b92fb7`, ya reemplazada), V-04 fallaba con
`n/d` — el registro y login del customer de prueba sí funcionaban (ambos con JWT válido en
`login-resp.json`), pero la extracción del token con `python3 -c "...json.load..."` devolvía vacío
y el script no decía por qué. Se corrigió así:
- Los `curl` de registro/login ahora capturan su propio código HTTP (`-w '%{http_code}'`) y se
  imprimen (`registro: HTTP ... · login: HTTP ...`).
- La condición para intentar leer el carrito ajeno ahora exige `login_code = 200` **y** token no
  vacío, no solo el token.
- El `stderr` de la extracción con `python3` ya no se descarta con `2>/dev/null`: se guarda en
  `token-extraction.err` dentro de la carpeta de evidencia de V-04 si algo realmente falla, para
  poder diagnosticarlo la próxima vez en vez de un `n/d` sin explicación.
