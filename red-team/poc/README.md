# PoCs Red Team — Hito 2

Una PoC reproducible por vulnerabilidad explotada. Clasificación completa (OWASP Top 10:2025, CWE,
CVSS v3.1) en [`docs/hito-2/hallazgos-red-team.md`](../../docs/hito-2/hallazgos-red-team.md).

## Requisitos

Instancia local del equipo (solo loopback):

```bash
docker run --rm -d --name juice-shop-red-h2 -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.3.0
```

Reglas de enfrentamiento: se ataca **solo** esta instancia local; nunca el Juice Shop público ni
terceros. Todas las PoCs usan `BASE_URL` (por defecto `http://127.0.0.1:3000`).

## Ejecución

```bash
BASE_URL=http://127.0.0.1:3000 bash red-team/poc/V-01-sqli-login/poc.sh
# ... y así cada V-0x. V-03 requiere además PLAYWRIGHT_DIR apuntando a una instalación de Playwright.
```

Cada script regenera su evidencia (con hora en CST) en `red-team/evidencias/h2-V-0x-<slug>/`.

| PoC | Vulnerabilidad | OWASP / CWE | CVSS |
|---|---|---|---|
| [V-01](V-01-sqli-login/) | SQLi en login → admin | A05 / CWE-89 | 9.8 |
| [V-02](V-02-sqli-union-search/) | SQLi UNION → exfiltración | A05 / CWE-89 | 7.5 |
| [V-03](V-03-xss-dom-search/) | DOM XSS en búsqueda | A05 / CWE-79 | 6.1 |
| [V-04](V-04-idor-basket/) | IDOR de carrito | A01 / CWE-639 | 6.5 |
| [V-05](V-05-jwt-forgery/) | JWT forjado con clave filtrada | A07 / CWE-347,321 | 9.8 |
| [V-06](V-06-brute-force-login/) | Login sin rate-limit | A07 / CWE-307 | 7.5 |

## H3 — repetir las PoC a través del WAF

Para el Hito 3 las 6 PoC se repiten **a través del WAF** (`localhost:8080`, no `:3000` directo),
para que el Blue Team demuestre detección (SIEM) y bloqueo (WAF en `On`). Instrucciones y el mapeo
de cada PoC a objetivos, data flow y límites de confianza: [`h3-waf/`](h3-waf/).

Requisito: entorno Blue Team arriba (`cd entorno-blue-team && docker compose up -d && ./verificar.sh`).

```bash
# Pasada 1 — WAF en DetectionOnly (registra, no bloquea):
bash red-team/poc/h3-waf/run-h3.sh

# Pasada 2 — WAF en On (bloquea). Cambiar MODSEC_RULE_ENGINE=On en entorno-blue-team/.env,
# recrear el WAF (docker compose up -d --force-recreate waf) y volver a correr:
bash red-team/poc/h3-waf/run-h3.sh
```

El script detecta el modo del WAF, clasifica cada PoC (observado vs esperado) y marca cada petición
con un `User-Agent` único (`redteam-h3-<fecha>`) para correlacionar en Kibana. Evidencia en
`red-team/evidencias/h3-<modo>-<marcador>/`. Solo ataca loopback; no fabrica evidencia.
