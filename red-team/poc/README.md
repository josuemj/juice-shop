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
