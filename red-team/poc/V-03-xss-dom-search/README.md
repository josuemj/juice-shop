# V-03 · DOM XSS en la búsqueda

- **Vulnerabilidad:** `search-result.component.ts:146` (`bypassSecurityTrustHtml(q)`) + `[innerHTML]` en la plantilla (A05:2025 / CWE-79, CVSS 6.1).
- **Precondición:** instancia en `BASE_URL`. Para la captura automática: `PLAYWRIGHT_DIR` apuntando a una instalación de Playwright (aislada, no es dependencia del proyecto).
- **Comando:** `PLAYWRIGHT_DIR=<ruta> bash poc.sh` · **Manual:** abrir `http://127.0.0.1:3000/#/search?q=<iframe src="javascript:alert(`xss`)">`.
- **Resultado esperado:** se ejecuta `alert('xss')` en el navegador (`dialogFired=true`); el payload también llega a `/rest/products/search?q=` (HTTP 200), visible para el WAF.
- **Evidencia:** `../../evidencias/h2-V-03-xss-dom-search/` (`xss-ejecutado.png`, `resultado.json`).
