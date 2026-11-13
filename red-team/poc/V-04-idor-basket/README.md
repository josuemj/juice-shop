# V-04 · IDOR de carrito

- **Vulnerabilidad:** `routes/basket.ts:19` busca el carrito por `id` sin verificar el dueño contra el JWT (A01:2025 / CWE-639, CVSS 6.5).
- **Precondición:** instancia en `BASE_URL`. `TARGET_BASKET` (por defecto 1) = carrito ajeno a leer.
- **Comando:** `bash poc.sh`
- **Resultado esperado:** un customer nuevo (su propio `bid`) obtiene HTTP 200 al pedir `GET /rest/basket/1` (dueño `UserId=1`, admin).
- **Evidencia:** `../../evidencias/h2-V-04-idor-basket/` (`login-resp.json`, `basket-ajeno.json`).
