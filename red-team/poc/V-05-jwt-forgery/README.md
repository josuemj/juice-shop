# V-05 · JWT forjado con la clave privada filtrada → admin

- **Vulnerabilidad:** `lib/insecurity.ts:21` incrusta la clave privada RSA en el código; el server verifica con la pública (A07:2025 / CWE-347, CWE-321, CVSS 9.8).
- **Precondición:** instancia en `BASE_URL`; Node disponible. `forge.js` firma el token (sin librerías externas).
- **Comando:** `bash poc.sh`
- **Resultado esperado:** `GET /api/Users/` sin token = HTTP 401; con el token admin forjado (sin credenciales) = HTTP 200.
- **Evidencia:** `../../evidencias/h2-V-05-jwt-forgery/` (`token-forjado.txt`, `api-users-con-token-forjado.json`).
