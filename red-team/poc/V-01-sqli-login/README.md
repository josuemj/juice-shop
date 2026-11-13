# V-01 · SQLi en login → bypass a admin

- **Vulnerabilidad:** `routes/login.ts:34` interpola `email` en SQL crudo (A05:2025 / CWE-89, CVSS 9.8).
- **Precondición:** instancia en `BASE_URL` (ver `../README.md`).
- **Comando:** `bash poc.sh`
- **Resultado esperado:** `POST /rest/user/login` con `email = ' OR 1=1--` devuelve HTTP 200 y un JWT con `role=admin` sin contraseña válida.
- **Evidencia:** `../../evidencias/h2-V-01-sqli-login/` (`response.json`, `token-decoded.json`).
