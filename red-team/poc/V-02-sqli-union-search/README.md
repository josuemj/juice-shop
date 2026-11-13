# V-02 · SQLi UNION en búsqueda → exfiltración de usuarios

- **Vulnerabilidad:** `routes/search.ts:21` interpola `q` en SQL crudo; `Products` tiene 10 columnas (A05:2025 / CWE-89, CVSS 7.5).
- **Precondición:** instancia en `BASE_URL`.
- **Comando:** `bash poc.sh`
- **Resultado esperado:** `GET /rest/products/search?q=...UNION SELECT (10 cols) FROM Users--` devuelve HTTP 200 con 25 usuarios (email + hash MD5).
- **Evidencia:** `../../evidencias/h2-V-02-sqli-union-search/` (`usuarios-exfiltrados.txt`).
