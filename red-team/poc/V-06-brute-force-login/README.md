# V-06 · Login sin límite de intentos (fuerza bruta / ráfaga por IP)

- **Vulnerabilidad:** `routes/login.ts` sin rate-limit; el limitador solo cubre `reset-password` (A07:2025 / CWE-307, CVSS 7.5).
- **Precondición:** instancia en `BASE_URL`. `N` (por defecto 30) = intentos.
- **Comando:** `bash poc.sh`
- **Resultado esperado:** N intentos fallidos desde la misma IP → N×401 y 0×429 (sin anti-automatización). Insumo de la regla de detección ráfaga/escaneo por IP en H3.
- **Evidencia:** `../../evidencias/h2-V-06-brute-force-login/` (`codigos.txt`, `resumen.txt`).
