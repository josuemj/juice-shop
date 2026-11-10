# Log de evidencia - Reconocimiento H1 (Red Team)

Objetivo: instancia local propia del equipo, `http://127.0.0.1:3000` (contenedor Docker `juice-shop-red`, bind explícito a `127.0.0.1`, no expuesto a `0.0.0.0`).
Imagen: `bkimminich/juice-shop:v20.3.0` (misma versión que `package.json` del repo: `20.3.0`).
Herramienta: `curl` manual, una petición a la vez, sin automatización de barrido.
Zona horaria de las marcas: America/Guatemala (CST, UTC-6). El encabezado `Date` de cada respuesta queda en UTC dentro de los archivos `.headers` en `red-team/evidencias/h1-recon/`.

Todas las rutas y evidencias crudas (headers/body) están en `red-team/evidencias/h1-recon/`.

| # | Fecha y hora (CST) | Método | Ruta | HTTP | Observación | Evidencia |
|---|---|---|---|---|---|---|
| 1 | 2026-11-09 21:44:47 | GET | / | 200 | Verificación de arranque del contenedor tras `docker run`. | - |
| 2 | 2026-11-09 21:48:23 | GET | / | 200 | Página raíz SPA Angular. Headers: `X-Recruiting: /#/jobs`, `Access-Control-Allow-Origin: *`, sin `Content-Security-Policy` ni `Strict-Transport-Security`. | `01-GET-raiz.*` |
| 3 | 2026-11-09 21:48:31 | GET | /robots.txt | 200 | `Disallow: /ftp` - el propio robots.txt delata la existencia de /ftp. | `02-GET-robots.*` |
| 4 | 2026-11-09 21:48:43 | GET | /ftp | 200 | Listado de directorio navegable (serve-index). Archivos listados: `acquisitions.md`, `announcement_encrypted.md`, `coupons_2013.md.bak`, `legal.md`, `package.json.bak`, `package-lock.json.bak`. | `03-GET-ftp.body` |
| 5 | 2026-11-09 21:48:54 | GET | /rest/admin/application-version | 200 | `{"version":"20.3.0"}` - confirma versión de la app sin autenticación. | `04-GET-application-version.body` |
| 6 | 2026-11-09 21:49:03 | GET | /rest/products/search?q=apple | 200 | API de búsqueda de productos, responde JSON del backend sin autenticación. | `05-GET-products-search.body` |
| 7 | 2026-11-09 21:49:10 | GET | /api/Products?size=2 | 200 | API REST genérica (Sequelize) expuesta en `/api/`, sin autenticación para lectura. | `06-GET-api-Products.body` |
| 8 | 2026-11-09 21:49:15 | GET | /rest/user/whoami | 200 | `{"user":{}}` sin sesión. | `07-GET-whoami-anon.body` |
| 9 | 2026-11-09 21:49:20 | GET | /api-docs/ | 200 | Swagger UI expuesto públicamente. | - |
| 10 | 2026-11-09 21:49:28 | GET | /metrics | 200 | Endpoint Prometheus sin autenticación, expone métricas internas (incluye contadores `juiceshop_llm_*`). | `09-GET-metrics.body` |
| 11 | 2026-11-09 21:49:36 | POST | /rest/user/login | 401 | Credenciales ficticias (`recon-test@example.com`). Respuesta genérica: `Invalid email or password.` (no distingue usuario inexistente de contraseña incorrecta). | `10-POST-login-dummy-401.body` |
| 12 | 2026-11-09 21:50:12 | POST | /rest/user/login | 200 | Cuenta semilla pública y documentada por el propio OWASP Juice Shop (`admin@juice-sh.op` / `admin123`), no es un secreto descubierto. Devuelve JWT RS256. Payload decodificado (base64, sin verificar firma) incluye el hash MD5 de la contraseña (`0192023a7bbd73250516f069df18b500`) y el rol (`admin`) en texto claro dentro del token. | `11-POST-login-admin-seed-200.body` |
| 13 | 2026-11-09 21:50:38 | GET | /api/Challenges/?size=3 | 200 | Catálogo completo de retos (incluye `passwordHashLeakChallenge`, coincide con el hallazgo anterior) expuesto sin autenticación; es el API que alimenta `/#/score-board`. | `12-GET-api-Challenges.body` |
| 14 | 2026-11-09 21:50:50 | POST | /file-upload | 204 | Subida de archivo `.txt` benigno (`h1_upload_test.txt`), **sin header `Authorization`**. Aceptado (204 No Content). | `13-POST-file-upload-txt.headers` |
| 15 | 2026-11-09 21:51:01 | GET | /api/Users/ | 401 | Sin token. Página de error revela versión exacta de Express: `OWASP Juice Shop (Express ^4.22.1)`. | `14-GET-api-Users-anon-401.body` |
| 16 | 2026-11-09 21:51:11 | GET | /api/Users/?size=3 | 200 | Con JWT de `admin@juice-sh.op`. Lista completa de usuarios (sin campo password). | `15-GET-api-Users-admin-token-200.body` |
| 17 | 2026-11-09 21:51:23 | POST | /api/Users/ | 201 | Registro de cuenta de prueba desechable `recon.customer@example.com`, rol asignado por defecto: `customer`, id 25. | `16-POST-register-customer-201.body` |
| 18 | 2026-11-09 21:51:31 | POST | /rest/user/login | 200 | Login con la cuenta `customer` recién creada. | - |
| 19 | 2026-11-09 21:51:35 | GET | /api/Users/?size=3 | 200 | **Con JWT de rol `customer` (no admin)** se obtiene la misma lista completa de usuarios que en la fila 16. El endpoint `/api/Users/` no valida rol, solo exige un JWT válido. | `18-GET-api-Users-customer-token-200.body` |
| 20 | 2026-11-09 21:52:06 | GET | /some-nonexistent-spa-route | 200 | Respuesta idéntica (byte a byte en los primeros 500 bytes comparados) a la ruta raíz: confirma fallback SPA de Express sirviendo `index.html` para cualquier ruta no reconocida, consistente con enrutamiento Angular por hash (`/#/score-board`, etc. nunca llegan al servidor). | - |

Nota sobre alcance: las filas 12 y 19 son observaciones de reconocimiento (superficie y comportamiento), no explotación formal. La clasificación OWASP/CWE/CVSS de estos hallazgos corresponde al hito H2, cuando el Red Team explote formalmente cada vulnerabilidad con PoC reproducible.
