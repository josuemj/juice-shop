# Reconocimiento Red Team - H1

## Alcance y metodología

Objetivo exclusivo: instancia local propia del equipo, levantada para este reconocimiento con:

```
docker run -d --name juice-shop-red -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.3.0
```

El bind es explícito a `127.0.0.1`, no a `0.0.0.0`: el contenedor solo es alcanzable desde esta máquina. La versión de imagen (`v20.3.0`) coincide con el `version` de `package.json` del fork (`20.3.0`), así que el comportamiento observado es el del código que este equipo audita.

El reconocimiento se hizo en dos pasadas:

1. **`curl` manual**, una petición a la vez, sin scripts de barrido automatizado. Cada petición está registrada con fecha, hora, payload y resultado en `red-team/evidencias/h1-reconocimiento.md`, con los cuerpos y cabeceras crudas en `red-team/evidencias/h1-recon/`.
2. **Navegador real (Chromium) controlado por Playwright**, instalado de forma aislada en el entorno de ejecución (no se agregó como dependencia del proyecto, para no tocar el `package.json` de la app vulnerable), para los flujos que la primera pasada no podía cubrir: estado de `localStorage`/cookies tras login, formularios de subida, y el panel `/#/administration` desde la UI. Registrado con capturas de pantalla, HTML servido y volcados de almacenamiento en `red-team/evidencias/h1-recon-browser/`, con el detalle paso a paso en `red-team/evidencias/h1-reconocimiento-navegador.md`.

No se usó Burp ni ZAP en modo manual/interactivo para esta parte del reconocimiento. Sí se corrió, por separado, un spider y un active scan de OWASP ZAP contra esta misma instancia (ver sección 9) - eso ya es una pasada de **explotación activa automatizada**, no reconocimiento pasivo, y sus hallazgos deben tratarse como insumo para H2, no como parte de la superficie "observada sin atacar" que cubren las secciones 1 a 8.

## 1. Tecnologías

Confirmadas desde el propio código del repositorio (no son una suposición del modelo) y corroboradas por respuestas del servidor:

| Componente | Tecnología y versión | Evidencia |
|---|---|---|
| Frontend | Angular `^22.0.1` (SPA, enrutamiento por hash `/#/...`) | `frontend/package.json`; fallback SPA confirmado (fila 20 del log: cualquier ruta no reconocida devuelve el mismo `index.html`) |
| Backend | Express `^4.22.1` | `package.json`; confirmado también por una página de error 401 que imprime literalmente `OWASP Juice Shop (Express ^4.22.1)` (fila 15 del log) |
| ORM | Sequelize `^6.37.3` | `package.json`; comportamiento de `/api/<Modelo>` típico de `sequelize-rest` |
| Base de datos | SQLite, vía `sqlite3 ^5.1.7` | `package.json` |
| Versión de la app | `20.3.0` | `GET /rest/admin/application-version` sin autenticación -> `{"version":"20.3.0"}` (fila 5) |
| Documentación de API | Swagger UI | `GET /api-docs/` responde 200 con la interfaz Swagger (fila 9); contrato en `swagger.yml` del repo |
| Métricas | Prometheus | `GET /metrics` responde 200 sin autenticación (fila 10) |

Cabeceras de seguridad observadas en la respuesta raíz (fila 2): `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Feature-Policy: payment 'self'`, `Access-Control-Allow-Origin: *`, `X-Recruiting: /#/jobs`. No hay `Content-Security-Policy` ni `Strict-Transport-Security` (la instancia corre en HTTP plano, sin TLS).

## 2. Endpoints REST (`/rest/` y `/api/`)

Juice Shop expone dos capas de API distintas, con comportamiento de autenticación diferente:

- **`/rest/*`**: endpoints propios de la aplicación (`routes/`), con lógica de negocio explícita.
  - `GET /rest/admin/application-version` - público, versión de la app (fila 5).
  - `GET /rest/products/search?q=...` - público, búsqueda de catálogo (fila 6).
  - `POST /rest/user/login` - login, devuelve JWT (filas 11, 12, 18).
  - `GET /rest/user/whoami` - público, devuelve `{"user":{}}` si no hay sesión (fila 8).
- **`/api/<Modelo>`**: capa REST genérica generada sobre los modelos de Sequelize (`Products`, `Users`, `Challenges`, etc.), con autorización inconsistente entre modelos:
  - `GET /api/Products` - lectura pública, sin autenticación (fila 7).
  - `GET /api/Challenges/` - lectura pública, sin autenticación; es el catálogo que alimenta el score board (fila 13).
  - `GET /api/Users/` - **requiere** un JWT válido (401 sin token, fila 15), pero **no valida el rol del token**: un JWT de usuario `customer` recién registrado obtiene la misma lista completa de usuarios que el JWT de `admin` (filas 16 y 19, mismo contenido). Esto es una observación de reconocimiento sobre falta de control de acceso por rol en esa ruta; la clasificación formal (OWASP/CWE/CVSS) y la PoC reproducible quedan para H2.

## 3. `/ftp`

- `robots.txt` (fila 3) declara `Disallow: /ftp`, lo que en la práctica delata la ruta a cualquiera que lo lea (el fichero es público).
- `GET /ftp` (fila 4) devuelve un listado de directorio navegable (middleware `serve-index`), con archivos visibles: `acquisitions.md`, `announcement_encrypted.md`, `coupons_2013.md.bak`, `legal.md`, `package.json.bak`, `package-lock.json.bak`.
- No se descargó ni se intentó acceder al contenido de esos archivos ni se probó path traversal (`%2e%2e/`) en este reconocimiento: queda para la fase de explotación en H2, donde corresponde documentarlo como PoC con su propia clasificación.

## 4. `/#/score-board`

Es una ruta puramente del lado del cliente (Angular Router con `HashLocationStrategy`): el servidor nunca ve el fragmento después de `#`, por lo que cualquier petición HTTP a `/#/score-board` en la práctica es una petición a `/` (confirmado indirectamente por el fallback SPA de la fila 20, donde incluso una ruta inexistente devuelve el mismo `index.html`).

La pantalla de score board se alimenta en el cliente de `GET /api/Challenges/` (fila 13), que está expuesto sin autenticación y devuelve el catálogo completo de retos de Juice Shop, incluyendo nombre, categoría, dificultad y descripción de cada uno (por ejemplo, el reto `passwordHashLeakChallenge`, cuya descripción coincide exactamente con lo observado en la fila 12: el JWT de login expone el hash de la contraseña en su payload). Esto es relevante para el equipo: el propio backend documenta sus vulnerabilidades intencionales a quien sepa consultar `/api/Challenges/`, sin necesidad de abrir la UI.

**Confirmado con navegador** (`red-team/evidencias/h1-recon-browser/02-score-board-sin-sesion.png`): contadores de "Hacking Challenges" / "Coding Challenges" / "Challenges Solved" (186 retos totales en esta build), filtros por categoría que coinciden con nombres de categorías OWASP (Broken Access Control, XSS, Injection, Sensitive Data Exposure, etc.), y un aviso explícito: "18 challenges are unavailable on Docker due to security concerns or technical incompatibility" - relevante porque significa que no todos los 186 retos son alcanzables en este despliegue, algo a tener en cuenta si el equipo usa el score board como checklist de cobertura.

## 5. Flujos de autenticación

- **Login** (`POST /rest/user/login`, `Content-Type: application/json`, body `{"email":..., "password":...}`):
  - Con credenciales inexistentes: `401`, mensaje genérico `Invalid email or password.` (fila 11). El mensaje no distingue "usuario no existe" de "contraseña incorrecta", lo cual es correcto desde el punto de vista de prevención de enumeración de usuarios por mensaje; no se evaluó si hay diferencia de tiempo de respuesta (timing attack) entre ambos casos.
  - Con la cuenta semilla pública `admin@juice-sh.op` / `admin123` (cuenta de demostración documentada por el propio proyecto OWASP Juice Shop, no un secreto descubierto por este equipo): `200`, devuelve `{"authentication":{"token": "<JWT>", "bid":1, "umail":"admin@juice-sh.op"}}` (fila 12).
- **Estructura del JWT observado**: cabecera `{"typ":"JWT","alg":"RS256"}`; el payload (base64, decodificable por cualquiera sin verificar la firma) contiene el registro de usuario completo, incluido el **hash MD5 de la contraseña** (`0192023a7bbd73250516f069df18b500` para `admin123`) y el **rol** (`admin`) en texto claro. Esto es información sensible expuesta del lado del cliente en cada sesión autenticada; queda para H2 su clasificación formal (coincide con el reto propio del juego `passwordHashLeakChallenge` ya mencionado).
- **Registro** (`POST /api/Users/`, body con `email`, `password`, `passwordRepeat`, `securityQuestion`, `securityAnswer`): `201`, asigna automáticamente `role: "customer"` (fila 17, cuenta de prueba desechable `recon.customer@example.com`, id 25).
- **`GET /rest/user/whoami`**: sin sesión devuelve `{"user":{}}` (fila 8); no se probó con sesión activa en este reconocimiento.

**Confirmado con navegador** (`red-team/evidencias/h1-reconocimiento-navegador.md`, filas 4 y 8): tras un login exitoso, el JWT se guarda **a la vez** en `localStorage` (clave `token`) y en una cookie `token` con el mismo valor exacto. La cookie tiene `httpOnly: false` y `secure: false`. Esto es relevante: duplica la superficie de robo de sesión por XSS (no hace falta evadir `httpOnly`, el token ya es legible por JavaScript en cualquiera de las dos ubicaciones) y, al no ser `secure`, viajaría también en claro si la app se sirviera accidentalmente por HTTP en un entorno con TLS mixto. Además aparece una cookie `continueCode` tras el login, no investigada en este reconocimiento.

Otro hallazgo de la pasada con navegador: al navegar a `/#/logout`, el token en `localStorage` y en la cookie siguieron presentes, sin cambiar, después de la "sesión cerrada". Dado que Juice Shop usa JWT sin estado (sin lista de revocación del lado del servidor), es esperable que el token siga siendo criptográficamente válido tras el logout; lo que no quedó claro es si el cliente debería al menos limpiar su propio almacenamiento y no lo hace. Queda para H2 confirmar si ese JWT "cerrado" sigue siendo aceptado por el backend (reenviarlo en el header `Authorization` tras el logout).

No se investigó el comportamiento de 2FA/TOTP en esta pasada (el payload del JWT trae un campo `totpSecret` vacío para la cuenta admin, lo que sugiere que 2FA existe como funcionalidad pero no está activada en esta cuenta semilla); queda pendiente para quien amplíe este reconocimiento.

## 6. Uploads

- `POST /file-upload` (multipart, campo `file`): se probó con un archivo `.txt` benigno, **sin cabecera `Authorization`**. Resultado: `204 No Content`, es decir, la petición fue aceptada sin exigir sesión (fila 14). No se intentó subir un archivo malicioso (zip con path traversal, XML con entidades externas, etc.); eso corresponde a la fase de explotación en H2.
- **Subida de imagen de perfil, confirmada con navegador**: vive en `/profile` (vista legacy renderizada en el servidor con Pug, `views/userProfile.pug` + rutas `server.ts:694-695,338-339` - **no** es una ruta de Angular, a diferencia de casi todo lo demás en esta app). Expone dos mecanismos:
  - `POST /profile/image/file` (`multipart/form-data`, campo `file`) - subida directa de archivo.
  - `POST /profile/image/url` (form POST clásico, campo `imageUrl`) - el usuario pega una URL externa (el placeholder sugiere Gravatar) y el servidor la descarga. Esta es la superficie clásica de SSRF/descarga de imagen por URL de Juice Shop; no se probó en este reconocimiento, queda para H2.
  - Esta vista se autentica con la cookie `token`, no con el header `Authorization` (confirma el hallazgo de la sección 5: el token también vive en cookie).
- **"File complaint", confirmado con navegador**: formulario en `/#/complain` con campos `Customer` (prellenado con el email de la sesión), `Message` (máx. 4096 caracteres) e `Invoice` (selector de archivo). No se identificó en este reconocimiento a qué ruta de backend postea el adjunto ni si comparte la misma falta de autenticación que `/file-upload`; queda para H2.

## 7. Roles

- Roles observados hasta ahora: `admin` y `customer`.
- La cuenta semilla `admin@juice-sh.op` tiene `role: "admin"` (fila 12). Una cuenta nueva registrada por el endpoint público de registro recibe `role: "customer"` por defecto, sin que el cliente pueda elegir el rol en el payload de registro (fila 17).
- Hallazgo relevante de control de acceso: `GET /api/Users/` exige un JWT válido pero no valida que el rol sea `admin`. Un JWT de una cuenta `customer` recién creada obtuvo la misma respuesta completa (lista de todos los usuarios) que el JWT de la cuenta `admin` (filas 16 y 19 - cuerpos de respuesta idénticos en estructura y contenido). Esto es una observación de superficie para reconocimiento; la clasificación OWASP/CWE y el vector CVSS v3.1, junto con una PoC reproducible, se producen en H2 cuando el equipo decida si esta es una de las vulnerabilidades a explotar formalmente.
- No se exploró en este reconocimiento si existen rutas específicas de panel de administración (`/#/administration` es, igual que `/#/score-board`, una ruta de cliente; su contenido real se arma con llamadas a `/api/Users/`, `/api/Products/`, etc., ya cubiertas arriba) ni roles adicionales como `deluxe` (el campo `deluxeToken` aparece vacío en las cuentas observadas).

**Confirmado con navegador** (`red-team/evidencias/h1-recon-browser/05-administration-admin.png` y `10-administration-customer.png`): con sesión `admin`, `/#/administration` muestra "Registered Users" (lista completa) y "Customer Feedback" (con borrado); con sesión `customer`, la misma ruta muestra un banner "403 - You are not allowed to access this page!" en vez del contenido. Esto deja clara la distinción importante para H2: **el control de acceso por rol existe en el guard de Angular (interfaz), pero no en el endpoint `/api/Users/` que realmente sirve los datos** (sección 2). Un atacante que no pase por la UI - llamando directamente a `/api/Users/` con un token de `customer`, como ya se hizo en la fila 19 del log de `curl` - evade por completo esa pantalla de "acceso denegado".

## 8. Pasada con navegador real (Playwright)

Resumen ejecutivo; el detalle paso a paso con capturas está en `red-team/evidencias/h1-reconocimiento-navegador.md` y `red-team/evidencias/h1-recon-browser/`.

- JWT confirmado en `localStorage` **y** cookie `token` (no `httpOnly`, no `secure`) - ver sección 5.
- `/#/logout` no limpia el token del lado del cliente (localStorage ni cookie) - ver sección 5, pendiente de confirmar en H2 si el backend sigue aceptando ese token.
- `/#/score-board` confirmado visualmente, 186 retos totales, 18 deshabilitados en esta imagen Docker - ver sección 4.
- Subida de imagen de perfil confirmada en `/profile` (vista legacy, no Angular), con vía de archivo y vía de URL externa (superficie de SSRF) - ver sección 6.
- Formulario "File complaint" confirmado en `/#/complain` - ver sección 6.
- `/#/administration` confirma visualmente que el control de acceso por rol es solo de interfaz (guard de Angular), no del endpoint de backend - ver sección 7.

## 9. OWASP ZAP - spider y active scan (explotación activa, no reconocimiento)

Se ejecutó OWASP ZAP 2.17.0 en un contenedor Docker separado (`zap-red`, imagen `ghcr.io/zaproxy/zaproxy:stable`), con la API habilitada y expuesta solo en `127.0.0.1:8090`. El contenedor de ZAP alcanza el Juice Shop del host vía `host.docker.internal:3000` (confirmado antes de lanzar nada, con `GET /JSON/core/action/accessUrl/` contra la raíz del sitio).

**Esto no es reconocimiento pasivo**: un active scan manda payloads reales (inyección SQL, XSS, manipulación de parámetros, etc.) contra la aplicación. Se documenta aquí porque el usuario lo pidió como parte de esta tarea, pero conceptualmente es trabajo de H2 (DAST) y sus hallazgos deben pasar a `docs/hito-2/hallazgos-red-team.md` con clasificación OWASP Top 10:2025 / CWE / CVSS v3.1 y PoC reproducible antes de contar como parte de la matriz de trazabilidad, no quedarse aquí como si fueran observación pasiva.

### Spider

Lanzado el 2026-11-09 22:14:34 CST contra `http://host.docker.internal:3000`, completado en ~25 segundos (100% a las 22:14:58). Descubrió 116 URLs. Dos hallazgos relevantes de esta fase:

1. El spider "descubrió" decenas de rutas con forma `/juice-shop/node_modules/express/lib/router/index.js:280:10` y `/juice-shop/build/routes/fileServer.js:68:18`. Verificado manualmente: **no son archivos ni directorios reales servidos por la app** (todas devuelven 200 con el mismo `index.html` del fallback SPA, ver sección 1). Son artefactos: ZAP extrajo esas cadenas de un **stack trace de Node.js/Express que la aplicación devuelve en una respuesta de error** y las interpretó como enlaces. El stack trace real viene de `GET /ftp/eastere.gg` -> `403 Error: Only .md and .pdf files are allowed!`, con un `<ul id="stacktrace">` que expone, en texto plano, la ruta absoluta de instalación del servidor (`/juice-shop/...`) y la cadena de llamadas internas de Express. Esto sí es un hallazgo real de reconocimiento (divulgación de información vía mensaje de error verboso), separado de las URLs fantasma que generó. Evidencia: `red-team/evidencias/h1-recon-zap/spider-urls.json`, `red-team/evidencias/h1-recon-zap/stacktrace-ftp-eastere-gg.json`.
2. Confirma `/sitemap.xml`, no cubierto en la pasada con `curl`.

### Active scan

Lanzado el 2026-11-09 22:15:33 CST contra `http://host.docker.internal:3000`, completado el 2026-11-09 22:30:38 CST (status 100%, ~15 minutos). Evidencia completa: `red-team/evidencias/h1-recon-zap/alerts.json` (263 instancias), `alerts-summary.json`, `zap-report.html` (reporte HTML nativo de ZAP).

**Resultado: 0 alertas High, 0 Low, 171 instancias Medium, 92 Informational.** Por tipo único de alerta:

| Riesgo | Instancias | Alerta |
|---|---|---|
| Medium | 94 | Cross-Domain Misconfiguration (`Access-Control-Allow-Origin: *`) |
| Medium | 76 | Content Security Policy (CSP) Header Not Set |
| Medium | 1 | HTTP Only Site (sin TLS) |
| Informational | 68 | Modern Web Application (detección, no vulnerabilidad) |
| Informational | 24 | User Agent Fuzzer (ruido, confirma que el servidor no distingue por User-Agent) |

**Esto no significa que Juice Shop esté limpio - significa que el active scan no llegó a donde están los bugs reales, y hay que decirlo así de claro.** Las tres alertas Medium ya estaban identificadas en la sección 1 por la vía simple de leer cabeceras con `curl` (CORS abierto, sin CSP, sin TLS); no aportan nada nuevo. Lo que SÍ es relevante es lo que el active scan **no** encontró: cero alertas de inyección SQL, XSS, path traversal, etc., pese a que este equipo ya documentó en esta misma sesión (secciones 2 y 7) que `/api/Users/` tiene control de acceso roto, y pese a que Juice Shop tiene decenas de vulnerabilidades de inyección conocidas y documentadas por el propio proyecto (ver `/api/Challenges/`, categoría "Injection").

La causa, verificada: de las 96 URLs únicas que recibieron alguna alerta, **ninguna es `/rest/*` ni `/api/*`** - son todas rutas estáticas (JS, CSS, favicon), `/ftp/*` y variantes del fallback SPA. El spider tradicional de ZAP no ejecuta JavaScript, así que nunca vio las llamadas que Angular hace en tiempo de ejecución a `/rest/products/search`, `/rest/user/login`, `/api/Products`, `/api/Users`, etc. (todas descubiertas manualmente con `curl` en las secciones 2, 5 y 7 de este documento). El active scan, por diseño, solo ataca URLs que el spider ya conoce - si el spider nunca encontró la API real, el active scan nunca la atacó.

**Para H2, esto importa directamente**: un active scan de ZAP "de fábrica" contra esta app no sirve como evidencia de ausencia de vulnerabilidades, y tampoco va a encontrar los hallazgos que el Red Team necesita para las 4 PoC mínimas. Para que el job de DAST del pipeline (`docs/hito-2/pipeline.md`) aporte algo real, hace falta como mínimo una de estas opciones, ninguna de las cuales se hizo en esta sesión:
- Sembrar el spider con las URLs conocidas de `/rest/` y `/api/` (por ejemplo, importando `swagger.yml` a ZAP, o pasando la lista de URLs ya documentada en este reconocimiento como `contextInclude`/URLs semilla).
- Usar el AJAX Spider de ZAP (renderiza con un navegador real y sí ejecuta el JS de Angular) en vez del spider tradicional.
- Correr el active scan con contexto autenticado (el JWT ya obtenido en la sección 5), porque buena parte de la superficie relevante de Juice Shop requiere sesión.

## Resumen de lo que falta

- Confirmar en H2 si el backend sigue aceptando el JWT emitido antes de un `/#/logout` (sección 5).
- Confirmar a qué ruta de backend postea el adjunto de "File complaint" y si comparte la falta de autenticación de `/file-upload` (sección 6).
- Probar la vía `/profile/image/url` como superficie de SSRF (sección 6) - no se tocó en ningún reconocimiento, ni con `curl` ni con navegador ni con ZAP.
- El active scan de ZAP (sección 9) no encontró nada nuevo que valga la pena llevar a `docs/hito-2/hallazgos-red-team.md` tal cual - las 3 alertas Medium que produjo ya estaban documentadas por `curl`. Lo que sí hay que llevar a H2 es repetirlo bien: con AJAX Spider o URLs semilla de `/rest/`/`/api/`, y con contexto autenticado, para que el DAST del pipeline aporte algo real.
- En general: ninguna de las secciones 1 a 8 intentó explotar nada más allá de una observación puntual (sin path traversal real en `/ftp`, sin upload malicioso, sin forzar el bypass de rol más de una vez por cuenta). Esa fase corresponde a H2 con PoC reproducible y clasificación formal.
