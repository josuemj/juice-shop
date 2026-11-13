# Superficie de ataque - H1 (Red Team)

Segunda mitad del entregable Red Team de H1 ("reconocimiento **y superficie de ataque**"). Este
documento **consolida** la superficie de ataque que quedó descrita en prosa a lo largo del
reconocimiento (`docs/hito-1/07-reconocimiento-red-team.md`, §1-§9) y la organiza desde la óptica
del atacante: puntos de entrada, activos expuestos, límites de confianza y priorización para la
fase de explotación (H2).

No se ejecutó ninguna petición ni ataque nuevo para este documento: todo lo que sigue está anclado
a una observación ya registrada en el reconocimiento. Cada fila referencia su evidencia en
`red-team/evidencias/h1-reconocimiento.md` (log de `curl`, filas 1-20),
`red-team/evidencias/h1-reconocimiento-navegador.md` (pasada con Playwright) o
`red-team/evidencias/h1-recon-zap/` (spider/active scan de ZAP).

Alcance del objetivo: instancia local propia del equipo, imagen `bkimminich/juice-shop:v20.3.0`
(misma versión que el `package.json` del fork), levantada con bind explícito a `127.0.0.1:3000`.

> La clasificación formal (OWASP Top 10:2025 / CWE / vector CVSS v3.1) y las PoC reproducibles
> **no** se producen aquí: corresponden a H2. Este documento solo mapea y prioriza la superficie.

## 1. Puntos de entrada

Inventario consolidado de los puntos de entrada observados, agrupados por capa. La columna
"Auth exigida" refleja lo que **el servidor** realmente exige (no lo que la UI aparenta).

### 1.1 Capa `/rest/*` (lógica de negocio propia)

| Ruta | Método | Auth exigida | Observación | Evidencia |
|---|---|---|---|---|
| `/rest/admin/application-version` | GET | Ninguna | Devuelve `{"version":"20.3.0"}` | recon §1/§2, fila 5 |
| `/rest/products/search?q=` | GET | Ninguna | Búsqueda de catálogo; superficie clásica de inyección | recon §2, fila 6 |
| `/rest/user/login` | POST | Ninguna (es el endpoint de auth) | Devuelve JWT RS256; mensaje de error genérico en 401 | recon §5, filas 11, 12, 18 |
| `/rest/user/whoami` | GET | Ninguna | Sin sesión devuelve `{"user":{}}` | recon §2, fila 8 |

### 1.2 Capa `/api/<Modelo>` (REST genérica sobre Sequelize)

| Ruta | Método | Auth exigida | Observación | Evidencia |
|---|---|---|---|---|
| `/api/Products` | GET | Ninguna (lectura) | Lectura pública del catálogo | recon §2, fila 7 |
| `/api/Challenges/` | GET | Ninguna | Catálogo completo de retos; delata las vulnerabilidades intencionales | recon §2/§4, fila 13 |
| `/api/Users/` | GET | **JWT válido, sin validar rol** | Un JWT `customer` obtiene la misma lista completa que `admin` | recon §2/§7, filas 15, 16, 19 |
| `/api/Users/` | POST | Ninguna | Registro; asigna `role: customer` por defecto, sin que el cliente elija rol | recon §5/§7, fila 17 |

### 1.3 Vistas legacy (Pug, renderizado en servidor - no Angular)

| Ruta | Método | Auth exigida | Observación | Evidencia |
|---|---|---|---|---|
| `/profile` | GET/POST | Cookie `token` | Vista legacy de perfil (no es ruta Angular) | recon §6 (navegador) |
| `/profile/image/file` | POST | Cookie `token` | Subida directa de archivo (multipart) | recon §6 (navegador) |
| `/profile/image/url` | POST | Cookie `token` | El servidor descarga una URL externa provista por el usuario -> superficie de SSRF | recon §6 (navegador) |

### 1.4 Cargas y formularios

| Ruta | Método | Auth exigida | Observación | Evidencia |
|---|---|---|---|---|
| `/file-upload` | POST | **Ninguna** | Aceptó un `.txt` con `204 No Content` **sin** header `Authorization` | recon §6, fila 14 |
| `/#/complain` (adjunto de "File complaint") | POST | Por confirmar | Formulario con selector de archivo; ruta de backend del adjunto no identificada en recon | recon §6 (navegador) |

### 1.5 Infraestructura, documentación y estáticos

| Ruta | Método | Auth exigida | Observación | Evidencia |
|---|---|---|---|---|
| `/` y rutas no reconocidas | GET | Ninguna | Fallback SPA: cualquier ruta desconocida devuelve el mismo `index.html` | recon §1, filas 2, 20 |
| `/robots.txt` | GET | Ninguna | `Disallow: /ftp` -> delata la ruta `/ftp` | recon §3, fila 3 |
| `/ftp` | GET | Ninguna | Listado de directorio navegable (`serve-index`) | recon §3, fila 4 |
| `/ftp/eastere.gg` | GET | Ninguna | 403 con stack trace verboso (`<ul id="stacktrace">`) | recon §9 (ZAP) |
| `/api-docs/` | GET | Ninguna | Swagger UI expuesto | recon §1, fila 9 |
| `/metrics` | GET | Ninguna | Métricas Prometheus (incluye contadores `juiceshop_llm_*`) | recon §1, fila 10 |
| `/sitemap.xml` | GET | Ninguna | Confirmado por el spider de ZAP | recon §9 (ZAP) |

### 1.6 Enrutamiento del lado del cliente (no llega al servidor)

Angular usa `HashLocationStrategy`: el servidor nunca ve el fragmento tras `#`. Rutas como
`/#/score-board` y `/#/administration` son **solo del cliente**; su contenido real se arma con
llamadas a las APIs de §1.1 y §1.2. Relevante para el atacante: **saltarse la UI** (llamar directo
a `/api/Users/`) evade cualquier control que viva únicamente en el guard de Angular (ver §3).
Evidencia: recon §4 y §7 (navegador, capturas `05-administration-admin.png` y `10-administration-customer.png`).

## 2. Activos expuestos

| Activo | Dónde queda expuesto | Por qué importa | Evidencia |
|---|---|---|---|
| Hash de contraseña (MD5) y rol en el JWT | Payload base64 del token, legible en cliente sin verificar firma (`0192023a7bbd73250516f069df18b500` = `admin123`, `role: admin`) | Exposición de dato sensible del lado del cliente en cada sesión | recon §5, fila 12 |
| JWT duplicado en `localStorage` **y** cookie `token` (`httpOnly:false`, `secure:false`) | Almacenamiento del navegador tras login | Duplica la superficie de robo de sesión por XSS; viajaría en claro sin TLS | recon §5/§8 (navegador) |
| Lista completa de usuarios | `GET /api/Users/` con cualquier JWT válido | Acceso a datos de todos los usuarios sin rol admin | recon §2/§7, filas 16, 19 |
| Catálogo de vulnerabilidades intencionales | `GET /api/Challenges/` sin auth | El backend documenta sus propios fallos a quien consulte la API | recon §2/§4, fila 13 |
| Archivos de respaldo y sensibles en `/ftp` | Listado `serve-index`: `package.json.bak`, `package-lock.json.bak`, `coupons_2013.md.bak`, `announcement_encrypted.md`, `acquisitions.md`, `legal.md` | Fuga potencial de dependencias, cupones y material interno | recon §3, fila 4 |
| Ruta absoluta de instalación y versión de Express | Stack trace de `/ftp/eastere.gg` (`/juice-shop/...`, `Express ^4.22.1`) y error 401 de `/api/Users/` | Divulgación de información que facilita el fingerprinting | recon §9 y fila 15 |
| Métricas internas | `GET /metrics` sin auth | Telemetría de la aplicación expuesta a cualquiera | recon §1, fila 10 |

## 3. Límites de confianza (óptica del atacante)

1. **Anónimo -> `customer` -> `admin`**: el registro público (`POST /api/Users/`) crea una cuenta
   `customer` sin aprobación; el login devuelve un JWT. La cuenta semilla pública
   `admin@juice-sh.op` / `admin123` (documentada por el propio OWASP Juice Shop) otorga rol `admin`.
   El salto relevante es que **un JWT `customer` ya alcanza datos que deberían ser de `admin`**
   (`/api/Users/`), sin cruzar realmente el límite de privilegio en el servidor.
2. **Frontera cliente / servidor**: el control de acceso por rol existe en el **guard de Angular**
   (la UI muestra "403 - You are not allowed..." a un `customer` en `/#/administration`), pero
   **no** en el endpoint `/api/Users/` que sirve los datos. El límite de confianza "visual" no
   coincide con el límite real; el atacante que no pasa por la UI lo ignora por completo.
3. **Contenedor Docker**: bind explícito a `127.0.0.1:3000`; la instancia de reconocimiento no está
   expuesta a la red. (En el entorno de grupo, el acceso real al sistema bajo prueba es a través del
   WAF; eso se evalúa en H3, no aquí.)
4. **Transporte y cabeceras**: sin `Content-Security-Policy`, sin `Strict-Transport-Security`,
   `Access-Control-Allow-Origin: *` y HTTP plano (sin TLS). Amplían la explotabilidad de un XSS y
   permiten lectura cruzada de respuestas. Evidencia: recon §1, filas 2 y 15; ZAP §9.

## 4. Superficie priorizada para H2

Vectores candidatos a PoC reproducible en H2, ordenados por lo que el reconocimiento ya dejó
preparado. La clasificación OWASP/CWE/CVSS se asigna en H2, no aquí.

| # | Vector | Punto de entrada | Qué falta probar en H2 |
|---|---|---|---|
| 1 | Broken Access Control por falta de validación de rol | `GET /api/Users/` | PoC con token `customer` y vector CVSS; base de fila 19 |
| 2 | SSRF por descarga de imagen desde URL | `POST /profile/image/url` | No se tocó en ningún recon; probar descarga de URL interna |
| 3 | Subida de archivo sin autenticación | `POST /file-upload` | Probar archivo malicioso (no solo `.txt` benigno) |
| 4 | Inyección en búsqueda de productos | `GET /rest/products/search?q=` | Confirmar SQLi/NoSQLi con payload |
| 5 | Exposición de hash de contraseña en el JWT | `POST /rest/user/login` | Formalizar como fuga de dato sensible (coincide con `passwordHashLeakChallenge`) |
| 6 | Divulgación de información | `/ftp` (listado + `.bak`), `/ftp/eastere.gg` (stack trace) | Descargar `.bak`, documentar path traversal si aplica |
| 7 | JWT no invalidado tras `/#/logout` | `/rest/*` con `Authorization` | Confirmar si el backend sigue aceptando el token tras el logout |

## 5. Nota sobre el DAST (ZAP) y su cobertura de esta superficie

El active scan "de fábrica" de ZAP (recon §9) produjo 0 alertas High y solo 3 tipos Medium
(CORS abierto, sin CSP, HTTP sin TLS) que ya se conocían por lectura de cabeceras con `curl`.
**No tocó `/rest/*` ni `/api/*`**: el spider tradicional no ejecuta JavaScript, así que nunca vio
las llamadas que Angular hace en tiempo de ejecución, y el active scan solo ataca lo que el spider
descubrió. Implicación directa para la superficie real y para el job de DAST del pipeline (H2): un
ZAP de fábrica **no** cubre la API, que es donde está casi toda la superficie priorizada de §4.
Para que el DAST aporte, en H2 hay que sembrar las URLs de `/rest/` y `/api/` (p. ej. importando
`swagger.yml`), usar el AJAX Spider, y correr con contexto autenticado (JWT de §1.1). No se
re-ejecuta aquí; se referencia como insumo de H2.
