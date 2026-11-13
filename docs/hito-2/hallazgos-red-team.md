# Hallazgos Red Team — H2 (explotación)

Mitad ofensiva del Hito 2: al menos 4 vulnerabilidades **explotadas** con PoC reproducible y
clasificadas con OWASP Top 10:2025, CWE y vector CVSS v3.1. Se documentan **6** (V-01 a V-06).

La otra mitad de H2 (pipeline DevSecOps del grupo: SAST/SCA/SBOM/DAST + security gate) vive en
`docs/hito-2/pipeline-devsecops.md` y `.github/workflows/devsecops.yml` y no se modifica aquí.

## Alcance y reglas de enfrentamiento

- **Objetivo exclusivo:** instancia local del equipo
  `docker run --rm -d --name juice-shop-red-h2 -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.3.0`
  (bind solo a `127.0.0.1`; misma versión que audita el fork). Nunca se atacó `juice-shop.herokuapp.com`
  ni recursos de la Universidad o de terceros.
- **Reproducción:** con la instancia arriba, `bash red-team/poc/V-0x-<slug>/poc.sh`
  (variable `BASE_URL`, por defecto `http://127.0.0.1:3000`). Cada script regenera su evidencia en
  `red-team/evidencias/h2-V-0x-<slug>/`.
- Las vulnerabilidades se confirmaron primero en el **código fuente** del fork y luego se explotaron
  en vivo. La evidencia contiene valores semilla **públicos e intencionales** de Juice Shop (p. ej.
  el hash MD5 de `admin123`), no secretos reales.
- La clasificación OWASP usa **OWASP Top 10:2025** (A01 BAC, A05 Injection, A07 Authentication
  Failures). Los vectores CVSS v3.1 se justifican métrica por métrica en cada hallazgo.

## Resumen

| ID | Vulnerabilidad | OWASP 2025 | CWE | CVSS v3.1 | Caso de abuso | Detección esperada H3 |
|---|---|---|---|---|---|---|
| V-01 | SQLi en login → bypass a admin | A05 Injection | CWE-89 | **9.8** Crítico | AC-01 | Regla SQLi |
| V-02 | SQLi UNION → exfiltración de usuarios | A05 Injection | CWE-89 | **7.5** Alto | AC-02 | Regla SQLi |
| V-03 | DOM XSS en la búsqueda | A05 Injection | CWE-79 | **6.1** Medio | AC-03 | Regla XSS |
| V-04 | IDOR de carrito (acceso a carrito ajeno) | A01 Broken Access Control | CWE-639 | **6.5** Medio | AC-06 | Sin payload (ver §V-04) |
| V-05 | JWT forjado con clave filtrada → admin | A07 Authentication Failures | CWE-347, CWE-321 | **9.8** Crítico | AC-07 | Sin payload (ver §V-05) |
| V-06 | Login sin rate-limit (fuerza bruta) | A07 Authentication Failures | CWE-307 | **7.5** Alto | AC-04/05 | Regla ráfaga/escaneo por IP |

---

## V-01 · SQLi en el login — bypass de autenticación a admin

**Descripción.** `routes/login.ts:34` arma la consulta de login por interpolación directa de
`req.body.email` en SQL crudo:
`SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${hash(password)}' ...`.
Inyectando `' OR 1=1--` en `email` se neutraliza el filtro de contraseña y la consulta
(`plain: true`) devuelve el **primer** usuario de la tabla: el admin.

**Reproducción.** `bash red-team/poc/V-01-sqli-login/poc.sh`
- `POST /rest/user/login` con `{"email":"' OR 1=1--","password":"x"}`.
- Resultado observado: **HTTP 200** con un JWT cuyo payload es `role: admin`, `email: admin@juice-sh.op`.

**Evidencia** (`red-team/evidencias/h2-V-01-sqli-login/`, 2026-11-13 14:27 CST): `request.json`,
`response.json`, `token-decoded.json` (muestra `role=admin`).

**Clasificación.** A05:2025 Injection · CWE-89 (SQL Injection).

**CVSS v3.1 = 9.8 (Crítico)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **AV:N** el login es un endpoint HTTP remoto. **AC:L** un payload fijo y conocido basta.
- **PR:N / UI:N** no requiere credenciales ni interacción de víctima.
- **S:U** la vulnerabilidad y el impacto están en el mismo componente (la app).
- **C:H / I:H / A:H** la toma de la cuenta admin da lectura, modificación y control total de la
  aplicación (gestión de usuarios, catálogo, pedidos).

**H3 / correlación.** Caso de abuso AC-01. El payload viaja en el cuerpo JSON de `/rest/user/login`;
detectable por regla SQLi (CRS 942xxx) y por SIEM sobre el cuerpo de la petición.

---

## V-02 · SQLi UNION en la búsqueda — exfiltración de usuarios

**Descripción.** `routes/search.ts:21` interpola `req.query.q` en
`SELECT * FROM Products WHERE ((name LIKE '%${q}%' OR description LIKE '%${q}%') AND deletedAt IS NULL) ...`.
La tabla `Products` expone **10 columnas** (`SELECT *`), así que un `UNION SELECT` de 10 columnas
desde `Users` devuelve credenciales dentro del resultado de búsqueda.

**Reproducción.** `bash red-team/poc/V-02-sqli-union-search/poc.sh`
- `GET /rest/products/search?q=` con
  `qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9','10' FROM Users--`.
- Resultado observado: **HTTP 200**, **25 usuarios** con email (en `name`) y hash MD5 (en `description`).

**Evidencia** (`red-team/evidencias/h2-V-02-sqli-union-search/`, 2026-11-13 14:27 CST):
`payload.txt`, `response.json`, `usuarios-exfiltrados.txt` (25 pares email→hash, incluido
`admin@juice-sh.op → 0192023a7bbd73250516f069df18b500`).

**Clasificación.** A05:2025 Injection · CWE-89.

**CVSS v3.1 = 7.5 (Alto)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **AV:N / AC:L / PR:N / UI:N** endpoint de búsqueda público, sin autenticación ni interacción.
- **C:H** exfiltra todas las cuentas y sus hashes (dato sensible). **I:N / A:N** la PoC solo lee.

**H3 / correlación.** AC-02. Payload en el query string de `/rest/products/search`; detectable por
regla SQLi (`UNION SELECT`, comillas, `--`).

---

## V-03 · DOM XSS en la búsqueda

**Descripción.** El frontend trata el parámetro `q` como HTML de confianza:
`search-result.component.ts:146` → `this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)`,
y la plantilla `search-result.component.html:11` lo pinta con `[innerHTML]="searchValue"`. Un `q`
con un `<iframe src="javascript:alert(\`xss\`)">` se ejecuta en el navegador de la víctima.

**Reproducción.** `PLAYWRIGHT_DIR=<pw> bash red-team/poc/V-03-xss-dom-search/poc.sh`
(o manual: abrir `http://127.0.0.1:3000/#/search?q=<iframe src="javascript:alert(\`xss\`)">`).
- El script abre la URL en Chromium y confirma que el diálogo `alert('xss')` se dispara.
- Resultado observado: `dialogFired=true`, `dialogMessage="xss"`; además la SPA llama a
  `/rest/products/search?q=<payload>` (**HTTP 200**), por lo que el payload también es visible al WAF.

**Evidencia** (`red-team/evidencias/h2-V-03-xss-dom-search/`, 2026-11-13 14:27 CST):
`xss-ejecutado.png` (captura del alert), `resultado.json`, `repro-url.txt`, `traza-servidor.txt`.

**Clasificación.** A05:2025 Injection · CWE-79 (Cross-site Scripting).

**CVSS v3.1 = 6.1 (Medio)** — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **AV:N / AC:L / PR:N** el ataque es un enlace; no requiere privilegios.
- **UI:R** la víctima debe abrir el enlace malicioso.
- **S:C** el script se ejecuta en el contexto del navegador de la víctima (cambio de ámbito).
- **C:L / I:L** permite robar el token (que vive en `localStorage`/cookie, ver recon H1) y actuar
  como la víctima, con alcance limitado por interacción. **A:N**.

**H3 / correlación.** Misma categoría que AC-03 (el XSS reflejado por rastreo de pedidos vive en
`track-result.component.ts`, mismo patrón `bypassSecurityTrustHtml`). Detectable por regla XSS
(`<iframe`, `javascript:`, `onerror`) sobre el query string.

---

## V-04 · IDOR de carrito — acceso al carrito de otro usuario

**Descripción.** `routes/basket.ts:19` resuelve `BasketModel.findOne({ where: { id } })` con el `id`
de la URL y **no** comprueba que ese carrito pertenezca al usuario del JWT. Cualquier usuario
autenticado lee cualquier carrito.

**Reproducción.** `bash red-team/poc/V-04-idor-basket/poc.sh`
- Registra un `customer` nuevo, inicia sesión (obtiene su propio `bid`, p. ej. 7) y pide
  `GET /rest/basket/1` con **su** token.
- Resultado observado: **HTTP 200**, se devuelve el carrito `id=1` (dueño `UserId=1`, el admin),
  distinto del carrito propio del atacante.

**Evidencia** (`red-team/evidencias/h2-V-04-idor-basket/`, 2026-11-13 14:27 CST): `login-resp.json`
(bid propio), `basket-ajeno.json` (`UserId` del dueño), `http_code.txt`.

**Clasificación.** A01:2025 Broken Access Control · CWE-639 (Authorization Bypass Through
User-Controlled Key).

**CVSS v3.1 = 6.5 (Medio)** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **AV:N / AC:L** petición HTTP directa y trivial. **PR:L** requiere una sesión de customer
  (registro público). **UI:N**.
- **C:H** acceso no autorizado a los datos de carrito de cualquier usuario. **I:N / A:N** (la PoC lee).

**H3 / correlación.** AC-06. La petición es **sintácticamente legítima** (un GET con un id válido):
ni el WAF ni una regla de firma la detectan. Es el ejemplo de que el WAF no sustituye la
autorización en el código; en H3 requiere logging de autorización a nivel de aplicación (RS-03/RS-13
del diseño del grupo).

---

## V-05 · JWT forjado con la clave privada filtrada — escalamiento a admin

**Descripción.** `lib/insecurity.ts:21` incrusta la **clave privada RSA** en el código fuente, y el
servidor verifica los JWT con la pública correspondiente (`encryptionkeys/jwt.pub`,
`isAuthorized = expressJwt({ secret: publicKey })`). Con la clave del repositorio, un atacante firma
un JWT RS256 válido para cualquier identidad y rol, **sin credenciales**.

**Reproducción.** `bash red-team/poc/V-05-jwt-forgery/poc.sh` (usa `forge.js`, solo Node, sin libs).
- Forja `{ data:{ id:1, email:"admin@juice-sh.op", role:"admin", ... }, bid:1 }` firmado con la clave
  filtrada y lo envía a `GET /api/Users/`.
- Resultado observado: **sin token → HTTP 401**; **con token forjado → HTTP 200** (lista de usuarios).

**Evidencia** (`red-team/evidencias/h2-V-05-jwt-forgery/`, 2026-11-13 14:27 CST): `token-forjado.txt`,
`api-users-con-token-forjado.json`, `http_code.txt` (`sin_token=401 con_token_forjado=200`).

**Clasificación.** A07:2025 Authentication Failures · CWE-347 (Improper Verification of Cryptographic
Signature), CWE-321 (Use of Hard-coded Cryptographic Key).

**CVSS v3.1 = 9.8 (Crítico)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **AV:N / AC:L** la clave es pública (está en el repo); firmar un token es determinista.
- **PR:N / UI:N** no se necesitan credenciales ni interacción.
- **C:H / I:H / A:H** un token admin forjado da control total de la aplicación.

**H3 / correlación.** AC-07. Un JWT con **firma válida** hecha con la clave filtrada es
indistinguible de uno legítimo: el WAF no puede detectarlo por firma. Mitigación real = rotar la
clave fuera del código y fijar `algorithms:['RS256']` (H4). En H3 se documenta como brecha de
visibilidad; detectable solo por anomalías de uso (p. ej. admin desde IP/UA nuevos).

---

## V-06 · Login sin límite de intentos — fuerza bruta / ráfaga por IP

**Descripción.** `routes/login.ts` no aplica rate-limiting ni bloqueo por intentos fallidos (el
limitador de Juice Shop solo cubre `reset-password`, `server.ts:371`). Una misma IP puede probar
contraseñas sin fricción.

**Reproducción.** `bash red-team/poc/V-06-brute-force-login/poc.sh` (`N=30` por defecto)
- 30 `POST /rest/user/login` con contraseñas incorrectas para `admin@juice-sh.op` desde la misma IP.
- Resultado observado: **30 × HTTP 401, 0 × HTTP 429** → no hay anti-automatización.

**Evidencia** (`red-team/evidencias/h2-V-06-brute-force-login/`, 2026-11-13 14:27 CST): `codigos.txt`
(los 30 códigos), `resumen.txt` (`401=30 429=0`).

**Clasificación.** A07:2025 Authentication Failures · CWE-307 (Improper Restriction of Excessive
Authentication Attempts).

**CVSS v3.1 = 7.5 (Alto)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **AV:N / AC:L / PR:N / UI:N** endpoint de login remoto, sin privilegios ni interacción.
- **C:H** la ausencia de límite habilita el compromiso de cuentas por adivinación (el éxito depende
  de la robustez de la contraseña; se puntúa la debilidad habilitante). **I:N / A:N** por sí sola.

**H3 / correlación.** AC-04 (fuerza bruta) y AC-05 (escaneo). Es la fuente de tráfico para la regla
de detección de **ráfaga/escaneo por IP** de H3 (umbral de intentos por `source.ip` en ventana de tiempo).

---

## Observación adicional (no incluida como PoC formal)

Durante V-03 se observó que `PUT /api/Products/:id` responde **HTTP 200 sin token** (modificación no
autenticada del catálogo): otra instancia de Broken Access Control (A01:2025 / CWE-284). Se registra
como superficie para ampliar en el informe final; no se contabiliza entre las 6 PoCs.

## Matriz de trazabilidad (preliminar — se completa en H3/H4)

Una fila por hallazgo, con las columnas de la matriz del curso. Las columnas de SIEM/WAF/corrección
se llenan en H3 y H4.

| Hallazgo | OWASP / CWE | CVSS v3.1 (vector) | ¿Pipeline? | ¿SIEM? | ¿WAF? | Corrección | Re-prueba |
|---|---|---|---|---|---|---|---|
| V-01 SQLi login | A05 / CWE-89 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | SAST (Semgrep) | Pendiente H3 (regla SQLi) | Pendiente H3 | Pendiente H4 | Pendiente |
| V-02 SQLi UNION | A05 / CWE-89 | 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | SAST (Semgrep) | Pendiente H3 (regla SQLi) | Pendiente H3 | Pendiente H4 | Pendiente |
| V-03 DOM XSS | A05 / CWE-79 | 6.1 `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | SAST (Semgrep) | Pendiente H3 (regla XSS) | Pendiente H3 | Pendiente H4 | Pendiente |
| V-04 IDOR carrito | A01 / CWE-639 | 6.5 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | — (lógica, no firma) | Pendiente H3 (log autz.) | No (petición legítima) | Pendiente H4 | Pendiente |
| V-05 JWT forjado | A07 / CWE-347, CWE-321 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | SAST (secreto en código) | Pendiente H3 (anomalía) | No (firma válida) | Pendiente H4 | Pendiente |
| V-06 Fuerza bruta | A07 / CWE-307 | 7.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | — | Pendiente H3 (ráfaga/IP) | Pendiente H3 | Pendiente H4 | Pendiente |

> Las columnas «¿Pipeline?» indican el control que *debería* señalar cada clase; su confirmación con
> el resultado real de `semgrep`/`npm audit`/ZAP del workflow del grupo se consolida en el informe final.
