# Plan · Hito 4 — Remediación con IA (V-01 y V-02)

## Contexto

El H4 pide corregir en el código **al menos 2 vulnerabilidades** del Red Team con un asistente de IA, **auditar** lo generado (SAST en el pipeline, revisión manual con la checklist del curso, verificar que las dependencias sugeridas existan — slopsquatting — y que no haya secretos), y que el **Red Team repita el PoC y confirme la corrección** con el **pipeline pasando**. La checklist del curso precisa que la re-prueba es **en DetectionOnly** (así un 401 demuestra el fix del código, no el bloqueo del WAF).

Se corrigen **V-01 (SQLi en login)** y **V-02 (SQLi UNION en búsqueda)**, elegidas porque:
- Las dos las marca nuestra regla propia de Semgrep `juice-shop-sequelize-raw-query-interpolation` → al corregirlas baja el conteo `sast.error` del gate (ratchet), que es la prueba de "el pipeline pasa".
- Las dos tienen `poc.sh` reproducible (re-prueba automática): hoy V-01 devuelve un JWT admin (200) y V-02 exfiltra 25 usuarios; tras el fix deben fallar.
- Juice Shop trae codefixes de referencia para las dos líneas (`data/static/codefixes/`). **Ojo:** el de V-02 no sirve tal cual con la versión actual de Sequelize (ver §Cambios, fix 2). Ese hallazgo es parte de la auditoría.

**Asistente de IA usado:** Claude (Anthropic) vía Claude Code. Se documenta herramienta, prompt, respuesta y cambios en `docs/ia/`.

## Rama

Crear `hito-4` desde el `master` más reciente (ya con H1–H3 mergeados). El H4 es de todo el grupo, igual que el H1; la convención `hito-N` del README lo refleja. No commitear sin confirmación; usar `-s` (DCO) y **sin** la línea Co-Authored-By de Claude.

## Cambios de código (los 2 fixes)

Las dos consultas pasan de interpolación de strings a **consultas parametrizadas de Sequelize**. No se agregan dependencias.

### 1. `routes/login.ts:34` (V-01)
De interpolación directa a `bind` (ref: `data/static/codefixes/loginAdminChallenge_4_correct.ts`):
```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',
  { bind: [req.body.email || '', security.hash(req.body.password || '')], model: UserModel, plain: true }
)
```
Se conservan `model: UserModel` y `plain: true` (ya importados/usados). El resto de la función no cambia.

**Verificado con Sequelize 6.37.7 + SQLite:** `' OR 1=1--` devuelve `null` (sin sesión); las credenciales correctas siguen devolviendo el usuario; un `email` que no es texto (`["a"]`, `{"a":1}`) devuelve `null` sin romper la consulta.

### 2. `routes/search.ts:23` (V-02)
De interpolación a `replacements`, con los comodines `%` **en el valor**, no en la consulta:
```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { criteria: `%${criteria}%` } }
)
```
El `criteria` ya está truncado a 200 chars arriba. El resto (bloques de detección de retos, map de `req.__`) no cambia; el destructuring `.then(([products]: any) => …)` sigue válido.

**Por qué no se usa el codefix de referencia** (`unionSqlInjectionChallenge_2_correct.ts`, `LIKE '%:criteria%'`): pone el parámetro **dentro** de una cadena entre comillas, y las versiones actuales de Sequelize 6 ya no reemplazan parámetros dentro de cadenas literales. La consulta busca el texto literal `:criteria` y **devuelve 0 productos para cualquier búsqueda**, incluida la búsqueda vacía con la que la SPA carga el catálogo (`search-result.component.ts:63`). Resultado: la tienda queda sin productos (rompe BO-1) y la re-prueba de V-02 daría "0 usuarios" por el motivo equivocado. Verificado con Sequelize 6.37.7 + SQLite:

| Consulta | `q=""` | `q="apple"` | `q=<UNION de V-02>` |
|---|---|---|---|
| Codefix de referencia `LIKE '%:criteria%'` | 0 filas  | 0 filas  | 0 filas |
| Fix elegido `LIKE :criteria` con `%…%` en el valor | todo el catálogo  | Apple Juice  | 0 filas  |

Si la IA propone el codefix de referencia, se rechaza y se documenta como **hallazgo de la auditoría** (ver abajo).

## Auditoría del código generado por IA (el núcleo del H4)

1. **SAST en el pipeline.** Tras el push, Semgrep ya no marca `login.ts:34` ni `search.ts:23`; `sast.error` baja (probablemente de 40 a ~37–38, porque además de nuestra regla, `p/nodejsscan`/`express-sequelize-injection` también marcaban esas líneas). El número exacto sale del run.
2. **Revisión manual con la checklist del curso.** Documentar en `docs/hito-4/` la aplicación de la checklist (https://locano-uvg.github.io/proyecto_integrador/#checklist) al ítem de H4, más una revisión de código enfocada: la consulta queda parametrizada, no hay nueva ruta de concatenación, se mantiene el manejo de errores y el truncado de entrada, **y la funcionalidad legítima sigue igual** (login correcto y búsqueda devuelven lo mismo que antes).
3. **Hallazgos concretos de la auditoría.** La rúbrica pide "auditoría con hallazgos concretos sobre el código generado". Registrar cada propuesta de la IA que se corrigió o rechazó, con su evidencia. Hallazgo ya conocido: el patrón `LIKE '%:criteria%'` (el del codefix de referencia, y una sugerencia típica de IA) elimina la inyección pero deja la búsqueda inservible con Sequelize 6.37; se reemplazó por `LIKE :criteria` con los comodines en el valor.
4. **Slopsquatting (dependencias sugeridas existen).** Si la IA **no sugiere ninguna dependencia nueva** (los fixes usan Sequelize ya presente), se verifica que `package.json`/`frontend/package.json` no cambian y se documenta como "sin dependencias nuevas". Si sugiere alguna, verificarla en el registro de npm (que exista, quién la publica, antigüedad, descargas) antes de aceptarla.
5. **Sin secretos.** El escaneo de secretos del pipeline (`p/secrets` + regla propia `juice-shop-hardcoded-private-key`) sigue sin hallazgos nuevos; los fixes no introducen credenciales.

## Re-prueba del Red Team (confirmar la corrección)

1. En `entorno-blue-team/`: dejar el WAF en **DetectionOnly** y hacer que Juice Shop se **construya desde el código del fork** (descomentar el bloque `build:` del `docker-compose.yml`, comentar `image:`), luego `docker compose up -d --build juice-shop`. La primera construcción tarda (instala dependencias y compila el frontend) y necesita la RAM de Docker que ya tiene el entorno.
2. **Confirmar que corre el código corregido y no la imagen vieja:** `docker compose images juice-shop` debe mostrar la imagen construida localmente, no `bkimminich/juice-shop:v20.3.0`.
3. Correr los PoC **a través del WAF** y **con carpeta de evidencia propia**. Los `poc.sh` apuntan por defecto a `:3000`, que el entorno no expone (verificar.sh paso 2), y escriben en las carpetas de evidencia de H2:
   ```bash
   # desde la raíz del repo, en Git Bash
   BASE_URL=http://localhost:8080 EVID=red-team/evidencias/h4-retest-V-01 bash red-team/poc/V-01-sqli-login/poc.sh
   BASE_URL=http://localhost:8080 EVID=red-team/evidencias/h4-retest-V-02 bash red-team/poc/V-02-sqli-union-search/poc.sh
   ```
   Sin `BASE_URL`, curl no conecta (HTTP 000) y V-01 imprime "FAIL: sin token": parecería corregido sin haber probado nada. Sin `EVID`, se sobrescribe la evidencia original del H2.
4. **Criterio de éxito explícito** (no basta con "FAIL: sin token"):
   - V-01: `http_code.txt` = **401** y `response.json` sin campo `authentication`.
   - V-02: `http_code.txt` = **200** y **0 filas** en `response.json`.
5. **Control funcional** (que el fix no rompió la tienda; mismas condiciones):
   ```bash
   # login legítimo con la cuenta semilla: debe dar 200 con token
   curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/rest/user/login -H 'Content-Type: application/json' --data '{"email":"admin@juice-sh.op","password":"admin123"}'
   # búsqueda legítima: debe devolver al menos 1 producto
   curl -s 'http://localhost:8080/rest/products/search?q=apple'
   # catálogo completo (búsqueda vacía, la que usa la SPA): debe devolver todos los productos
   curl -s 'http://localhost:8080/rest/products/search?q='
   ```
   Además, abrir `http://localhost:8080` en el navegador y confirmar que se ve el catálogo. Opcional: correr `blue-team/falsos-positivos/generar-trafico-legitimo.sh` como prueba de regresión.
6. Guardar la evidencia de la re-prueba (que el ataque ahora falla y la tienda sigue funcionando), con la hora en que se corrió.

## Pipeline / gate (prueba de "el pipeline pasa")

1. Push de la rama → corre `devsecops.yml`.
2. Leer en el summary el nuevo `sast.error` y **bajar la línea base** (`.github/security-gate/baseline.json`) a ese valor (ratchet; el commit documenta que bajó por la corrección de V-01/V-02).
3. Cambiar el gate a **`mode: "enforce"`** (transición H2→H4 ya prevista): así la corrección queda bloqueada contra regresión. El run final debe salir verde.
4. **Si el gate marca una regresión que no viene de estos cambios** (por ejemplo, `sca.backend.high` subió porque npm publicó advisories nuevos desde la línea base del 12-nov): no es culpa del fix. Se actualiza esa métrica hacia arriba con justificación en el commit, como dice `docs/hito-2/pipeline-devsecops.md` §5, y se registra como riesgo residual.

## Documentación

- **`docs/ia/h4-remediacion-sqli.md`**: por cada fix → herramienta (Claude), prompt usado, respuesta de la IA (el código generado), qué se aceptó, qué se corrigió o rechazó y por qué, y el diff aplicado. Es obligatorio del H4.
- **`docs/hito-4/remediacion-h4.md`**: vulnerabilidades corregidas, los 2 diffs, la auditoría (SAST antes/después, checklist, hallazgos concretos, slopsquatting, secretos), la re-prueba del Red Team (antes 200/25 usuarios → después 401/0), el control funcional (login legítimo y catálogo siguen funcionando), el resultado del pipeline y las columnas "Corrección" y "Re-prueba" de la matriz de trazabilidad para V-01 y V-02.
- Actualizar `README-PROYECTO.md`: H4 a "En progreso/Completado".

## Verificación end-to-end

1. **Local, antes del push (opcional en Windows):** `npm run build:server` compila (los fixes son TypeScript válido). Si no se instalan las dependencias en local, la construcción de la imagen del paso 2 también compila el servidor y falla si hay un error de TypeScript. Correr Semgrep local con `.semgrep/` y confirmar que ya **no** aparecen los hallazgos en `login.ts` y `search.ts`.
2. **Re-prueba funcional:** con la app reconstruida en DetectionOnly, V-01 da 401 y V-02 no devuelve usuarios (PoC del Red Team), **y** el login legítimo y el catálogo siguen funcionando.
3. **Pipeline en GitHub:** 6 jobs en verde; `sast.error` menor que la línea base previa; gate en enforce pasa tras ratchet.

## Fuera de alcance / notas

- **RSN y codefixes upstream:** corregir estas líneas rompe a propósito los retos `loginAdminChallenge` y `unionSqlInjectionChallenge`. No mantenemos la solvencia de los retos ni el RSN (su workflow se eliminó en H2); el objetivo es eliminar la vulnerabilidad. Se nota en el documento.
- **Tests unitarios del propio Juice Shop:** algunos esperan que el SQLi funcione; no corren en nuestro pipeline (solo SAST/SCA/SBOM/DAST/gate), así que no bloquean.
- La página de la checklist del curso contenía texto de inyección (instrucciones falsas de herramientas); se ignoró.
- **Alternativa no elegida:** V-01 y V-02 son de la misma clase (CWE-89). Si el grupo quiere un tercer fix que muestre la lección central del H3, V-04 (IDOR del carrito, `routes/basket.ts:19`) es la candidata: el WAF no lo ve y solo el código lo corrige. No es obligatorio.