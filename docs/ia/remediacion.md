# Uso de IA · Hito 4 — Remediación de V-01 y V-02 (SQL injection)

Registro del uso de IA en el Hito 4, según la guía de la UVG y el requisito del proyecto: herramienta, prompt, respuesta y cambios realizados. La evaluación de la respuesta (§6) es la auditoría del código generado.

| Campo | Valor |
|---|---|
| Fecha | 2026-11-19 |
| Responsable | Juan Pablo Solís |
| Herramientas | **Claude Code** (Anthropic) para generar y probar los fixes. **Claude** (claude.ai) para revisar el plan del H4 antes de pedir los cambios |
| Vulnerabilidades | V-01 · SQLi en login (`routes/login.ts:34`) · V-02 · SQLi UNION en búsqueda (`routes/search.ts:23`) |
| Clasificación | A05:2025 Injection · CWE-89 |
| Plan de referencia | [`docs/hito-4/plan-h4.md`](../hito-4/plan-h4.md) |
| Rama | `hito-4` |

---

## 1. Cómo se usó la IA

1. **Revisión del plan (Claude, claude.ai).** Antes de pedir los cambios se revisó el plan del H4. La revisión detectó que el codefix de referencia de Juice Shop para V-02 (`LIKE '%:criteria%'`) no funciona con la versión de Sequelize del proyecto, y que la re-prueba propuesta podía dar falsos "corregido" (PoC apuntando a `:3000`, falta de `python3` en Git Bash, evidencia sobrescrita). El plan se corrigió antes de usarlo.
2. **Generación de los fixes (Claude Code).** Con el plan corregido como contexto, se pidió a Claude Code que aplicara los dos cambios sin hacer commit y que justificara y verificara cada uno (§2 y §3).
3. **Revisión humana.** Se revisó el diff línea por línea antes de autorizar el commit (§6).

## 2. Prompt (textual)

```
Estamos en el fork del grupo de OWASP Juice Shop para el proyecto final del curso
Desarrollo Seguro (Hito 4: remediación con IA). En ESTE fork el objetivo es eliminar
vulnerabilidades, no conservarlas.

Contexto obligatorio: lee docs/hito-4/plan-h4.md completo y sigue la sección
"Cambios de código (los 2 fixes)".

Tarea:
1. Corrige V-01 en routes/login.ts:34 (SQL injection en el login) usando una consulta
   parametrizada con `bind`, como dice el plan.
2. Corrige V-02 en routes/search.ts:23 (SQL injection con UNION en la búsqueda) usando
   `replacements` con `LIKE :criteria` y los comodines % en el VALOR
   (`criteria: \`%${criteria}%\``). NO uses el patrón `LIKE '%:criteria%'` del codefix
   de referencia: con Sequelize 6.37 no reemplaza parámetros dentro de comillas y la
   búsqueda devuelve 0 productos.
3. No cambies nada más de esas funciones (manejo de errores, truncado a 200 caracteres,
   bloques de verificación de retos, map de req.__).

Restricciones:
- AGENTS.md pide correr el RSN y actualizar data/static/codefixes/ cuando se toca código
  de un reto. En este proyecto NO aplica: no corras `npm run rsn`, no modifiques
  data/static/codefixes/, data/static/challenges.yml ni .ai/. Romper los retos
  loginAdminChallenge y unionSqlInjectionChallenge es esperado.
- No agregues dependencias ni modifiques package.json.
- No hagas commit. Muéstrame el diff y espera mi confirmación.

Al terminar, explícame:
- El diff exacto de los dos archivos.
- Por qué cada cambio elimina la inyección.
- Qué casos legítimos verificaste que siguen funcionando (login con credenciales
  correctas, búsqueda "apple", búsqueda vacía que carga el catálogo).
- Si sugeriste alguna dependencia o patrón que hayas descartado, y por qué.
```

## 3. Respuesta de la IA (textual)

> Corregí los dos archivos y no hice commit. Probé las consultas con Sequelize 6.37.7 y SQLite: los dos ataques ya no funcionan y los casos legítimos dan lo mismo que antes. No compilé el TypeScript ni levanté la app, porque el repo no tiene node_modules.
>
> git status muestra solo routes/login.ts y routes/search.ts modificados. No toqué package.json, data/static/codefixes/, challenges.yml ni .ai/, y no corrí npm run rsn.
>
> **Diff exacto:** *(ver §4)*
>
> Cambia una línea por archivo. El resto de cada función quedó igual: el manejo de errores (.catch), el truncado a 200 caracteres, los bloques de los retos y el map de req.__. Dejé los comentarios vuln-code-snippet al final de la línea para que el diff sea mínimo; a Semgrep no le afectan.
>
> **Por qué cada cambio elimina la inyección**
>
> V-01 (bind): la consulta es ahora un texto fijo con $1 y $2. El email y el hash viajan aparte a SQLite como parámetros, así que la base nunca los lee como SQL. Una comilla en ' OR 1=1-- se compara como parte del email y no cierra la cadena.
>
> V-02 (replacements): la consulta también es fija, con :criteria. Sequelize pone el valor como un literal de texto escapado: las comillas se duplican, así que qwert')) no puede cerrar los paréntesis ni agregar el UNION. Los comodines % van dentro del valor, no en la consulta, así que el marcador queda fuera de comillas y Sequelize sí lo reemplaza.
>
> **Lo que verifiqué**
>
> | Caso | Antes | Después |
> |---|---|---|
> | Login `' OR 1=1--` (PoC de V-01) | sesión de admin | null → 401 |
> | Login `admin@juice-sh.op'--` | — | null |
> | Login `admin@juice-sh.op` / `admin123` (correcto) | usuario | usuario ✅ |
> | Login admin con contraseña incorrecta | — | null ✅ |
> | Login con comilla legítima (`o'brien@…`) | — | usuario ✅ |
> | Email que no es texto (`["a"]`, `{"a":1}`) o cuerpo vacío | — | null, sin error |
> | Búsqueda con el UNION de V-02 | 3 filas de Users (email y hash) | 0 filas ✅ |
> | Búsqueda `""` (la que usa la tienda para cargar el catálogo) | — | catálogo completo ✅ |
> | Búsqueda `"apple"` | — | Apple Juice ✅ |
> | Búsqueda `"monkeys"` (coincide en la descripción) | — | Banana Juice ✅ |
> | Búsqueda con comilla (`o'`) | — | 0 filas, sin error |
>
> Cómo se hizo la prueba: en una carpeta aparte instalé sequelize@6.37.7 y sqlite3@5.1.7, las mismas que pide package.json. Ahí creé tablas Users y Products en memoria y corrí las consultas viejas, las nuevas y la del codefix de referencia. No probé la app completa: falta la re-prueba del Red Team contra el contenedor que indica el plan (V-01 → 401, V-02 → 0 filas) y compilar el TypeScript con npm run build:server, que también se hace al construir la imagen.
>
> Una búsqueda con % o _ sigue funcionando como comodín de LIKE: "100%" encuentra "Apple Juice (1000ml)". Eso ya pasaba antes y no es una inyección, porque solo cambia qué productos coinciden, no la consulta.
>
> **Patrones descartados y dependencias**
>
> LIKE '%:criteria%' (el codefix de referencia): lo probé y lo descarté. Con Sequelize 6.37.7 devuelve 0 filas tanto para "" como para "apple", porque el marcador está entre comillas y no se reemplaza. Confirma el hallazgo del plan.
>
> Dependencias nuevas: no sugerí ninguna (nada de validadores ni ORMs extra). Los dos fixes usan Sequelize, que ya estaba. sequelize y sqlite3 solo se instalaron en la carpeta temporal para probar y no entraron al repo.
>
> Como esperaba el plan, esto rompe los retos loginAdminChallenge y unionSqlInjectionChallenge. También rompe dbSchemaChallenge, que usa la misma línea de la búsqueda.
>
> ¿Hago el commit con -s y sin la línea Co-Authored-By, como pide el plan?

## 4. Cambios aplicados (diff)

```diff
--- a/routes/login.ts
+++ b/routes/login.ts
@@ -31,7 +31,7 @@ export function login () {
   return (req: Request, res: Response, next: NextFunction) => {
     verifyPreLoginChallenges(req) // vuln-code-snippet hide-line
-    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
+    models.sequelize.query('SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL', { bind: [req.body.email || '', security.hash(req.body.password || '')], model: UserModel, plain: true }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge

--- a/routes/search.ts
+++ b/routes/search.ts
@@ -20,7 +20,7 @@ export function searchProducts () {
     let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
     criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
-    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
+    models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name', { replacements: { criteria: `%${criteria}%` } }) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
```

Commit: `fix(h4): consultas parametrizadas en login y búsqueda (V-01, V-02)` · hash: *pendiente*

## 5. Qué se aceptó, corrigió o rechazó

| Elemento | Decisión | Motivo |
|---|---|---|
| V-01 con `bind` (`$1`, `$2`) | **Aceptado** | Consulta fija; el email y el hash viajan como parámetros. Coincide con el codefix de referencia `loginAdminChallenge_4_correct.ts` |
| V-02 con `replacements` y `LIKE :criteria`, comodines en el valor | **Aceptado** | Consulta fija; el valor se escapa como literal. Funciona con la búsqueda vacía, por nombre y por descripción |
| Patrón `LIKE '%:criteria%'` (codefix de referencia `unionSqlInjectionChallenge_2_correct.ts`) | **Rechazado** | Con Sequelize 6.37.7 el marcador entre comillas no se reemplaza: devuelve 0 productos para cualquier búsqueda, incluida la vacía con la que la SPA carga el catálogo. Elimina la inyección, pero rompe la tienda (BO-1) |
| Comentarios `// vuln-code-snippet vuln-line …` en las líneas corregidas | **Aceptado con nota** | Se conservan para que el diff sea mínimo. Son etiquetas del proyecto original para sus retos de código; en este fork ya no describen una línea vulnerable |
| Dependencias nuevas | **Ninguna** | La IA no propuso paquetes; `package.json` y `frontend/package.json` no cambian |

## 6. Auditoría del código generado (hallazgos concretos)

1. **El fix "canónico" de V-02 no servía.** La referencia del propio proyecto, y una sugerencia típica de IA, usa `LIKE '%:criteria%'`. Se verificó con Sequelize 6.37.7 y SQLite que devuelve 0 filas para `""` y para `"apple"`. Se detectó al revisar el plan, se prohibió en el prompt y Claude Code lo confirmó con su propia prueba. Lección: un fix de seguridad puede eliminar la vulnerabilidad y a la vez romper la funcionalidad; hay que probar los casos legítimos, no solo el ataque.
2. **Las instrucciones para IA del repositorio empujaban en la dirección contraria.** `AGENTS.md` (y `.claude/CLAUDE.md`, que apunta a él) describe Juice Shop como vulnerable a propósito y pide correr el RSN y actualizar `data/static/codefixes/` al tocar código de un reto. Seguirlas habría mantenido la consistencia de los retos, no la seguridad. El prompt las anuló de forma explícita y el asistente lo respetó: `git status` solo muestra `routes/login.ts` y `routes/search.ts`. Lección: los archivos de instrucciones que vienen con un repositorio también son una entrada no confiable para un asistente de IA.
3. **Impacto no previsto en el plan.** El asistente señaló que el fix de la búsqueda también rompe `dbSchemaChallenge`, que usa la misma línea. Es esperado y se agrega a las notas del H4.
4. **Límite de la verificación de la IA.** Las pruebas de Claude Code se hicieron sobre tablas en memoria, no sobre la aplicación. No compiló el TypeScript ni levantó Juice Shop, y lo dijo explícitamente. La compilación y la re-prueba contra el contenedor se hacen aparte (§7).
5. **Slopsquatting.** Sin dependencias nuevas. `sequelize@6.37.7` y `sqlite3@5.1.7` se instalaron solo en una carpeta temporal fuera del repositorio para la prueba; son las versiones que ya declara `package.json`.
6. **Secretos.** Los cambios no agregan credenciales, llaves ni tokens. Se confirma con el escaneo de secretos del pipeline (`p/secrets` y regla `juice-shop-hardcoded-private-key`): *resultado pendiente* (§7).

## 7. Verificación fuera de la IA

| Verificación | Esperado | Resultado |
|---|---|---|
| Construcción de la imagen desde el fork (compila el TypeScript) | Sin errores | *pendiente* |
| Re-prueba V-01 por el WAF en DetectionOnly (`BASE_URL=http://localhost:8080`) | HTTP 401, sin `authentication` | *pendiente* |
| Re-prueba V-02 por el WAF en DetectionOnly | HTTP 200, 0 filas | *pendiente* |
| Control funcional: login `admin@juice-sh.op` / `admin123` | HTTP 200 con token | *pendiente* |
| Control funcional: búsqueda `apple` y catálogo (`q=`) | ≥1 producto y catálogo completo | *pendiente* |
| SAST en el pipeline: `sast.error` | Menor que 40; sin hallazgos en `login.ts:34` ni `search.ts:23` | *pendiente* |
| Gate en `enforce` tras el ratchet | Verde | *pendiente* |

El detalle de la re-prueba y del pipeline está en [`docs/hito-4/remediacion-h4.md`](../hito-4/remediacion-h4.md).