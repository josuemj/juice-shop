# Hito 3 · Detección y respuesta - Blue Team

## 1. Resumen

**logs del WAF en Elastic, reglas de detección, WAF en DetectionOnly y luego en On, con los falsos positivos documentados y ajustados**.

Orden:

1. **DetectionOnly** (el WAF registra, no bloquea) → se genera tráfico legítimo y se observan los **falsos positivos** en Kibana.
2. Se **ajusta** el WAF con exclusiones específicas para cada falso positivo.
3. Se verifica en DetectionOnly que el tráfico legítimo ya no dispara reglas, sin perder la detección de ataques.
4. Se pasa el WAF a **On** (bloquea con 403) y se comprueba que el cliente legítimo no se bloquea y que los ataques sí.

## 2. Reglas de detección en el SIEM

[`blue-team/reglas-siem/`](../../blue-team/reglas-siem/) y se cargan en Kibana con [`cargar-reglas.sh`](../../blue-team/reglas-siem/cargar-reglas.sh).

| Regla (Kibana) | Tipo | Lógica | Detecta |
|---|---|---|---|
| **H3-01 · Inyección SQL** | Query | `tags:"waf" and ...ruleId : 942*` | V-01 (SQLi login), V-02 (SQLi UNION) |
| **H3-02 · XSS** | Query | `tags:"waf" and ...ruleId : 941*` | V-03 (XSS) |
| **H3-03 · Ráfaga de logins por IP** | Threshold | ≥20 respuestas 401 en `/rest/user/login` por `source.ip` en 1 min | V-06 (fuerza bruta) |

Verlas en Kibana: **☰ → Security → Rules → Detection rules (SIEM)**. Las alertas: **Security → Alerts**.

## 3. Falsos positivos documentados

En DetectionOnly se generó tráfico de un cliente normal con [`generar-trafico-legitimo.sh`](../../blue-team/falsos-positivos/generar-trafico-legitimo.sh) (registro, búsqueda, carrito, reseña, feedback, perfil).

Se observaron **3 falsos positivos**, los tres alcanzando el score de anomalía 5 (regla `949110`), es decir, en modo On los tres habrían devuelto **403 y roto la tienda** para un usuario real:

| # | Regla CRS | Petición legítima | Causa |
|---|---|---|---|
| FP-1 | **911100** · Method is not allowed by policy | `PUT /rest/products/:id/reviews` | El CRS solo permite GET/HEAD/POST/OPTIONS por defecto; Juice Shop es una API REST y usa PUT/PATCH/DELETE de forma legítima |
| FP-2 | **932260** · Remote Command Execution (Unix) | `GET /rest/user/whoami` | La ruta contiene la palabra `whoami`, que es un comando Unix: la regla la marca por el **nombre del endpoint**, no por un ataque |
| FP-3 | **920420** · Request content type is not allowed | `POST /socket.io/...` | El canal de notificaciones en tiempo real de la tienda hace polling con un content-type que la regla no permite |

## 4. Ajustes aplicados

Por cada falso positivo se escribió una exclusión en [`entorno-blue-team/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`](../../entorno-blue-team/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf) (IDs 1001–1003). El archivo se monta dentro del WAF, así que las exclusiones se aplican solas al levantar el entorno y siguen activas tanto en DetectionOnly como en On.

| Exclusión | Qué hace | Por qué NO abre la puerta al Red Team |
|---|---|---|
| **1001** (FP-1) | Amplía los métodos permitidos a GET/HEAD/POST/OPTIONS/PUT/PATCH/DELETE | Todas las PoC del Red Team usan solo GET/POST; permitir PUT/PATCH/DELETE no habilita ninguna |
| **1002** (FP-2) | Quita **solo** la regla 932260 y **solo** en `/rest/user/whoami` | Ninguna PoC pasa por `/rest/user/whoami`; el resto de reglas RCE siguen activas en todo el sitio |
| **1003** (FP-3) | Quita **solo** la regla 920420 y **solo** en `/socket.io/` | Ninguna PoC pasa por `/socket.io/`; la validación de content-type sigue activa en el resto de rutas |

Tras aplicar las exclusiones, un ataque de control de SQLi siguió disparando `942100` y uno de XSS siguió disparando la familia `941xxx`. Las exclusiones eliminan los falsos positivos sin afectar la detección de ataques reales.

## 5. Evidencia (4 escenarios)

Cada escenario tiene un **marcador** en el `User-Agent` para filtrarlo exactamente en Kibana. Las horas están en UTC (en Kibana, ajustar el rango de tiempo a la ventana indicada; Kibana muestra hora local America/Guatemala = UTC−6).

### S1 - DetectionOnly - ANTES del ajuste (3 falsos positivos)

Tráfico legítimo con el WAF en DetectionOnly y **sin** exclusiones. Se ven las reglas `911100` y `932260` sobre peticiones legítimas (y `920420` sobre el `/socket.io/` que genera la propia app).

- **KQL:** `user_agent.original : "cliente-legitimo-20261119T194941" and modsec.transaction.messages.details.ruleId : *`
- **Rango:** 2026-11-19 19:49:40 – 19:50:10 (hora local)
- **Resultado esperado en la captura:** eventos con `ruleId` 911100 y 932260 sobre `/rest/products/*/reviews` y `/rest/user/whoami`.

![S1 falsos positivos antes del ajuste](img/s1-detectiononly-antes-fp.jpg)

### S2 - DetectionOnly - DESPUÉS del ajuste (0 falsos positivos)

Mismo tráfico legítimo, con las exclusiones ya aplicadas. No aparece ninguna regla.

- **KQL:** `user_agent.original : "cliente-legitimo-20261119T195257" and modsec.transaction.messages.details.ruleId : *`
- **Rango:** 2026-11-19 19:53:00 – 19:53:30 (hora local)

![S2 sin falsos positivos tras el ajuste](img/s2-detectiononly-despues-ok.jpg)

### S3 - Modo On - tráfico legítimo NO se bloquea

WAF en On (bloqueo). Tráfico legítimo: ninguna petición recibe 403.

- **KQL:** `user_agent.original : "cliente-legitimo-20261119T202339"`
- **Rango:** 2026-11-19 20:23:40 – 20:24:00 (hora local)

![S3 modo On, cliente legítimo sin bloqueos](img/s3-on-legitimo-sin-403.jpg)

### S4 - Modo On - ataques BLOQUEADOS y alertados

WAF en On. Ataques SQLi y XSS: los tres reciben **403** y disparan las reglas del SIEM.

- **KQL (eventos del WAF):** `user_agent.original : "ataque-on-*" and http.response.status_code : 403`
- **Captura de alertas:** **☰ → Security → Alerts**, rango 2026-11-19 20:23:45 – 20:24:00.

| Ataque | Ruta | HTTP | Alerta SIEM |
|---|---|---|---|
| V-01 SQLi login | `/rest/user/login` | 403 | H3-01 · Inyección SQL |
| V-02 SQLi UNION | `/rest/products/search` | 403 | H3-01 · Inyección SQL |
| V-03 XSS | `/rest/products/search` | 403 | H3-02 · XSS |

![S4 modo On, ataques bloqueados con 403](img/s4-on-ataques-403.jpg)
![S4 alertas del SIEM](img/s4-on-alertas-siem.jpg)

## 6. Resultado

| | DetectionOnly | Modo On |
|---|---|---|
| **Cliente legítimo, antes del ajuste** | 3 falsos positivos (S1) | (habría dado 403: no se llega a este punto) |
| **Cliente legítimo, después del ajuste** | 0 falsos positivos (S2) | 0 bloqueos (S3) |
| **Ataques SQLi/XSS** | detectados, pasan (DetectionOnly no bloquea) | **403 bloqueados + alertados** (S4) |

El WAF quedó ajustado: bloquea los ataques del perímetro sin estorbar al cliente legítimo, y el SIEM genera alertas con hora, IP, ruta y regla.

## 7. Cómo Reproducir

```bash
# 1. Entorno  /entorno-blue-team
docker compose up -d && ./verificar.sh

# 2. Reglas de detección en Kibana
bash blue-team/reglas-siem/cargar-reglas.sh

# 3. Tráfico legítimo
bash blue-team/falsos-positivos/generar-trafico-legitimo.sh

# 4. Cambiar el WAF a modo On (bloqueo) para la demo
#    en entorno-blue-team/.env: MODSEC_RULE_ENGINE=On
cd entorno-blue-team && docker compose up -d --force-recreate waf
```
