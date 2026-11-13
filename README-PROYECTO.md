# Proyecto Final: Juice Shop y el SSDLC

Universidad del Valle de Guatemala, Campus Central
Curso: Desarrollo Seguro, Ciclo 2, Año 2026

Este repositorio es un fork de [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop). Se usa para recorrer el ciclo de vida de desarrollo seguro (Secure SDLC) sobre OWASP Juice Shop: modelado de amenazas, pipeline DevSecOps, pruebas ofensivas, detección y bloqueo en tiempo de ejecución, y remediación asistida por IA.

El `README.md` original de Juice Shop se conserva sin cambios. Este archivo documenta únicamente el proyecto del grupo.

## Equipo y roles

| Integrante | Rol | Responsabilidad principal |
|---|---|---|
| Sebastián Huertas | Red Team | Estructura del repositorio, reconocimiento, casos de abuso, PoC de inyección (SQLi, XSS) |
| Gerson Ramírez | Red Team | PoC de control de acceso y configuración, ráfagas y escaneo para detección por IP |
| Juan Pablo Solís | Blue Team | A completar por el equipo |
| Josué Marroquín | Blue Team | A completar por el equipo |

El pipeline DevSecOps, la auditoría del código generado por IA y el informe final son responsabilidad de los cuatro integrantes.

## Reglas de enfrentamiento

1. Solo se ataca la instancia local del grupo (Juice Shop levantado con Docker en una máquina de un integrante).
2. Está prohibido escanear o atacar el Juice Shop público (`juice-shop.herokuapp.com`), recursos de la Universidad o de terceros.
3. Todo ataque ejecutado queda registrado en el informe, con fecha, hora, payload y resultado.
4. El incumplimiento se sanciona según el reglamento de la Universidad.

## Uso de IA

El uso de IA está permitido según la guía de la UVG. En el Hito 4 es obligatorio y debe documentarse: herramienta, prompt, respuesta y cambios realizados. Los registros se guardan en `docs/ia/`. Todo código generado por IA se audita con el mismo rigor que cualquier otro antes de integrarse (SAST, revisión manual con la checklist del curso, verificación de dependencias sugeridas y búsqueda de secretos).

## Estructura del repositorio

```
.
├── .github/workflows/        Workflow DevSecOps del grupo (los originales de Juice Shop fueron eliminados)
├── entorno-blue-team/        Docker Compose: Juice Shop tras ModSecurity + OWASP CRS, Elasticsearch, Kibana, Filebeat
├── blue-team/
│   ├── reglas-siem/          Reglas de detección exportadas
│   └── consultas/            Consultas y búsquedas guardadas
├── red-team/
│   ├── poc/                  Una PoC reproducible por vulnerabilidad
│   └── evidencias/           Capturas y logs con fecha y hora
└── docs/
    ├── hito-1/               Diseño seguro y modelado de amenazas
    ├── hito-2/               Pipeline y ataque (incluye sbom/)
    ├── hito-3/               Detección y respuesta
    ├── hito-4/               Remediación con IA
    ├── ia/                   Registro del uso de IA
    └── informe-final/        Matriz de trazabilidad e informe consolidado
```

## Hitos

| Hito | Contenido | Carpeta | Estado |
|---|---|---|---|
| Configuración | Grupos y roles, repositorio, entorno levantado (Juice Shop responde por el WAF en `localhost:8080`) | `entorno-blue-team/` | Pendiente |
| H1 | PASTA etapas 1-4, DFD con límites de confianza, STRIDE, requisitos de seguridad, 5 casos de abuso, reconocimiento | `docs/hito-1/` | Pendiente |
| H2 | Workflow con SAST, SCA, SBOM (CycloneDX con Syft) y DAST (ZAP baseline), security gate, 4 vulnerabilidades explotadas | `docs/hito-2/`, `.github/workflows/` | En progreso |
| H3 | Logs del WAF en Elastic, 3 reglas de detección, dashboard, WAF en DetectionOnly y luego en On | `docs/hito-3/`, `blue-team/` | Pendiente |
| H4 | Corrección de 2 vulnerabilidades con IA, auditoría del código generado, re-prueba | `docs/hito-4/`, `docs/ia/` | Pendiente |
| Informe final | Línea de tiempo, matriz de trazabilidad, riesgo residual, lecciones aprendidas | `docs/informe-final/` | Pendiente |

## Cómo levantar el entorno

Pendiente. Esta sección se completa cuando el Blue Team entregue `entorno-blue-team/`. Debe incluir como mínimo:

1. Requisitos (Docker, Docker Compose, memoria disponible para Elasticsearch).
2. Comando para levantar el entorno.
3. URL de acceso a Juice Shop a través del WAF: `http://localhost:8080`.
4. URL de Kibana.
5. Alternativa con Elastic Cloud si Elastic no corre localmente.

Para pruebas rápidas de reconocimiento, sin WAF ni SIEM, se puede levantar Juice Shop de forma aislada:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Esta instancia queda en `http://localhost:3000`. Los resultados de pruebas hechas aquí no sirven como evidencia de detección o bloqueo, porque no pasan por el WAF.

## Flujo de trabajo en Git

- La rama principal es `master`. No se hace push directo; todo entra por Pull Request con al menos una aprobación de otro integrante.
- Convención de ramas: `hito-N`, `blue/<tema>`, `red/<tema>`.
- Mensajes de commit en formato `tipo: descripción` (por ejemplo `feat:`, `fix:`, `docs:`, `chore:`).
- Los secretos nunca se versionan. Cualquier credencial o token va en GitHub Secrets.
- Las evidencias de ataque incluyen fecha y hora, porque el Blue Team las usa para validar sus reglas.

## Clasificación de hallazgos

Cada vulnerabilidad encontrada por el Red Team se documenta con:

- Descripción y pasos de reproducción (PoC en `red-team/poc/`).
- Categoría OWASP Top 10:2025.
- CWE.
- Vector CVSS v3.1 con justificación por cada métrica.
- Evidencia con fecha y hora.

Cada hallazgo se registra como una fila en `docs/informe-final/matriz-trazabilidad.md`, con las columnas: hallazgo, OWASP/CWE, CVSS v3.1, detección en pipeline, detección en SIEM, bloqueo en WAF, corrección y re-prueba.

## Referencias

- OWASP Juice Shop: https://github.com/juice-shop/juice-shop
- OWASP CRS (imagen Docker): https://github.com/coreruleset/modsecurity-crs-docker
- ZAP: https://www.zaproxy.org/docs/docker/
- Syft (SBOM): https://github.com/anchore/syft
- Elastic Stack: https://www.elastic.co/docs
- UcedaVélez, T. y Morana, M. (2015). Risk Centric Threat Modeling: Process for Attack Simulation and Threat Analysis. Wiley.
