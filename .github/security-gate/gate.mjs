// Lee los reportes de Semgrep, npm audit, Syft y ZAP, los compara contra
// baseline.json y decide si el pipeline pasa. Sin dependencias externas.
// Uso: node gate.mjs <carpeta-de-reportes> <baseline.json> [salida.json]

import fs from 'node:fs'
import path from 'node:path'

const [reportsDir = 'reports', baselinePath = '.github/security-gate/baseline.json', outPath] = process.argv.slice(2)

const readJson = (relPath) => {
  const file = path.join(reportsDir, relPath)
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

const missing = []

function semgrepMetrics () {
  const report = readJson('semgrep-report/semgrep.json')
  if (!Array.isArray(report?.results)) {
    missing.push('SAST (semgrep-report/semgrep.json)')
    return {}
  }
  const counts = { error: 0, warning: 0, info: 0 }
  for (const result of report.results) {
    const severity = String(result.extra?.severity ?? '').toUpperCase()
    if (['ERROR', 'CRITICAL', 'HIGH'].includes(severity)) counts.error++
    else if (['WARNING', 'MEDIUM'].includes(severity)) counts.warning++
    else counts.info++
  }
  return {
    'sast.error': counts.error,
    'sast.warning': counts.warning,
    'sast.info': counts.info,
    'sast.scan-errors': report.errors?.length ?? 0
  }
}

function npmAuditMetrics (scope) {
  const report = readJson(`sca-report/npm-audit-${scope}.json`)
  const vulns = report?.metadata?.vulnerabilities
  if (!vulns || report.error) {
    missing.push(`SCA ${scope} (sca-report/npm-audit-${scope}.json)`)
    return {}
  }
  return {
    [`sca.${scope}.critical`]: vulns.critical ?? 0,
    [`sca.${scope}.high`]: vulns.high ?? 0,
    [`sca.${scope}.moderate`]: vulns.moderate ?? 0,
    [`sca.${scope}.low`]: vulns.low ?? 0
  }
}

function sbomMetrics () {
  const sbom = readJson('sbom-cyclonedx/sbom-juice-shop.cdx.json')
  const components = sbom?.components?.length ?? 0
  if (sbom?.bomFormat !== 'CycloneDX' || components === 0) {
    missing.push('SBOM (sbom-cyclonedx/sbom-juice-shop.cdx.json)')
    return {}
  }
  return { 'sbom.components': components }
}

// Se cuentan TIPOS de alerta distintos por riesgo (no instancias), porque el
// número de URLs que encuentra el spider varía entre corridas.
function zapMetrics () {
  const report = readJson('zap-report/zap-report.json')
  if (!Array.isArray(report?.site)) {
    missing.push('DAST (zap-report/zap-report.json)')
    return {}
  }
  const byRisk = { 3: new Set(), 2: new Set(), 1: new Set(), 0: new Set() }
  for (const site of report.site) {
    for (const alert of site.alerts ?? []) {
      byRisk[Number(alert.riskcode)]?.add(alert.alertRef ?? alert.pluginid)
    }
  }
  return {
    'dast.high': byRisk[3].size,
    'dast.medium': byRisk[2].size,
    'dast.low': byRisk[1].size,
    'dast.info': byRisk[0].size
  }
}

const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'))
const mode = baseline.mode === 'enforce' ? 'enforce' : 'report'

const current = {
  ...semgrepMetrics(),
  ...npmAuditMetrics('backend'),
  ...npmAuditMetrics('frontend'),
  ...sbomMetrics(),
  ...zapMetrics()
}

const rows = []
const regressions = []
const unset = []
let improved = false

for (const [metric, limit] of Object.entries(baseline.metrics)) {
  const value = current[metric]
  let status
  if (value === undefined) {
    status = ' sin reporte'
  } else if (limit === null) {
    status = ' registrado (sin línea base)'
    unset.push(metric)
  } else if (value > limit) {
    status = ` subió (+${value - limit})`
    regressions.push(`${metric}: ${limit} → ${value}`)
  } else if (value < limit) {
    status = ` mejoró (${value - limit})`
    improved = true
  } else {
    status = ' igual'
  }
  rows.push(`| \`${metric}\` | ${limit ?? '—'} | ${value ?? '—'} | ${status} |`)
}

const informative = Object.entries(current)
  .filter(([metric]) => !(metric in baseline.metrics))
  .map(([metric, value]) => `| \`${metric}\` | ${value} |`)

const failures = [
  ...regressions.map(r => `Regresión ${r}`),
  ...missing.map(m => `Falta el reporte ${m}`),
  ...(mode === 'enforce' ? unset.map(m => `Métrica sin línea base en modo enforce: ${m}`) : [])
]
const blocked = mode === 'enforce' && failures.length > 0

const suggested = Object.fromEntries(
  Object.keys(baseline.metrics).map(metric => [metric, current[metric] ?? baseline.metrics[metric]])
)

const summary = [
  '## Security gate (no-regresión)',
  '',
  `**Modo:** \`${mode}\` · **Resultado:** ${blocked ? 'BLOQUEADO' : failures.length > 0 ? '⚠️ PASA (modo reporte, con observaciones)' : '✅ PASA'}`,
  '',
  '| Métrica controlada | Línea base | Actual | Estado |',
  '|---|---:|---:|---|',
  ...rows,
  '',
  '<details><summary>Métricas informativas (no bloquean)</summary>',
  '',
  '| Métrica | Valor |',
  '|---|---:|',
  ...informative,
  '',
  '</details>',
  ''
]
if (failures.length > 0) {
  summary.push('### Observaciones', '', ...failures.map(f => `- ${f}`), '')
}
if (improved || unset.length > 0) {
  summary.push(
    '### Línea base sugerida',
    '',
    'Si la reducción es real (o es la primera corrida), copiar en `.github/security-gate/baseline.json`:',
    '',
    '```json',
    JSON.stringify(suggested, null, 2),
    '```',
    ''
  )
}

const markdown = summary.join('\n')
if (process.env.GITHUB_STEP_SUMMARY) {
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + '\n')
}
console.log(markdown)

for (const failure of failures) {
  console.log(`::${blocked ? 'error' : 'warning'} title=Security gate::${failure}`)
}

if (outPath) {
  fs.writeFileSync(outPath, JSON.stringify({ mode, blocked, failures, baseline: baseline.metrics, current, suggested }, null, 2))
}

process.exit(blocked ? 1 : 0)
