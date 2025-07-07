#!/usr/bin/env node

/**
 * Race Condition Observer
 *
 * O que é: um utilitário JavaScript para analisar localmente registros de operações concorrentes previamente coletados.
 * O que faz: organiza eventos por recurso, detecta sobreposição temporal, versões conflitantes, resultados divergentes e
 * violações de invariantes declaradas; gera relatórios de pontos que requerem revisão. Ele não dispara requisições paralelas,
 * não altera dados, não testa sistemas externos e não tenta explorar condições de corrida.
 *
 * Uso como módulo:
 *   import { observeRaces, formatMarkdownReport } from './race-condition-observer.js';
 *
 *   const report = observeRaces({
 *     operations: [
 *       { id: 'op-1', resource: 'order-100', action: 'redeem-coupon', startedAt: '2026-09-07T20:00:00.000Z', endedAt: '2026-09-07T20:00:00.300Z', outcome: 'success', versionBefore: 4, versionAfter: 5 },
 *       { id: 'op-2', resource: 'order-100', action: 'redeem-coupon', startedAt: '2026-09-07T20:00:00.100Z', endedAt: '2026-09-07T20:00:00.400Z', outcome: 'success', versionBefore: 4, versionAfter: 5 }
 *     ]
 *   });
 *
 * Uso via CLI:
 *   node race-condition-observer.js --input operation-log.json --format markdown --output race-review.md
 */

import { readFile, writeFile } from 'node:fs/promises';

/**
 * O que é: função para interpretar timestamps de operação.
 * O que faz: converte datas ISO para milissegundos Unix e rejeita valores inválidos para permitir comparação temporal confiável.
 */
function parseTime(value, field, operationId) {
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) throw new TypeError(`Operação ${operationId}: ${field} inválido (${value}).`);
  return time;
}

/**
 * O que é: função para normalizar uma operação concorrente previamente registrada.
 * O que faz: valida identificador, recurso, ação, intervalos de tempo, resultado, versões e metadados sem executar nenhuma ação.
 */
function normalizeOperation(operation, index) {
  if (!operation || typeof operation !== 'object' || Array.isArray(operation)) {
    throw new TypeError(`operations[${index}] deve ser um objeto.`);
  }

  const id = String(operation.id ?? `op-${index + 1}`).trim();
  const resource = String(operation.resource ?? operation.resourceId ?? '').trim();
  const action = String(operation.action ?? '').trim();
  if (!id || !resource || !action) throw new TypeError(`operations[${index}] exige id, resource e action.`);

  const startedAtMs = parseTime(operation.startedAt, 'startedAt', id);
  const endedAtMs = parseTime(operation.endedAt ?? operation.finishedAt ?? operation.startedAt, 'endedAt', id);
  if (endedAtMs < startedAtMs) throw new TypeError(`Operação ${id}: endedAt é anterior a startedAt.`);

  return {
    id,
    resource,
    action,
    actor: operation.actor ?? null,
    startedAt: new Date(startedAtMs).toISOString(),
    endedAt: new Date(endedAtMs).toISOString(),
    startedAtMs,
    endedAtMs,
    durationMs: endedAtMs - startedAtMs,
    outcome: String(operation.outcome ?? operation.status ?? 'unknown').toLowerCase(),
    statusCode: Number.isInteger(operation.statusCode) ? operation.statusCode : null,
    versionBefore: operation.versionBefore ?? null,
    versionAfter: operation.versionAfter ?? null,
    idempotencyKey: operation.idempotencyKey ?? null,
    requestFingerprint: operation.requestFingerprint ?? null,
    resultFingerprint: operation.resultFingerprint ?? null,
    beforeState: operation.beforeState ?? null,
    afterState: operation.afterState ?? null,
    notes: operation.notes ?? null,
  };
}

/**
 * O que é: função para criar achados padronizados de concorrência.
 * O que faz: registra severidade, código, recurso, operações relacionadas, mensagem e recomendação para priorização de revisão.
 */
function finding(severity, code, resource, operationIds, message, recommendation) {
  return { severity, code, resource, operationIds, message, recommendation };
}

/**
 * O que é: função para verificar sobreposição entre duas operações.
 * O que faz: retorna true quando os intervalos de execução se cruzam, incluindo operações iniciadas antes de outra terminar.
 */
function overlaps(first, second) {
  return first.startedAtMs < second.endedAtMs && second.startedAtMs < first.endedAtMs;
}

/**
 * O que é: função para normalizar invariantes declaradas para um recurso.
 * O que faz: aceita regras simples de não duplicação, máximo de sucessos e versão monotônica, usadas apenas na revisão de logs locais.
 */
function normalizeInvariants(invariants = []) {
  if (!Array.isArray(invariants)) throw new TypeError('invariants deve ser um array.');
  return invariants.map((invariant, index) => {
    if (!invariant || typeof invariant !== 'object') throw new TypeError(`invariants[${index}] deve ser um objeto.`);
    const type = String(invariant.type ?? '').trim();
    if (!['max-successes', 'unique-success-per-key', 'version-monotonic'].includes(type)) {
      throw new TypeError(`invariants[${index}].type inválido: ${type}`);
    }
    return {
      id: String(invariant.id ?? `invariant-${index + 1}`),
      type,
      resource: invariant.resource ?? null,
      action: invariant.action ?? null,
      max: invariant.max === undefined ? null : Number(invariant.max),
      key: invariant.key ?? 'idempotencyKey',
      notes: invariant.notes ?? null,
    };
  });
}

/**
 * O que é: função para aplicar invariantes a registros de operação.
 * O que faz: procura padrões documentados de duplicação ou progressão de versão inválida; resultados são hipóteses de revisão e
 * não provam uma condição de corrida sem análise do domínio, transações e logs de backend.
 */
function checkInvariants(operations, invariants) {
  const findings = [];

  for (const invariant of invariants) {
    const scope = operations.filter((operation) =>
      (!invariant.resource || operation.resource === invariant.resource) &&
      (!invariant.action || operation.action === invariant.action)
    );

    if (invariant.type === 'max-successes' && Number.isFinite(invariant.max)) {
      const successes = scope.filter((operation) => operation.outcome === 'success');
      if (successes.length > invariant.max) {
        findings.push(finding('high', 'invariant-max-successes-violated', invariant.resource ?? 'all', successes.map((operation) => operation.id), `Invariante ${invariant.id}: ${successes.length} sucessos observados, máximo declarado ${invariant.max}.`, 'Implemente transações, bloqueios, constraints ou controle de concorrência compatível com a regra de negócio.'));
      }
    }

    if (invariant.type === 'unique-success-per-key') {
      const groups = new Map();
      for (const operation of scope.filter((item) => item.outcome === 'success')) {
        const value = operation[invariant.key];
        if (!value) continue;
        const group = groups.get(String(value)) ?? [];
        group.push(operation);
        groups.set(String(value), group);
      }
      for (const [key, group] of groups) {
        if (group.length > 1) {
          findings.push(finding('high', 'invariant-unique-success-violated', invariant.resource ?? 'all', group.map((operation) => operation.id), `Invariante ${invariant.id}: ${group.length} sucessos compartilham ${invariant.key}=${key}.`, 'Aplique constraint de unicidade e tratamento idempotente no servidor; registre resultado consistente para repetições legítimas.'));
        }
      }
    }

    if (invariant.type === 'version-monotonic') {
      const byResource = new Map();
      for (const operation of scope) {
        const group = byResource.get(operation.resource) ?? [];
        group.push(operation);
        byResource.set(operation.resource, group);
      }
      for (const [resource, group] of byResource) {
        const ordered = [...group].sort((a, b) => a.endedAtMs - b.endedAtMs);
        for (let index = 1; index < ordered.length; index += 1) {
          const previous = ordered[index - 1];
          const current = ordered[index];
          if (typeof previous.versionAfter === 'number' && typeof current.versionAfter === 'number' && current.versionAfter < previous.versionAfter) {
            findings.push(finding('medium', 'invariant-version-monotonic-violated', resource, [previous.id, current.id], `Invariante ${invariant.id}: versão final regrediu de ${previous.versionAfter} para ${current.versionAfter}.`, 'Use controle de versão otimista, transações ou serialização apropriada para preservar consistência.'));
          }
        }
      }
    }
  }

  return findings;
}

/**
 * O que é: observador local de possíveis condições de corrida.
 * O que faz: agrupa operações por recurso, detecta sobreposições e padrões de versão/resultado que merecem revisão; não gera
 * concorrência, não chama a aplicação e não conclui que uma vulnerabilidade exista sem confirmação no contexto autorizado.
 *
 * @param {object} input Registros locais de operações e invariantes opcionais.
 * @returns {object} Relatório de análise de concorrência.
 */
export function observeRaces(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('input deve ser um objeto.');
  if (!Array.isArray(input.operations) || input.operations.length === 0) throw new TypeError('operations deve ser um array não vazio.');

  const operations = input.operations.map(normalizeOperation).sort((a, b) => a.startedAtMs - b.startedAtMs);
  const invariants = normalizeInvariants(input.invariants ?? []);
  const byResource = new Map();
  const findings = [];

  for (const operation of operations) {
    const group = byResource.get(operation.resource) ?? [];
    group.push(operation);
    byResource.set(operation.resource, group);
  }

  for (const [resource, group] of byResource) {
    for (let firstIndex = 0; firstIndex < group.length; firstIndex += 1) {
      for (let secondIndex = firstIndex + 1; secondIndex < group.length; secondIndex += 1) {
        const first = group[firstIndex];
        const second = group[secondIndex];
        if (!overlaps(first, second)) continue;

        findings.push(finding('info', 'overlapping-operations', resource, [first.id, second.id], `Operações ${first.id} e ${second.id} se sobrepõem por recurso ${resource}.`, 'Revise se a operação exige serialização, idempotência, lock, constraint ou controle de versão otimista.'));

        if (first.action === second.action && first.outcome === 'success' && second.outcome === 'success') {
          findings.push(finding('medium', 'concurrent-successes-same-action', resource, [first.id, second.id], `Duas operações concorrentes da ação ${first.action} foram registradas como sucesso.`, 'Confirme se múltiplos sucessos são válidos no domínio; para operações únicas, use idempotência e controles transacionais.'));
        }

        if (first.versionBefore !== null && second.versionBefore !== null && first.versionBefore === second.versionBefore && first.outcome === 'success' && second.outcome === 'success') {
          findings.push(finding('high', 'same-version-concurrent-commit', resource, [first.id, second.id], `Operações concorrentes bem-sucedidas partiram da mesma versão ${first.versionBefore}.`, 'Aplique controle otimista de concorrência com comparação atômica de versão ou use bloqueio/transação adequado.'));
        }

        if (first.idempotencyKey && second.idempotencyKey && first.idempotencyKey === second.idempotencyKey && first.outcome === 'success' && second.outcome === 'success') {
          const resultsDiffer = first.resultFingerprint && second.resultFingerprint && first.resultFingerprint !== second.resultFingerprint;
          findings.push(finding(resultsDiffer ? 'high' : 'medium', resultsDiffer ? 'idempotency-key-divergent-result' : 'duplicate-idempotency-key-success', resource, [first.id, second.id], resultsDiffer ? 'Mesmo idempotency key produziu resultados diferentes em operações concorrentes.' : 'Mesmo idempotency key produziu mais de um sucesso concorrente.', 'Armazene e retorne o primeiro resultado idempotente de forma atômica, com constraint de unicidade para a chave e escopo apropriado.'));
        }
      }
    }
  }

  findings.push(...checkInvariants(operations, invariants));

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    observedAt: new Date().toISOString(),
    operations: operations.map(({ startedAtMs, endedAtMs, ...operation }) => operation),
    invariants,
    findings,
    summary: {
      operations: operations.length,
      resources: byResource.size,
      overlappingPairs: findings.filter((item) => item.code === 'overlapping-operations').length,
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
    },
    limitation: 'O relatório analisa somente registros locais. Sobreposição temporal é um sinal de concorrência, não prova de falha; confirme invariantes, transações, locks, isolamento e estado final no ambiente autorizado.',
  };
}

/**
 * O que é: gerador de relatório Markdown de observação de concorrência.
 * O que faz: apresenta operações, invariantes e achados em tabelas legíveis para revisão de engenharia, QA e segurança.
 */
export function formatMarkdownReport(report) {
  if (!report || !Array.isArray(report.operations) || !Array.isArray(report.findings)) {
    throw new TypeError('Forneça um relatório retornado por observeRaces.');
  }

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Race Condition Observation Report',
    '',
    `- **Operações observadas:** ${report.summary.operations}`,
    `- **Recursos envolvidos:** ${report.summary.resources}`,
    `- **Pares sobrepostos:** ${report.summary.overlappingPairs}`,
    `- **Maior severidade:** ${report.summary.highestSeverity}`,
    `- **Limitação:** ${report.limitation}`,
    '',
    '## Operações',
    '',
    '| ID | Recurso | Ação | Início | Fim | Resultado | Versão antes → depois | Idempotency key |',
    '|---|---|---|---|---|---|---|---|',
  ];

  for (const operation of report.operations) {
    lines.push(`| ${clean(operation.id)} | ${clean(operation.resource)} | ${clean(operation.action)} | ${operation.startedAt} | ${operation.endedAt} | ${clean(operation.outcome)} | ${clean(`${operation.versionBefore ?? '—'} → ${operation.versionAfter ?? '—'}`)} | ${clean(operation.idempotencyKey ? '[registrada]' : '—')} |`);
  }

  lines.push('', '## Achados', '', '| Severidade | Recurso | Operações | Código | Observação | Recomendação |', '|---|---|---|---|---|---|');
  if (report.findings.length === 0) {
    lines.push('| — | — | — | — | Nenhum achado produzido pelas regras locais. | Revise invariantes e logs completos quando necessário. |');
  } else {
    for (const item of report.findings) {
      lines.push(`| ${item.severity} | ${clean(item.resource)} | ${clean(item.operationIds.join(', '))} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter argumentos de terminal.
 * O que faz: retorna o valor após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: descreve o formato de logs locais e a geração de relatórios sem disparar cargas concorrentes contra aplicações.
 */
function showHelp() {
  console.log(`\nUso:\n  node race-condition-observer.js --input operation-log.json [opções]\n\nFormato de entrada:\n  {\n    "operations": [\n      {\n        "id": "op-1",\n        "resource": "order-100",\n        "action": "redeem-coupon",\n        "startedAt": "2026-09-07T20:00:00.000Z",\n        "endedAt": "2026-09-07T20:00:00.300Z",\n        "outcome": "success",\n        "versionBefore": 4,\n        "versionAfter": 5,\n        "idempotencyKey": "chave-redigida-ou-hash"\n      }\n    ],\n    "invariants": [\n      { "id": "um-resgate", "type": "max-successes", "resource": "order-100", "action": "redeem-coupon", "max": 1 },\n      { "id": "idempotencia", "type": "unique-success-per-key", "key": "idempotencyKey" }\n    ]\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node race-condition-observer.js --input operation-log.json --format markdown --output race-review.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const report = observeRaces(JSON.parse(await readFile(input, 'utf8')));
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(report)
        : JSON.stringify(report, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
