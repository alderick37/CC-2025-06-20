#!/usr/bin/env node

/**
 * Response Differ
 *
 * O que é: um utilitário JavaScript para comparar respostas HTTP previamente coletadas e armazenadas em arquivos locais.
 * O que faz: normaliza status, headers e corpo, mascara valores voláteis configuráveis, calcula diferenças estruturadas e
 * gera relatórios JSON ou Markdown. Ele não envia requisições, não acessa URLs e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { diffResponses, formatMarkdownReport } from './response-differ.js';
 *
 *   const diff = diffResponses(
 *     { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' },
 *     { status: 500, headers: { 'content-type': 'application/json' }, body: '{"error":"internal"}' }
 *   );
 *   console.log(formatMarkdownReport(diff));
 *
 * Uso via CLI:
 *   node response-differ.js --baseline baseline.json --candidate candidate.json --format markdown --output diff.md
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

/**
 * O que é: função para normalizar um objeto de headers HTTP.
 * O que faz: converte nomes para minúsculas, valores para texto e agrupa valores duplicados, permitindo comparação
 * consistente mesmo quando a capitalização original dos headers for diferente.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TypeError('headers deve ser um objeto simples.');
  }

  const normalized = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase().trim();
    if (!name) continue;
    const value = Array.isArray(rawValue) ? rawValue.map(String).join(', ') : String(rawValue ?? '');
    normalized[name] = normalized[name] ? `${normalized[name]}, ${value}` : value;
  }
  return normalized;
}

/**
 * O que é: função para obter um hash curto de conteúdo.
 * O que faz: calcula SHA-256 e retorna apenas os primeiros caracteres para identificar corpos sem incluí-los integralmente
 * em relatórios, o que reduz ruído e exposição de dados potencialmente sensíveis.
 */
function shortHash(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
}

/**
 * O que é: função para aplicar máscaras em valores voláteis.
 * O que faz: substitui padrões como timestamps, UUIDs, IDs numéricos ou expressões personalizadas por marcadores antes da
 * comparação, reduzindo falsos positivos entre respostas semanticamente equivalentes.
 */
function maskVolatileValues(value, patterns = []) {
  let result = String(value ?? '');
  for (const pattern of patterns) {
    const expression = pattern instanceof RegExp ? pattern : new RegExp(String(pattern), 'g');
    const flags = expression.flags.includes('g') ? expression.flags : `${expression.flags}g`;
    result = result.replace(new RegExp(expression.source, flags), '[VALOR_VOLATIL]');
  }
  return result;
}

/**
 * O que é: função para ordenar objetos JSON recursivamente.
 * O que faz: cria uma representação determinística de objetos e arrays para permitir comparação de JSON independente da
 * ordem de propriedades; arrays preservam sua ordem por poderem ter significado semântico.
 */
function stableJson(value) {
  if (Array.isArray(value)) return value.map(stableJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableJson(value[key])]));
  }
  return value;
}

/**
 * O que é: função para tentar interpretar um corpo como JSON.
 * O que faz: retorna o valor JSON e sua forma estável quando válido, ou null quando o corpo não representa JSON válido.
 */
function parseJsonBody(body) {
  try {
    const value = JSON.parse(body);
    return { value, stable: JSON.stringify(stableJson(value)) };
  } catch {
    return null;
  }
}

/**
 * O que é: função para comparar conjuntos de chaves de objetos simples.
 * O que faz: lista campos adicionados, removidos e alterados até uma profundidade limitada, produzindo um resumo útil de
 * JSON sem implementar um patch completo ou expor todo o corpo da resposta.
 */
function diffJsonValues(before, after, path = '$', depth = 0, limit = 4) {
  if (depth >= limit) return before === after ? [] : [{ path, type: 'changed', before: typeof before, after: typeof after }];
  if (JSON.stringify(before) === JSON.stringify(after)) return [];

  const beforeObject = before && typeof before === 'object' && !Array.isArray(before);
  const afterObject = after && typeof after === 'object' && !Array.isArray(after);

  if (!beforeObject || !afterObject) {
    return [{ path, type: 'changed', before: summarizeValue(before), after: summarizeValue(after) }];
  }

  const changes = [];
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const key of [...keys].sort()) {
    const childPath = `${path}.${key}`;
    if (!Object.prototype.hasOwnProperty.call(before, key)) {
      changes.push({ path: childPath, type: 'added', after: summarizeValue(after[key]) });
    } else if (!Object.prototype.hasOwnProperty.call(after, key)) {
      changes.push({ path: childPath, type: 'removed', before: summarizeValue(before[key]) });
    } else {
      changes.push(...diffJsonValues(before[key], after[key], childPath, depth + 1, limit));
    }
  }
  return changes;
}

/**
 * O que é: função para resumir valores em diferenças JSON.
 * O que faz: limita strings longas, arrays e objetos para que o relatório seja legível e não replique conteúdos extensos.
 */
function summarizeValue(value) {
  if (typeof value === 'string') return value.length > 160 ? `${value.slice(0, 157)}…` : value;
  if (Array.isArray(value)) return `[array: ${value.length} item(ns)]`;
  if (value && typeof value === 'object') return `{object: ${Object.keys(value).length} chave(s)}`;
  return value;
}

/**
 * O que é: função que compara headers HTTP normalizados.
 * O que faz: informa headers adicionados, removidos e modificados; permite ignorar nomes específicos, como date ou set-cookie.
 */
function diffHeaders(baseline, candidate, ignoredHeaders = []) {
  const before = normalizeHeaders(baseline);
  const after = normalizeHeaders(candidate);
  const ignored = new Set(ignoredHeaders.map((name) => String(name).toLowerCase()));
  const names = new Set([...Object.keys(before), ...Object.keys(after)]);
  const changes = [];

  for (const name of [...names].sort()) {
    if (ignored.has(name)) continue;
    if (!(name in before)) changes.push({ name, type: 'added', after: after[name] });
    else if (!(name in after)) changes.push({ name, type: 'removed', before: before[name] });
    else if (before[name] !== after[name]) changes.push({ name, type: 'changed', before: before[name], after: after[name] });
  }

  return changes;
}

/**
 * O que é: função para comparar o corpo de duas respostas HTTP coletadas.
 * O que faz: mascara padrões voláteis, compara hashes, detecta JSON e oferece diferenças de estrutura; para conteúdo não JSON,
 * informa tamanho e hash em vez de reproduzir o corpo inteiro.
 */
function diffBodies(baselineBody, candidateBody, volatilePatterns) {
  const before = maskVolatileValues(baselineBody, volatilePatterns);
  const after = maskVolatileValues(candidateBody, volatilePatterns);
  const beforeJson = parseJsonBody(before);
  const afterJson = parseJsonBody(after);
  const equal = before === after || (beforeJson && afterJson && beforeJson.stable === afterJson.stable);

  return {
    equal,
    baseline: { characters: before.length, hash: shortHash(before), isJson: Boolean(beforeJson) },
    candidate: { characters: after.length, hash: shortHash(after), isJson: Boolean(afterJson) },
    jsonChanges: beforeJson && afterJson && !equal ? diffJsonValues(beforeJson.value, afterJson.value) : [],
  };
}

/**
 * O que é: comparador local de respostas HTTP.
 * O que faz: compara status, headers e corpo de um baseline e de uma resposta candidata já coletados; os resultados servem
 * para regressão, QA e análise autorizada, sem enviar tráfego a qualquer endpoint.
 *
 * @param {object} baseline Resposta de referência.
 * @param {object} candidate Resposta a comparar.
 * @param {object} [options] Configurações de comparação.
 * @param {string[]} [options.ignoreHeaders=['date','set-cookie','x-request-id']] Headers a ignorar.
 * @param {(string|RegExp)[]} [options.volatilePatterns=[]] Padrões a mascarar nos corpos antes da comparação.
 * @returns {object} Diferença estruturada.
 */
export function diffResponses(baseline = {}, candidate = {}, options = {}) {
  const settings = {
    ignoreHeaders: ['date', 'set-cookie', 'x-request-id', 'x-correlation-id'],
    volatilePatterns: [],
    ...options,
  };

  const baselineStatus = Number.isInteger(baseline.status) ? baseline.status : null;
  const candidateStatus = Number.isInteger(candidate.status) ? candidate.status : null;
  const headerChanges = diffHeaders(baseline.headers ?? {}, candidate.headers ?? {}, settings.ignoreHeaders);
  const body = diffBodies(baseline.body ?? '', candidate.body ?? '', settings.volatilePatterns);

  const changes = {
    statusChanged: baselineStatus !== candidateStatus,
    headersChanged: headerChanges.length > 0,
    bodyChanged: !body.equal,
  };

  return {
    baseline: { url: baseline.url ?? null, status: baselineStatus },
    candidate: { url: candidate.url ?? null, status: candidateStatus },
    changes,
    equal: !changes.statusChanged && !changes.headersChanged && !changes.bodyChanged,
    status: changes.statusChanged ? { before: baselineStatus, after: candidateStatus } : null,
    headerChanges,
    body,
    limitation: 'A comparação considera apenas os dados locais fornecidos. Igualdade de respostas não comprova equivalência de comportamento, autenticação, cache ou efeitos no servidor.',
  };
}

/**
 * O que é: gerador de relatório Markdown para diferenças de resposta.
 * O que faz: apresenta status, alterações de headers e diferenças JSON de forma legível, usando hashes e resumos para corpos.
 */
export function formatMarkdownReport(diff) {
  if (!diff || !diff.baseline || !diff.candidate || !diff.body) {
    throw new TypeError('Forneça um resultado retornado por diffResponses.');
  }

  const lines = [
    '# Response Diff Report',
    '',
    `- **Resultado:** ${diff.equal ? 'Sem diferenças após normalização' : 'Diferenças encontradas'}`,
    `- **Baseline:** ${diff.baseline.url ?? 'Não informado'} (${diff.baseline.status ?? '—'})`,
    `- **Candidato:** ${diff.candidate.url ?? 'Não informado'} (${diff.candidate.status ?? '—'})`,
    `- **Limitação:** ${diff.limitation}`,
    '',
    '## Status',
    '',
  ];

  lines.push(diff.status ? `- Alterado: ${diff.status.before ?? '—'} → ${diff.status.after ?? '—'}` : '- Sem alteração.');
  lines.push('', '## Headers', '');

  if (diff.headerChanges.length === 0) {
    lines.push('- Sem alterações relevantes.');
  } else {
    lines.push('| Header | Tipo | Antes | Depois |', '|---|---|---|---|');
    for (const change of diff.headerChanges) {
      const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
      lines.push(`| ${change.name} | ${change.type} | ${clean(change.before)} | ${clean(change.after)} |`);
    }
  }

  lines.push('', '## Corpo', '');
  lines.push(`- Igual após normalização: ${diff.body.equal ? 'sim' : 'não'}.`);
  lines.push(`- Baseline: ${diff.body.baseline.characters} caracteres, hash ${diff.body.baseline.hash}, JSON: ${diff.body.baseline.isJson ? 'sim' : 'não'}.`);
  lines.push(`- Candidato: ${diff.body.candidate.characters} caracteres, hash ${diff.body.candidate.hash}, JSON: ${diff.body.candidate.isJson ? 'sim' : 'não'}.`);

  if (diff.body.jsonChanges.length > 0) {
    lines.push('', '### Alterações JSON', '', '| Caminho | Tipo | Antes | Depois |', '|---|---|---|---|');
    for (const change of diff.body.jsonChanges) {
      const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
      lines.push(`| ${change.path} | ${change.type} | ${clean(change.before)} | ${clean(change.after)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler opções da linha de comando.
 * O que faz: obtém o valor logo após flags como --baseline, --candidate e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para transformar uma lista separada por vírgulas em padrões de máscara.
 * O que faz: cria expressões regulares globais a partir de textos informados para ignorar valores voláteis durante a comparação.
 */
function parseMaskPatterns(value) {
  if (!value) return [];
  return value.split(',').map((pattern) => new RegExp(pattern.trim(), 'g')).filter((pattern) => pattern.source);
}

/**
 * O que é: função de ajuda do terminal.
 * O que faz: explica como comparar dois arquivos JSON de respostas já coletadas e como configurar headers ou padrões ignorados.
 */
function showHelp() {
  console.log(`\nUso:\n  node response-differ.js --baseline baseline.json --candidate candidate.json [opções]\n\nFormato de cada resposta:\n  {\n    "url": "https://app.exemplo.com/api/status",\n    "status": 200,\n    "headers": { "content-type": "application/json" },\n    "body": "{\\"ok\\":true}"\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva o resultado em arquivo local\n  --pretty               Formata JSON com indentação\n  --ignore-headers LISTA Headers adicionais ignorados, separados por vírgula\n  --mask REGEXS          Expressões regulares separadas por vírgula para mascarar dados voláteis no corpo\n\nExemplo:\n  node response-differ.js --baseline antes.json --candidate depois.json --format markdown --output diff.md --mask '"timestamp":"[^"]+"'\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const baselineFile = getCliOption('baseline');
  const candidateFile = getCliOption('candidate');

  if (process.argv.includes('--help') || !baselineFile || !candidateFile) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const [baseline, candidate] = await Promise.all([
        readFile(baselineFile, 'utf8').then(JSON.parse),
        readFile(candidateFile, 'utf8').then(JSON.parse),
      ]);
      const extraIgnored = (getCliOption('ignore-headers') ?? '').split(',').map((name) => name.trim()).filter(Boolean);
      const diff = diffResponses(baseline, candidate, {
        ignoreHeaders: ['date', 'set-cookie', 'x-request-id', 'x-correlation-id', ...extraIgnored],
        volatilePatterns: parseMaskPatterns(getCliOption('mask')),
      });
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(diff)
        : JSON.stringify(diff, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
      process.exitCode = diff.equal ? 0 : 2;
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
