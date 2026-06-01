#!/usr/bin/env node

/**
 * Change Monitor
 *
 * O que é: um utilitário JavaScript para comparar snapshots locais de ativos, configurações, respostas ou documentos.
 * O que faz: carrega dois arquivos JSON, normaliza objetos, ignora caminhos configuráveis, calcula adições, remoções e mudanças
 * estruturais e gera relatórios JSON ou Markdown. Ele não coleta dados, não agenda monitoramento, não envia alertas e não acessa
 * redes ou sistemas externos; os snapshots devem ser capturados previamente por processos autorizados.
 *
 * Uso como módulo:
 *   import { compareSnapshots, formatMarkdownReport } from './change-monitor.js';
 *
 *   const report = compareSnapshots(
 *     { version: '1.0', endpoints: ['/health'] },
 *     { version: '1.1', endpoints: ['/health', '/status'] },
 *     { ignorePaths: ['generatedAt'] }
 *   );
 *   console.log(formatMarkdownReport(report));
 *
 * Uso via CLI:
 *   node change-monitor.js --baseline before.json --current after.json --format markdown --output changes.md
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

/**
 * O que é: função para identificar objetos JSON comuns.
 * O que faz: diferencia objetos de arrays e null para aplicar comparação estrutural adequada a cada tipo de valor.
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * O que é: função para serializar valores de forma estável.
 * O que faz: ordena chaves de objetos recursivamente para calcular hashes e comparar conteúdo sem ser afetada pela ordem das propriedades.
 */
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (isPlainObject(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

/**
 * O que é: função para criar uma impressão curta de snapshot.
 * O que faz: calcula SHA-256 truncado da representação estável, permitindo identificar versões sem repetir todo o conteúdo no relatório.
 */
function fingerprint(value) {
  return createHash('sha256').update(stableStringify(value)).digest('hex').slice(0, 16);
}

/**
 * O que é: função para normalizar uma lista de caminhos ignorados.
 * O que faz: aceita JSONPath simplificado no formato $.campo.subcampo e remove espaços ou duplicatas para a comparação local.
 */
function normalizeIgnorePaths(paths = []) {
  if (!Array.isArray(paths)) throw new TypeError('ignorePaths deve ser um array.');
  return [...new Set(paths.map((path) => String(path).trim()).filter(Boolean).map((path) => path.startsWith('$') ? path : `$.${path}`))];
}

/**
 * O que é: função para verificar se um caminho deve ser ignorado.
 * O que faz: compara caminhos exatos e prefixos com wildcard terminal, como $.metadata.* ou $.items[*].updatedAt.
 */
function shouldIgnore(path, ignorePaths) {
  return ignorePaths.some((rule) => {
    if (rule === path) return true;
    if (rule.endsWith('.*')) return path.startsWith(rule.slice(0, -1));
    if (rule.includes('[*]')) {
      const expression = new RegExp(`^${rule.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace('\\[\\*\\]', '\\[\\d+\\]')}$`);
      return expression.test(path);
    }
    return false;
  });
}

/**
 * O que é: função para resumir valores alterados.
 * O que faz: limita strings extensas, objetos e arrays em uma representação curta para que relatórios mostrem contexto sem repetir dados sensíveis ou volumosos.
 */
function summarizeValue(value) {
  if (typeof value === 'string') return value.length > 180 ? `${value.slice(0, 177)}…` : value;
  if (Array.isArray(value)) return `[array: ${value.length} item(ns), hash=${fingerprint(value)}]`;
  if (isPlainObject(value)) return `{object: ${Object.keys(value).length} chave(s), hash=${fingerprint(value)}}`;
  return value;
}

/**
 * O que é: função para ordenar arrays quando configurados como conjuntos.
 * O que faz: cria uma cópia ordenada pela representação estável para comparar coleções em que a ordem não é significativa.
 */
function normalizeArrayOrder(value, path, unorderedArrayPaths) {
  if (!Array.isArray(value)) return value;
  if (!unorderedArrayPaths.includes(path)) return value;
  return [...value].sort((first, second) => stableStringify(first).localeCompare(stableStringify(second)));
}

/**
 * O que é: mecanismo recursivo de diferença estrutural para snapshots JSON.
 * O que faz: identifica adições, remoções, mudanças de tipo e valores alterados, respeitando caminhos ignorados e arrays opcionais sem ordem.
 */
function diffValues(before, after, path, changes, options, depth = 0) {
  if (depth > options.maxDepth) {
    if (stableStringify(before) !== stableStringify(after)) changes.push({ type: 'changed', path, before: '[depth-limit]', after: '[depth-limit]' });
    return;
  }
  if (shouldIgnore(path, options.ignorePaths)) return;
  if (stableStringify(before) === stableStringify(after)) return;

  if (before === undefined) {
    changes.push({ type: 'added', path, after: summarizeValue(after) });
    return;
  }
  if (after === undefined) {
    changes.push({ type: 'removed', path, before: summarizeValue(before) });
    return;
  }

  const beforeArray = Array.isArray(before);
  const afterArray = Array.isArray(after);
  const beforeObject = isPlainObject(before);
  const afterObject = isPlainObject(after);

  if (beforeArray && afterArray) {
    const normalizedBefore = normalizeArrayOrder(before, path, options.unorderedArrayPaths);
    const normalizedAfter = normalizeArrayOrder(after, path, options.unorderedArrayPaths);
    const length = Math.max(normalizedBefore.length, normalizedAfter.length);
    for (let index = 0; index < length; index += 1) {
      diffValues(normalizedBefore[index], normalizedAfter[index], `${path}[${index}]`, changes, options, depth + 1);
    }
    return;
  }

  if (beforeObject && afterObject) {
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const key of [...keys].sort()) diffValues(before[key], after[key], `${path}.${key}`, changes, options, depth + 1);
    return;
  }

  changes.push({
    type: typeof before !== typeof after ? 'type-changed' : 'changed',
    path,
    before: summarizeValue(before),
    after: summarizeValue(after),
  });
}

/**
 * O que é: função para classificar severidade sugestiva de uma mudança.
 * O que faz: usa heurísticas por caminho e tipo de alteração para destacar mudanças em segurança, autenticação, endpoints e configurações; a classificação não substitui avaliação humana de risco.
 */
function classifyChange(change) {
  const path = change.path.toLowerCase();
  const text = `${path} ${JSON.stringify(change.before)} ${JSON.stringify(change.after)}`.toLowerCase();
  if (/(secret|password|token|api[_-]?key|private[_-]?key|authorization|credential)/.test(text)) return 'high';
  if (/(security|cors|auth|oauth|jwt|permission|role|allow|deny|firewall|redirect|webhook)/.test(text)) return 'medium';
  if (/(endpoint|path|url|host|server|version|dependency|header)/.test(text)) return 'low';
  return 'info';
}

/**
 * O que é: comparador local de snapshots JSON.
 * O que faz: produz uma lista estruturada de mudanças entre baseline e snapshot atual, permitindo monitorar ativos documentais,
 * configurações ou respostas previamente coletadas. Ele não coleta novos snapshots ou envia alertas.
 *
 * @param {unknown} baseline Snapshot de referência local.
 * @param {unknown} current Snapshot atual local.
 * @param {object} [options] Opções de comparação.
 * @returns {object} Relatório de mudanças.
 */
export function compareSnapshots(baseline, current, options = {}) {
  const settings = {
    ignorePaths: [],
    unorderedArrayPaths: [],
    maxDepth: 30,
    baselineLabel: 'baseline',
    currentLabel: 'current',
    ...options,
  };
  settings.ignorePaths = normalizeIgnorePaths(settings.ignorePaths);
  settings.unorderedArrayPaths = normalizeIgnorePaths(settings.unorderedArrayPaths);
  if (!Number.isInteger(settings.maxDepth) || settings.maxDepth < 1) throw new TypeError('maxDepth deve ser inteiro maior que zero.');

  const changes = [];
  diffValues(baseline, current, '$', changes, settings);
  const classified = changes.map((change) => ({ ...change, severity: classifyChange(change) }));
  const counts = { added: 0, removed: 0, changed: 0, 'type-changed': 0 };
  const severities = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const change of classified) {
    counts[change.type] = (counts[change.type] ?? 0) + 1;
    severities[change.severity] = (severities[change.severity] ?? 0) + 1;
  }

  return {
    comparedAt: new Date().toISOString(),
    baseline: { label: settings.baselineLabel, fingerprint: fingerprint(baseline) },
    current: { label: settings.currentLabel, fingerprint: fingerprint(current) },
    options: { ignorePaths: settings.ignorePaths, unorderedArrayPaths: settings.unorderedArrayPaths, maxDepth: settings.maxDepth },
    equal: classified.length === 0,
    changes: classified,
    summary: {
      totalChanges: classified.length,
      byType: counts,
      bySeverity: severities,
      highestSeverity: ['critical', 'high', 'medium', 'low', 'info'].find((level) => severities[level] > 0) ?? 'info',
    },
    limitation: 'A comparação avalia somente snapshots locais e regras configuradas. Ela não coleta dados, não valida a origem dos arquivos, não confirma impacto real e não substitui revisão humana de mudanças relevantes.',
  };
}

/**
 * O que é: gerador de relatório Markdown para mudanças detectadas.
 * O que faz: transforma o relatório estruturado em tabela legível com tipo, caminho, severidade e resumo de valores antes/depois.
 */
export function formatMarkdownReport(report) {
  if (!report || !Array.isArray(report.changes)) throw new TypeError('Forneça um relatório retornado por compareSnapshots.');
  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|').replace(/\n/g, '<br>');
  const lines = [
    '# Change Monitor Report',
    '',
    `- **Comparado em:** ${report.comparedAt}`,
    `- **Baseline:** ${report.baseline.label} (${report.baseline.fingerprint})`,
    `- **Atual:** ${report.current.label} (${report.current.fingerprint})`,
    `- **Resultado:** ${report.equal ? 'Sem mudanças após normalização' : `${report.summary.totalChanges} mudança(s) detectada(s)`}`,
    `- **Maior severidade sugerida:** ${report.summary.highestSeverity}`,
    `- **Limitação:** ${report.limitation}`,
    '',
    '## Mudanças',
    '',
    '| Tipo | Severidade | Caminho | Antes | Depois |',
    '|---|---|---|---|---|',
  ];

  if (report.changes.length === 0) {
    lines.push('| — | — | — | Nenhuma mudança | Nenhuma mudança |');
  } else {
    for (const change of report.changes) {
      lines.push(`| ${change.type} | ${change.severity} | ${clean(change.path)} | ${clean(typeof change.before === 'object' ? JSON.stringify(change.before) : change.before)} | ${clean(typeof change.after === 'object' ? JSON.stringify(change.after) : change.after)} |`);
    }
  }

  lines.push('', '## Resumo', '');
  for (const [type, count] of Object.entries(report.summary.byType)) lines.push(`- ${type}: ${count}`);
  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler opções da linha de comando.
 * O que faz: devolve o valor após flags como --baseline, --current, --ignore, --unordered-arrays e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para transformar uma lista separada por vírgulas em caminhos JSON simples.
 * O que faz: remove espaços e entradas vazias para facilitar configuração de campos ignorados ou arrays sem ordem no terminal.
 */
function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como comparar dois snapshots JSON locais, ignorar campos voláteis e gerar relatório sem coletar dados externos.
 */
function showHelp() {
  console.log(`\nUso:\n  node change-monitor.js --baseline before.json --current after.json [opções]\n\nOpções:\n  --ignore LISTA             Caminhos ignorados, separados por vírgula. Ex.: generatedAt,metadata.updatedAt\n  --unordered-arrays LISTA   Caminhos de arrays onde a ordem não importa. Ex.: endpoints,users\n  --baseline-label TEXTO     Rótulo do baseline\n  --current-label TEXTO      Rótulo do snapshot atual\n  --max-depth N              Profundidade máxima. Padrão: 30\n  --format FORMATO           json ou markdown. Padrão: json\n  --output ARQUIVO           Salva relatório em arquivo local\n  --pretty                   Formata JSON com indentação\n\nExemplo:\n  node change-monitor.js --baseline before.json --current after.json --ignore 'generatedAt,metadata.updatedAt' --unordered-arrays endpoints --format markdown --output changes.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const baselineFile = getCliOption('baseline');
  const currentFile = getCliOption('current');

  if (process.argv.includes('--help') || !baselineFile || !currentFile) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const [baseline, current] = await Promise.all([
        readFile(baselineFile, 'utf8').then(JSON.parse),
        readFile(currentFile, 'utf8').then(JSON.parse),
      ]);
      const report = compareSnapshots(baseline, current, {
        ignorePaths: splitList(getCliOption('ignore')),
        unorderedArrayPaths: splitList(getCliOption('unordered-arrays')),
        maxDepth: Number(getCliOption('max-depth') ?? 30),
        baselineLabel: getCliOption('baseline-label') ?? baselineFile,
        currentLabel: getCliOption('current-label') ?? currentFile,
      });
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(report)
        : JSON.stringify(report, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
      process.exitCode = report.equal ? 0 : 2;
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
