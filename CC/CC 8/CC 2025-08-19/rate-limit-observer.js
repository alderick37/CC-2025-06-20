#!/usr/bin/env node

/**
 * Rate Limit Observer
 *
 * O que é: um utilitário JavaScript para observar e analisar localmente evidências de rate limiting previamente coletadas.
 * O que faz: interpreta status HTTP, headers padronizados e legados de limite, Retry-After e registros temporais de respostas;
 * estima janelas, identifica inconsistências e gera relatórios. Ele não envia requisições repetidas, não executa brute force,
 * não tenta contornar limites e não acessa ou altera sistemas externos.
 *
 * Uso como módulo:
 *   import { observeRateLimit, observeRateLimitBatch, formatMarkdownReport } from './rate-limit-observer.js';
 *
 *   const report = observeRateLimit({
 *     url: 'https://api.exemplo.com/v1/login',
 *     timestamp: '2026-09-07T20:34:00Z',
 *     status: 429,
 *     headers: { 'retry-after': '60', 'ratelimit-limit': '10', 'ratelimit-remaining': '0' }
 *   });
 *
 * Uso via CLI:
 *   node rate-limit-observer.js --input rate-limit-evidence.json --format markdown --output rate-limit-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const RATE_LIMIT_HEADER_NAMES = new Set([
  'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset',
  'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
  'retry-after', 'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
]);

/**
 * O que é: função para normalizar headers HTTP locais.
 * O que faz: converte nomes para minúsculas e valores para texto, permitindo ler formatos de rate limit com capitalização diversa.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return {};
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value ?? '')]));
}

/**
 * O que é: função para localizar o primeiro header disponível entre nomes alternativos.
 * O que faz: suporta convenções RateLimit, X-RateLimit e X-Rate-Limit sem presumir qual gateway ou framework gerou a resposta.
 */
function firstHeader(headers, names) {
  for (const name of names) {
    if (headers[name] !== undefined) return { name, value: headers[name] };
  }
  return { name: null, value: null };
}

/**
 * O que é: função para interpretar números inteiros não negativos de headers.
 * O que faz: devolve null para valores ausentes, negativos ou inválidos e evita tratar dados não confiáveis como métricas válidas.
 */
function parseNonNegativeInteger(value) {
  const text = String(value ?? '').trim();
  return /^\d+$/.test(text) ? Number(text) : null;
}

/**
 * O que é: função para interpretar Retry-After.
 * O que faz: aceita segundos ou data HTTP e devolve segundos aproximados até nova tentativa, usando somente o timestamp local informado.
 */
function parseRetryAfter(value, timestamp) {
  if (value === null || value === undefined || String(value).trim() === '') return null;
  const seconds = parseNonNegativeInteger(value);
  if (seconds !== null) return { raw: String(value), seconds, retryAt: new Date(timestamp.getTime() + seconds * 1000).toISOString() };

  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return { raw: String(value), seconds: null, retryAt: null };
  return { raw: String(value), seconds: Math.max(0, Math.ceil((date.getTime() - timestamp.getTime()) / 1000)), retryAt: date.toISOString() };
}

/**
 * O que é: função para interpretar reset de rate limit.
 * O que faz: aceita valores relativos em segundos ou timestamps Unix plausíveis e retorna uma representação de janela aproximada.
 */
function parseReset(value, timestamp) {
  const number = parseNonNegativeInteger(value);
  if (number === null) return null;

  const currentUnix = Math.floor(timestamp.getTime() / 1000);
  if (number > currentUnix - 86_400) {
    const date = new Date(number * 1000);
    return { raw: String(value), type: 'unix-timestamp', secondsUntilReset: Math.max(0, Math.ceil((date.getTime() - timestamp.getTime()) / 1000)), resetAt: date.toISOString() };
  }

  return { raw: String(value), type: 'relative-seconds', secondsUntilReset: number, resetAt: new Date(timestamp.getTime() + number * 1000).toISOString() };
}

/**
 * O que é: função para criar achados de rate limiting em formato consistente.
 * O que faz: registra severidade, código, mensagem e recomendação para revisão de proteção contra abuso e automação excessiva.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: função para normalizar uma evidência de resposta HTTP.
 * O que faz: valida status e timestamp e preserva somente campos úteis para observação local de rate limiting.
 */
function normalizeEvidence(evidence = {}) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) throw new TypeError('Cada evidência deve ser um objeto.');
  const timestamp = new Date(evidence.timestamp ?? new Date());
  if (Number.isNaN(timestamp.getTime())) throw new TypeError(`timestamp inválido: ${evidence.timestamp}`);
  const status = Number(evidence.status ?? 0);
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new TypeError(`status inválido: ${evidence.status}`);

  return {
    url: evidence.url ?? null,
    endpoint: evidence.endpoint ?? null,
    method: evidence.method ? String(evidence.method).toUpperCase() : null,
    timestamp,
    status,
    headers: normalizeHeaders(evidence.headers ?? evidence.responseHeaders ?? {}),
    notes: evidence.notes ?? null,
  };
}

/**
 * O que é: observador local de uma resposta relacionada a rate limit.
 * O que faz: extrai limites, restante, reset e Retry-After dos headers coletados e aponta inconsistências ou ausência de sinais;
 * não mede um endpoint diretamente e não confirma se o limite é aplicado de forma uniforme no servidor.
 *
 * @param {object} evidence Evidência HTTP previamente coletada.
 * @returns {object} Relatório de observação local.
 */
export function observeRateLimit(evidence = {}) {
  const item = normalizeEvidence(evidence);
  const limitHeader = firstHeader(item.headers, ['ratelimit-limit', 'x-ratelimit-limit', 'x-rate-limit-limit']);
  const remainingHeader = firstHeader(item.headers, ['ratelimit-remaining', 'x-ratelimit-remaining', 'x-rate-limit-remaining']);
  const resetHeader = firstHeader(item.headers, ['ratelimit-reset', 'x-ratelimit-reset', 'x-rate-limit-reset']);
  const retryHeader = firstHeader(item.headers, ['retry-after']);
  const limit = parseNonNegativeInteger(limitHeader.value);
  const remaining = parseNonNegativeInteger(remainingHeader.value);
  const reset = parseReset(resetHeader.value, item.timestamp);
  const retryAfter = parseRetryAfter(retryHeader.value, item.timestamp);
  const findings = [];

  if (item.status === 429) {
    if (!retryAfter) {
      findings.push(finding('medium', '429-without-retry-after', 'Resposta 429 não contém Retry-After.', 'Inclua Retry-After para orientar clientes sobre quando podem tentar novamente.'));
    }
    if (remaining !== null && remaining > 0) {
      findings.push(finding('low', '429-with-positive-remaining', `Resposta 429 informa remaining=${remaining}.`, 'Confirme semântica dos headers e consistência entre gateway, aplicação e documentação.'));
    }
  }

  if (limit === null && remaining === null && reset === null && !retryAfter) {
    findings.push(finding('info', 'no-rate-limit-headers', 'Nenhum header reconhecido de rate limiting foi observado.', 'A ausência pode ser intencional; para endpoints sensíveis, confirme limites, alertas e proteção contra abuso no servidor.'));
  }

  if (limit !== null && remaining !== null && remaining > limit) {
    findings.push(finding('medium', 'remaining-exceeds-limit', `remaining=${remaining} é maior que limit=${limit}.`, 'Revise geração de headers e sincronização do contador de limites.'));
  }

  if (limit === 0) {
    findings.push(finding('medium', 'zero-limit', 'O header de limite informa 0.', 'Confirme se o endpoint está deliberadamente bloqueado ou se houve erro na configuração do limitador.'));
  }

  if (resetHeader.value !== null && !reset) {
    findings.push(finding('low', 'invalid-reset-header', `Header ${resetHeader.name} possui valor não interpretável: ${resetHeader.value}`, 'Use segundos relativos ou timestamp Unix documentado de forma consistente.'));
  }

  if (retryHeader.value !== null && retryAfter?.seconds === null) {
    findings.push(finding('low', 'invalid-retry-after', `Retry-After possui valor não interpretável: ${retryHeader.value}`, 'Use segundos inteiros ou data HTTP válida em Retry-After.'));
  }

  if (item.status >= 500 && item.status <= 599 && (limit !== null || remaining !== null)) {
    findings.push(finding('info', 'rate-limit-headers-on-server-error', 'Headers de rate limit foram observados em resposta 5xx.', 'Confirme se o consumo de quota em erros de servidor é intencional e documentado.'));
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const itemFinding of findings) counts[itemFinding.severity] += 1;

  return {
    target: item.url ?? item.endpoint,
    method: item.method,
    timestamp: item.timestamp.toISOString(),
    status: item.status,
    rateLimit: {
      limit: limit === null ? null : { value: limit, header: limitHeader.name },
      remaining: remaining === null ? null : { value: remaining, header: remainingHeader.name },
      reset: reset ? { ...reset, header: resetHeader.name } : null,
      retryAfter: retryAfter ? { ...retryAfter, header: retryHeader.name } : null,
      observedHeaders: Object.fromEntries(Object.entries(item.headers).filter(([name]) => RATE_LIMIT_HEADER_NAMES.has(name))),
    },
    findings,
    summary: {
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
      rateLimitSignalsObserved: [limit, remaining, reset, retryAfter].filter(Boolean).length,
    },
    limitation: 'A observação usa uma resposta previamente coletada. Ela não mede quota, não executa repetição de requisições, não avalia chaves de rate limit e não confirma aplicação uniforme entre endpoints, usuários ou IPs.',
  };
}

/**
 * O que é: observador em lote de evidências locais de rate limiting.
 * O que faz: ordena respostas por tempo, agrupa por endpoint/método e procura sinais de inconsistência temporal sem fazer tráfego adicional.
 */
export function observeRateLimitBatch(evidences) {
  if (!Array.isArray(evidences)) throw new TypeError('evidences deve ser um array.');
  const results = evidences.map((evidence) => observeRateLimit(evidence)).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  const timelineFindings = [];
  const groups = new Map();

  for (const result of results) {
    const key = `${result.method ?? 'ANY'} ${result.target ?? 'unknown'}`;
    const group = groups.get(key) ?? [];
    group.push(result);
    groups.set(key, group);
  }

  for (const [key, group] of groups) {
    for (let index = 1; index < group.length; index += 1) {
      const previous = group[index - 1];
      const current = group[index];
      const previousRemaining = previous.rateLimit.remaining?.value;
      const currentRemaining = current.rateLimit.remaining?.value;
      const previousLimit = previous.rateLimit.limit?.value;
      const currentLimit = current.rateLimit.limit?.value;

      if (previousLimit !== undefined && currentLimit !== undefined && previousLimit !== currentLimit) {
        timelineFindings.push(finding('info', 'limit-changed-over-time', `${key}: limit mudou de ${previousLimit} para ${currentLimit}.`, 'Confirme se a mudança decorre de plano, endpoint, janela, usuário ou configuração esperada.'));
      }
      if (previousRemaining !== undefined && currentRemaining !== undefined && currentRemaining > previousRemaining) {
        timelineFindings.push(finding('info', 'remaining-increased-over-time', `${key}: remaining aumentou de ${previousRemaining} para ${currentRemaining}.`, 'Isso pode indicar reset de janela; compare com reset e documentação do algoritmo de rate limiting.'));
      }
    }
  }

  const allFindings = [...results.flatMap((result) => result.findings), ...timelineFindings];
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const item of allFindings) counts[item.severity] += 1;

  return {
    results,
    timelineFindings,
    summary: {
      responsesObserved: results.length,
      groups: groups.size,
      responsesWith429: results.filter((result) => result.status === 429).length,
      totalFindings: allFindings.length,
      counts,
    },
    limitation: 'A análise temporal compara somente a amostra local fornecida. Ela não gera carga, não determina a chave do contador e não prova proteção contra brute force, scraping ou abuso.',
  };
}

/**
 * O que é: gerador de relatório Markdown de rate limiting.
 * O que faz: transforma resultados individuais ou em lote em tabelas de sinais observados, respostas 429 e recomendações de revisão.
 */
export function formatMarkdownReport(report) {
  const results = Array.isArray(report?.results) ? report.results : [report];
  if (!results.every((result) => result?.rateLimit && Array.isArray(result.findings))) throw new TypeError('Forneça um resultado de observeRateLimit ou observeRateLimitBatch.');

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Rate Limit Observation Report',
    '',
    `- **Respostas observadas:** ${results.length}`,
    '- **Escopo:** análise passiva de evidências locais; a ferramenta não repete requisições, não tenta contornar limites e não mede a quota real.',
    '',
    '## Sinais observados',
    '',
    '| Horário | Alvo | Status | Limite | Restante | Reset | Retry-After |',
    '|---|---|---:|---:|---:|---|---|',
  ];

  for (const result of results) {
    lines.push(`| ${result.timestamp} | ${clean(result.target)} | ${result.status} | ${result.rateLimit.limit?.value ?? '—'} | ${result.rateLimit.remaining?.value ?? '—'} | ${clean(result.rateLimit.reset?.resetAt)} | ${clean(result.rateLimit.retryAfter?.retryAt)} |`);
  }

  lines.push('', '## Achados', '', '| Alvo | Severidade | Código | Observação | Recomendação |', '|---|---|---|---|---|');
  const rows = results.flatMap((result) => result.findings.map((item) => ({ result, item })));
  if (report?.timelineFindings) rows.push(...report.timelineFindings.map((item) => ({ result: { target: 'Linha do tempo' }, item })));

  if (rows.length === 0) {
    lines.push('| — | — | — | Nenhum achado produzido pelas regras locais. | Revise a política e monitore endpoints sensíveis conforme necessário. |');
  } else {
    for (const { result, item } of rows) {
      lines.push(`| ${clean(result.target)} | ${item.severity} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos de terminal.
 * O que faz: retorna o valor logo após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como observar evidências de rate limit locais e gerar relatórios sem disparar requisições repetidas.
 */
function showHelp() {
  console.log(`\nUso:\n  node rate-limit-observer.js --input rate-limit-evidence.json [opções]\n\nFormato de entrada:\n  Um objeto ou array de objetos:\n  {\n    "url": "https://api.exemplo.com/v1/login",\n    "method": "POST",\n    "timestamp": "2026-09-07T20:34:00Z",\n    "status": 429,\n    "headers": {\n      "retry-after": "60",\n      "ratelimit-limit": "10",\n      "ratelimit-remaining": "0",\n      "ratelimit-reset": "60"\n    }\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node rate-limit-observer.js --input rate-limit-evidence.json --format markdown --output rate-limit-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const report = Array.isArray(data) ? observeRateLimitBatch(data) : observeRateLimit(data);
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
