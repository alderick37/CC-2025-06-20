#!/usr/bin/env node

/**
 * CORS Auditor
 *
 * O que é: um utilitário JavaScript para auditar localmente headers CORS previamente coletados de respostas HTTP autorizadas.
 * O que faz: interpreta Access-Control-Allow-Origin, Allow-Credentials, Allow-Methods, Allow-Headers, Expose-Headers,
 * Max-Age e Vary; identifica configurações que merecem revisão e gera um relatório estruturado. Ele não envia preflights,
 * não faz requisições, não testa origens remotas e não altera sistemas externos.
 *
 * Uso como módulo:
 *   import { auditCors, formatMarkdownReport } from './cors-auditor.js';
 *
 *   const report = auditCors({
 *     url: 'https://api.exemplo.com/v1/profile',
 *     status: 204,
 *     request: { origin: 'https://app.exemplo.com', method: 'OPTIONS' },
 *     responseHeaders: {
 *       'access-control-allow-origin': 'https://app.exemplo.com',
 *       'access-control-allow-credentials': 'true',
 *       'access-control-allow-methods': 'GET, POST',
 *       'vary': 'Origin'
 *     }
 *   });
 *
 * Uso via CLI:
 *   node cors-auditor.js --input cors-evidence.json --format markdown --output cors-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const SENSITIVE_RESPONSE_HEADERS = new Set(['authorization', 'set-cookie', 'x-api-key', 'x-auth-token', 'x-csrf-token']);
const HIGH_RISK_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * O que é: função para normalizar headers HTTP locais.
 * O que faz: converte nomes de headers para minúsculas e valores para strings, independente da capitalização usada na coleta.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TypeError('responseHeaders deve ser um objeto simples.');
  }
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value ?? '')]));
}

/**
 * O que é: função para separar valores de headers CORS separados por vírgula.
 * O que faz: devolve uma lista limpa e em maiúsculas ou minúsculas conforme solicitado, removendo itens vazios e duplicados.
 */
function commaList(value, transform = (item) => item) {
  if (!value) return [];
  return [...new Set(String(value).split(',').map((item) => transform(item.trim())).filter(Boolean))];
}

/**
 * O que é: função para validar uma origin no formato scheme://host[:porta].
 * O que faz: identifica origins especiais como null e curingas, e retorna uma URL apenas para origins HTTP(S) sintaticamente válidas.
 */
function parseOrigin(value) {
  const origin = String(value ?? '').trim();
  if (!origin) return { raw: '', type: 'missing', url: null };
  if (origin === '*') return { raw: origin, type: 'wildcard', url: null };
  if (origin === 'null') return { raw: origin, type: 'null', url: null };

  try {
    const url = new URL(origin);
    const isExactOrigin = url.origin === origin && ['http:', 'https:'].includes(url.protocol);
    return { raw: origin, type: isExactOrigin ? 'http-origin' : 'invalid', url: isExactOrigin ? url : null };
  } catch {
    return { raw: origin, type: 'invalid', url: null };
  }
}

/**
 * O que é: função para interpretar os headers CORS de uma resposta.
 * O que faz: converte valores relevantes em uma configuração estruturada, incluindo origin permitida, credenciais, métodos,
 * headers, headers expostos, cache de preflight e diretivas Vary declaradas.
 */
export function parseCorsHeaders(responseHeaders = {}) {
  const headers = normalizeHeaders(responseHeaders);
  const allowOrigin = String(headers['access-control-allow-origin'] ?? '').trim();
  const allowCredentials = String(headers['access-control-allow-credentials'] ?? '').trim().toLowerCase() === 'true';
  const maxAgeValue = String(headers['access-control-max-age'] ?? '').trim();
  const maxAge = /^\d+$/.test(maxAgeValue) ? Number(maxAgeValue) : null;

  return {
    rawHeaders: headers,
    allowOrigin,
    allowOriginParsed: parseOrigin(allowOrigin),
    allowCredentials,
    allowMethods: commaList(headers['access-control-allow-methods'], (item) => item.toUpperCase()),
    allowHeaders: commaList(headers['access-control-allow-headers'], (item) => item.toLowerCase()),
    exposeHeaders: commaList(headers['access-control-expose-headers'], (item) => item.toLowerCase()),
    maxAge,
    vary: commaList(headers.vary, (item) => item.toLowerCase()),
  };
}

/**
 * O que é: função para criar achados de auditoria CORS de forma consistente.
 * O que faz: padroniza severidade, código, mensagem e recomendação de cada condição observada nas evidências locais.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: função que avalia uma configuração CORS local.
 * O que faz: identifica combinações comuns de risco ou erro de configuração, como wildcard com credenciais, reflexão de origin,
 * ausência de Vary: Origin, null origin, métodos de escrita amplos e exposição de headers sensíveis. Os achados são indicativos
 * e precisam ser confirmados na política de negócio e na configuração completa do servidor.
 */
function analyzeCorsConfiguration(cors, request = {}) {
  const findings = [];
  const requestedOrigin = String(request.origin ?? '').trim();
  const requestedMethod = String(request.requestMethod ?? request.method ?? '').trim().toUpperCase();
  const requestedHeaders = commaList(request.requestHeaders ?? '', (item) => item.toLowerCase());

  if (!cors.allowOrigin) {
    findings.push(finding('info', 'no-acao', 'A resposta não inclui Access-Control-Allow-Origin.', 'Confirme se a ausência é intencional para este recurso e origin.'));
    return findings;
  }

  if (cors.allowOrigin === '*' && cors.allowCredentials) {
    findings.push(finding('high', 'wildcard-with-credentials', 'Access-Control-Allow-Origin: * aparece junto de Access-Control-Allow-Credentials: true.', 'Não use wildcard para respostas com credenciais; aplique allowlist explícita de origins confiáveis.'));
  } else if (cors.allowOrigin === '*') {
    findings.push(finding('medium', 'wildcard-origin', 'A resposta permite qualquer origin por meio de Access-Control-Allow-Origin: *.', 'Confirme que o recurso é realmente público e não contém dados personalizados, credenciais ou operações sensíveis.'));
  }

  if (cors.allowOrigin === 'null') {
    findings.push(finding('high', 'null-origin', 'A resposta permite a origin especial null.', 'Evite permitir null, salvo necessidade muito específica e controles compensatórios revisados.'));
  }

  if (cors.allowOriginParsed.type === 'invalid') {
    findings.push(finding('medium', 'invalid-allow-origin', `Access-Control-Allow-Origin possui formato inválido ou não representa uma origin única: ${cors.allowOrigin}`, 'Use uma origin exata, https://dominio[:porta], ou wildcard somente quando apropriado.'));
  }

  if (requestedOrigin && cors.allowOrigin === requestedOrigin && cors.allowOrigin !== '*' && !cors.vary.includes('origin')) {
    findings.push(finding('medium', 'missing-vary-origin', 'A resposta parece variar Access-Control-Allow-Origin conforme a origin solicitada, mas não declara Vary: Origin.', 'Inclua Vary: Origin quando a resposta ou os headers CORS forem gerados dinamicamente por origin.'));
  }

  if (cors.allowCredentials && !requestedOrigin) {
    findings.push(finding('info', 'credentials-without-request-context', 'Credenciais são permitidas, mas a evidência não inclui a Origin da requisição.', 'Registre a Origin de teste para revisar se ela pertence à allowlist pretendida.'));
  }

  if (cors.allowCredentials && cors.allowOrigin && cors.allowOrigin !== '*' && cors.allowOriginParsed.type === 'http-origin') {
    findings.push(finding('info', 'credentialed-cors', `Credenciais são permitidas para ${cors.allowOrigin}.`, 'Confirme que a origin é controlada e que endpoints expostos não retornam dados além do necessário.'));
  }

  const unsafeMethods = cors.allowMethods.filter((method) => HIGH_RISK_METHODS.has(method));
  if (unsafeMethods.length > 0 && (cors.allowOrigin === '*' || cors.allowCredentials)) {
    findings.push(finding('medium', 'cross-origin-write-methods', `Métodos potencialmente modificadores liberados: ${unsafeMethods.join(', ')}.`, 'Restrinja origins e métodos ao mínimo necessário e confirme proteção CSRF quando houver autenticação baseada em cookies.'));
  }

  const sensitiveExposed = cors.exposeHeaders.filter((header) => SENSITIVE_RESPONSE_HEADERS.has(header));
  if (sensitiveExposed.length > 0) {
    findings.push(finding('medium', 'sensitive-exposed-headers', `Headers sensíveis expostos ao JavaScript: ${sensitiveExposed.join(', ')}.`, 'Evite expor headers de autenticação ou sessão; exponha apenas os headers necessários ao frontend.'));
  }

  if (cors.maxAge !== null && cors.maxAge > 86_400) {
    findings.push(finding('low', 'long-preflight-cache', `Access-Control-Max-Age é ${cors.maxAge} segundos.`, 'Use um tempo de cache compatível com a frequência de mudanças da política CORS.'));
  }

  if (requestedMethod && cors.allowMethods.length > 0 && !cors.allowMethods.includes(requestedMethod)) {
    findings.push(finding('info', 'requested-method-not-allowed', `O método solicitado ${requestedMethod} não aparece em Access-Control-Allow-Methods.`, 'Se esta for uma resposta de preflight esperada, revise a configuração do método e a evidência coletada.'));
  }

  const missingRequestedHeaders = requestedHeaders.filter((header) => !cors.allowHeaders.includes('*') && !cors.allowHeaders.includes(header));
  if (requestedHeaders.length > 0 && cors.allowHeaders.length > 0 && missingRequestedHeaders.length > 0) {
    findings.push(finding('info', 'requested-headers-not-allowed', `Headers solicitados não declarados como permitidos: ${missingRequestedHeaders.join(', ')}.`, 'Se esta for uma resposta de preflight esperada, inclua somente os headers necessários na allowlist.'));
  }

  return findings;
}

/**
 * O que é: função para resumir achados por severidade.
 * O que faz: conta níveis de risco e retorna a maior severidade observada para apoiar priorização de revisão.
 */
function summarizeFindings(findings) {
  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] = (counts[item.severity] ?? 0) + 1;
  return { counts, highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info' };
}

/**
 * O que é: auditor local de configuração CORS.
 * O que faz: interpreta evidências de uma resposta já capturada e produz uma análise explicável de cabeçalhos CORS, sem fazer
 * preflight, requisições cross-origin ou tentativas de acesso ao recurso indicado.
 *
 * @param {object} evidence Dados de uma resposta HTTP coletada.
 * @param {string|null} [evidence.url=null] URL de referência no relatório.
 * @param {number|null} [evidence.status=null] Status HTTP observado.
 * @param {object} [evidence.request={}] Contexto opcional: origin, method, requestMethod e requestHeaders.
 * @param {object} [evidence.responseHeaders={}] Headers da resposta coletada.
 * @returns {object} Relatório de auditoria local.
 */
export function auditCors(evidence = {}) {
  const cors = parseCorsHeaders(evidence.responseHeaders ?? {});
  const findings = analyzeCorsConfiguration(cors, evidence.request ?? {});

  return {
    target: evidence.url ?? null,
    status: Number.isInteger(evidence.status) ? evidence.status : null,
    request: {
      origin: evidence.request?.origin ?? null,
      method: evidence.request?.requestMethod ?? evidence.request?.method ?? null,
      requestHeaders: evidence.request?.requestHeaders ?? null,
    },
    cors: {
      allowOrigin: cors.allowOrigin || null,
      allowCredentials: cors.allowCredentials,
      allowMethods: cors.allowMethods,
      allowHeaders: cors.allowHeaders,
      exposeHeaders: cors.exposeHeaders,
      maxAge: cors.maxAge,
      vary: cors.vary,
    },
    findings,
    summary: summarizeFindings(findings),
    limitation: 'A auditoria avalia somente headers previamente coletados. Ela não confirma a política completa do servidor, comportamento por origin, autenticação, cache intermediário ou explorabilidade.',
  };
}

/**
 * O que é: auditor para múltiplas evidências CORS locais.
 * O que faz: processa uma lista de respostas já capturadas e consolida os achados, sem gerar tráfego ou preflights adicionais.
 */
export function auditCorsBatch(evidences) {
  if (!Array.isArray(evidences)) throw new TypeError('evidences deve ser um array.');

  const results = evidences.map((evidence) => auditCors(evidence));
  const allFindings = results.flatMap((result) => result.findings);

  return {
    results,
    summary: {
      responsesAnalyzed: results.length,
      responsesWithFindings: results.filter((result) => result.findings.length > 0).length,
      totalFindings: allFindings.length,
      ...summarizeFindings(allFindings),
    },
  };
}

/**
 * O que é: gerador de relatório CORS em Markdown.
 * O que faz: converte um resultado individual ou em lote em uma tabela legível com configuração observada, achados e recomendações.
 */
export function formatMarkdownReport(report) {
  const results = Array.isArray(report?.results) ? report.results : [report];
  if (!results.every((result) => result && result.cors && Array.isArray(result.findings))) {
    throw new TypeError('Forneça um resultado de auditCors ou auditCorsBatch.');
  }

  const lines = [
    '# CORS Audit Report',
    '',
    `- **Respostas analisadas:** ${results.length}`,
    `- **Limitação:** ${results[0]?.limitation ?? 'Análise baseada em evidências locais.'}`,
    '',
    '## Configuração observada',
    '',
    '| Alvo | Origin solicitada | Allow-Origin | Credenciais | Métodos | Vary |',
    '|---|---|---|---|---|---|',
  ];

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  for (const result of results) {
    lines.push(`| ${clean(result.target)} | ${clean(result.request.origin)} | ${clean(result.cors.allowOrigin)} | ${result.cors.allowCredentials ? 'true' : 'false'} | ${clean(result.cors.allowMethods.join(', '))} | ${clean(result.cors.vary.join(', '))} |`);
  }

  lines.push('', '## Achados', '', '| Alvo | Severidade | Código | Observação | Recomendação |', '|---|---|---|---|---|');
  const rows = results.flatMap((result) => result.findings.map((item) => ({ result, item })));

  if (rows.length === 0) {
    lines.push('| — | — | — | Nenhum achado produzido pelas regras locais. | Revise a política completa conforme necessário. |');
  } else {
    for (const { result, item } of rows) {
      lines.push(`| ${clean(result.target)} | ${item.severity} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter valores de flags da linha de comando.
 * O que faz: retorna o valor imediatamente após opções como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: apresenta o formato de evidência CORS local e os comandos para gerar relatórios JSON ou Markdown.
 */
function showHelp() {
  console.log(`\nUso:\n  node cors-auditor.js --input cors-evidence.json [opções]\n\nFormato de entrada:\n  Um objeto ou array de objetos:\n  {\n    "url": "https://api.exemplo.com/v1/profile",\n    "status": 204,\n    "request": {\n      "origin": "https://app.exemplo.com",\n      "method": "OPTIONS",\n      "requestMethod": "POST",\n      "requestHeaders": "authorization, content-type"\n    },\n    "responseHeaders": {\n      "access-control-allow-origin": "https://app.exemplo.com",\n      "access-control-allow-credentials": "true",\n      "access-control-allow-methods": "GET, POST",\n      "vary": "Origin"\n    }\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva o relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node cors-auditor.js --input cors-evidence.json --format markdown --output cors-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const report = Array.isArray(data) ? auditCorsBatch(data) : auditCors(data);
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
