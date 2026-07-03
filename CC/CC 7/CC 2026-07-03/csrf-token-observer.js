#!/usr/bin/env node

/**
 * CSRF Token Observer
 *
 * O que é: um utilitário JavaScript para observar e revisar localmente evidências de proteção CSRF previamente coletadas.
 * O que faz: analisa HTML, headers, cookies e metadados de requisições/respostas para identificar tokens CSRF, padrões double
 * submit cookie, atributos de cookie e requisitos Origin/Referer documentados; produz achados de configuração. Ele não envia
 * formulários, não cria requisições cross-site, não extrai cookies de navegadores e não acessa ou modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { observeCsrf, formatMarkdownReport } from './csrf-token-observer.js';
 *
 *   const report = observeCsrf({
 *     url: 'https://app.exemplo.com/profile',
 *     request: { method: 'POST', headers: { origin: 'https://app.exemplo.com' } },
 *     response: { headers: { 'set-cookie': 'csrf_token=abc; Secure; SameSite=Lax' }, html: '<input type="hidden" name="_csrf" value="token">' }
 *   });
 *
 * Uso via CLI:
 *   node csrf-token-observer.js --input csrf-evidence.json --format markdown --output csrf-review.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const TOKEN_NAME_PATTERN = /(?:csrf|xsrf|anti[-_]?forgery|requestverificationtoken|authenticity[_-]?token)/i;
const TOKEN_HEADER_PATTERN = /^(?:x[-_])?(?:csrf|xsrf|anti[-_]?forgery|requestverificationtoken|authenticity)[-_]?(?:token)?$/i;

/**
 * O que é: função para normalizar um objeto de headers HTTP.
 * O que faz: converte nomes de headers para minúsculas e valores para texto, facilitando análise independente de capitalização.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return {};
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), Array.isArray(value) ? value.join('\n') : String(value ?? '')]));
}

/**
 * O que é: função para converter Set-Cookie em registros locais de cookie.
 * O que faz: separa nome, valor redigido e atributos como Secure, HttpOnly, SameSite, Path e Domain sem persistir valor do token.
 */
function parseSetCookies(value) {
  const rawCookies = Array.isArray(value) ? value : String(value ?? '').split(/\n(?=[^\s])/);
  return rawCookies.filter(Boolean).map((raw) => {
    const parts = String(raw).split(';').map((part) => part.trim()).filter(Boolean);
    const [nameValue, ...attributes] = parts;
    const separator = nameValue.indexOf('=');
    const name = separator >= 0 ? nameValue.slice(0, separator).trim() : nameValue;
    const tokenValue = separator >= 0 ? nameValue.slice(separator + 1) : '';
    const parsed = { name, valuePresent: Boolean(tokenValue), secure: false, httpOnly: false, sameSite: null, path: null, domain: null };

    for (const attribute of attributes) {
      const [rawKey, ...rawParts] = attribute.split('=');
      const key = rawKey.trim().toLowerCase();
      const attributeValue = rawParts.join('=').trim();
      if (key === 'secure') parsed.secure = true;
      if (key === 'httponly') parsed.httpOnly = true;
      if (key === 'samesite') parsed.sameSite = attributeValue || null;
      if (key === 'path') parsed.path = attributeValue || null;
      if (key === 'domain') parsed.domain = attributeValue || null;
    }
    return parsed;
  });
}

/**
 * O que é: função para redigir uma amostra de token.
 * O que faz: retorna somente informação de presença e comprimento aproximado, evitando registrar valores que possam ser secretos.
 */
function redactedToken(value) {
  const text = String(value ?? '').trim();
  return text ? `[REDACTED length=${text.length}]` : null;
}

/**
 * O que é: extrator de tokens CSRF presentes em HTML local.
 * O que faz: reconhece inputs hidden, meta tags e atributos cujo nome sugere CSRF/XSRF; coleta somente nome, origem e tamanho,
 * sem exibir ou armazenar o valor original do token.
 */
function extractHtmlTokens(html) {
  const tokens = [];
  const source = String(html ?? '');
  const inputExpression = /<input\b[^>]*>/gi;

  for (const match of source.matchAll(inputExpression)) {
    const tag = match[0];
    const name = tag.match(/\bname\s*=\s*(["'])(.*?)\1/i)?.[2] ?? tag.match(/\bname\s*=\s*([^\s>]+)/i)?.[1] ?? '';
    const type = tag.match(/\btype\s*=\s*(["'])(.*?)\1/i)?.[2] ?? tag.match(/\btype\s*=\s*([^\s>]+)/i)?.[1] ?? '';
    const value = tag.match(/\bvalue\s*=\s*(["'])(.*?)\1/i)?.[2] ?? tag.match(/\bvalue\s*=\s*([^\s>]+)/i)?.[1] ?? '';
    if (String(type).toLowerCase() === 'hidden' && TOKEN_NAME_PATTERN.test(name)) {
      tokens.push({ source: 'html-hidden-input', name, value: redactedToken(value) });
    }
  }

  const metaExpression = /<meta\b[^>]*>/gi;
  for (const match of source.matchAll(metaExpression)) {
    const tag = match[0];
    const name = tag.match(/\bname\s*=\s*(["'])(.*?)\1/i)?.[2] ?? '';
    const content = tag.match(/\bcontent\s*=\s*(["'])(.*?)\1/i)?.[2] ?? '';
    if (TOKEN_NAME_PATTERN.test(name)) tokens.push({ source: 'html-meta', name, value: redactedToken(content) });
  }

  return tokens;
}

/**
 * O que é: extrator de tokens ou pistas CSRF em headers locais.
 * O que faz: encontra headers de request e response com nomes associados a CSRF/XSRF e redige seus valores antes do relatório.
 */
function extractHeaderTokens(headers, source) {
  const tokens = [];
  for (const [name, value] of Object.entries(headers)) {
    if (TOKEN_HEADER_PATTERN.test(name) || TOKEN_NAME_PATTERN.test(name)) {
      tokens.push({ source, name, value: redactedToken(value) });
    }
  }
  return tokens;
}

/**
 * O que é: função para criar achados de revisão CSRF padronizados.
 * O que faz: registra severidade, código, mensagem e recomendação para facilitar relatórios e priorização de correções.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: função para avaliar se Origin ou Referer presentes são uma origin HTTP(S) válida.
 * O que faz: retorna hostname e origin normalizados para comparação documental, sem verificar DNS, certificados ou posse do domínio.
 */
function parseWebOrigin(value) {
  if (!value) return null;
  try {
    const url = new URL(String(value));
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * O que é: observador local de evidências CSRF.
 * O que faz: correlaciona tokens identificados, cookies, headers e método da requisição para apontar configurações que merecem
 * revisão. O relatório é indicativo e não prova proteção efetiva, exploração ou ausência de validação server-side.
 *
 * @param {object} evidence Evidências HTTP/HTML já coletadas.
 * @returns {object} Relatório de observação local.
 */
export function observeCsrf(evidence = {}) {
  const requestHeaders = normalizeHeaders(evidence.request?.headers ?? evidence.requestHeaders ?? {});
  const responseHeaders = normalizeHeaders(evidence.response?.headers ?? evidence.responseHeaders ?? {});
  const requestMethod = String(evidence.request?.method ?? evidence.method ?? 'GET').toUpperCase();
  const html = String(evidence.response?.html ?? evidence.html ?? '');
  const setCookieValue = evidence.response?.setCookies ?? evidence.setCookies ?? responseHeaders['set-cookie'] ?? '';
  const cookies = parseSetCookies(setCookieValue);
  const htmlTokens = extractHtmlTokens(html);
  const requestTokens = extractHeaderTokens(requestHeaders, 'request-header');
  const responseTokens = extractHeaderTokens(responseHeaders, 'response-header');
  const csrfCookies = cookies.filter((cookie) => TOKEN_NAME_PATTERN.test(cookie.name));
  const tokens = [...htmlTokens, ...requestTokens, ...responseTokens];
  const findings = [];
  const unsafeMethod = UNSAFE_METHODS.has(requestMethod);
  const origin = parseWebOrigin(requestHeaders.origin);
  const referer = parseWebOrigin(requestHeaders.referer);

  if (unsafeMethod && tokens.length === 0 && csrfCookies.length === 0) {
    findings.push(finding('medium', 'no-csrf-evidence-observed', `Nenhum token ou cookie CSRF foi observado para método ${requestMethod}.`, 'Confirme proteção server-side por token sincronizado, double submit cookie, validação Origin/Referer ou outro mecanismo apropriado ao modelo de autenticação.'));
  }

  if (unsafeMethod && !origin && !referer) {
    findings.push(finding('medium', 'missing-origin-referer-evidence', `A evidência de ${requestMethod} não inclui Origin ou Referer válido.`, 'Para requisições autenticadas por cookie, considere validar Origin e/ou Referer como defesa complementar, respeitando cenários legítimos de ausência.'));
  }

  if (csrfCookies.length > 0 && requestTokens.length === 0 && htmlTokens.length === 0) {
    findings.push(finding('low', 'csrf-cookie-without-observed-submission', 'Cookie com nome associado a CSRF foi observado, mas não há token em header ou formulário na evidência.', 'Confirme se o padrão double submit envia o token em header/corpo e se a comparação ocorre no servidor.'));
  }

  for (const cookie of csrfCookies) {
    if (!cookie.secure) {
      findings.push(finding('medium', 'csrf-cookie-without-secure', `Cookie ${cookie.name} não possui atributo Secure na evidência.`, 'Use Secure para cookies enviados por HTTPS, exceto em ambiente local de desenvolvimento controlado.'));
    }
    if (cookie.httpOnly) {
      findings.push(finding('info', 'csrf-cookie-httponly', `Cookie ${cookie.name} possui HttpOnly.`, 'No padrão double submit, o cliente pode precisar ler o cookie; confirme se a arquitetura usa token em HTML ou mecanismo compatível.'));
    }
    if (!cookie.sameSite) {
      findings.push(finding('low', 'csrf-cookie-without-samesite', `Cookie ${cookie.name} não declara SameSite.`, 'Defina SameSite=Lax ou Strict quando compatível; trate SameSite como defesa complementar, não substituto de validação CSRF.'));
    }
  }

  if (unsafeMethod && htmlTokens.length > 0 && requestTokens.length === 0) {
    findings.push(finding('info', 'form-token-observed', 'Token CSRF foi observado em HTML; confirme que ele é validado em todas as rotas que alteram estado.', 'Associe tokens à sessão ou requisição conforme o framework e rejeite tokens ausentes, inválidos ou expirados no servidor.'));
  }

  if (unsafeMethod && requestTokens.length > 0) {
    findings.push(finding('info', 'csrf-request-header-observed', 'Token com nome associado a CSRF/XSRF foi observado em header da requisição.', 'Confirme validação server-side, rotação apropriada e cobertura de todos os métodos que alteram estado.'));
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    target: evidence.url ?? null,
    request: {
      method: requestMethod,
      origin: origin ?? null,
      referer: referer ?? null,
      unsafeMethod,
    },
    observations: {
      tokens,
      csrfCookies,
      allCookies: cookies.map((cookie) => ({ name: cookie.name, secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite, path: cookie.path, domain: cookie.domain })),
      htmlAnalyzed: Boolean(html),
    },
    findings,
    summary: {
      tokenSignals: tokens.length,
      csrfCookies: csrfCookies.length,
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
    },
    limitation: 'A observação usa apenas evidências locais previamente coletadas. Ela não confirma geração, vínculo à sessão, imprevisibilidade, validação server-side, cobertura de rotas, política SameSite real ou resistência a CSRF.',
  };
}

/**
 * O que é: observador de múltiplas evidências CSRF locais.
 * O que faz: analisa uma lista de registros e consolida achados, preservando o resultado individual sem gerar tráfego ou acessar cookies reais.
 */
export function observeCsrfBatch(evidences) {
  if (!Array.isArray(evidences)) throw new TypeError('evidences deve ser um array.');
  const results = evidences.map((evidence) => observeCsrf(evidence));
  const allFindings = results.flatMap((result) => result.findings);
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const item of allFindings) counts[item.severity] += 1;

  return {
    results,
    summary: {
      evidences: results.length,
      unsafeRequests: results.filter((result) => result.request.unsafeMethod).length,
      totalFindings: allFindings.length,
      counts,
    },
  };
}

/**
 * O que é: gerador de relatório CSRF em Markdown.
 * O que faz: transforma observações individuais ou em lote em tabelas de sinais observados e achados, sempre com tokens redigidos.
 */
export function formatMarkdownReport(report) {
  const results = Array.isArray(report?.results) ? report.results : [report];
  if (!results.every((result) => result?.observations && Array.isArray(result.findings))) throw new TypeError('Forneça um resultado de observeCsrf ou observeCsrfBatch.');

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# CSRF Token Observation Report',
    '',
    `- **Evidências analisadas:** ${results.length}`,
    '- **Escopo:** análise local de HTML e metadados HTTP; não envia formulários, não cria requisições cross-site e não armazena tokens em claro.',
  ];

  for (const result of results) {
    lines.push('', `## ${clean(result.target)}`, '');
    lines.push(`- Método: ${result.request.method}`);
    lines.push(`- Origin observada: ${result.request.origin ?? 'não informada'}`);
    lines.push(`- Referer observado: ${result.request.referer ?? 'não informado'}`);
    lines.push(`- Sinais de token: ${result.summary.tokenSignals}`);
    lines.push(`- Cookies CSRF: ${result.summary.csrfCookies}`);
    lines.push('', '### Tokens e cookies observados', '');
    lines.push('| Origem | Nome | Valor |', '|---|---|---|');
    for (const token of result.observations.tokens) lines.push(`| ${clean(token.source)} | ${clean(token.name)} | ${clean(token.value)} |`);
    for (const cookie of result.observations.csrfCookies) lines.push(`| cookie | ${clean(cookie.name)} | [REDACTED] |`);
    if (result.observations.tokens.length === 0 && result.observations.csrfCookies.length === 0) lines.push('| — | — | Nenhum sinal observado |');

    lines.push('', '### Achados', '');
    if (result.findings.length === 0) lines.push('- Nenhum achado produzido pelas regras locais.');
    else {
      lines.push('| Severidade | Código | Observação | Recomendação |', '|---|---|---|---|');
      for (const item of result.findings) {
        lines.push(`| ${item.severity} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
      }
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos de terminal.
 * O que faz: retorna o valor imediatamente após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como analisar evidências CSRF locais e gerar relatórios sem realizar requisições ou manipular sessões.
 */
function showHelp() {
  console.log(`\nUso:\n  node csrf-token-observer.js --input csrf-evidence.json [opções]\n\nFormato de entrada:\n  Um objeto ou array de objetos:\n  {\n    "url": "https://app.exemplo.com/profile",\n    "request": {\n      "method": "POST",\n      "headers": { "origin": "https://app.exemplo.com", "x-csrf-token": "valor" }\n    },\n    "response": {\n      "headers": { "set-cookie": "csrf_token=valor; Secure; SameSite=Lax" },\n      "html": "<input type=\\"hidden\\" name=\\"_csrf\\" value=\\"valor\\">"\n    }\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node csrf-token-observer.js --input csrf-evidence.json --format markdown --output csrf-review.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const report = Array.isArray(data) ? observeCsrfBatch(data) : observeCsrf(data);
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
