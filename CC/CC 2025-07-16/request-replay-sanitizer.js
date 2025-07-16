#!/usr/bin/env node

/**
 * Request Replay Sanitizer
 *
 * O que é: um utilitário JavaScript para sanitizar requisições HTTP brutas locais antes de usá-las em documentação, QA ou
 * reprodução autorizada em ambientes de teste.
 * O que faz: remove ou redige credenciais, cookies, tokens, chaves, identificadores de sessão e campos sensíveis do corpo;
 * pode substituir Host e URL base por alvos de teste explicitamente configurados. Ele não reenvia requisições, não abre proxy,
 * não acessa redes e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { sanitizeRawHttpRequest, sanitizeRequestCollection } from './request-replay-sanitizer.js';
 *
 *   const result = sanitizeRawHttpRequest('POST /api/profile HTTP/1.1\r\nHost: prod.exemplo.com\r\nAuthorization: Bearer secret\r\n\r\n{"email":"ana@exemplo.com"}', {
 *     replacementHost: 'staging.exemplo.test',
 *     redactJsonFields: ['email']
 *   });
 *
 * Uso via CLI:
 *   node request-replay-sanitizer.js --input requests.txt --output sanitized-requests.txt --host staging.exemplo.test
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const DEFAULT_SENSITIVE_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'api-key',
  'x-auth-token', 'x-access-token', 'x-refresh-token', 'x-csrf-token', 'x-xsrf-token',
]);
const DEFAULT_SENSITIVE_FIELD_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session|sid|csrf|xsrf|email|phone|cpf|cnpj|credit[_-]?card|card[_-]?number|cvv|ssn)/i;

/**
 * O que é: função para calcular um hash curto de valor original local.
 * O que faz: cria uma impressão SHA-256 truncada para permitir correlação de conteúdo sanitizado sem preservar dados sensíveis.
 */
function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 12);
}

/**
 * O que é: função para construir marcador seguro de redação.
 * O que faz: substitui o valor original por um marcador com comprimento e hash curto, sem incluir o conteúdo confidencial.
 */
function redaction(value, label = 'REDACTED') {
  const text = String(value ?? '');
  return `[${label} length=${text.length} sha256=${fingerprint(text)}]`;
}

/**
 * O que é: função para separar um texto local em blocos de requisições HTTP.
 * O que faz: reconhece request lines HTTP e retorna blocos distintos, sem executar, enviar ou modificar nenhuma requisição.
 */
export function splitRawHttpRequests(text) {
  if (typeof text !== 'string') throw new TypeError('text deve ser uma string.');
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let current = [];
  const requestLine = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/\d(?:\.\d)?$/i;

  for (const line of lines) {
    if (requestLine.test(line.trim()) && current.some((item) => item.trim())) {
      blocks.push(current.join('\n').trim());
      current = [line];
    } else {
      current.push(line);
    }
  }
  if (current.some((item) => item.trim())) blocks.push(current.join('\n').trim());
  return blocks.filter((block) => requestLine.test(block.split('\n')[0]?.trim() ?? ''));
}

/**
 * O que é: função para interpretar uma requisição HTTP bruta local.
 * O que faz: separa request line, headers e corpo para sanitização, preservando a estrutura e rejeitando formato inválido.
 */
function parseRawRequest(raw) {
  const text = String(raw).replace(/\r\n?/g, '\n');
  const separator = text.indexOf('\n\n');
  const head = separator >= 0 ? text.slice(0, separator) : text;
  const body = separator >= 0 ? text.slice(separator + 2) : '';
  const lines = head.split('\n');
  const requestLine = lines.shift()?.trim() ?? '';
  const match = requestLine.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)$/i);
  if (!match) throw new TypeError(`Request line inválida: ${requestLine}`);

  const headers = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const index = line.indexOf(':');
    if (index < 1) throw new TypeError(`Header inválido: ${line}`);
    headers.push({ name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() });
  }

  return { method: match[1].toUpperCase(), target: match[2], httpVersion: match[3], headers, body };
}

/**
 * O que é: função para verificar se um nome de campo deve ser redigido.
 * O que faz: combina lista explícita de campos com padrões sensíveis padrão e personalizados, sem tentar inferir valores secretos.
 */
function shouldRedactField(name, options) {
  const normalized = String(name ?? '').toLowerCase();
  if (options.redactJsonFields.has(normalized)) return true;
  return options.sensitiveFieldPatterns.some((pattern) => pattern.test(normalized));
}

/**
 * O que é: função para sanitizar recursivamente um JSON local.
 * O que faz: redige valores de campos sensíveis mantendo chaves e estrutura, permitindo reproduzir formato sem preservar PII,
 * tokens ou segredos; limita profundidade para evitar processamento excessivo de dados aninhados.
 */
function sanitizeJson(value, options, path = '$', depth = 0, changes = []) {
  if (depth > options.maxJsonDepth) return redaction(JSON.stringify(value), 'REDACTED_DEPTH_LIMIT');

  if (Array.isArray(value)) {
    return value.map((item, index) => sanitizeJson(item, options, `${path}[${index}]`, depth + 1, changes));
  }

  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      if (shouldRedactField(key, options)) {
        output[key] = redaction(typeof item === 'string' ? item : JSON.stringify(item));
        changes.push({ location: childPath, action: 'redacted-json-field', field: key });
      } else {
        output[key] = sanitizeJson(item, options, childPath, depth + 1, changes);
      }
    }
    return output;
  }

  return value;
}

/**
 * O que é: função para sanitizar corpo urlencoded local.
 * O que faz: mantém as chaves e redige valores cujo nome aparece em regras sensíveis, preservando formato application/x-www-form-urlencoded.
 */
function sanitizeUrlEncodedBody(body, options, changes) {
  const parameters = new URLSearchParams(body);
  for (const [name, value] of parameters) {
    if (shouldRedactField(name, options)) {
      parameters.set(name, redaction(value));
      changes.push({ location: `body.${name}`, action: 'redacted-form-field', field: name });
    }
  }
  return parameters.toString();
}

/**
 * O que é: função para sanitizar corpo de request conforme Content-Type.
 * O que faz: trata JSON e form-urlencoded por estrutura; para tipos desconhecidos, pode manter ou redigir o corpo integralmente
 * conforme política, sem executar, decodificar binários ou processar multipart.
 */
function sanitizeBody(body, contentType, options, changes) {
  if (!body) return '';
  const normalizedType = String(contentType ?? '').toLowerCase();

  if (normalizedType.includes('application/json') || normalizedType.includes('+json')) {
    try {
      return JSON.stringify(sanitizeJson(JSON.parse(body), options, '$', 0, changes));
    } catch {
      changes.push({ location: 'body', action: 'redacted-invalid-json-body' });
      return options.redactUnknownBodies ? redaction(body, 'REDACTED_BODY') : body;
    }
  }

  if (normalizedType.includes('application/x-www-form-urlencoded')) {
    return sanitizeUrlEncodedBody(body, options, changes);
  }

  if (options.redactUnknownBodies) {
    changes.push({ location: 'body', action: 'redacted-unknown-body' });
    return redaction(body, 'REDACTED_BODY');
  }

  return body;
}

/**
 * O que é: função para alterar Host e target de forma controlada.
 * O que faz: substitui Host ou reescreve URL absoluta para um host de ambiente de teste configurado; não resolve DNS ou envia tráfego.
 */
function applyTargetReplacement(parsed, replacementHost, replacementScheme, changes) {
  if (!replacementHost) return parsed;
  const cleanHost = String(replacementHost).trim();
  if (!cleanHost || /[\s/]/.test(cleanHost)) throw new TypeError('replacementHost deve conter apenas host[:porta].');

  let replacedHost = false;
  parsed.headers = parsed.headers.map((header) => {
    if (header.name.toLowerCase() !== 'host') return header;
    replacedHost = true;
    changes.push({ location: 'header.host', action: 'replaced-host' });
    return { ...header, value: cleanHost };
  });
  if (!replacedHost) {
    parsed.headers.push({ name: 'Host', value: cleanHost });
    changes.push({ location: 'header.host', action: 'added-replacement-host' });
  }

  if (/^https?:\/\//i.test(parsed.target)) {
    const url = new URL(parsed.target);
    url.host = cleanHost;
    if (replacementScheme) url.protocol = replacementScheme;
    parsed.target = url.toString();
    changes.push({ location: 'request-target', action: 'replaced-absolute-target-host' });
  }

  return parsed;
}

/**
 * O que é: sanitizador local de requisição HTTP bruta.
 * O que faz: remove ou redige headers sensíveis, sanitiza campos estruturados do corpo e opcionalmente substitui o host por alvo
 * de teste. O resultado não é enviado automaticamente e deve ser usado somente em ambientes explicitamente autorizados.
 *
 * @param {string} raw Requisição HTTP bruta local.
 * @param {object} [options] Regras de sanitização.
 * @returns {{sanitized: string, changes: object[], summary: object}} Requisição sanitizada e lista de alterações.
 */
export function sanitizeRawHttpRequest(raw, options = {}) {
  const settings = {
    replacementHost: null,
    replacementScheme: null,
    removeSensitiveHeaders: true,
    redactSensitiveHeaders: false,
    sensitiveHeaders: [],
    redactJsonFields: [],
    sensitiveFieldPatterns: [DEFAULT_SENSITIVE_FIELD_PATTERN],
    redactUnknownBodies: true,
    maxJsonDepth: 20,
    ...options,
  };
  settings.redactJsonFields = new Set(settings.redactJsonFields.map((field) => String(field).toLowerCase()));
  settings.sensitiveFieldPatterns = settings.sensitiveFieldPatterns.map((pattern) => pattern instanceof RegExp ? pattern : new RegExp(String(pattern), 'i'));
  const sensitiveHeaders = new Set([...DEFAULT_SENSITIVE_HEADERS, ...settings.sensitiveHeaders.map((name) => String(name).toLowerCase())]);
  const parsed = parseRawRequest(raw);
  const changes = [];
  const originalHeaders = parsed.headers.length;

  parsed.headers = parsed.headers.flatMap((header) => {
    const normalized = header.name.toLowerCase();
    if (!sensitiveHeaders.has(normalized)) return [header];
    if (settings.removeSensitiveHeaders && !settings.redactSensitiveHeaders) {
      changes.push({ location: `header.${normalized}`, action: 'removed-sensitive-header' });
      return [];
    }
    changes.push({ location: `header.${normalized}`, action: 'redacted-sensitive-header' });
    return [{ ...header, value: redaction(header.value) }];
  });

  const contentType = parsed.headers.find((header) => header.name.toLowerCase() === 'content-type')?.value ?? '';
  parsed.body = sanitizeBody(parsed.body, contentType, settings, changes);
  applyTargetReplacement(parsed, settings.replacementHost, settings.replacementScheme, changes);

  const lines = [
    `${parsed.method} ${parsed.target} ${parsed.httpVersion}`,
    ...parsed.headers.map((header) => `${header.name}: ${header.value}`),
    '',
    parsed.body,
  ];

  return {
    sanitized: lines.join('\r\n'),
    changes,
    summary: {
      method: parsed.method,
      target: parsed.target,
      originalHeaders,
      remainingHeaders: parsed.headers.length,
      bodyCharacters: parsed.body.length,
      changes: changes.length,
      originalFingerprint: fingerprint(raw),
      sanitizedFingerprint: fingerprint(lines.join('\r\n')),
    },
    limitation: 'A sanitização é local e baseada em nomes e padrões. Revise o resultado antes de qualquer reprodução autorizada, pois dados sensíveis podem existir em campos não reconhecidos, URLs, headers personalizados ou formatos binários.',
  };
}

/**
 * O que é: sanitizador de coleção local de requisições HTTP.
 * O que faz: divide um arquivo de requests em blocos, sanitiza cada bloco e devolve texto consolidado com relatório de alterações,
 * sem reexecutar ou enviar qualquer requisição.
 */
export function sanitizeRequestCollection(text, options = {}) {
  const requests = splitRawHttpRequests(text);
  const results = requests.map((request) => sanitizeRawHttpRequest(request, options));
  return {
    results,
    sanitized: results.map((result) => result.sanitized).join('\r\n\r\n'),
    summary: {
      requests: results.length,
      changes: results.reduce((total, result) => total + result.changes.length, 0),
    },
    limitation: 'A coleção é apenas sanitizada localmente. Nenhum request é transmitido, enfileirado ou executado por esta ferramenta.',
  };
}

/**
 * O que é: gerador de relatório Markdown da sanitização.
 * O que faz: documenta quantidade de requisições, alterações e fingerprints sem reproduzir o conteúdo integral dos requests sanitizados.
 */
export function formatMarkdownReport(report) {
  const results = Array.isArray(report?.results) ? report.results : [report];
  if (!results.every((result) => result?.summary && Array.isArray(result.changes))) throw new TypeError('Forneça um resultado de sanitizeRawHttpRequest ou sanitizeRequestCollection.');

  const lines = [
    '# Request Replay Sanitization Report',
    '',
    `- **Requisições sanitizadas:** ${results.length}`,
    `- **Alterações aplicadas:** ${results.reduce((total, result) => total + result.changes.length, 0)}`,
    '- **Escopo:** processamento local; nenhum request é enviado ou executado pela ferramenta.',
    '',
    '## Resumo',
    '',
    '| Request | Método | Target sanitizado | Headers restantes | Alterações |',
    '|---:|---|---|---:|---:|',
  ];

  for (const [index, result] of results.entries()) {
    lines.push(`| ${index + 1} | ${result.summary.method} | ${String(result.summary.target).replace(/\|/g, '\\|')} | ${result.summary.remainingHeaders} | ${result.summary.changes} |`);
  }

  lines.push('', '## Alterações aplicadas', '');
  for (const [index, result] of results.entries()) {
    lines.push(`### Request ${index + 1}`);
    if (result.changes.length === 0) lines.push('- Nenhuma alteração aplicada.');
    else for (const change of result.changes) lines.push(`- ${change.location}: ${change.action}${change.field ? ` (${change.field})` : ''}`);
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter valores de flags de terminal.
 * O que faz: retorna o argumento imediatamente após opções como --input, --output, --host e --format.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para transformar lista separada por vírgulas em campos JSON a redigir.
 * O que faz: remove espaços e entradas vazias para aceitar flags simples como --redact-fields email,phone,customerId.
 */
function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como sanitizar requisições locais antes de reprodução autorizada, sem acionar proxy ou rede.
 */
function showHelp() {
  console.log(`\nUso:\n  node request-replay-sanitizer.js --input requests.txt --output sanitized-requests.txt [opções]\n\nOpções:\n  --host HOST[:PORTA]      Substitui Host por alvo de teste explicitamente informado\n  --scheme http:|https:    Altera esquema quando o request target for URL absoluta\n  --redact-headers         Redige headers sensíveis em vez de removê-los\n  --redact-fields LISTA    Campos JSON/form adicionais para redigir, separados por vírgula\n  --keep-unknown-bodies    Mantém corpos não JSON/form; por padrão eles são redigidos integralmente\n  --report ARQUIVO         Salva relatório Markdown das alterações\n\nExemplo:\n  node request-replay-sanitizer.js --input requests.txt --output sanitized-requests.txt --host staging.exemplo.test --redact-fields 'customerId,documento' --report sanitize-report.md\n\nObservação: revise manualmente o arquivo sanitizado antes de qualquer reprodução em ambiente explicitamente autorizado.\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');
  const output = getCliOption('output');

  if (process.argv.includes('--help') || !input || !output) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const report = sanitizeRequestCollection(await readFile(input, 'utf8'), {
        replacementHost: getCliOption('host') ?? null,
        replacementScheme: getCliOption('scheme') ?? null,
        redactSensitiveHeaders: process.argv.includes('--redact-headers'),
        redactJsonFields: splitList(getCliOption('redact-fields')),
        redactUnknownBodies: !process.argv.includes('--keep-unknown-bodies'),
      });
      await writeFile(output, `${report.sanitized}\n`, 'utf8');

      const reportOutput = getCliOption('report');
      if (reportOutput) await writeFile(reportOutput, `${formatMarkdownReport(report)}\n`, 'utf8');
      console.log(`Requisições sanitizadas: ${report.summary.requests}. Alterações: ${report.summary.changes}.`);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
