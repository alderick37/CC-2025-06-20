#!/usr/bin/env node

/**
 * Burp Request Importer
 *
 * O que é: um utilitário JavaScript para importar e normalizar requisições HTTP brutas previamente exportadas do Burp Suite
 * ou registradas manualmente em arquivos locais.
 * O que faz: interpreta request line, headers e corpo, reconstrói uma URL a partir de Host ou URL base informada, redige
 * credenciais e cookies, cria fingerprints e exporta inventários JSON, CSV ou Markdown. Ele não envia requisições, não abre
 * proxies, não acessa o Burp Suite e não interage com servidores externos.
 *
 * Uso como módulo:
 *   import { parseRawHttpRequest, importBurpRequests, formatMarkdownReport } from './burp-request-importer.js';
 *
 *   const request = parseRawHttpRequest('GET /api/profile HTTP/1.1\r\nHost: app.exemplo.com\r\nAuthorization: Bearer segredo\r\n\r\n');
 *   console.log(formatMarkdownReport(importBurpRequests([request])));
 *
 * Uso via CLI:
 *   node burp-request-importer.js --input burp-requests.txt --base-url 'https://app.exemplo.com' --format markdown --output requests-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const SENSITIVE_HEADER_PATTERN = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;
const KNOWN_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']);

/**
 * O que é: função para calcular hash curto de valores locais.
 * O que faz: cria uma impressão SHA-256 truncada para correlacionar corpos e requisições sem salvar conteúdo sensível em claro.
 */
function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 16);
}

/**
 * O que é: função para redigir header sensível.
 * O que faz: substitui valor de authorization, cookie, API key ou token por metadados de comprimento e hash antes de exportar dados.
 */
function redactHeader(name, value) {
  const text = String(value ?? '');
  return SENSITIVE_HEADER_PATTERN.test(name)
    ? `[REDACTED length=${text.length} sha256=${fingerprint(text)}]`
    : text;
}

/**
 * O que é: função para dividir um texto em blocos de requisições HTTP brutas.
 * O que faz: localiza linhas de request conhecidas e separa blocos consecutivos, permitindo importar exports de texto sem executar
 * ou reenviar nenhum dos requests presentes no arquivo.
 */
export function splitRawHttpRequests(text) {
  if (typeof text !== 'string') throw new TypeError('text deve ser uma string.');
  const normalized = text.replace(/\r\n?/g, '\n');
  const lines = normalized.split('\n');
  const blocks = [];
  let current = [];

  const isRequestLine = (line) => /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/\d(?:\.\d)?$/i.test(line.trim());

  for (const line of lines) {
    if (isRequestLine(line) && current.length > 0) {
      blocks.push(current.join('\n').trim());
      current = [line];
    } else {
      current.push(line);
    }
  }
  if (current.join('\n').trim()) blocks.push(current.join('\n').trim());

  return blocks.filter((block) => isRequestLine(block.split('\n')[0] ?? ''));
}

/**
 * O que é: função para normalizar um objeto de headers HTTP.
 * O que faz: converte nomes para minúsculas, agrupa cabeçalhos repetidos e preserva valores como texto para análise local.
 */
function normalizeHeaders(headers) {
  const output = {};
  for (const [name, value] of Object.entries(headers)) {
    const key = String(name).trim().toLowerCase();
    if (!key) continue;
    const text = Array.isArray(value) ? value.map(String).join(', ') : String(value ?? '');
    output[key] = output[key] ? `${output[key]}, ${text}` : text;
  }
  return output;
}

/**
 * O que é: função para construir uma URL de referência a partir de request target e Host.
 * O que faz: suporta targets absolutos e origin-form, aplica protocolo base configurado e retorna null quando não for possível
 * reconstruir uma URL HTTP(S) segura somente com os dados locais fornecidos.
 */
function reconstructUrl(target, headers, baseUrl) {
  try {
    const direct = new URL(target);
    if (['http:', 'https:'].includes(direct.protocol)) return direct.toString();
  } catch {
    // Origin-form será tratado usando baseUrl ou Host.
  }

  if (!target.startsWith('/')) return null;
  let base = baseUrl;
  if (!base && headers.host) base = `https://${headers.host}`;
  if (!base) return null;

  try {
    const url = new URL(target, base);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * O que é: função para resumir corpo de requisição sem expor conteúdo inteiro.
 * O que faz: calcula tamanho, hash, identifica JSON e lista chaves de primeiro nível quando possível, sem registrar valores do payload.
 */
function summarizeBody(body) {
  const text = String(body ?? '');
  const summary = { characters: text.length, sha256: fingerprint(text), isJson: false, topLevelKeys: [] };
  if (!text.trim()) return summary;
  try {
    const data = JSON.parse(text);
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      summary.isJson = true;
      summary.topLevelKeys = Object.keys(data).slice(0, 50);
    }
  } catch {
    // Conteúdo pode ser urlencoded, multipart ou binário representado em export local.
  }
  return summary;
}

/**
 * O que é: parser local de uma requisição HTTP bruta.
 * O que faz: interpreta método, target, versão HTTP, headers e corpo, reconstrói URL quando possível e redige valores sensíveis.
 * Ele não reenvia a requisição, não executa payloads e não acessa hosts ou proxies.
 *
 * @param {string} raw Texto de uma requisição HTTP bruta.
 * @param {object} [options] Opções de interpretação local.
 * @param {string|null} [options.baseUrl=null] URL base usada para targets relativos quando Host não for suficiente.
 * @returns {object} Requisição normalizada e redigida.
 */
export function parseRawHttpRequest(raw, options = {}) {
  if (typeof raw !== 'string' || !raw.trim()) throw new TypeError('raw deve conter uma requisição HTTP não vazia.');
  const text = raw.replace(/\r\n?/g, '\n');
  const separator = text.indexOf('\n\n');
  const head = separator >= 0 ? text.slice(0, separator) : text;
  const body = separator >= 0 ? text.slice(separator + 2) : '';
  const lines = head.split('\n');
  const requestLine = lines.shift()?.trim() ?? '';
  const match = requestLine.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)$/i);
  if (!match) throw new TypeError(`Request line inválida: ${requestLine}`);

  const [, rawMethod, target, httpVersion] = match;
  const method = rawMethod.toUpperCase();
  if (!KNOWN_METHODS.has(method)) throw new TypeError(`Método HTTP não suportado: ${method}`);

  const headers = {};
  for (const line of lines) {
    if (!line.trim()) continue;
    const separatorIndex = line.indexOf(':');
    if (separatorIndex < 1) throw new TypeError(`Header inválido: ${line}`);
    const name = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim();
    headers[name] = headers[name] ? `${headers[name]}, ${value}` : value;
  }

  const normalizedHeaders = normalizeHeaders(headers);
  const url = reconstructUrl(target, normalizedHeaders, options.baseUrl ?? null);
  const redactedHeaders = Object.fromEntries(Object.entries(normalizedHeaders).map(([name, value]) => [name, redactHeader(name, value)]));

  return {
    id: `request-${fingerprint(`${method}|${target}|${body}`)}`,
    method,
    target,
    url,
    httpVersion,
    headers: redactedHeaders,
    headerNames: Object.keys(normalizedHeaders),
    body: summarizeBody(body),
    rawFingerprint: fingerprint(text),
    notes: url ? null : 'URL não pôde ser reconstruída; informe baseUrl ou inclua Host válido na requisição.',
  };
}

/**
 * O que é: importador local de várias requisições brutas.
 * O que faz: aceita texto exportado, blocos separados ou requisições já normalizadas, deduplica por fingerprint e constrói um
 * inventário de métodos, hosts, caminhos e sinais de autenticação, sem enviar qualquer requisição.
 */
export function importBurpRequests(input, options = {}) {
  const rawRequests = typeof input === 'string'
    ? splitRawHttpRequests(input)
    : Array.isArray(input)
      ? input
      : (() => { throw new TypeError('input deve ser texto ou array de requisições.'); })();

  const requests = rawRequests.map((item) => typeof item === 'string' ? parseRawHttpRequest(item, options) : item)
    .filter((item) => item && item.method && item.target);
  const unique = [];
  const seen = new Set();
  for (const request of requests) {
    const key = request.rawFingerprint ?? `${request.method}|${request.target}|${request.body?.sha256 ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(request);
  }

  const methods = {};
  const hosts = new Set();
  const paths = new Set();
  const authSignals = [];
  for (const request of unique) {
    methods[request.method] = (methods[request.method] ?? 0) + 1;
    if (request.url) {
      const url = new URL(request.url);
      hosts.add(url.host);
      paths.add(url.pathname);
    }
    const securityHeaders = request.headerNames.filter((name) => SENSITIVE_HEADER_PATTERN.test(name));
    if (securityHeaders.length > 0) authSignals.push({ id: request.id, headers: securityHeaders });
  }

  return {
    importedAt: new Date().toISOString(),
    requests: unique,
    summary: {
      parsed: requests.length,
      unique: unique.length,
      duplicatesRemoved: requests.length - unique.length,
      methods,
      hosts: [...hosts].sort(),
      paths: [...paths].sort(),
      requestsWithSensitiveHeaders: authSignals.length,
      authSignals,
    },
    limitation: 'A ferramenta interpreta dados locais e redige valores sensíveis. Ela não preserva o corpo original, não reproduz requisições e não confirma comportamento, autorização ou vulnerabilidades em sistemas externos.',
  };
}

/**
 * O que é: função para escapar valores em CSV.
 * O que faz: protege aspas, vírgulas e quebras de linha para exportar inventário de requests em formato compatível com planilhas.
 */
function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * O que é: exportador CSV do inventário de requisições.
 * O que faz: cria uma tabela plana com método, URL, target, headers, metadados de corpo e sinais de autenticação redigidos.
 */
export function formatCsv(report) {
  if (!report || !Array.isArray(report.requests)) throw new TypeError('Forneça um relatório retornado por importBurpRequests.');
  const header = ['id', 'method', 'url', 'target', 'http_version', 'header_names', 'body_characters', 'body_sha256', 'body_is_json', 'body_top_level_keys', 'notes'];
  const rows = report.requests.map((request) => [
    request.id,
    request.method,
    request.url ?? '',
    request.target,
    request.httpVersion,
    request.headerNames.join('; '),
    request.body.characters,
    request.body.sha256,
    request.body.isJson,
    request.body.topLevelKeys.join('; '),
    request.notes ?? '',
  ].map(csvCell).join(','));
  return [header.join(','), ...rows].join('\n');
}

/**
 * O que é: gerador de relatório Markdown para requisições importadas.
 * O que faz: apresenta inventário redigido de métodos, hosts, caminhos e requests sem reproduzir cookies, tokens ou payloads.
 */
export function formatMarkdownReport(report) {
  if (!report || !Array.isArray(report.requests)) throw new TypeError('Forneça um relatório retornado por importBurpRequests.');
  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Burp Request Import Report',
    '',
    `- **Requisições interpretadas:** ${report.summary.parsed}`,
    `- **Requisições únicas:** ${report.summary.unique}`,
    `- **Duplicatas removidas:** ${report.summary.duplicatesRemoved}`,
    `- **Hosts identificados:** ${report.summary.hosts.join(', ') || 'Nenhum'}`,
    `- **Sinais de headers sensíveis:** ${report.summary.requestsWithSensitiveHeaders}`,
    `- **Limitação:** ${report.limitation}`,
    '',
    '## Inventário de requisições',
    '',
    '| ID | Método | URL | Target | Headers | Corpo |',
    '|---|---|---|---|---|---|',
  ];

  for (const request of report.requests) {
    const body = request.body.characters ? `${request.body.characters} chars, hash ${request.body.sha256}${request.body.isJson ? `, JSON: ${request.body.topLevelKeys.join(', ')}` : ''}` : 'Sem corpo';
    lines.push(`| ${request.id} | ${request.method} | ${clean(request.url)} | ${clean(request.target)} | ${clean(request.headerNames.join(', '))} | ${clean(body)} |`);
  }

  lines.push('', '## Métodos observados', '');
  for (const [method, count] of Object.entries(report.summary.methods)) lines.push(`- ${method}: ${count}`);

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos da linha de comando.
 * O que faz: retorna o valor logo após flags como --input, --base-url, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: descreve como importar texto HTTP local e exportar inventários sem abrir proxy, conectar ao Burp ou reenviar tráfego.
 */
function showHelp() {
  console.log(`\nUso:\n  node burp-request-importer.js --input burp-requests.txt [opções]\n\nEntrada:\n  Arquivo texto com uma ou mais requisições HTTP brutas. Cada bloco deve iniciar com uma request line, como:\n  GET /api/profile HTTP/1.1\n  Host: app.exemplo.com\n\nOpções:\n  --base-url URL          Base para reconstruir URLs de request targets relativos\n  --format FORMATO        json, csv ou markdown. Padrão: json\n  --output ARQUIVO        Salva o relatório em arquivo local\n  --pretty                Formata JSON com indentação\n\nExemplo:\n  node burp-request-importer.js --input burp-requests.txt --base-url 'https://app.exemplo.com' --format markdown --output requests-report.md\n\nObservação: authorization, cookies, tokens e API keys são redigidos automaticamente no inventário.\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const report = importBurpRequests(await readFile(input, 'utf8'), { baseUrl: getCliOption('base-url') ?? null });
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(report)
        : format === 'csv'
          ? formatCsv(report)
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
