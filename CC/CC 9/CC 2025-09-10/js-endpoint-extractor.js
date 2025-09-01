#!/usr/bin/env node

/**
 * JavaScript Endpoint Extractor
 *
 * O que é: um utilitário JavaScript para extrair referências explícitas de endpoints HTTP(S) e caminhos de API
 * a partir de arquivos JavaScript locais ou texto fornecido pelo usuário.
 * O que faz: identifica literais de string usados em chamadas fetch, axios, XMLHttpRequest e padrões de URL/caminho,
 * normaliza e remove duplicatas, classifica referências absolutas, relativas e potencialmente dinâmicas. Ele não baixa
 * scripts, não visita endpoints, não executa JavaScript e não tenta descobrir rotas por força bruta.
 *
 * Uso como módulo:
 *   import { extractEndpoints, extractFromFiles } from './js-endpoint-extractor.js';
 *
 *   const result = extractEndpoints('fetch("/api/v1/profile"); axios.get("https://api.exemplo.com/status");');
 *
 * Uso via CLI:
 *   node js-endpoint-extractor.js --input app.js --json
 *   node js-endpoint-extractor.js --input dist/app.js,dist/vendor.js --base-url 'https://app.exemplo.com' --output endpoints.txt
 */

import { readFile, writeFile } from 'node:fs/promises';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const LIKELY_ENDPOINT_PREFIXES = ['/', './', '../', 'http://', 'https://'];

/**
 * O que é: função para calcular a posição de uma ocorrência dentro do texto.
 * O que faz: converte um índice de caracteres em número de linha e coluna, facilitando auditoria manual do resultado.
 */
function locationFromIndex(text, index) {
  const before = text.slice(0, index);
  const line = before.split('\n').length;
  const lastBreak = before.lastIndexOf('\n');
  return { line, column: index - lastBreak };
}

/**
 * O que é: função para desescapar literais simples de JavaScript.
 * O que faz: trata escapes frequentes de aspas, barras e sequências unicode/hexadecimais sem executar o código-fonte.
 */
function unescapeJavaScriptString(value) {
  return value
    .replace(/\\u\{([\da-f]{1,6})\}/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/\\u([\da-f]{4})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x([\da-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\([\\'"`/bnrtvf])/g, (_, character) => ({ b: '\b', n: '\n', r: '\r', t: '\t', v: '\v', f: '\f' }[character] ?? character));
}

/**
 * O que é: função para remover comentários JavaScript preservando índices e quebras de linha.
 * O que faz: substitui comentários de linha e bloco por espaços, reduzindo falsos positivos sem alterar as posições
 * originais de referências encontradas no arquivo.
 */
function maskComments(source) {
  let output = '';
  let index = 0;
  let quote = null;

  while (index < source.length) {
    const current = source[index];
    const next = source[index + 1];

    if (quote) {
      output += current;
      if (current === '\\') {
        output += next ?? '';
        index += 2;
        continue;
      }
      if (current === quote) quote = null;
      index += 1;
      continue;
    }

    if (current === '"' || current === "'" || current === '`') {
      quote = current;
      output += current;
      index += 1;
      continue;
    }

    if (current === '/' && next === '/') {
      while (index < source.length && source[index] !== '\n') {
        output += ' ';
        index += 1;
      }
      continue;
    }

    if (current === '/' && next === '*') {
      output += '  ';
      index += 2;
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) {
        output += source[index] === '\n' ? '\n' : ' ';
        index += 1;
      }
      if (index < source.length) {
        output += '  ';
        index += 2;
      }
      continue;
    }

    output += current;
    index += 1;
  }

  return output;
}

/**
 * O que é: função de normalização segura de referências de endpoint.
 * O que faz: remove espaços externos, preserva placeholders dinâmicos e, quando possível, padroniza URLs HTTP(S)
 * sem fazer requisições, resolver DNS ou seguir redirecionamentos.
 */
function normalizeReference(value) {
  const trimmed = value.trim();
  if (!trimmed) return null;

  try {
    const url = new URL(trimmed);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.hostname = url.hostname.toLowerCase();
    if ((url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80')) {
      url.port = '';
    }
    return url.toString();
  } catch {
    return trimmed.replace(/\/{2,}/g, '/').replace(/^\.(?=\/)/, '');
  }
}

/**
 * O que é: função para classificar o formato de uma referência encontrada.
 * O que faz: diferencia URL absoluta, caminho absoluto, caminho relativo e valor que contém interpolação ou placeholder.
 */
function classifyReference(value) {
  if (/^https?:\/\//i.test(value)) return 'absolute-url';
  if (/^\//.test(value)) return 'absolute-path';
  if (/^(\.\/|\.\.\/)/.test(value)) return 'relative-path';
  if (/\$\{|\{\{|:\w+|%[a-z0-9_]+%/i.test(value)) return 'dynamic-template';
  return 'other';
}

/**
 * O que é: função para identificar se um literal parece uma rota ou endpoint.
 * O que faz: aceita URLs HTTP(S), caminhos iniciados por /, ./ ou ../ e valores de API recorrentes; rejeita literais
 * comuns como nomes de arquivos estáticos, identificadores simples e esquemas não HTTP.
 */
function looksLikeEndpoint(value) {
  const normalized = value.trim();
  if (!normalized || normalized.length > 2048) return false;
  if (!LIKELY_ENDPOINT_PREFIXES.some((prefix) => normalized.toLowerCase().startsWith(prefix))) return false;
  if (/^(?:data|javascript|mailto|tel):/i.test(normalized)) return false;
  if (/\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp3|mp4|webm)(?:[?#].*)?$/i.test(normalized)) return false;
  return true;
}

/**
 * O que é: função para registrar um endpoint sem duplicação.
 * O que faz: adiciona a referência normalizada ao mapa de resultados e agrega fontes, linhas, contextos e métodos HTTP
 * associados, em vez de repetir a mesma URL ou caminho diversas vezes.
 */
function addCandidate(candidates, source, value, index, context, method = null) {
  const decoded = unescapeJavaScriptString(value);
  if (!looksLikeEndpoint(decoded)) return;

  const normalized = normalizeReference(decoded);
  if (!normalized) return;

  const key = normalized.toLowerCase();
  const location = locationFromIndex(source, index);
  const existing = candidates.get(key) ?? {
    endpoint: normalized,
    type: classifyReference(decoded),
    methods: [],
    occurrences: [],
  };

  if (method && !existing.methods.includes(method)) existing.methods.push(method);
  existing.occurrences.push({ ...location, context });
  candidates.set(key, existing);
}

/**
 * O que é: função para localizar strings em chamadas de bibliotecas HTTP conhecidas.
 * O que faz: reconhece fetch, axios.<método>, axios({...}), XMLHttpRequest.open e $.ajax para associar, quando possível,
 * a referência de endpoint ao método HTTP declarado no próprio código.
 */
function extractHttpCallLiterals(source, candidates) {
  const patterns = [
    { context: 'fetch', expression: /\bfetch\s*\(\s*(['"`])([\s\S]*?)\1/g, method: null },
    { context: 'axios-method', expression: /\baxios\.(get|post|put|patch|delete|head|options)\s*\(\s*(['"`])([\s\S]*?)\2/g, methodIndex: 1, valueIndex: 3 },
    { context: 'xhr-open', expression: /\.open\s*\(\s*(['"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(['"`])([\s\S]*?)\3/gi, methodIndex: 2, valueIndex: 4 },
    { context: 'jquery-ajax-url', expression: /\$\.ajax\s*\(\s*\{[\s\S]{0,1000}?\burl\s*:\s*(['"`])([\s\S]*?)\1/gi, valueIndex: 2 },
    { context: 'request-url', expression: /\b(?:url|endpoint|baseURL)\s*:\s*(['"`])([\s\S]*?)\1/g, valueIndex: 2 },
  ];

  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern.expression)) {
      const valueIndex = pattern.valueIndex ?? 2;
      const value = match[valueIndex];
      const valueOffset = match[0].lastIndexOf(value);
      const method = pattern.methodIndex ? match[pattern.methodIndex].toUpperCase() : pattern.method;
      addCandidate(candidates, source, value, match.index + valueOffset, pattern.context, method);
    }
  }
}

/**
 * O que é: função para localizar strings de URL ou caminho fora de chamadas HTTP reconhecidas.
 * O que faz: varre literais simples entre aspas e template strings sem interpolação, permitindo encontrar constantes de API
 * e rotas declaradas indiretamente; classificações deixam claro que a ocorrência não prova uma chamada de rede.
 */
function extractStandaloneLiterals(source, candidates) {
  const expression = /(['"])((?:\\.|(?!\1)[\s\S]){1,2048}?)\1|`([^`$]{1,2048})`/g;

  for (const match of source.matchAll(expression)) {
    const value = match[2] ?? match[3];
    const valueOffset = match[0].indexOf(value);
    addCandidate(candidates, source, value, match.index + valueOffset, 'string-literal');
  }
}

/**
 * O que é: extrator de endpoints a partir de código JavaScript local.
 * O que faz: analisa texto sem executar o código, extrai referências estáticas prováveis, remove duplicatas e devolve
 * ocorrências rastreáveis. Referências dinâmicas que dependem de variáveis ou lógica em tempo de execução não são resolvidas.
 *
 * @param {string} source Código JavaScript ou TypeScript como texto.
 * @param {object} [options] Opções da extração.
 * @param {string|null} [options.baseUrl=null] Base usada apenas para resolver caminhos relativos em resolvedUrl.
 * @param {boolean} [options.includeStandalone=true] Inclui literais fora de chamadas HTTP reconhecidas.
 * @returns {{endpoints: object[], summary: object}}
 */
export function extractEndpoints(source, options = {}) {
  if (typeof source !== 'string') throw new TypeError('source deve ser uma string.');

  const settings = { baseUrl: null, includeStandalone: true, ...options };
  const masked = maskComments(source);
  const candidates = new Map();

  extractHttpCallLiterals(masked, candidates);
  if (settings.includeStandalone) extractStandaloneLiterals(masked, candidates);

  const endpoints = [...candidates.values()]
    .map((candidate) => {
      let resolvedUrl = null;
      if (settings.baseUrl) {
        try {
          resolvedUrl = new URL(candidate.endpoint, settings.baseUrl).toString();
        } catch {
          resolvedUrl = null;
        }
      }
      return { ...candidate, methods: candidate.methods.sort(), resolvedUrl };
    })
    .sort((a, b) => a.endpoint.localeCompare(b.endpoint));

  const byType = Object.fromEntries(
    [...new Set(endpoints.map((item) => item.type))].map((type) => [type, endpoints.filter((item) => item.type === type).length])
  );

  return {
    endpoints,
    summary: {
      totalUnique: endpoints.length,
      totalOccurrences: endpoints.reduce((total, item) => total + item.occurrences.length, 0),
      byType,
      recognizedMethods: HTTP_METHODS.filter((method) => endpoints.some((item) => item.methods.includes(method))),
    },
  };
}

/**
 * O que é: extrator para diversos arquivos JavaScript locais.
 * O que faz: lê arquivos fornecidos explicitamente, extrai referências em cada um e consolida a saída, mantendo o nome
 * do arquivo em cada ocorrência. Não percorre diretórios nem descobre arquivos automaticamente.
 */
export async function extractFromFiles(files, options = {}) {
  if (!Array.isArray(files) || files.length === 0) {
    throw new TypeError('files deve ser um array não vazio de caminhos locais.');
  }

  const all = new Map();

  for (const file of files) {
    const source = await readFile(file, 'utf8');
    const result = extractEndpoints(source, options);

    for (const item of result.endpoints) {
      const key = item.endpoint.toLowerCase();
      const existing = all.get(key) ?? { ...item, methods: [...item.methods], occurrences: [] };
      for (const method of item.methods) if (!existing.methods.includes(method)) existing.methods.push(method);
      existing.occurrences.push(...item.occurrences.map((occurrence) => ({ file, ...occurrence })));
      all.set(key, existing);
    }
  }

  const endpoints = [...all.values()].sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  return {
    endpoints,
    summary: {
      filesProcessed: files.length,
      totalUnique: endpoints.length,
      totalOccurrences: endpoints.reduce((total, item) => total + item.occurrences.length, 0),
    },
  };
}

/**
 * O que é: função auxiliar para obter flags da linha de comando.
 * O que faz: retorna o valor depois de uma opção, como --input app.js ou --output endpoints.txt.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda do terminal.
 * O que faz: apresenta argumentos para analisar arquivos JavaScript locais e exportar endpoints encontrados.
 */
function showHelp() {
  console.log(`\nUso:\n  node js-endpoint-extractor.js --input app.js [opções]\n\nObrigatório:\n  --input ARQUIVOS          Arquivo(s) JavaScript locais, separados por vírgula\n\nOpções:\n  --base-url URL            Resolve caminhos encontrados contra uma URL base, sem fazer requisições\n  --output ARQUIVO          Salva uma lista simples, com um endpoint por linha\n  --json                    Exibe o relatório detalhado em JSON\n  --no-standalone           Ignora strings fora de chamadas HTTP reconhecidas\n\nExemplo:\n  node js-endpoint-extractor.js --input dist/app.js,dist/vendor.js --base-url 'https://app.exemplo.com' --output endpoints.txt\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const files = input.split(',').map((file) => file.trim()).filter(Boolean);
      const result = await extractFromFiles(files, {
        baseUrl: getCliOption('base-url') ?? null,
        includeStandalone: !process.argv.includes('--no-standalone'),
      });

      const output = getCliOption('output');
      if (output) {
        await writeFile(output, `${result.endpoints.map((item) => item.resolvedUrl ?? item.endpoint).join('\n')}\n`, 'utf8');
      }

      if (process.argv.includes('--json')) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`Arquivos processados: ${result.summary.filesProcessed}.`);
        console.log(`Endpoints únicos: ${result.summary.totalUnique}. Ocorrências: ${result.summary.totalOccurrences}.`);
        for (const item of result.endpoints) {
          const methods = item.methods.length ? ` [${item.methods.join(', ')}]` : '';
          console.log(`${item.resolvedUrl ?? item.endpoint}${methods}`);
        }
      }
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
