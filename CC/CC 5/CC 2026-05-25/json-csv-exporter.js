#!/usr/bin/env node

/**
 * JSON CSV Exporter
 *
 * O que é: um utilitário JavaScript para converter dados JSON locais em CSV ou converter CSV simples em JSON.
 * O que faz: achata objetos aninhados, preserva arrays como JSON, permite selecionar colunas, ordenar registros, escolher
 * delimitador e redigir campos sensíveis antes da exportação. Ele não acessa rede, não envia dados e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { jsonToCsv, csvToJson } from './json-csv-exporter.js';
 *
 *   const csv = jsonToCsv([{ id: 1, user: { name: 'Ana' } }]);
 *   const data = csvToJson('id,name\n1,Ana');
 *
 * Uso via CLI:
 *   node json-csv-exporter.js --input data.json --to csv --output data.csv
 *   node json-csv-exporter.js --input data.csv --to json --output data.json
 */

import { readFile, writeFile } from 'node:fs/promises';

const DEFAULT_SENSITIVE_FIELD_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session|sid|csrf|xsrf|email|phone|telefone|cpf|cnpj|credit[_-]?card|card[_-]?number|cvv|ssn)/i;

/**
 * O que é: função para identificar se um objeto é um mapa JSON simples.
 * O que faz: diferencia objetos comuns de arrays, null e outros valores para decidir quando achatar propriedades na exportação.
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * O que é: função para achatar um objeto JSON recursivamente.
 * O que faz: transforma estruturas como user.name em colunas user.name, mantendo arrays serializados em JSON para não perder informação.
 */
export function flattenObject(value, prefix = '', output = {}) {
  if (!isPlainObject(value)) {
    output[prefix || 'value'] = Array.isArray(value) ? JSON.stringify(value) : value;
    return output;
  }

  for (const [key, item] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (isPlainObject(item)) flattenObject(item, path, output);
    else output[path] = Array.isArray(item) ? JSON.stringify(item) : item;
  }
  return output;
}

/**
 * O que é: função para redigir valores de campos potencialmente sensíveis.
 * O que faz: substitui valores por um marcador simples quando o caminho ou nome de coluna corresponde aos padrões configurados.
 */
function redactFieldValue(path, value, options) {
  const lastKey = path.split('.').at(-1) ?? path;
  const shouldRedact = options.redactFields.has(path.toLowerCase()) || options.redactFields.has(lastKey.toLowerCase()) || options.sensitiveFieldPatterns.some((pattern) => pattern.test(path) || pattern.test(lastKey));
  if (!shouldRedact || value === null || value === undefined || value === '') return value;
  return '[REDACTED]';
}

/**
 * O que é: função para normalizar registros JSON antes da exportação.
 * O que faz: aceita array de objetos, objeto isolado ou array de valores; achata objetos e aplica redação local de campos sensíveis.
 */
function normalizeJsonRows(data, options) {
  const records = Array.isArray(data) ? data : [data];
  return records.map((record) => {
    const flattened = flattenObject(record);
    return Object.fromEntries(Object.entries(flattened).map(([path, value]) => [path, redactFieldValue(path, value, options)]));
  });
}

/**
 * O que é: função para escapar células CSV.
 * O que faz: envolve valores entre aspas quando necessário e duplica aspas internas para preservar vírgulas, quebras de linha e texto.
 */
function csvCell(value, delimiter) {
  const text = value === null || value === undefined ? '' : String(value);
  const expression = new RegExp(`["\\n\\r${delimiter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`);
  return expression.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * O que é: exportador de JSON para CSV.
 * O que faz: reúne colunas, achata objetos, aplica redação opcional e produz texto CSV com delimitador configurável; não grava arquivo
 * nem compartilha os dados por conta própria.
 *
 * @param {unknown} data Dados JSON locais.
 * @param {object} [options] Opções de exportação.
 * @returns {{csv: string, columns: string[], rows: number, redactionEnabled: boolean}} Resultado em CSV e metadados.
 */
export function jsonToCsv(data, options = {}) {
  const settings = {
    delimiter: ',',
    columns: null,
    sortBy: null,
    redactSensitive: false,
    redactFields: [],
    sensitiveFieldPatterns: [DEFAULT_SENSITIVE_FIELD_PATTERN],
    includeHeader: true,
    ...options,
  };
  if (typeof settings.delimiter !== 'string' || settings.delimiter.length !== 1) throw new TypeError('delimiter deve ter exatamente um caractere.');
  settings.redactFields = new Set(settings.redactFields.map((field) => String(field).toLowerCase()));
  settings.sensitiveFieldPatterns = settings.redactSensitive
    ? settings.sensitiveFieldPatterns.map((pattern) => pattern instanceof RegExp ? pattern : new RegExp(String(pattern), 'i'))
    : [];

  const rows = normalizeJsonRows(data, settings);
  const columns = settings.columns
    ? settings.columns.map(String)
    : [...new Set(rows.flatMap((row) => Object.keys(row)))].sort((a, b) => a.localeCompare(b));
  if (settings.sortBy) {
    const field = String(settings.sortBy);
    rows.sort((first, second) => String(first[field] ?? '').localeCompare(String(second[field] ?? ''), 'pt-BR', { numeric: true }));
  }

  const output = [];
  if (settings.includeHeader) output.push(columns.map((column) => csvCell(column, settings.delimiter)).join(settings.delimiter));
  for (const row of rows) output.push(columns.map((column) => csvCell(row[column], settings.delimiter)).join(settings.delimiter));

  return { csv: output.join('\n'), columns, rows: rows.length, redactionEnabled: settings.redactSensitive };
}

/**
 * O que é: parser simples de texto CSV.
 * O que faz: interpreta aspas, delimitadores e quebras de linha em CSV padrão, retornando uma matriz de células sem inferir tipos.
 */
export function parseCsv(text, delimiter = ',') {
  if (typeof text !== 'string') throw new TypeError('text deve ser uma string CSV.');
  if (typeof delimiter !== 'string' || delimiter.length !== 1) throw new TypeError('delimiter deve ter exatamente um caractere.');

  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    const next = text[index + 1];

    if (character === '"') {
      if (quoted && next === '"') {
        cell += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
      continue;
    }

    if (character === delimiter && !quoted) {
      row.push(cell);
      cell = '';
      continue;
    }

    if ((character === '\n' || character === '\r') && !quoted) {
      if (character === '\r' && next === '\n') index += 1;
      row.push(cell);
      if (row.some((value) => value !== '')) rows.push(row);
      row = [];
      cell = '';
      continue;
    }

    cell += character;
  }

  if (quoted) throw new SyntaxError('CSV possui aspas não fechadas.');
  row.push(cell);
  if (row.some((value) => value !== '')) rows.push(row);
  return rows;
}

/**
 * O que é: conversor de CSV para JSON.
 * O que faz: usa primeira linha como cabeçalho, cria objetos por linha e pode converter strings vazias para null; não faz upload ou
 * inferência agressiva de tipos para evitar alterações inesperadas nos dados.
 *
 * @param {string} text Conteúdo CSV local.
 * @param {object} [options] Opções de conversão.
 * @returns {{data: object[], columns: string[], rows: number}} Dados JSON e metadados.
 */
export function csvToJson(text, options = {}) {
  const settings = { delimiter: ',', emptyAsNull: false, ...options };
  const rows = parseCsv(text, settings.delimiter);
  if (rows.length === 0) return { data: [], columns: [], rows: 0 };

  const columns = rows[0].map((column, index) => String(column).trim() || `column_${index + 1}`);
  const data = rows.slice(1).map((row) => Object.fromEntries(columns.map((column, index) => [column, row[index] === '' && settings.emptyAsNull ? null : row[index] ?? ''])));
  return { data, columns, rows: data.length };
}

/**
 * O que é: função para gerar relatório Markdown da conversão.
 * O que faz: resume direção, quantidade de registros, colunas, delimitador e redação sem reproduzir o conjunto inteiro de dados.
 */
export function formatMarkdownReport(result, metadata = {}) {
  const columns = result.columns ?? [];
  const lines = [
    '# JSON / CSV Export Report',
    '',
    `- **Conversão:** ${metadata.direction ?? 'Não informada'}`,
    `- **Registros:** ${result.rows ?? 0}`,
    `- **Colunas:** ${columns.length}`,
    `- **Delimitador:** ${metadata.delimiter ?? ','}`,
    `- **Redação sensível:** ${result.redactionEnabled ? 'ativada' : 'desativada'}`,
    '',
    '## Colunas',
    '',
  ];
  if (columns.length === 0) lines.push('- Nenhuma coluna encontrada.');
  else for (const column of columns) lines.push(`- ${column}`);
  lines.push('', '## Limitação', '', 'A conversão é local e preserva valores como texto no caminho CSV → JSON. Revise dados sensíveis e tipos antes de compartilhar ou importar em outro sistema.');
  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos de terminal.
 * O que faz: retorna o valor logo após flags como --input, --output, --to, --delimiter e --columns.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para transformar listas separadas por vírgula em arrays limpos.
 * O que faz: remove espaços e entradas vazias para flags como --columns e --redact-fields.
 */
function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como converter arquivos locais entre JSON e CSV com opções de colunas, delimitador e redação de campos.
 */
function showHelp() {
  console.log(`\nUso:\n  node json-csv-exporter.js --input data.json --to csv --output data.csv [opções]\n  node json-csv-exporter.js --input data.csv --to json --output data.json [opções]\n\nOpções:\n  --delimiter CARACTERE   Delimitador CSV. Padrão: ,\n  --columns LISTA         Colunas para exportação JSON → CSV, separadas por vírgula\n  --sort-by CAMPO         Campo para ordenar JSON → CSV\n  --redact-sensitive      Redige campos sensíveis por padrão antes de exportar CSV\n  --redact-fields LISTA   Campos adicionais a redigir, separados por vírgula\n  --empty-as-null         Converte células vazias para null em CSV → JSON\n  --report ARQUIVO        Salva resumo Markdown da conversão\n\nExemplo:\n  node json-csv-exporter.js --input data.json --to csv --output data.csv --columns 'id,name,email' --redact-sensitive --report export-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');
  const output = getCliOption('output');
  const to = String(getCliOption('to') ?? '').toLowerCase();

  if (process.argv.includes('--help') || !input || !output || !['csv', 'json'].includes(to)) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const delimiter = getCliOption('delimiter') ?? ',';
      const source = await readFile(input, 'utf8');
      const result = to === 'csv'
        ? jsonToCsv(JSON.parse(source), {
            delimiter,
            columns: getCliOption('columns') ? splitList(getCliOption('columns')) : null,
            sortBy: getCliOption('sort-by') ?? null,
            redactSensitive: process.argv.includes('--redact-sensitive'),
            redactFields: splitList(getCliOption('redact-fields')),
          })
        : csvToJson(source, { delimiter, emptyAsNull: process.argv.includes('--empty-as-null') });
      const content = to === 'csv' ? result.csv : JSON.stringify(result.data, null, 2);

      await writeFile(output, `${content}\n`, 'utf8');
      const reportFile = getCliOption('report');
      if (reportFile) {
        await writeFile(reportFile, `${formatMarkdownReport(result, { direction: to === 'csv' ? 'JSON → CSV' : 'CSV → JSON', delimiter })}\n`, 'utf8');
      }
      console.log(`Conversão concluída: ${result.rows} registro(s), ${result.columns.length} coluna(s).`);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
