#!/usr/bin/env node

/**
 * OpenAPI Authorization Matrix
 *
 * O que é: um utilitário JavaScript para transformar um inventário OpenAPI local em uma matriz documental de autenticação
 * e autorização declaradas.
 * O que faz: importa uma especificação OpenAPI/Swagger JSON ou o inventário do api-spec-parser, lista endpoints, métodos,
 * esquemas de segurança, operações de escrita e lacunas de documentação; exporta JSON, CSV ou Markdown. Ele não chama APIs,
 * não envia credenciais, não testa bypasses e não confirma os controles efetivos de um servidor em produção.
 *
 * Uso como módulo:
 *   import { buildOpenApiAuthMatrix, analyzeOpenApiAuthMatrix } from './openapi-auth-matrix.js';
 *
 *   const matrix = buildOpenApiAuthMatrix(openApiInventory);
 *   const analysis = analyzeOpenApiAuthMatrix(matrix);
 *
 * Uso via CLI:
 *   node openapi-auth-matrix.js --input api-inventory.json --format markdown --output auth-matrix.md
 *   node openapi-auth-matrix.js --input openapi.json --format csv --output auth-matrix.csv
 */

import { readFile, writeFile } from 'node:fs/promises';

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const VALID_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']);

/**
 * O que é: função para normalizar métodos HTTP declarados.
 * O que faz: converte valores para maiúsculas e rejeita métodos fora do conjunto suportado, mantendo a matriz consistente.
 */
function normalizeMethod(value) {
  const method = String(value ?? '').trim().toUpperCase();
  if (!VALID_METHODS.has(method)) throw new TypeError(`Método HTTP inválido ou não suportado: ${value}`);
  return method;
}

/**
 * O que é: função para normalizar caminhos de endpoint.
 * O que faz: garante barra inicial e remove barras redundantes, preservando placeholders OpenAPI como {userId}.
 */
function normalizePath(value) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError('Cada endpoint deve possuir um path não vazio.');
  let path = value.trim();
  if (!path.startsWith('/')) path = `/${path}`;
  path = path.replace(/\/{2,}/g, '/');
  return path.length > 1 ? path.replace(/\/+$/, '') : path;
}

/**
 * O que é: função para garantir listas de texto únicas.
 * O que faz: remove valores vazios e duplicados preservando a ordem, para tags, esquemas de segurança e códigos de resposta.
 */
function uniqueStrings(values = []) {
  const output = [];
  const seen = new Set();
  for (const value of Array.isArray(values) ? values : [values]) {
    const text = String(value ?? '').trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    output.push(text);
  }
  return output;
}

/**
 * O que é: função para extrair nomes de esquemas de segurança de formatos OpenAPI compatíveis.
 * O que faz: aceita requisitos como [{ bearerAuth: [] }] e o formato resumido do api-spec-parser, sem inferir escopos ou
 * verificar credenciais reais.
 */
function securitySchemeNames(security) {
  if (!Array.isArray(security)) return [];
  const names = [];

  for (const requirement of security) {
    if (Array.isArray(requirement)) {
      for (const item of requirement) if (item?.scheme) names.push(item.scheme);
    } else if (requirement && typeof requirement === 'object') {
      names.push(...Object.keys(requirement));
    }
  }

  return uniqueStrings(names);
}

/**
 * O que é: função para normalizar informações de esquemas de segurança.
 * O que faz: converte securitySchemes OpenAPI 3 ou securityDefinitions Swagger 2 em um mapa de metadados para o relatório.
 */
function normalizeSecuritySchemes(schemes = {}) {
  if (!schemes || typeof schemes !== 'object' || Array.isArray(schemes)) return {};

  return Object.fromEntries(Object.entries(schemes).map(([name, scheme]) => [name, {
    name,
    type: scheme?.type ?? null,
    scheme: scheme?.scheme ?? null,
    bearerFormat: scheme?.bearerFormat ?? null,
    in: scheme?.in ?? null,
    nameIn: scheme?.name ?? null,
    openIdConnectUrl: scheme?.openIdConnectUrl ?? null,
  }]));
}

/**
 * O que é: função para converter uma especificação OpenAPI/Swagger em inventário mínimo.
 * O que faz: percorre paths locais, combina segurança global e de operação conforme declarado e preserva metadados necessários
 * para a matriz. Não resolve referências externas nem faz chamadas HTTP.
 */
function inventoryFromOpenApi(spec) {
  if (!spec || typeof spec !== 'object' || !spec.paths || typeof spec.paths !== 'object') {
    throw new TypeError('Especificação OpenAPI/Swagger inválida: paths ausente ou inválido.');
  }

  const globalSecurity = spec.security;
  const endpoints = [];

  for (const [rawPath, pathItem] of Object.entries(spec.paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;

    for (const [rawMethod, operation] of Object.entries(pathItem)) {
      const method = rawMethod.toUpperCase();
      if (!VALID_METHODS.has(method) || !operation || typeof operation !== 'object') continue;
      const security = operation.security === undefined ? globalSecurity : operation.security;

      endpoints.push({
        method,
        path: rawPath,
        operationId: operation.operationId ?? null,
        summary: operation.summary ?? null,
        tags: operation.tags ?? [],
        deprecated: Boolean(operation.deprecated),
        security,
        securityDeclared: Array.isArray(security) && security.length > 0,
        responses: Object.keys(operation.responses ?? {}).map((status) => ({ status })),
      });
    }
  }

  return {
    specification: {
      title: spec.info?.title ?? null,
      apiVersion: spec.info?.version ?? null,
      openApiVersion: spec.openapi ?? spec.swagger ?? null,
      securitySchemes: Object.values(normalizeSecuritySchemes(spec.components?.securitySchemes ?? spec.securityDefinitions ?? {})),
    },
    endpoints,
    summary: { endpointCount: endpoints.length, pathCount: Object.keys(spec.paths).length },
  };
}

/**
 * O que é: função para reconhecer formatos de entrada locais aceitos.
 * O que faz: aceita especificação OpenAPI/Swagger bruta, saída do api-spec-parser ou inventário com endpoints, sem carregar
 * dependências externas nem fazer descoberta de documentos remotos.
 */
function normalizeInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('A entrada deve ser um objeto OpenAPI/Swagger ou inventário local.');
  }

  if (input.paths && (input.openapi || input.swagger)) return inventoryFromOpenApi(input);
  if (Array.isArray(input.endpoints)) return input;
  throw new TypeError('Formato não reconhecido. Forneça OpenAPI/Swagger com paths ou um objeto com endpoints.');
}

/**
 * O que é: função para converter um endpoint documentado em uma linha de matriz.
 * O que faz: relaciona método, caminho, operação, esquemas de segurança declarados, risco de escrita e observações de revisão,
 * sem afirmar se a autenticação ou autorização funciona no ambiente real.
 */
function matrixRowFromEndpoint(endpoint, schemeMap) {
  const method = normalizeMethod(endpoint.method);
  const path = normalizePath(endpoint.path);
  const schemeNames = uniqueStrings(endpoint.securitySchemes ?? securitySchemeNames(endpoint.security));
  const declared = endpoint.securityDeclared === undefined ? Array.isArray(endpoint.security) && endpoint.security.length > 0 : Boolean(endpoint.securityDeclared);
  const schemes = schemeNames.map((name) => schemeMap[name] ?? { name, type: 'não resolvido', scheme: null, bearerFormat: null, in: null, nameIn: null });
  const responses = uniqueStrings((endpoint.responses ?? []).map((response) => typeof response === 'object' ? response.status : response));
  const tags = uniqueStrings(endpoint.tags ?? []);
  const reviewFlags = [];

  if (!declared) reviewFlags.push('Sem segurança declarada');
  if (WRITE_METHODS.has(method)) reviewFlags.push('Operação de escrita');
  if (endpoint.deprecated) reviewFlags.push('Depreciado');
  if (method === 'TRACE') reviewFlags.push('Método TRACE documentado');
  if (schemeNames.length > 1) reviewFlags.push('Múltiplos esquemas declarados');

  return {
    id: `${method} ${path}`,
    method,
    path,
    operationId: endpoint.operationId ?? null,
    summary: endpoint.summary ?? null,
    tags,
    deprecated: Boolean(endpoint.deprecated),
    isWriteOperation: WRITE_METHODS.has(method),
    securityDeclared: declared,
    securitySchemes: schemes,
    responseCodes: responses,
    reviewFlags,
  };
}

/**
 * O que é: construtor de matriz de autenticação e autorização baseada em OpenAPI.
 * O que faz: transforma documentação local em linhas revisáveis para cada endpoint, incorporando segurança global ou por operação
 * quando disponível. A matriz é documental e não envia tokens, requisições ou testes para a API.
 *
 * @param {object} input Especificação OpenAPI/Swagger ou inventário local compatível.
 * @returns {{generatedAt: string, api: object, securitySchemes: object[], rows: object[], summary: object}}
 */
export function buildOpenApiAuthMatrix(input) {
  const inventory = normalizeInput(input);
  const schemeSource = inventory.specification?.securitySchemes ?? [];
  const schemeMap = Object.fromEntries(schemeSource.map((scheme) => [scheme.name, scheme]));
  const rows = inventory.endpoints.map((endpoint) => matrixRowFromEndpoint(endpoint, schemeMap))
    .sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));

  return {
    generatedAt: new Date().toISOString(),
    api: {
      title: inventory.specification?.title ?? null,
      apiVersion: inventory.specification?.apiVersion ?? null,
      openApiVersion: inventory.specification?.version ?? inventory.specification?.openApiVersion ?? null,
    },
    securitySchemes: Object.values(schemeMap),
    rows,
    summary: {
      endpointCount: rows.length,
      writeOperations: rows.filter((row) => row.isWriteOperation).length,
      withDeclaredSecurity: rows.filter((row) => row.securityDeclared).length,
      withoutDeclaredSecurity: rows.filter((row) => !row.securityDeclared).length,
      deprecated: rows.filter((row) => row.deprecated).length,
    },
  };
}

/**
 * O que é: analisador de cobertura declarativa da matriz OpenAPI.
 * O que faz: agrupa endpoints sem segurança, operações de escrita, esquemas não resolvidos e combinações que requerem revisão;
 * não determina vulnerabilidade, pois documentação e comportamento real podem divergir.
 */
export function analyzeOpenApiAuthMatrix(matrix) {
  if (!matrix || !Array.isArray(matrix.rows)) throw new TypeError('Forneça uma matriz retornada por buildOpenApiAuthMatrix.');

  const withoutDeclaredSecurity = matrix.rows.filter((row) => !row.securityDeclared);
  const writeWithoutDeclaredSecurity = matrix.rows.filter((row) => row.isWriteOperation && !row.securityDeclared);
  const unresolvedSchemes = matrix.rows.filter((row) => row.securitySchemes.some((scheme) => scheme.type === 'não resolvido'));
  const traceOperations = matrix.rows.filter((row) => row.method === 'TRACE');
  const byScheme = {};

  for (const row of matrix.rows) {
    const names = row.securitySchemes.length ? row.securitySchemes.map((scheme) => scheme.name) : ['Sem segurança declarada'];
    for (const name of names) byScheme[name] = (byScheme[name] ?? 0) + 1;
  }

  return {
    matrix,
    analysis: {
      withoutDeclaredSecurity,
      writeWithoutDeclaredSecurity,
      unresolvedSchemes,
      traceOperations,
      byScheme: Object.fromEntries(Object.entries(byScheme).sort(([a], [b]) => a.localeCompare(b))),
      reviewNotes: [
        'Ausência de segurança declarada na especificação não prova que a operação seja desprotegida; ela pode ser pública por projeto ou ter controles implementados fora do documento.',
        'Operações de escrita sem segurança declarada devem ser revisadas com prioridade para confirmar requisitos de autenticação, autorização por objeto e proteção CSRF quando houver cookies.',
        'A matriz descreve autenticação declarada. Controle de acesso fino precisa ser validado no servidor por ação e recurso, especialmente para IDs em path, query ou body.',
      ],
    },
  };
}

/**
 * O que é: função para formatar células CSV com segurança.
 * O que faz: escapa aspas e delimitadores para permitir exportação da matriz em planilhas e sistemas de acompanhamento.
 */
function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * O que é: exportador CSV da matriz de segurança OpenAPI.
 * O que faz: gera uma tabela plana por endpoint com esquemas declarados, códigos de resposta, flags e pontos de revisão.
 */
export function formatCsv(matrix) {
  if (!matrix || !Array.isArray(matrix.rows)) throw new TypeError('Forneça uma matriz válida.');

  const header = ['method', 'path', 'operation_id', 'summary', 'tags', 'write_operation', 'security_declared', 'security_schemes', 'response_codes', 'deprecated', 'review_flags'];
  const rows = matrix.rows.map((row) => [
    row.method,
    row.path,
    row.operationId ?? '',
    row.summary ?? '',
    row.tags.join('; '),
    row.isWriteOperation,
    row.securityDeclared,
    row.securitySchemes.map((scheme) => `${scheme.name} (${scheme.type ?? 'tipo não informado'}${scheme.scheme ? `/${scheme.scheme}` : ''})`).join('; '),
    row.responseCodes.join('; '),
    row.deprecated,
    row.reviewFlags.join('; '),
  ].map(csvCell).join(','));

  return [header.join(','), ...rows].join('\n');
}

/**
 * O que é: gerador de relatório Markdown da matriz OpenAPI.
 * O que faz: apresenta esquemas de segurança e endpoints documentados, destacando lacunas e operações que requerem revisão.
 */
export function formatMarkdownReport(result) {
  const matrix = result?.matrix ?? result;
  const analysis = result?.analysis ?? analyzeOpenApiAuthMatrix(matrix).analysis;
  if (!matrix || !Array.isArray(matrix.rows)) throw new TypeError('Forneça uma matriz ou resultado de análise válido.');

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# OpenAPI Authentication & Authorization Matrix',
    '',
    `- **API:** ${matrix.api.title ?? 'Não informada'}`,
    `- **Versão da API:** ${matrix.api.apiVersion ?? 'Não informada'}`,
    `- **Endpoints documentados:** ${matrix.summary.endpointCount}`,
    `- **Com segurança declarada:** ${matrix.summary.withDeclaredSecurity}`,
    `- **Sem segurança declarada:** ${matrix.summary.withoutDeclaredSecurity}`,
    `- **Operações de escrita:** ${matrix.summary.writeOperations}`,
    '',
    '## Esquemas de segurança declarados',
    '',
  ];

  if (matrix.securitySchemes.length === 0) lines.push('- Nenhum esquema de segurança foi encontrado na documentação importada.');
  else for (const scheme of matrix.securitySchemes) {
    lines.push(`- ${scheme.name}: tipo ${scheme.type ?? 'não informado'}${scheme.scheme ? ` (${scheme.scheme})` : ''}${scheme.in ? ` em ${scheme.in}` : ''}`);
  }

  lines.push('', '## Matriz por endpoint', '', '| Método | Caminho | Escrita | Segurança declarada | Esquema(s) | Respostas | Revisão |', '|---|---|---|---|---|---|---|');
  for (const row of matrix.rows) {
    const schemes = row.securitySchemes.map((scheme) => scheme.name).join(', ') || '—';
    lines.push(`| ${row.method} | ${clean(row.path)} | ${row.isWriteOperation ? 'Sim' : 'Não'} | ${row.securityDeclared ? 'Sim' : 'Não'} | ${clean(schemes)} | ${clean(row.responseCodes.join(', ') || '—')} | ${clean(row.reviewFlags.join('; ') || '—')} |`);
  }

  lines.push('', '## Pontos de revisão', '');
  lines.push(`- Operações de escrita sem segurança declarada: ${analysis.writeWithoutDeclaredSecurity.length}.`);
  lines.push(`- Endpoints com esquemas não resolvidos: ${analysis.unresolvedSchemes.length}.`);
  lines.push(`- Operações TRACE documentadas: ${analysis.traceOperations.length}.`);
  for (const note of analysis.reviewNotes) lines.push(`- ${note}`);

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos do terminal.
 * O que faz: retorna o valor imediatamente após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como gerar a matriz a partir de OpenAPI/Swagger ou inventários locais, sem acessar a API declarada.
 */
function showHelp() {
  console.log(`\nUso:\n  node openapi-auth-matrix.js --input openapi.json [opções]\n  node openapi-auth-matrix.js --input api-inventory.json [opções]\n\nEntrada:\n  Aceita OpenAPI 3, Swagger 2 ou inventários com um array endpoints, como a saída do api-spec-parser.js.\n\nOpções:\n  --format FORMATO       json, csv ou markdown. Padrão: json\n  --output ARQUIVO       Salva resultado em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node openapi-auth-matrix.js --input openapi.json --format markdown --output auth-matrix.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const matrix = buildOpenApiAuthMatrix(data);
      const analysis = analyzeOpenApiAuthMatrix(matrix);
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(analysis)
        : format === 'csv'
          ? formatCsv(matrix)
          : JSON.stringify(analysis, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
