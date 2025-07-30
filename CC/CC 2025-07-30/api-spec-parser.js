#!/usr/bin/env node

/**
 * API Specification Parser
 *
 * O que é: um utilitário JavaScript para interpretar especificações OpenAPI locais nos formatos JSON ou YAML simples.
 * O que faz: extrai informações de API, servidores declarados, caminhos, métodos HTTP, parâmetros, corpos de requisição,
 * respostas e esquemas de segurança; também gera inventário e relatórios. Ele não acessa servidores, não chama endpoints,
 * não resolve referências remotas e não executa testes contra APIs.
 *
 * Uso como módulo:
 *   import { parseApiSpec, buildApiInventory } from './api-spec-parser.js';
 *
 *   const spec = parseApiSpec(openApiText);
 *   const inventory = buildApiInventory(spec);
 *
 * Uso via CLI:
 *   node api-spec-parser.js --input openapi.json --format markdown --output api-inventory.md
 *   node api-spec-parser.js --input openapi.yaml --format json --pretty
 */

import { readFile, writeFile } from 'node:fs/promises';

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']);

/**
 * O que é: função para remover comentários simples de YAML.
 * O que faz: elimina comentários iniciados por # quando aparecem fora de aspas, preservando valores entre aspas.
 */
function stripYamlComment(line) {
  let quote = null;
  let escaped = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\' && quote === '"') {
      escaped = true;
      continue;
    }
    if ((character === '"' || character === "'") && (!quote || quote === character)) {
      quote = quote ? null : character;
      continue;
    }
    if (character === '#' && !quote) return line.slice(0, index).trimEnd();
  }

  return line.trimEnd();
}

/**
 * O que é: função para separar uma lista YAML simples em itens.
 * O que faz: trata listas inline como [a, b] e valores escalares separados por vírgula, sem cobrir todos os recursos YAML.
 */
function splitYamlInlineList(value) {
  const content = value.trim().replace(/^\[|\]$/g, '');
  if (!content) return [];

  const items = [];
  let current = '';
  let quote = null;

  for (const character of content) {
    if ((character === '"' || character === "'") && (!quote || quote === character)) {
      quote = quote ? null : character;
      current += character;
      continue;
    }
    if (character === ',' && !quote) {
      items.push(current.trim());
      current = '';
      continue;
    }
    current += character;
  }
  if (current.trim()) items.push(current.trim());
  return items;
}

/**
 * O que é: função para interpretar valores escalares YAML comuns.
 * O que faz: reconhece strings entre aspas, booleanos, null, números, arrays e objetos JSON inline; valores complexos
 * permanecem como texto quando não puderem ser interpretados com segurança pelo parser simplificado.
 */
function parseYamlScalar(value) {
  const trimmed = value.trim();
  if (!trimmed) return {};
  if (trimmed === 'null' || trimmed === '~') return null;
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return Number(trimmed);

  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    const quote = trimmed[0];
    const inner = trimmed.slice(1, -1);
    return quote === '"' ? JSON.parse(trimmed) : inner.replace(/''/g, "'");
  }

  if ((trimmed.startsWith('[') && trimmed.endsWith(']')) || (trimmed.startsWith('{') && trimmed.endsWith('}'))) {
    try {
      return JSON.parse(trimmed);
    } catch {
      if (trimmed.startsWith('[')) return splitYamlInlineList(trimmed).map(parseYamlScalar);
    }
  }

  return trimmed;
}

/**
 * O que é: parser YAML básico focado em especificações OpenAPI legíveis.
 * O que faz: converte mapas e listas por indentação para objetos JavaScript, cobrindo casos usuais de OpenAPI; não pretende
 * substituir um parser YAML completo e informa erro quando encontra uma estrutura ambígua ou incompatível.
 */
export function parseSimpleYaml(text) {
  if (typeof text !== 'string') throw new TypeError('O conteúdo YAML deve ser texto.');

  const rawLines = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n');
  const lines = rawLines
    .map((raw, index) => ({ raw: stripYamlComment(raw), line: index + 1 }))
    .filter(({ raw }) => raw.trim());

  const root = {};
  const stack = [{ indent: -1, value: root, type: 'object' }];

  for (let index = 0; index < lines.length; index += 1) {
    const { raw, line } = lines[index];
    const indent = raw.match(/^\s*/)[0].length;
    const content = raw.trim();

    while (stack.length > 1 && indent <= stack.at(-1).indent) stack.pop();
    const parent = stack.at(-1);

    if (content.startsWith('- ')) {
      if (!Array.isArray(parent.value)) {
        throw new SyntaxError(`Linha ${line}: item de lista sem uma lista pai.`);
      }

      const itemContent = content.slice(2).trim();
      if (!itemContent) {
        const next = lines[index + 1];
        const nextIsList = next && next.raw.match(/^\s*/)[0].length > indent && next.raw.trim().startsWith('- ');
        const value = nextIsList ? [] : {};
        parent.value.push(value);
        stack.push({ indent, value, type: Array.isArray(value) ? 'array' : 'object' });
        continue;
      }

      const keyValue = itemContent.match(/^([^:][^:]*):(?:\s*(.*))?$/);
      if (keyValue) {
        const item = {};
        parent.value.push(item);
        const [, key, rawValue = ''] = keyValue;
        const next = lines[index + 1];
        const nextIsList = next && next.raw.match(/^\s*/)[0].length > indent && next.raw.trim().startsWith('- ');
        item[key.trim()] = rawValue.trim() ? parseYamlScalar(rawValue) : (nextIsList ? [] : {});
        stack.push({ indent, value: item, type: 'object' });
        if (!rawValue.trim()) stack.push({ indent: indent + 1, value: item[key.trim()], type: Array.isArray(item[key.trim()]) ? 'array' : 'object' });
      } else {
        parent.value.push(parseYamlScalar(itemContent));
      }
      continue;
    }

    const match = content.match(/^([^:][^:]*):(?:\s*(.*))?$/);
    if (!match) throw new SyntaxError(`Linha ${line}: sintaxe YAML não reconhecida.`);

    if (Array.isArray(parent.value)) {
      throw new SyntaxError(`Linha ${line}: chave encontrada dentro de lista sem item de objeto.`);
    }

    const [, rawKey, rawValue = ''] = match;
    const key = rawKey.trim();
    const next = lines[index + 1];
    const nextIndent = next ? next.raw.match(/^\s*/)[0].length : -1;
    const nextIsList = next && nextIndent > indent && next.raw.trim().startsWith('- ');
    const value = rawValue.trim() ? parseYamlScalar(rawValue) : (nextIsList ? [] : {});

    parent.value[key] = value;
    if (!rawValue.trim()) stack.push({ indent, value, type: Array.isArray(value) ? 'array' : 'object' });
  }

  return root;
}

/**
 * O que é: função para interpretar uma especificação OpenAPI em JSON ou YAML simples.
 * O que faz: detecta JSON pelo primeiro caractere útil; caso contrário, aplica parseSimpleYaml e valida se o documento tem
 * um campo openapi ou swagger e uma estrutura paths adequada, sem carregar arquivos ou referências externas.
 */
export function parseApiSpec(text) {
  if (typeof text !== 'string') throw new TypeError('A especificação deve ser fornecida como texto.');

  const clean = text.replace(/^\uFEFF/, '').trim();
  if (!clean) throw new TypeError('A especificação está vazia.');

  let spec;
  try {
    spec = clean.startsWith('{') || clean.startsWith('[') ? JSON.parse(clean) : parseSimpleYaml(clean);
  } catch (error) {
    throw new SyntaxError(`Não foi possível interpretar a especificação: ${error.message}`);
  }

  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
    throw new TypeError('A especificação precisa ser um objeto JSON ou YAML.');
  }

  const version = spec.openapi ?? spec.swagger;
  if (!version) throw new TypeError('Documento não parece ser OpenAPI/Swagger: campo openapi ou swagger ausente.');
  if (!spec.paths || typeof spec.paths !== 'object') throw new TypeError('A especificação não possui um objeto paths válido.');

  return spec;
}

/**
 * O que é: resolvedor local de referências JSON Pointer internas.
 * O que faz: resolve somente referências iniciadas por #/, como #/components/schemas/User; não busca arquivos, URLs ou
 * referências externas para manter o processamento previsível e totalmente local.
 */
export function resolveLocalRef(spec, reference) {
  if (typeof reference !== 'string' || !reference.startsWith('#/')) return null;

  return reference
    .slice(2)
    .split('/')
    .map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
    .reduce((value, part) => (value && Object.prototype.hasOwnProperty.call(value, part) ? value[part] : null), spec);
}

/**
 * O que é: função para combinar parâmetros de caminho e de operação.
 * O que faz: une os parâmetros declarados em paths./rota.parameters e no método específico, dando precedência ao método
 * para a mesma combinação de name e in.
 */
function mergeParameters(pathParameters = [], operationParameters = []) {
  const merged = new Map();
  for (const parameter of [...pathParameters, ...operationParameters]) {
    if (!parameter || typeof parameter !== 'object') continue;
    const key = `${parameter.in ?? ''}:${parameter.name ?? ''}`;
    merged.set(key, parameter);
  }
  return [...merged.values()];
}

/**
 * O que é: função para resumir um parâmetro OpenAPI.
 * O que faz: extrai nome, localização, obrigatoriedade, descrição e tipo, resolvendo apenas referências internas quando possível.
 */
function summarizeParameter(spec, parameter) {
  const resolved = parameter.$ref ? resolveLocalRef(spec, parameter.$ref) ?? parameter : parameter;
  const schema = resolved.schema?.$ref ? resolveLocalRef(spec, resolved.schema.$ref) ?? resolved.schema : resolved.schema ?? {};

  return {
    name: resolved.name ?? null,
    in: resolved.in ?? null,
    required: Boolean(resolved.required),
    description: resolved.description ?? null,
    type: schema.type ?? (schema.enum ? 'enum' : null),
    format: schema.format ?? null,
  };
}

/**
 * O que é: função para resumir um corpo de requisição OpenAPI.
 * O que faz: lista tipos de conteúdo, obrigatoriedade e referências ou tipos de schema declarados, sem gerar requisições.
 */
function summarizeRequestBody(spec, requestBody) {
  if (!requestBody) return null;
  const resolved = requestBody.$ref ? resolveLocalRef(spec, requestBody.$ref) ?? requestBody : requestBody;
  const content = resolved.content ?? {};

  return {
    required: Boolean(resolved.required),
    description: resolved.description ?? null,
    contentTypes: Object.entries(content).map(([contentType, media]) => {
      const schema = media?.schema?.$ref ? resolveLocalRef(spec, media.schema.$ref) ?? media.schema : media?.schema ?? {};
      return {
        contentType,
        schemaType: schema.type ?? (schema.properties ? 'object' : null),
        schemaRef: media?.schema?.$ref ?? null,
      };
    }),
  };
}

/**
 * O que é: função para resumir respostas de uma operação OpenAPI.
 * O que faz: organiza códigos de resposta, descrição e content types definidos na especificação, sem inferir comportamento real.
 */
function summarizeResponses(responses = {}) {
  return Object.entries(responses).map(([status, response]) => ({
    status,
    description: response?.description ?? null,
    contentTypes: Object.keys(response?.content ?? {}),
  }));
}

/**
 * O que é: função para resumir requisitos de segurança OpenAPI.
 * O que faz: normaliza os esquemas exigidos em uma operação ou no documento, indicando que a exigência é declarativa e não testada.
 */
function summarizeSecurity(security) {
  if (security === undefined) return null;
  if (!Array.isArray(security)) return [];
  return security.map((requirement) => Object.entries(requirement ?? {}).map(([scheme, scopes]) => ({ scheme, scopes })));
}

/**
 * O que é: função que transforma uma especificação OpenAPI em inventário de endpoints.
 * O que faz: percorre somente paths e operações declaradas, lista métodos, parâmetros, request bodies, respostas, tags e
 * segurança; não realiza descoberta adicional, chamadas HTTP ou verificação de disponibilidade.
 *
 * @param {object} spec Objeto retornado por parseApiSpec.
 * @returns {object} Inventário estruturado da API.
 */
export function buildApiInventory(spec) {
  if (!spec || typeof spec !== 'object' || !spec.paths) throw new TypeError('Forneça uma especificação OpenAPI válida.');

  const endpoints = [];
  for (const [path, pathItem] of Object.entries(spec.paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    const pathParameters = pathItem.parameters ?? [];

    for (const [name, operation] of Object.entries(pathItem)) {
      const method = name.toLowerCase();
      if (!HTTP_METHODS.has(method) || !operation || typeof operation !== 'object') continue;

      const parameters = mergeParameters(pathParameters, operation.parameters ?? []).map((parameter) => summarizeParameter(spec, parameter));
      endpoints.push({
        method: method.toUpperCase(),
        path,
        operationId: operation.operationId ?? null,
        summary: operation.summary ?? null,
        description: operation.description ?? null,
        tags: operation.tags ?? [],
        deprecated: Boolean(operation.deprecated),
        parameters,
        requestBody: summarizeRequestBody(spec, operation.requestBody),
        responses: summarizeResponses(operation.responses),
        security: summarizeSecurity(operation.security ?? spec.security),
      });
    }
  }

  endpoints.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  const methods = Object.fromEntries([...HTTP_METHODS].map((method) => [method.toUpperCase(), endpoints.filter((item) => item.method === method.toUpperCase()).length]).filter(([, count]) => count > 0));

  return {
    specification: {
      version: spec.openapi ?? spec.swagger,
      title: spec.info?.title ?? null,
      apiVersion: spec.info?.version ?? null,
      description: spec.info?.description ?? null,
      servers: (spec.servers ?? []).map((server) => ({ url: server.url ?? null, description: server.description ?? null })),
      securitySchemes: Object.entries(spec.components?.securitySchemes ?? spec.securityDefinitions ?? {}).map(([name, scheme]) => ({
        name,
        type: scheme.type ?? null,
        scheme: scheme.scheme ?? null,
        bearerFormat: scheme.bearerFormat ?? null,
        in: scheme.in ?? null,
      })),
    },
    endpoints,
    summary: {
      endpointCount: endpoints.length,
      pathCount: Object.keys(spec.paths).length,
      methods,
      deprecatedEndpoints: endpoints.filter((endpoint) => endpoint.deprecated).length,
      endpointsWithDeclaredSecurity: endpoints.filter((endpoint) => endpoint.security && endpoint.security.length > 0).length,
    },
  };
}

/**
 * O que é: gerador de relatório Markdown para inventário de API.
 * O que faz: produz uma visão legível de servidores declarados, esquemas de segurança e endpoints documentados na especificação.
 */
export function formatMarkdownReport(inventory) {
  if (!inventory || !Array.isArray(inventory.endpoints)) {
    throw new TypeError('Forneça um inventário retornado por buildApiInventory.');
  }

  const { specification, summary } = inventory;
  const lines = [
    '# API Specification Inventory',
    '',
    `- **Título:** ${specification.title ?? 'Não informado'}`,
    `- **Versão OpenAPI/Swagger:** ${specification.version ?? 'Não informada'}`,
    `- **Versão da API:** ${specification.apiVersion ?? 'Não informada'}`,
    `- **Endpoints documentados:** ${summary.endpointCount}`,
    `- **Caminhos documentados:** ${summary.pathCount}`,
    '',
    '## Servidores declarados',
    '',
  ];

  if (specification.servers.length === 0) lines.push('- Nenhum servidor declarado.');
  for (const server of specification.servers) lines.push(`- ${server.url ?? 'URL ausente'}${server.description ? ` — ${server.description}` : ''}`);

  lines.push('', '## Segurança declarada', '');
  if (specification.securitySchemes.length === 0) lines.push('- Nenhum esquema de segurança declarado.');
  for (const scheme of specification.securitySchemes) {
    lines.push(`- ${scheme.name}: tipo ${scheme.type ?? 'não informado'}${scheme.scheme ? ` (${scheme.scheme})` : ''}`);
  }

  lines.push('', '## Endpoints', '', '| Método | Caminho | Resumo | Parâmetros | Respostas | Segurança declarada |', '|---|---|---|---:|---|---|');
  for (const endpoint of inventory.endpoints) {
    const responses = endpoint.responses.map((response) => response.status).join(', ') || '—';
    const security = endpoint.security === null ? 'Não declarada' : endpoint.security.length ? 'Sim' : 'Não';
    const summaryText = (endpoint.summary ?? endpoint.operationId ?? '—').replace(/\|/g, '\\|');
    lines.push(`| ${endpoint.method} | ${endpoint.path} | ${summaryText} | ${endpoint.parameters.length} | ${responses} | ${security} |`);
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para leitura de opções da linha de comando.
 * O que faz: devolve o argumento logo após flags como --input, --format ou --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda do terminal.
 * O que faz: explica como criar inventário a partir de documentos OpenAPI locais em JSON ou YAML simples, sem contatar a API.
 */
function showHelp() {
  console.log(`\nUso:\n  node api-spec-parser.js --input openapi.json [opções]\n  node api-spec-parser.js --input openapi.yaml [opções]\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva o inventário em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node api-spec-parser.js --input openapi.yaml --format markdown --output api-inventory.md\n\nObservação: o parser YAML cobre estruturas OpenAPI usuais. Para YAML avançado, prefira converter a especificação para JSON antes de usar a ferramenta.\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const spec = parseApiSpec(await readFile(input, 'utf8'));
      const inventory = buildApiInventory(spec);
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(inventory)
        : JSON.stringify(inventory, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
