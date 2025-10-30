#!/usr/bin/env node

/**
 * Schema Response Validator
 *
 * O que é: um utilitário JavaScript para validar respostas JSON locais contra schemas JSON Schema simples ou schemas
 * extraídos de especificações OpenAPI locais.
 * O que faz: verifica tipo, propriedades obrigatórias, propriedades adicionais, enums, const, itens, limites numéricos,
 * strings, arrays e combinações básicas; gera erros por caminho e relatórios. Ele não chama APIs, não envia payloads, não
 * resolve referências externas e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { validateResponse, extractOpenApiResponseSchema } from './schema-response-validator.js';
 *
 *   const result = validateResponse({ id: 42, name: 'Ana' }, {
 *     type: 'object',
 *     required: ['id', 'name'],
 *     properties: { id: { type: 'integer' }, name: { type: 'string', minLength: 1 } }
 *   });
 *
 * Uso via CLI:
 *   node schema-response-validator.js --response response.json --schema schema.json --format markdown --output validation.md
 *   node schema-response-validator.js --response response.json --openapi openapi.json --path /users/{id} --method GET --status 200
 */

import { readFile, writeFile } from 'node:fs/promises';

/**
 * O que é: função para comparar valores JSON em igualdade estrutural.
 * O que faz: serializa valores de forma estável para comparar const, enum e valores simples sem alterar os dados originais.
 */
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * O que é: função para identificar o tipo JSON de um valor.
 * O que faz: diferencia null, array, integer, number, string, boolean e object de modo compatível com verificações de schema.
 */
function jsonType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number' && Number.isInteger(value)) return 'integer';
  if (typeof value === 'number') return 'number';
  if (typeof value === 'object') return 'object';
  return typeof value;
}

/**
 * O que é: função para resolver referências JSON Pointer internas.
 * O que faz: resolve apenas referências iniciadas por #/, como #/components/schemas/User, sem carregar schemas externos.
 */
export function resolveLocalRef(root, reference) {
  if (typeof reference !== 'string' || !reference.startsWith('#/')) return null;
  return reference.slice(2).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
    .reduce((current, part) => current && Object.prototype.hasOwnProperty.call(current, part) ? current[part] : null, root);
}

/**
 * O que é: função para registrar erros de validação em formato consistente.
 * O que faz: inclui caminho JSON, palavra-chave de schema, mensagem e valores esperados/recebidos quando apropriado.
 */
function addError(errors, path, keyword, message, expected, received) {
  errors.push({ path, keyword, message, ...(expected !== undefined ? { expected } : {}), ...(received !== undefined ? { received } : {}) });
}

/**
 * O que é: função para escolher o schema efetivo após resolver $ref local.
 * O que faz: segue referências internas com proteção contra ciclos e mantém a validação inteiramente local.
 */
function dereference(schema, root, seen = new Set()) {
  if (!schema || typeof schema !== 'object' || !schema.$ref) return schema;
  if (seen.has(schema.$ref)) return schema;
  const target = resolveLocalRef(root, schema.$ref);
  if (!target) return schema;
  const nextSeen = new Set(seen);
  nextSeen.add(schema.$ref);
  return dereference(target, root, nextSeen);
}

/**
 * O que é: validador recursivo para um subconjunto prático de JSON Schema.
 * O que faz: aplica palavras-chave frequentes a dados JSON e acumula erros por caminho; suporte a schemas avançados é parcial
 * e explicitamente limitado para manter a ferramenta simples, previsível e sem dependências externas.
 */
function validateValue(value, originalSchema, root, path, errors, options, depth = 0) {
  if (depth > options.maxDepth) {
    addError(errors, path, 'maxDepth', `Profundidade máxima de validação (${options.maxDepth}) excedida.`);
    return;
  }

  const schema = dereference(originalSchema, root);
  if (!schema || typeof schema !== 'object') return;

  if (schema.$ref && schema === originalSchema) {
    addError(errors, path, '$ref', `Referência local não resolvida: ${schema.$ref}`);
    return;
  }

  if (schema.nullable === true && value === null) return;

  if (schema.const !== undefined && stableStringify(value) !== stableStringify(schema.const)) {
    addError(errors, path, 'const', 'Valor não corresponde ao valor constante esperado.', schema.const, value);
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((item) => stableStringify(item) === stableStringify(value))) {
    addError(errors, path, 'enum', 'Valor não faz parte do enum permitido.', schema.enum, value);
  }

  if (schema.type) {
    const expectedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actualType = jsonType(value);
    const matches = expectedTypes.some((expected) => expected === actualType || (expected === 'number' && actualType === 'integer'));
    if (!matches) {
      addError(errors, path, 'type', `Tipo inválido: esperado ${expectedTypes.join(' ou ')}, recebido ${actualType}.`, expectedTypes, actualType);
      return;
    }
  }

  if (typeof value === 'string') {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) {
      addError(errors, path, 'minLength', `String possui ${value.length} caracteres, mínimo é ${schema.minLength}.`, schema.minLength, value.length);
    }
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) {
      addError(errors, path, 'maxLength', `String possui ${value.length} caracteres, máximo é ${schema.maxLength}.`, schema.maxLength, value.length);
    }
    if (schema.pattern) {
      try {
        if (!(new RegExp(schema.pattern)).test(value)) {
          addError(errors, path, 'pattern', `String não corresponde ao padrão ${schema.pattern}.`, schema.pattern, value);
        }
      } catch {
        addError(errors, path, 'pattern', `Padrão de schema inválido: ${schema.pattern}.`);
      }
    }
    if (schema.format && options.checkFormats) {
      const formatPatterns = {
        email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        date: /^\d{4}-\d{2}-\d{2}$/,
        'date-time': /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/,
        uri: /^[a-z][a-z0-9+.-]*:\/\//i,
      };
      if (formatPatterns[schema.format] && !formatPatterns[schema.format].test(value)) {
        addError(errors, path, 'format', `String não corresponde ao formato ${schema.format}.`, schema.format, value);
      }
    }
  }

  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) addError(errors, path, 'minimum', `Valor ${value} é menor que minimum ${schema.minimum}.`, schema.minimum, value);
    if (typeof schema.maximum === 'number' && value > schema.maximum) addError(errors, path, 'maximum', `Valor ${value} é maior que maximum ${schema.maximum}.`, schema.maximum, value);
    if (typeof schema.exclusiveMinimum === 'number' && value <= schema.exclusiveMinimum) addError(errors, path, 'exclusiveMinimum', `Valor ${value} deve ser maior que ${schema.exclusiveMinimum}.`, schema.exclusiveMinimum, value);
    if (typeof schema.exclusiveMaximum === 'number' && value >= schema.exclusiveMaximum) addError(errors, path, 'exclusiveMaximum', `Valor ${value} deve ser menor que ${schema.exclusiveMaximum}.`, schema.exclusiveMaximum, value);
    if (typeof schema.multipleOf === 'number' && Number.isFinite(schema.multipleOf) && (value / schema.multipleOf) % 1 !== 0) {
      addError(errors, path, 'multipleOf', `Valor ${value} não é múltiplo de ${schema.multipleOf}.`, schema.multipleOf, value);
    }
  }

  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) addError(errors, path, 'minItems', `Array possui ${value.length} itens, mínimo é ${schema.minItems}.`, schema.minItems, value.length);
    if (Number.isInteger(schema.maxItems) && value.length > schema.maxItems) addError(errors, path, 'maxItems', `Array possui ${value.length} itens, máximo é ${schema.maxItems}.`, schema.maxItems, value.length);
    if (schema.uniqueItems) {
      const unique = new Set(value.map(stableStringify));
      if (unique.size !== value.length) addError(errors, path, 'uniqueItems', 'Array contém itens duplicados.');
    }
    if (schema.items) {
      value.forEach((item, index) => validateValue(item, schema.items, root, `${path}[${index}]`, errors, options, depth + 1));
    }
  }

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const properties = schema.properties && typeof schema.properties === 'object' ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required : [];

    for (const name of required) {
      if (!Object.prototype.hasOwnProperty.call(value, name)) {
        addError(errors, path, 'required', `Propriedade obrigatória ausente: ${name}.`, name);
      }
    }

    for (const [name, item] of Object.entries(value)) {
      const propertyPath = `${path}.${name}`;
      if (Object.prototype.hasOwnProperty.call(properties, name)) {
        validateValue(item, properties[name], root, propertyPath, errors, options, depth + 1);
      } else if (schema.additionalProperties === false) {
        addError(errors, propertyPath, 'additionalProperties', `Propriedade adicional não permitida: ${name}.`, Object.keys(properties), name);
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        validateValue(item, schema.additionalProperties, root, propertyPath, errors, options, depth + 1);
      }
    }
  }

  if (Array.isArray(schema.allOf)) {
    for (const subSchema of schema.allOf) validateValue(value, subSchema, root, path, errors, options, depth + 1);
  }

  if (Array.isArray(schema.anyOf) || Array.isArray(schema.oneOf)) {
    const variants = schema.anyOf ?? schema.oneOf;
    const matchingVariants = variants.filter((subSchema) => {
      const localErrors = [];
      validateValue(value, subSchema, root, path, localErrors, options, depth + 1);
      return localErrors.length === 0;
    }).length;
    const keyword = schema.oneOf ? 'oneOf' : 'anyOf';
    const valid = schema.oneOf ? matchingVariants === 1 : matchingVariants >= 1;
    if (!valid) addError(errors, path, keyword, `${keyword} não foi satisfeito; variantes compatíveis: ${matchingVariants}.`);
  }

  if (schema.not) {
    const localErrors = [];
    validateValue(value, schema.not, root, path, localErrors, options, depth + 1);
    if (localErrors.length === 0) addError(errors, path, 'not', 'Valor corresponde a um schema proibido por not.');
  }
}

/**
 * O que é: validador de resposta JSON contra schema local.
 * O que faz: aplica o subconjunto suportado de JSON Schema/OpenAPI a um valor já carregado, devolvendo erros detalhados sem
 * chamar qualquer API. O resultado não comprova comportamento em produção, apenas conformidade dos dados fornecidos.
 *
 * @param {unknown} response Corpo JSON já obtido.
 * @param {object} schema JSON Schema ou schema OpenAPI local.
 * @param {object} [options] Opções da validação.
 * @param {boolean} [options.checkFormats=true] Habilita validações básicas de email, uuid, date, date-time e uri.
 * @param {number} [options.maxDepth=32] Limite contra schemas ou dados excessivamente aninhados.
 * @returns {{valid: boolean, errors: object[], summary: object}}
 */
export function validateResponse(response, schema, options = {}) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new TypeError('schema deve ser um objeto JSON Schema ou OpenAPI Schema válido.');
  }

  const settings = { checkFormats: true, maxDepth: 32, ...options };
  const errors = [];
  validateValue(response, schema, schema, '$', errors, settings);

  return {
    valid: errors.length === 0,
    errors,
    summary: {
      errorCount: errors.length,
      checkedFormats: settings.checkFormats,
      supportedKeywords: ['type', 'required', 'properties', 'additionalProperties', 'enum', 'const', 'items', 'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern', 'format', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'allOf', 'anyOf', 'oneOf', 'not', '$ref local'],
    },
    limitation: 'O validador cobre um subconjunto prático de JSON Schema/OpenAPI e resolve somente $ref internos. Não chama a API nem implementa todas as palavras-chave, dialetos ou regras de serialização.',
  };
}

/**
 * O que é: função para extrair um schema de resposta a partir de uma especificação OpenAPI local.
 * O que faz: localiza paths, método, status e content type declarados e devolve o schema correspondente, resolvendo somente
 * referência local de response quando presente; não carrega documentos remotos nem consulta o endpoint real.
 */
export function extractOpenApiResponseSchema(openApi, path, method, status = '200', contentType = null) {
  if (!openApi || typeof openApi !== 'object' || !openApi.paths) throw new TypeError('openApi deve conter paths.');
  const pathItem = openApi.paths[path];
  if (!pathItem) throw new TypeError(`Path não encontrado na especificação: ${path}`);
  const operation = pathItem[String(method).toLowerCase()];
  if (!operation) throw new TypeError(`Método ${method} não encontrado em ${path}.`);

  let response = operation.responses?.[String(status)] ?? operation.responses?.default;
  if (!response) throw new TypeError(`Resposta ${status} não encontrada para ${String(method).toUpperCase()} ${path}.`);
  if (response.$ref) response = resolveLocalRef(openApi, response.$ref) ?? response;

  const content = response.content ?? {};
  const mediaTypes = Object.keys(content);
  if (mediaTypes.length === 0) throw new TypeError('A resposta selecionada não declara content/schema.');
  const selectedType = contentType
    ? mediaTypes.find((item) => item.toLowerCase() === contentType.toLowerCase())
    : mediaTypes.find((item) => item.includes('json')) ?? mediaTypes[0];
  if (!selectedType) throw new TypeError(`Content type não encontrado: ${contentType}`);

  const schema = content[selectedType]?.schema;
  if (!schema) throw new TypeError(`Schema ausente para content type ${selectedType}.`);
  return { schema, contentType: selectedType, responseDescription: response.description ?? null };
}

/**
 * O que é: gerador de relatório Markdown de validação.
 * O que faz: transforma o resultado da validação em uma lista clara de conformidades e violações por caminho JSON.
 */
export function formatMarkdownReport(result, metadata = {}) {
  if (!result || !Array.isArray(result.errors)) throw new TypeError('Forneça um resultado retornado por validateResponse.');

  const lines = [
    '# Schema Response Validation Report',
    '',
    `- **Resultado:** ${result.valid ? 'Válido' : 'Inválido'}`,
    `- **Erros:** ${result.summary.errorCount}`,
    metadata.path ? `- **Endpoint documentado:** ${String(metadata.method ?? '').toUpperCase()} ${metadata.path}` : null,
    metadata.status ? `- **Status:** ${metadata.status}` : null,
    metadata.contentType ? `- **Content-Type do schema:** ${metadata.contentType}` : null,
    `- **Limitação:** ${result.limitation}`,
    '',
    '## Resultado',
    '',
  ].filter(Boolean);

  if (result.valid) {
    lines.push('- A resposta local fornecida está em conformidade com as regras suportadas do schema.');
  } else {
    lines.push('| Caminho | Regra | Mensagem | Esperado | Recebido |', '|---|---|---|---|---|');
    for (const error of result.errors) {
      const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|').replace(/\n/g, '<br>');
      lines.push(`| ${clean(error.path)} | ${clean(error.keyword)} | ${clean(error.message)} | ${clean(typeof error.expected === 'object' ? JSON.stringify(error.expected) : error.expected)} | ${clean(typeof error.received === 'object' ? JSON.stringify(error.received) : error.received)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos da linha de comando.
 * O que faz: retorna o valor após flags como --response, --schema, --openapi, --path, --method e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda para a CLI.
 * O que faz: explica como validar JSON local usando schema separado ou schema extraído de OpenAPI, sem chamar o endpoint descrito.
 */
function showHelp() {
  console.log(`\nUso:\n  node schema-response-validator.js --response response.json --schema schema.json [opções]\n  node schema-response-validator.js --response response.json --openapi openapi.json --path /rota --method GET --status 200 [opções]\n\nEntrada:\n  --response ARQUIVO       Corpo JSON de resposta previamente coletado\n  --schema ARQUIVO         JSON Schema ou schema OpenAPI local\n  --openapi ARQUIVO        Especificação OpenAPI JSON local\n  --path ROTA              Path declarado no OpenAPI, necessário com --openapi\n  --method MÉTODO          Método HTTP, necessário com --openapi\n  --status CÓDIGO          Status da resposta documentada. Padrão: 200\n  --content-type TIPO      Content type a selecionar do OpenAPI\n\nSaída:\n  --format FORMATO         json ou markdown. Padrão: json\n  --output ARQUIVO         Salva relatório em arquivo local\n  --pretty                 Formata JSON com indentação\n  --no-format-check        Desativa validação básica de formatos\n\nExemplo:\n  node schema-response-validator.js --response response.json --openapi openapi.json --path /users/{id} --method GET --status 200 --format markdown --output validation.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const responseFile = getCliOption('response');
  const schemaFile = getCliOption('schema');
  const openApiFile = getCliOption('openapi');
  const path = getCliOption('path');
  const method = getCliOption('method');

  if (process.argv.includes('--help') || !responseFile || (!schemaFile && !openApiFile) || (openApiFile && (!path || !method))) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const response = JSON.parse(await readFile(responseFile, 'utf8'));
      let schema;
      let metadata = {};

      if (schemaFile) {
        schema = JSON.parse(await readFile(schemaFile, 'utf8'));
      } else {
        const openApi = JSON.parse(await readFile(openApiFile, 'utf8'));
        const extracted = extractOpenApiResponseSchema(openApi, path, method, getCliOption('status') ?? '200', getCliOption('content-type'));
        schema = extracted.schema;
        metadata = { path, method, status: getCliOption('status') ?? '200', contentType: extracted.contentType };
      }

      const result = validateResponse(response, schema, { checkFormats: !process.argv.includes('--no-format-check') });
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(result, metadata)
        : JSON.stringify({ ...result, metadata }, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
      process.exitCode = result.valid ? 0 : 2;
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
