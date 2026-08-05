#!/usr/bin/env node

/**
 * GraphQL Inspector
 *
 * O que é: um utilitário JavaScript para inspecionar documentos GraphQL locais, como queries, mutations, schemas SDL e
 * respostas JSON previamente coletadas.
 * O que faz: extrai operações, campos, variáveis, fragments e diretivas de documentos; resume schemas SDL e revisa respostas
 * por erros e possíveis mensagens técnicas. Ele não envia queries, não executa introspecção, não descobre schemas remotos e
 * não acessa endpoints GraphQL ou outros sistemas externos.
 *
 * Uso como módulo:
 *   import { inspectGraphqlDocument, inspectGraphqlResponse, formatMarkdownReport } from './graphql-inspector.js';
 *
 *   const report = inspectGraphqlDocument('query GetUser($id: ID!) { user(id: $id) { id name } }');
 *   console.log(formatMarkdownReport(report));
 *
 * Uso via CLI:
 *   node graphql-inspector.js --document query.graphql --format markdown --output graphql-report.md
 *   node graphql-inspector.js --schema schema.graphql --format json --pretty
 *   node graphql-inspector.js --response response.json --format markdown
 */

import { readFile, writeFile } from 'node:fs/promises';

const OPERATION_TYPES = new Set(['query', 'mutation', 'subscription']);

/**
 * O que é: função para remover comentários GraphQL preservando quebras de linha.
 * O que faz: substitui comentários iniciados com # por espaços até a quebra de linha, reduzindo falsos positivos sem alterar
 * a posição geral de tokens para referências de linha aproximadas.
 */
function maskComments(source) {
  let output = '';
  let inString = false;
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (inString) {
      output += character;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }

    if (character === '"') {
      inString = true;
      output += character;
      continue;
    }

    if (character === '#') {
      while (index < source.length && source[index] !== '\n') {
        output += ' ';
        index += 1;
      }
      output += source[index] ?? '';
      continue;
    }

    output += character;
  }

  return output;
}

/**
 * O que é: tokenizer simplificado para documentos GraphQL.
 * O que faz: separa nomes, variáveis, strings, números, pontuação e spread operators em tokens; suporta análise estrutural
 * de documentos comuns sem executar o conteúdo e sem depender de bibliotecas externas.
 */
function tokenize(source) {
  const tokens = [];
  const text = maskComments(source);
  let index = 0;

  while (index < text.length) {
    const character = text[index];
    if (/\s|,/.test(character)) {
      index += 1;
      continue;
    }

    if (text.slice(index, index + 3) === '...') {
      tokens.push({ type: 'spread', value: '...', index });
      index += 3;
      continue;
    }

    if ('!$():=@[]{}|&'.includes(character)) {
      tokens.push({ type: 'punctuation', value: character, index });
      index += 1;
      continue;
    }

    if (character === '"') {
      const start = index;
      const triple = text.slice(index, index + 3) === '\"\"\"';
      index += triple ? 3 : 1;
      let value = '';
      while (index < text.length) {
        if (triple && text.slice(index, index + 3) === '\"\"\"') {
          index += 3;
          break;
        }
        if (!triple && text[index] === '"' && text[index - 1] !== '\\') {
          index += 1;
          break;
        }
        value += text[index];
        index += 1;
      }
      tokens.push({ type: 'string', value, index: start });
      continue;
    }

    const nameMatch = text.slice(index).match(/^[_A-Za-z][_0-9A-Za-z]*/);
    if (nameMatch) {
      tokens.push({ type: 'name', value: nameMatch[0], index });
      index += nameMatch[0].length;
      continue;
    }

    const numberMatch = text.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (numberMatch) {
      tokens.push({ type: 'number', value: numberMatch[0], index });
      index += numberMatch[0].length;
      continue;
    }

    throw new SyntaxError(`Token GraphQL não reconhecido próximo ao caractere ${index}: ${JSON.stringify(character)}`);
  }

  return tokens;
}

/**
 * O que é: parser de documentos GraphQL baseado em tokens.
 * O que faz: oferece operações básicas de leitura, avanço, expectativa de token e leitura de blocos aninhados para produzir
 * um resumo estrutural, sem avaliar variáveis, directives ou lógica de resolver.
 */
class GraphqlParser {
  constructor(tokens) {
    this.tokens = tokens;
    this.position = 0;
  }

  peek(offset = 0) {
    return this.tokens[this.position + offset] ?? null;
  }

  consume() {
    const token = this.peek();
    if (!token) throw new SyntaxError('Fim inesperado do documento GraphQL.');
    this.position += 1;
    return token;
  }

  accept(value) {
    if (this.peek()?.value !== value) return false;
    this.position += 1;
    return true;
  }

  expect(value) {
    const token = this.consume();
    if (token.value !== value) throw new SyntaxError(`Esperado ${value}, encontrado ${token.value}.`);
    return token;
  }

  expectName() {
    const token = this.consume();
    if (token.type !== 'name') throw new SyntaxError(`Esperado nome GraphQL, encontrado ${token.value}.`);
    return token;
  }

  skipBalanced(open, close) {
    this.expect(open);
    let depth = 1;
    while (depth > 0) {
      const token = this.consume();
      if (token.value === open) depth += 1;
      if (token.value === close) depth -= 1;
    }
  }

  parseDirectives() {
    const directives = [];
    while (this.accept('@')) {
      const name = this.expectName().value;
      directives.push(name);
      if (this.peek()?.value === '(') this.skipBalanced('(', ')');
    }
    return directives;
  }

  parseVariableDefinitions() {
    const variables = [];
    if (!this.accept('(')) return variables;

    while (!this.accept(')')) {
      this.expect('$');
      const name = this.expectName().value;
      this.expect(':');
      const typeTokens = [];
      let bracketDepth = 0;

      while (this.peek() && !(bracketDepth === 0 && (this.peek().value === ')' || this.peek().value === '='))) {
        const token = this.consume();
        if (token.value === '[') bracketDepth += 1;
        if (token.value === ']') bracketDepth -= 1;
        typeTokens.push(token.value);
      }

      let defaultValue = null;
      if (this.accept('=')) {
        const values = [];
        let valueDepth = 0;
        while (this.peek() && !(valueDepth === 0 && this.peek().value === ')')) {
          const token = this.consume();
          if (['[', '{', '('].includes(token.value)) valueDepth += 1;
          if ([']', '}', ')'].includes(token.value)) valueDepth -= 1;
          values.push(token.value);
        }
        defaultValue = values.join(' ');
      }

      variables.push({ name, type: typeTokens.join(''), defaultValue });
      this.parseDirectives();
    }
    return variables;
  }

  parseSelectionSet() {
    this.expect('{');
    const fields = [];

    while (!this.accept('}')) {
      if (this.accept('...')) {
        if (this.peek()?.value === 'on') {
          this.consume();
          const typeCondition = this.expectName().value;
          const directives = this.parseDirectives();
          fields.push({ kind: 'inline-fragment', typeCondition, directives, fields: this.parseSelectionSet() });
        } else {
          const name = this.expectName().value;
          fields.push({ kind: 'fragment-spread', name, directives: this.parseDirectives() });
        }
        continue;
      }

      const first = this.expectName().value;
      let alias = null;
      let name = first;
      if (this.accept(':')) {
        alias = first;
        name = this.expectName().value;
      }

      let argumentsPresent = false;
      if (this.peek()?.value === '(') {
        argumentsPresent = true;
        this.skipBalanced('(', ')');
      }

      const directives = this.parseDirectives();
      const nestedFields = this.peek()?.value === '{' ? this.parseSelectionSet() : [];
      fields.push({ kind: 'field', name, alias, argumentsPresent, directives, fields: nestedFields });
    }

    return fields;
  }

  parseOperation() {
    let operationType = 'query';
    let name = null;
    let variables = [];
    let directives = [];
    const start = this.peek()?.index ?? 0;

    if (this.peek()?.value === '{') {
      return { kind: 'operation', operationType, name, variables, directives, fields: this.parseSelectionSet(), start };
    }

    const operationToken = this.expectName();
    if (!OPERATION_TYPES.has(operationToken.value)) {
      throw new SyntaxError(`Tipo de operação inválido: ${operationToken.value}`);
    }
    operationType = operationToken.value;

    if (this.peek()?.type === 'name') name = this.consume().value;
    variables = this.parseVariableDefinitions();
    directives = this.parseDirectives();
    const fields = this.parseSelectionSet();
    return { kind: 'operation', operationType, name, variables, directives, fields, start };
  }

  parseFragment() {
    const start = this.expectName().index;
    const name = this.expectName().value;
    this.expectName();
    const typeCondition = this.expectName().value;
    const directives = this.parseDirectives();
    return { kind: 'fragment', name, typeCondition, directives, fields: this.parseSelectionSet(), start };
  }

  parseDocument() {
    const definitions = [];
    while (this.peek()) {
      if (this.peek()?.value === '{' || OPERATION_TYPES.has(this.peek()?.value)) definitions.push(this.parseOperation());
      else if (this.peek()?.value === 'fragment') definitions.push(this.parseFragment());
      else throw new SyntaxError(`Definição GraphQL não reconhecida: ${this.peek()?.value}`);
    }
    return definitions;
  }
}

/**
 * O que é: função para achatar campos de uma seleção GraphQL.
 * O que faz: transforma campos aninhados em caminhos como user.orders.id, facilitando inventário de dados solicitados sem
 * executar a query nem conhecer valores de variáveis.
 */
function flattenFields(fields, prefix = '') {
  const paths = [];
  for (const field of fields) {
    if (field.kind === 'fragment-spread') {
      paths.push(`${prefix}...${field.name}`);
      continue;
    }
    if (field.kind === 'inline-fragment') {
      paths.push(...flattenFields(field.fields, `${prefix}...on ${field.typeCondition}.`));
      continue;
    }
    const segment = field.alias ? `${field.alias}:${field.name}` : field.name;
    const path = `${prefix}${segment}`;
    paths.push(path);
    paths.push(...flattenFields(field.fields, `${path}.`));
  }
  return paths;
}

/**
 * O que é: inspetor de documento GraphQL local.
 * O que faz: faz parsing de queries, mutations, subscriptions e fragments, criando um inventário de operações, variáveis e
 * campos solicitados. Variáveis dinâmicas e comportamento de resolvers não são avaliados ou executados.
 *
 * @param {string} source Documento GraphQL como texto.
 * @returns {object} Relatório estrutural do documento.
 */
export function inspectGraphqlDocument(source) {
  if (typeof source !== 'string' || !source.trim()) throw new TypeError('Forneça um documento GraphQL não vazio.');

  const definitions = new GraphqlParser(tokenize(source)).parseDocument();
  const operations = definitions.filter((item) => item.kind === 'operation').map((operation) => ({
    type: operation.operationType,
    name: operation.name,
    variables: operation.variables,
    directives: operation.directives,
    fields: flattenFields(operation.fields),
    fieldCount: flattenFields(operation.fields).length,
    hasArguments: JSON.stringify(operation.fields).includes('"argumentsPresent":true'),
  }));
  const fragments = definitions.filter((item) => item.kind === 'fragment').map((fragment) => ({
    name: fragment.name,
    typeCondition: fragment.typeCondition,
    directives: fragment.directives,
    fields: flattenFields(fragment.fields),
  }));

  const findings = [];
  for (const operation of operations) {
    if (operation.type === 'mutation' && !operation.name) {
      findings.push({ severity: 'low', code: 'unnamed-mutation', message: 'Mutation sem nome; nomes facilitam observabilidade, allowlists e auditoria.' });
    }
    if (operation.fieldCount > 100) {
      findings.push({ severity: 'medium', code: 'large-selection-set', message: `Operação ${operation.name ?? 'anônima'} solicita ${operation.fieldCount} campos; revise limites de profundidade, complexidade e paginação.` });
    }
  }

  return {
    type: 'document',
    operations,
    fragments,
    findings,
    summary: {
      operations: operations.length,
      queries: operations.filter((item) => item.type === 'query').length,
      mutations: operations.filter((item) => item.type === 'mutation').length,
      subscriptions: operations.filter((item) => item.type === 'subscription').length,
      fragments: fragments.length,
    },
    limitation: 'A inspeção é estática e local. Ela não valida schema, autenticação, autorização, custos reais, resolvers ou comportamento de um endpoint GraphQL.',
  };
}

/**
 * O que é: inspetor de schema GraphQL SDL local.
 * O que faz: identifica tipos, interfaces, inputs, enums, unions, scalars, directives e extensões declaradas em texto SDL;
 * o resultado é um inventário sintático, não uma validação completa do schema GraphQL.
 */
export function inspectGraphqlSchema(source) {
  if (typeof source !== 'string' || !source.trim()) throw new TypeError('Forneça um schema SDL não vazio.');

  const text = maskComments(source);
  const definitions = [];
  const expression = /\b(extend\s+)?(type|interface|input|enum|union|scalar|directive)\s+@?([_A-Za-z][_0-9A-Za-z]*)(?:\s+implements\s+[^\{]+)?(?:\s*=\s*[^\n\{]+)?/g;

  for (const match of text.matchAll(expression)) {
    const [, extendPrefix, kind, name] = match;
    definitions.push({ kind, name, extension: Boolean(extendPrefix), index: match.index });
  }

  const rootTypes = {};
  const schemaBlock = text.match(/\bschema\s*\{([\s\S]*?)\}/i)?.[1] ?? '';
  for (const match of schemaBlock.matchAll(/\b(query|mutation|subscription)\s*:\s*([_A-Za-z][_0-9A-Za-z]*)/g)) {
    rootTypes[match[1]] = match[2];
  }

  return {
    type: 'schema',
    definitions,
    rootTypes,
    summary: Object.fromEntries(['type', 'interface', 'input', 'enum', 'union', 'scalar', 'directive'].map((kind) => [kind, definitions.filter((item) => item.kind === kind).length])),
    limitation: 'A inspeção de SDL é sintática e local. Ela não executa introspecção, não valida resolvers nem confirma controles de acesso ou limites de consulta.',
  };
}

/**
 * O que é: inspetor de resposta GraphQL previamente coletada.
 * O que faz: analisa objetos JSON com data, errors e extensions, resume erros, reconhece mensagens técnicas comuns e mascara
 * padrões aparentes de segredo. Não envia queries nem tenta reproduzir erros contra o endpoint de origem.
 */
export function inspectGraphqlResponse(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    throw new TypeError('Forneça uma resposta GraphQL como objeto JSON.');
  }

  const errors = Array.isArray(response.errors) ? response.errors : [];
  const findings = [];
  const summarizedErrors = errors.map((error, index) => {
    const message = String(error?.message ?? 'Erro sem mensagem.');
    if (/(stack trace|traceback|exception|\/var\/www\/|node_modules\/|sqlstate|postgresql|mysql)/i.test(message)) {
      findings.push({ severity: 'medium', code: 'technical-error-detail', message: `Erro ${index + 1} contém possível detalhe técnico; avalie mensagens genéricas para clientes.` });
    }
    if (/(api[_-]?key|secret|password|token)\s*[=:]/i.test(message)) {
      findings.push({ severity: 'high', code: 'apparent-secret-in-error', message: `Erro ${index + 1} contém padrão parecido com segredo; revise e redija logs e respostas.` });
    }
    return {
      message: message.replace(/\b(api[_-]?key|secret|password|token)\s*[=:]\s*\S+/gi, '$1=[REDACTED]'),
      path: Array.isArray(error?.path) ? error.path : null,
      code: error?.extensions?.code ?? null,
    };
  });

  return {
    type: 'response',
    hasData: Object.prototype.hasOwnProperty.call(response, 'data'),
    errorCount: errors.length,
    errors: summarizedErrors,
    extensionKeys: response.extensions && typeof response.extensions === 'object' ? Object.keys(response.extensions) : [],
    findings,
    limitation: 'A inspeção analisa apenas a resposta local fornecida. Ela não determina causa raiz, vulnerabilidade ou comportamento do servidor GraphQL.',
  };
}

/**
 * O que é: gerador de relatório GraphQL em Markdown.
 * O que faz: formata resultados de documentos, schemas SDL ou respostas em seções legíveis para revisão e documentação local.
 */
export function formatMarkdownReport(report) {
  if (!report?.type) throw new TypeError('Forneça um relatório de inspeção GraphQL.');
  const lines = ['# GraphQL Inspection Report', '', `- **Tipo de análise:** ${report.type}`, `- **Limitação:** ${report.limitation}`, ''];

  if (report.type === 'document') {
    lines.push('## Operações', '', '| Tipo | Nome | Variáveis | Campos |', '|---|---|---:|---:|');
    for (const operation of report.operations) {
      lines.push(`| ${operation.type} | ${operation.name ?? 'Anônima'} | ${operation.variables.length} | ${operation.fieldCount} |`);
    }
    lines.push('', '## Campos solicitados', '');
    for (const operation of report.operations) {
      lines.push(`### ${operation.type} ${operation.name ?? 'anônima'}`);
      for (const field of operation.fields) lines.push(`- ${field}`);
    }
  }

  if (report.type === 'schema') {
    lines.push('## Tipos raiz', '');
    if (Object.keys(report.rootTypes).length === 0) lines.push('- Nenhum bloco schema explícito encontrado.');
    for (const [operation, type] of Object.entries(report.rootTypes)) lines.push(`- ${operation}: ${type}`);
    lines.push('', '## Definições', '', '| Tipo | Nome | Extensão |', '|---|---|---|');
    for (const item of report.definitions) lines.push(`| ${item.kind} | ${item.name} | ${item.extension ? 'Sim' : 'Não'} |`);
  }

  if (report.type === 'response') {
    lines.push('## Resposta', '', `- Campo data presente: ${report.hasData ? 'sim' : 'não'}.`, `- Erros: ${report.errorCount}.`, '');
    if (report.errors.length > 0) {
      lines.push('| Código | Caminho | Mensagem |', '|---|---|---|');
      for (const error of report.errors) lines.push(`| ${error.code ?? '—'} | ${(error.path ?? []).join('.') || '—'} | ${error.message.replace(/\|/g, '\\|')} |`);
    }
  }

  lines.push('', '## Achados', '');
  if (!report.findings?.length) lines.push('- Nenhum achado gerado pelas verificações locais.');
  else for (const finding of report.findings) lines.push(`- [${finding.severity}] ${finding.code}: ${finding.message}`);

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler valores de flags do terminal.
 * O que faz: devolve o argumento que sucede opções como --document, --schema, --response, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: apresenta como inspecionar artefatos GraphQL locais sem enviar queries, introspecção ou tráfego para servidores.
 */
function showHelp() {
  console.log(`\nUso:\n  node graphql-inspector.js --document query.graphql [opções]\n  node graphql-inspector.js --schema schema.graphql [opções]\n  node graphql-inspector.js --response response.json [opções]\n\nEscolha exatamente uma entrada:\n  --document ARQUIVO      Query, mutation, subscription ou fragment GraphQL local\n  --schema ARQUIVO        Schema GraphQL SDL local\n  --response ARQUIVO      Resposta GraphQL JSON já coletada\n\nOpções:\n  --format FORMATO        json ou markdown. Padrão: json\n  --output ARQUIVO        Salva o relatório em arquivo local\n  --pretty                Formata JSON com indentação\n\nExemplo:\n  node graphql-inspector.js --document query.graphql --format markdown --output graphql-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const documentFile = getCliOption('document');
  const schemaFile = getCliOption('schema');
  const responseFile = getCliOption('response');
  const selected = [documentFile, schemaFile, responseFile].filter(Boolean);

  if (process.argv.includes('--help') || selected.length !== 1) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const report = documentFile
        ? inspectGraphqlDocument(await readFile(documentFile, 'utf8'))
        : schemaFile
          ? inspectGraphqlSchema(await readFile(schemaFile, 'utf8'))
          : inspectGraphqlResponse(JSON.parse(await readFile(responseFile, 'utf8')));
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
