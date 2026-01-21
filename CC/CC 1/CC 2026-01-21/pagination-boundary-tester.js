#!/usr/bin/env node

/**
 * Pagination Boundary Tester
 *
 * O que é: um utilitário JavaScript para planejar e avaliar localmente casos de limite em paginação de APIs e interfaces.
 * O que faz: gera uma matriz de casos para offset/limit, page/perPage ou cursor, valida respostas já coletadas contra as
 * expectativas declaradas e destaca inconsistências de metadados, duplicação e ordenação. Ele não envia requisições, não
 * enumera registros, não tenta acessar APIs e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { createPaginationPlan, validatePaginationResponse } from './pagination-boundary-tester.js';
 *
 *   const plan = createPaginationPlan({ mode: 'offset-limit', totalItems: 53, defaultLimit: 20, maxLimit: 100 });
 *   const result = validatePaginationResponse(plan.cases[0], { items: [], total: 53, limit: 20, offset: 0 });
 *
 * Uso via CLI:
 *   node pagination-boundary-tester.js --config pagination-config.json --format markdown --output pagination-plan.md
 *   node pagination-boundary-tester.js --config pagination-config.json --responses collected-responses.json --format json
 */

import { readFile, writeFile } from 'node:fs/promises';

const MODES = new Set(['offset-limit', 'page-per-page', 'cursor']);

/**
 * O que é: função para converter um valor em inteiro não negativo.
 * O que faz: valida números de configuração como totalItems, offset, limit e tamanho de página, gerando erro claro quando inválidos.
 */
function nonNegativeInteger(value, field) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0) throw new TypeError(`${field} deve ser um inteiro maior ou igual a zero.`);
  return number;
}

/**
 * O que é: função para converter um valor em inteiro positivo.
 * O que faz: valida limites e tamanhos de página que não podem ser zero ou negativos.
 */
function positiveInteger(value, field) {
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0) throw new TypeError(`${field} deve ser um inteiro maior que zero.`);
  return number;
}

/**
 * O que é: função para garantir que uma lista possua valores únicos.
 * O que faz: remove duplicatas e entradas vazias mantendo a ordem, usada para tamanhos de página e valores de cursor declarados.
 */
function unique(values) {
  const seen = new Set();
  return values.filter((value) => {
    const key = JSON.stringify(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * O que é: normalizador de configuração de paginação.
 * O que faz: valida modo, total conhecido, tamanho padrão, máximo permitido, nomes de campos e IDs de itens, sem consultar uma API.
 */
export function normalizePaginationConfig(config = {}) {
  const mode = String(config.mode ?? 'offset-limit').trim().toLowerCase();
  if (!MODES.has(mode)) throw new TypeError(`mode inválido. Use: ${[...MODES].join(', ')}.`);

  const totalItems = config.totalItems === undefined || config.totalItems === null ? null : nonNegativeInteger(config.totalItems, 'totalItems');
  const defaultLimit = positiveInteger(config.defaultLimit ?? config.defaultPerPage ?? 20, 'defaultLimit');
  const maxLimit = config.maxLimit === undefined || config.maxLimit === null ? null : positiveInteger(config.maxLimit, 'maxLimit');
  if (maxLimit !== null && defaultLimit > maxLimit) throw new TypeError('defaultLimit não pode ser maior que maxLimit.');

  return {
    mode,
    totalItems,
    defaultLimit,
    maxLimit,
    baseUrl: config.baseUrl ?? null,
    itemArrayField: String(config.itemArrayField ?? 'items'),
    itemIdField: String(config.itemIdField ?? 'id'),
    totalField: String(config.totalField ?? 'total'),
    offsetField: String(config.offsetField ?? 'offset'),
    limitField: String(config.limitField ?? (mode === 'page-per-page' ? 'perPage' : 'limit')),
    pageField: String(config.pageField ?? 'page'),
    cursorField: String(config.cursorField ?? 'cursor'),
    nextCursorField: String(config.nextCursorField ?? 'nextCursor'),
    caseLimits: unique((config.caseLimits ?? [1, defaultLimit, maxLimit].filter(Boolean)).map((value) => positiveInteger(value, 'caseLimits'))),
    cursors: unique((config.cursors ?? [null, 'cursor-inicial', 'cursor-final-invalido']).map((value) => value === null ? null : String(value))),
  };
}

/**
 * O que é: função para estimar quantidade esperada de itens para offset/limit.
 * O que faz: calcula o tamanho máximo do lote quando totalItems é conhecido; retorna null quando a quantidade total é desconhecida.
 */
function expectedOffsetItemCount(totalItems, offset, limit) {
  if (totalItems === null) return null;
  return Math.max(0, Math.min(limit, totalItems - offset));
}

/**
 * O que é: gerador de casos para paginação offset/limit.
 * O que faz: cria limites comuns, início, última página parcial, fim exato e offsets além do total usando apenas a configuração local.
 */
function buildOffsetCases(config) {
  const total = config.totalItems;
  const cases = [];
  const limits = config.caseLimits;

  for (const limit of limits) {
    const offsets = [0, 1];
    if (total !== null) {
      const lastPageOffset = total === 0 ? 0 : Math.floor((total - 1) / limit) * limit;
      offsets.push(lastPageOffset, total, total + 1);
      if (total > 0) offsets.push(Math.max(0, total - limit), Math.max(0, total - limit + 1));
    }
    if (config.maxLimit !== null) offsets.push(0);

    for (const offset of unique(offsets)) {
      cases.push({
        id: `offset-limit_${cases.length + 1}`,
        mode: config.mode,
        parameters: { [config.offsetField]: offset, [config.limitField]: limit },
        scenario: offset === 0 ? 'primeira-pagina' : total !== null && offset >= total ? 'fora-do-total' : 'limite-ou-pagina-intermediaria',
        expected: {
          maxItems: expectedOffsetItemCount(total, offset, limit),
          totalItems: total,
          shouldBeEmpty: total !== null ? offset >= total : null,
          limitAccepted: config.maxLimit === null ? true : limit <= config.maxLimit,
        },
      });
    }
  }

  if (config.maxLimit !== null) {
    cases.push({
      id: `offset-limit_${cases.length + 1}`,
      mode: config.mode,
      parameters: { [config.offsetField]: 0, [config.limitField]: config.maxLimit + 1 },
      scenario: 'acima-do-maximo',
      expected: { maxItems: null, totalItems: total, shouldBeEmpty: null, limitAccepted: false },
    });
  }

  return cases;
}

/**
 * O que é: gerador de casos para paginação page/perPage.
 * O que faz: cria páginas inicial, válida, última, além do fim e valores inválidos de página ou tamanho, sem enviar requisições.
 */
function buildPageCases(config) {
  const total = config.totalItems;
  const cases = [];

  for (const perPage of config.caseLimits) {
    const pages = [1, 2];
    if (total !== null) {
      const lastPage = Math.max(1, Math.ceil(total / perPage));
      pages.push(lastPage, lastPage + 1);
    }

    for (const page of unique(pages)) {
      const offset = (page - 1) * perPage;
      cases.push({
        id: `page-per-page_${cases.length + 1}`,
        mode: config.mode,
        parameters: { [config.pageField]: page, [config.limitField]: perPage },
        scenario: page === 1 ? 'primeira-pagina' : total !== null && offset >= total ? 'fora-do-total' : 'pagina-valida-ou-limite',
        expected: {
          maxItems: expectedOffsetItemCount(total, offset, perPage),
          totalItems: total,
          shouldBeEmpty: total !== null ? offset >= total : null,
          limitAccepted: config.maxLimit === null ? true : perPage <= config.maxLimit,
        },
      });
    }
  }

  cases.push({
    id: `page-per-page_${cases.length + 1}`,
    mode: config.mode,
    parameters: { [config.pageField]: 0, [config.limitField]: config.defaultLimit },
    scenario: 'pagina-invalida-zero',
    expected: { maxItems: null, totalItems: total, shouldBeEmpty: null, inputShouldBeRejected: true },
  });

  return cases;
}

/**
 * O que é: gerador de casos para paginação baseada em cursor.
 * O que faz: cria casos documentais para cursor ausente, cursor inicial, cursor seguinte e cursor inválido, deixando explícito
 * que semântica de cursor deve ser definida pelo contrato da API e não pode ser inferida offline.
 */
function buildCursorCases(config) {
  return config.cursors.flatMap((cursor) => config.caseLimits.map((limit) => ({
    id: `cursor_${String(cursor ?? 'initial').replace(/[^a-z0-9]+/gi, '-').slice(0, 24)}_${limit}`,
    mode: config.mode,
    parameters: { [config.cursorField]: cursor, [config.limitField]: limit },
    scenario: cursor === null ? 'cursor-inicial' : cursor.includes('invalido') ? 'cursor-invalido' : 'cursor-fornecido',
    expected: {
      maxItems: null,
      totalItems: config.totalItems,
      limitAccepted: config.maxLimit === null ? true : limit <= config.maxLimit,
      nextCursorExpected: cursor !== 'cursor-final-invalido' ? 'depende-da-api' : null,
    },
  })));
}

/**
 * O que é: construtor de plano de testes de fronteira para paginação.
 * O que faz: gera casos documentais de parâmetros e resultados esperados para o modo escolhido; não monta URLs finais nem
 * dispara chamadas, servindo como base para QA, testes automatizados autorizados e revisão de contrato.
 *
 * @param {object} config Configuração de paginação local.
 * @returns {{generatedAt: string, config: object, cases: object[], summary: object}}
 */
export function createPaginationPlan(config = {}) {
  const normalized = normalizePaginationConfig(config);
  const cases = normalized.mode === 'offset-limit'
    ? buildOffsetCases(normalized)
    : normalized.mode === 'page-per-page'
      ? buildPageCases(normalized)
      : buildCursorCases(normalized);

  return {
    generatedAt: new Date().toISOString(),
    config: normalized,
    cases,
    summary: {
      cases: cases.length,
      mode: normalized.mode,
      totalItemsKnown: normalized.totalItems !== null,
      casesAboveMaxLimit: cases.filter((testCase) => testCase.expected.limitAccepted === false).length,
      casesExpectedEmpty: cases.filter((testCase) => testCase.expected.shouldBeEmpty === true).length,
    },
  };
}

/**
 * O que é: função para obter itens de uma resposta local de paginação.
 * O que faz: localiza o array configurado e retorna uma lista vazia quando o campo estiver ausente ou não for array, permitindo
 * gerar um erro de validação explícito em vez de assumir sucesso.
 */
function responseItems(response, field) {
  return Array.isArray(response?.[field]) ? response[field] : null;
}

/**
 * O que é: função para criar erros de validação de resposta de paginação.
 * O que faz: organiza código, mensagem, valor esperado e recebido para relatórios e integração em pipelines de QA.
 */
function issue(severity, code, message, expected, received) {
  return { severity, code, message, ...(expected !== undefined ? { expected } : {}), ...(received !== undefined ? { received } : {}) };
}

/**
 * O que é: validador local de resposta para um caso de paginação.
 * O que faz: compara uma resposta previamente coletada com expectativas de tamanho, total, parâmetros e IDs duplicados; não
 * solicita outras páginas nem tenta determinar se todos os registros reais foram enumerados corretamente.
 *
 * @param {object} testCase Caso retornado por createPaginationPlan.
 * @param {object} response Corpo JSON previamente coletado.
 * @param {object} [config] Configuração de campos; usa dados do caso quando omitida.
 * @returns {{valid: boolean, issues: object[], observed: object}}
 */
export function validatePaginationResponse(testCase, response, config = {}) {
  if (!testCase?.expected || !testCase?.parameters) throw new TypeError('Forneça um caso válido de createPaginationPlan.');
  if (!response || typeof response !== 'object' || Array.isArray(response)) throw new TypeError('response deve ser um objeto JSON.');

  const fields = {
    itemArrayField: config.itemArrayField ?? 'items',
    itemIdField: config.itemIdField ?? 'id',
    totalField: config.totalField ?? 'total',
    offsetField: config.offsetField ?? 'offset',
    limitField: config.limitField ?? 'limit',
    pageField: config.pageField ?? 'page',
    nextCursorField: config.nextCursorField ?? 'nextCursor',
  };
  const issues = [];
  const items = responseItems(response, fields.itemArrayField);

  if (items === null) {
    issues.push(issue('high', 'items-field-missing-or-invalid', `Campo ${fields.itemArrayField} ausente ou não é um array.`));
  } else {
    if (testCase.expected.maxItems !== null && items.length > testCase.expected.maxItems) {
      issues.push(issue('high', 'too-many-items', `Resposta contém ${items.length} itens, acima do máximo esperado para o caso.`, testCase.expected.maxItems, items.length));
    }

    if (testCase.expected.shouldBeEmpty === true && items.length > 0) {
      issues.push(issue('medium', 'expected-empty-page', 'Caso além do total esperado retornou itens.', 0, items.length));
    }

    const ids = items.map((item) => item?.[fields.itemIdField]).filter((id) => id !== undefined && id !== null);
    if (new Set(ids.map(String)).size !== ids.length) {
      issues.push(issue('medium', 'duplicate-item-ids', `Foram encontrados IDs duplicados no campo ${fields.itemIdField}.`));
    }
  }

  if (testCase.expected.totalItems !== null && response[fields.totalField] !== undefined && Number(response[fields.totalField]) !== testCase.expected.totalItems) {
    issues.push(issue('low', 'total-mismatch', `O total declarado diverge do total configurado no plano.`, testCase.expected.totalItems, response[fields.totalField]));
  }

  if (testCase.expected.limitAccepted === false) {
    const hasError = Boolean(response.error || response.errors || response.status >= 400);
    if (!hasError) {
      issues.push(issue('medium', 'limit-above-max-not-rejected', 'Caso acima do máximo não contém indicador de rejeição na resposta local.', 'erro ou status >= 400', 'sem indicador observado'));
    }
  }

  if (testCase.expected.inputShouldBeRejected) {
    const hasError = Boolean(response.error || response.errors || response.status >= 400);
    if (!hasError) issues.push(issue('medium', 'invalid-page-not-rejected', 'Página inválida não contém indicador de rejeição na resposta local.', 'erro ou status >= 400', 'sem indicador observado'));
  }

  if (testCase.mode === 'cursor' && testCase.expected.nextCursorExpected === 'depende-da-api' && response[fields.nextCursorField] === undefined) {
    issues.push(issue('info', 'next-cursor-not-observed', `Campo ${fields.nextCursorField} não foi observado; confirme o contrato de continuação de cursor.`));
  }

  return {
    valid: issues.filter((item) => ['medium', 'high', 'critical'].includes(item.severity)).length === 0,
    issues,
    observed: {
      itemCount: items?.length ?? null,
      total: response[fields.totalField] ?? null,
      nextCursor: response[fields.nextCursorField] ?? null,
    },
    limitation: 'A validação usa somente respostas locais fornecidas e expectativas configuradas. Ela não consulta páginas adjacentes, não garante ordenação global e não comprova cobertura total do conjunto de dados.',
  };
}

/**
 * O que é: função para validar um conjunto de respostas mapeadas a casos do plano.
 * O que faz: associa cada resposta ao caseId local, gera resultado individual e resume problemas, sem realizar coleta de dados.
 */
export function validatePaginationBatch(plan, collected = []) {
  if (!plan?.cases || !Array.isArray(plan.cases)) throw new TypeError('Forneça um plano retornado por createPaginationPlan.');
  if (!Array.isArray(collected)) throw new TypeError('collected deve ser um array.');

  const casesById = new Map(plan.cases.map((testCase) => [testCase.id, testCase]));
  const results = collected.map((entry, index) => {
    const caseId = entry?.caseId;
    const testCase = casesById.get(caseId);
    if (!testCase) return { caseId: caseId ?? null, valid: false, issues: [issue('high', 'unknown-case', `Entrada ${index + 1} não corresponde a um caseId do plano.`)] };
    return { caseId, ...validatePaginationResponse(testCase, entry.response ?? entry, plan.config) };
  });

  return {
    plan,
    results,
    summary: {
      plannedCases: plan.cases.length,
      responsesValidated: results.length,
      validResponses: results.filter((result) => result.valid).length,
      invalidResponses: results.filter((result) => !result.valid).length,
      missingCases: plan.cases.filter((testCase) => !results.some((result) => result.caseId === testCase.id)).map((testCase) => testCase.id),
    },
  };
}

/**
 * O que é: gerador de relatório Markdown de paginação.
 * O que faz: formata um plano ou resultados de validação em tabelas de casos, expectativas e problemas encontrados localmente.
 */
export function formatMarkdownReport(result) {
  const plan = result?.plan ?? result;
  if (!plan?.cases || !Array.isArray(plan.cases)) throw new TypeError('Forneça um plano ou resultado de validação válido.');
  const validationResults = result?.results ?? null;
  const lines = [
    '# Pagination Boundary Test Plan',
    '',
    `- **Modo:** ${plan.config.mode}`,
    `- **Total conhecido:** ${plan.config.totalItems ?? 'Não informado'}`,
    `- **Tamanho padrão:** ${plan.config.defaultLimit}`,
    `- **Máximo permitido:** ${plan.config.maxLimit ?? 'Não informado'}`,
    `- **Casos planejados:** ${plan.cases.length}`,
    '- **Escopo:** o plano e a validação são locais; a ferramenta não envia requisições.',
    '',
    '## Casos',
    '',
    '| ID | Cenário | Parâmetros | Máximo de itens | Esperado vazio | Limite aceito |',
    '|---|---|---|---:|---|---|',
  ];

  for (const testCase of plan.cases) {
    lines.push(`| ${testCase.id} | ${testCase.scenario} | ${Object.entries(testCase.parameters).map(([key, value]) => `${key}=${value ?? 'null'}`).join(', ')} | ${testCase.expected.maxItems ?? '—'} | ${testCase.expected.shouldBeEmpty === null ? '—' : testCase.expected.shouldBeEmpty ? 'Sim' : 'Não'} | ${testCase.expected.limitAccepted === undefined ? '—' : testCase.expected.limitAccepted ? 'Sim' : 'Não'} |`);
  }

  if (validationResults) {
    lines.push('', '## Validação de respostas', '', '| Caso | Válido | Itens observados | Problemas |', '|---|---|---:|---|');
    for (const validation of validationResults) {
      lines.push(`| ${validation.caseId ?? '—'} | ${validation.valid ? 'Sim' : 'Não'} | ${validation.observed?.itemCount ?? '—'} | ${(validation.issues ?? []).map((item) => item.code).join(', ') || '—'} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter valores de flags de terminal.
 * O que faz: retorna o argumento logo após opções como --config, --responses, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como gerar plano e validar respostas locais de paginação, sem acessar a API que produziu os dados.
 */
function showHelp() {
  console.log(`\nUso:\n  node pagination-boundary-tester.js --config pagination-config.json [opções]\n\nConfiguração exemplo:\n  {\n    "mode": "offset-limit",\n    "totalItems": 53,\n    "defaultLimit": 20,\n    "maxLimit": 100,\n    "itemArrayField": "items",\n    "itemIdField": "id",\n    "totalField": "total"\n  }\n\nOpções:\n  --responses ARQUIVO     Array local de { caseId, response } para validar contra o plano\n  --format FORMATO        json ou markdown. Padrão: json\n  --output ARQUIVO        Salva resultado em arquivo local\n  --pretty                Formata JSON com indentação\n\nExemplo:\n  node pagination-boundary-tester.js --config pagination-config.json --format markdown --output pagination-plan.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const configFile = getCliOption('config');

  if (process.argv.includes('--help') || !configFile) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const config = JSON.parse(await readFile(configFile, 'utf8'));
      const plan = createPaginationPlan(config);
      const responsesFile = getCliOption('responses');
      const result = responsesFile
        ? validatePaginationBatch(plan, JSON.parse(await readFile(responsesFile, 'utf8')))
        : plan;
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(result)
        : JSON.stringify(result, null, process.argv.includes('--pretty') ? 2 : 0);

      const output = getCliOption('output');
      if (output) await writeFile(output, `${content}\n`, 'utf8');
      else console.log(content);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
