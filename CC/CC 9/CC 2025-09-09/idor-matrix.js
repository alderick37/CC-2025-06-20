#!/usr/bin/env node

/**
 * IDOR Authorization Matrix
 *
 * O que é: um utilitário JavaScript para modelar e revisar regras de autorização por objeto (BOLA/IDOR) em APIs e aplicações.
 * O que faz: recebe uma matriz local de atores, recursos, ações e decisões esperadas, valida consistência, identifica lacunas
 * de política e exporta casos de teste documentais. Ele não envia requisições, não troca identidades, não enumera IDs e não
 * testa sistemas externos; a matriz serve para planejar testes autorizados e requisitos de controle de acesso no servidor.
 *
 * Uso como módulo:
 *   import { buildAuthorizationMatrix, analyzeMatrix } from './idor-matrix.js';
 *
 *   const matrix = buildAuthorizationMatrix({
 *     actors: [{ id: 'alice', role: 'customer' }, { id: 'admin', role: 'admin' }],
 *     resources: [{ type: 'order', id: 'order-100', ownerId: 'alice' }],
 *     actions: ['read', 'update'],
 *     rules: [{ actorRole: 'customer', resourceType: 'order', action: 'read', ownership: 'owner', decision: 'allow' }],
 *   });
 *
 * Uso via CLI:
 *   node idor-matrix.js --input authorization-policy.json --format markdown --output idor-matrix.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const VALID_DECISIONS = new Set(['allow', 'deny']);
const VALID_OWNERSHIP = new Set(['owner', 'non-owner', 'any']);

/**
 * O que é: função para criar uma chave estável de política.
 * O que faz: combina função, tipo de recurso, ação e relação de propriedade para localizar regras específicas rapidamente.
 */
function ruleKey(actorRole, resourceType, action, ownership) {
  return `${actorRole}|${resourceType}|${action}|${ownership}`;
}

/**
 * O que é: função para validar e padronizar listas de objetos com id.
 * O que faz: garante que atores e recursos tenham IDs únicos e devolve cópias simples, evitando alteração do objeto de entrada.
 */
function normalizeIdentifiedList(items, label) {
  if (!Array.isArray(items) || items.length === 0) {
    throw new TypeError(`${label} deve ser um array não vazio.`);
  }

  const seen = new Set();
  return items.map((item, index) => {
    if (!item || typeof item !== 'object' || !String(item.id ?? '').trim()) {
      throw new TypeError(`${label}[${index}] deve ser um objeto com id.`);
    }
    const id = String(item.id).trim();
    if (seen.has(id)) throw new TypeError(`${label} possui id duplicado: ${id}`);
    seen.add(id);
    return { ...item, id };
  });
}

/**
 * O que é: função para normalizar ações de uma política de autorização.
 * O que faz: remove espaços, converte ações para minúsculas e elimina duplicatas, como read, update, delete e download.
 */
function normalizeActions(actions) {
  if (!Array.isArray(actions) || actions.length === 0) {
    throw new TypeError('actions deve ser um array não vazio.');
  }

  const normalized = [...new Set(actions.map((action) => String(action).trim().toLowerCase()).filter(Boolean))];
  if (normalized.length === 0) throw new TypeError('actions deve conter pelo menos uma ação válida.');
  return normalized;
}

/**
 * O que é: função para classificar a relação entre ator e recurso.
 * O que faz: considera owner quando actor.id é igual a resource.ownerId; nos demais casos retorna non-owner, sem inferir relações
 * organizacionais, permissões indiretas ou propriedades não declaradas na matriz.
 */
function ownershipOf(actor, resource) {
  return resource.ownerId !== undefined && resource.ownerId !== null && String(resource.ownerId) === actor.id
    ? 'owner'
    : 'non-owner';
}

/**
 * O que é: função para validar e indexar regras declarativas de autorização.
 * O que faz: confere campos obrigatórios, decisões permitidas e evita regras duplicadas ou contraditórias para a mesma chave.
 */
function indexRules(rules = []) {
  if (!Array.isArray(rules)) throw new TypeError('rules deve ser um array.');

  const indexed = new Map();
  for (const [index, rule] of rules.entries()) {
    if (!rule || typeof rule !== 'object') throw new TypeError(`rules[${index}] deve ser um objeto.`);

    const actorRole = String(rule.actorRole ?? '').trim();
    const resourceType = String(rule.resourceType ?? '').trim();
    const action = String(rule.action ?? '').trim().toLowerCase();
    const ownership = String(rule.ownership ?? 'any').trim().toLowerCase();
    const decision = String(rule.decision ?? '').trim().toLowerCase();

    if (!actorRole || !resourceType || !action) {
      throw new TypeError(`rules[${index}] exige actorRole, resourceType e action.`);
    }
    if (!VALID_OWNERSHIP.has(ownership)) throw new TypeError(`rules[${index}] possui ownership inválido: ${ownership}`);
    if (!VALID_DECISIONS.has(decision)) throw new TypeError(`rules[${index}] possui decision inválida: ${decision}`);

    const key = ruleKey(actorRole, resourceType, action, ownership);
    if (indexed.has(key)) throw new TypeError(`Regra duplicada ou contraditória: ${key}`);
    indexed.set(key, { actorRole, resourceType, action, ownership, decision, rationale: rule.rationale ?? null });
  }

  return indexed;
}

/**
 * O que é: função para encontrar a decisão aplicável para um caso da matriz.
 * O que faz: procura primeiro uma regra específica para owner ou non-owner e, na ausência dela, uma regra any; quando não há
 * regra, aplica deny por padrão e marca a ausência como lacuna documental para revisão humana.
 */
function resolveDecision(rules, actorRole, resourceType, action, ownership) {
  const specific = rules.get(ruleKey(actorRole, resourceType, action, ownership));
  const generic = rules.get(ruleKey(actorRole, resourceType, action, 'any'));
  const rule = specific ?? generic ?? null;

  return {
    decision: rule?.decision ?? 'deny',
    source: rule ? (specific ? 'specific-rule' : 'generic-rule') : 'default-deny',
    rule,
  };
}

/**
 * O que é: construtor de matriz de autorização por objeto.
 * O que faz: combina atores, recursos e ações declarados para formar casos esperados de acesso, usando a política local como
 * fonte de verdade. Os casos gerados são documentais e não executam tentativas de acesso em aplicações reais.
 *
 * @param {object} policy Definição local da política.
 * @param {object[]} policy.actors Atores com id e role.
 * @param {object[]} policy.resources Recursos com id, type e opcionalmente ownerId.
 * @param {string[]} policy.actions Ações a avaliar.
 * @param {object[]} [policy.rules=[]] Regras de autorização declaradas.
 * @returns {{generatedAt: string, cases: object[], policySummary: object}}
 */
export function buildAuthorizationMatrix(policy = {}) {
  const actors = normalizeIdentifiedList(policy.actors, 'actors').map((actor, index) => {
    const role = String(actor.role ?? '').trim();
    if (!role) throw new TypeError(`actors[${index}] exige role.`);
    return { ...actor, role };
  });

  const resources = normalizeIdentifiedList(policy.resources, 'resources').map((resource, index) => {
    const type = String(resource.type ?? '').trim();
    if (!type) throw new TypeError(`resources[${index}] exige type.`);
    return { ...resource, type };
  });

  const actions = normalizeActions(policy.actions);
  const rules = indexRules(policy.rules ?? []);
  const cases = [];

  for (const actor of actors) {
    for (const resource of resources) {
      for (const action of actions) {
        const ownership = ownershipOf(actor, resource);
        const resolved = resolveDecision(rules, actor.role, resource.type, action, ownership);
        cases.push({
          id: `case-${String(cases.length + 1).padStart(4, '0')}`,
          actor: { id: actor.id, role: actor.role },
          resource: { id: resource.id, type: resource.type, ownerId: resource.ownerId ?? null },
          action,
          ownership,
          expectedDecision: resolved.decision,
          decisionSource: resolved.source,
          matchedRule: resolved.rule,
        });
      }
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    cases,
    policySummary: {
      actors: actors.length,
      resources: resources.length,
      actions: actions.length,
      declaredRules: rules.size,
      defaultDeny: true,
    },
  };
}

/**
 * O que é: analisador de qualidade da matriz de autorização.
 * O que faz: encontra lacunas que caíram em deny padrão, destaca permissões de non-owner e resume decisões por ação, sem
 * afirmar que exista uma vulnerabilidade real; a finalidade é orientar revisão de requisitos e testes autorizados.
 */
export function analyzeMatrix(matrix) {
  if (!matrix || !Array.isArray(matrix.cases)) throw new TypeError('Forneça uma matriz retornada por buildAuthorizationMatrix.');

  const defaultDenyCases = matrix.cases.filter((testCase) => testCase.decisionSource === 'default-deny');
  const nonOwnerAllows = matrix.cases.filter((testCase) => testCase.ownership === 'non-owner' && testCase.expectedDecision === 'allow');
  const ownerDenies = matrix.cases.filter((testCase) => testCase.ownership === 'owner' && testCase.expectedDecision === 'deny');
  const byAction = {};

  for (const testCase of matrix.cases) {
    byAction[testCase.action] ??= { allow: 0, deny: 0 };
    byAction[testCase.action][testCase.expectedDecision] += 1;
  }

  return {
    matrix,
    analysis: {
      totalCases: matrix.cases.length,
      allowedCases: matrix.cases.filter((testCase) => testCase.expectedDecision === 'allow').length,
      deniedCases: matrix.cases.filter((testCase) => testCase.expectedDecision === 'deny').length,
      defaultDenyCases,
      nonOwnerAllows,
      ownerDenies,
      byAction,
      reviewNotes: [
        'Permissões allow para non-owner não são necessariamente incorretas: podem representar administradores, equipes, compartilhamentos ou recursos públicos. Confirme a justificativa de negócio.',
        'Casos em default-deny indicam ausência de regra explícita na política importada. Avalie se o bloqueio padrão é intencional e está implementado no servidor.',
        'Para testes autorizados, valide a decisão esperada usando identidades de teste e recursos de teste, registrando somente resultados necessários.',
      ],
    },
  };
}

/**
 * O que é: função para converter um caso da matriz em linha CSV.
 * O que faz: protege delimitadores e aspas para que a matriz possa ser aberta em planilhas e ferramentas de acompanhamento.
 */
function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * O que é: exportador CSV de casos de autorização.
 * O que faz: gera uma tabela plana com ator, recurso, ação, relação de propriedade e decisão esperada para planejamento de QA.
 */
export function formatCsv(matrix) {
  if (!matrix || !Array.isArray(matrix.cases)) throw new TypeError('Forneça uma matriz válida.');

  const header = ['case_id', 'actor_id', 'actor_role', 'resource_id', 'resource_type', 'resource_owner_id', 'action', 'ownership', 'expected_decision', 'decision_source', 'matched_rule'];
  const rows = matrix.cases.map((testCase) => [
    testCase.id,
    testCase.actor.id,
    testCase.actor.role,
    testCase.resource.id,
    testCase.resource.type,
    testCase.resource.ownerId ?? '',
    testCase.action,
    testCase.ownership,
    testCase.expectedDecision,
    testCase.decisionSource,
    testCase.matchedRule ? `${testCase.matchedRule.actorRole}/${testCase.matchedRule.resourceType}/${testCase.matchedRule.action}/${testCase.matchedRule.ownership}` : '',
  ].map(csvCell).join(','));

  return [header.join(','), ...rows].join('\n');
}

/**
 * O que é: gerador de relatório Markdown para matriz de autorização.
 * O que faz: apresenta os casos esperados e pontos que requerem revisão de política, deixando claro que não são resultados de exploração.
 */
export function formatMarkdownReport(result) {
  const matrix = result?.matrix ?? result;
  const analysis = result?.analysis ?? analyzeMatrix(matrix).analysis;

  if (!matrix || !Array.isArray(matrix.cases)) throw new TypeError('Forneça uma matriz ou resultado de analyzeMatrix.');

  const lines = [
    '# IDOR / BOLA Authorization Matrix',
    '',
    `- **Gerada em:** ${matrix.generatedAt}`,
    `- **Casos documentais:** ${analysis.totalCases}`,
    `- **Permitir:** ${analysis.allowedCases}`,
    `- **Negar:** ${analysis.deniedCases}`,
    '- **Escopo:** esta matriz modela decisões esperadas; ela não executa requisições nem comprova uma vulnerabilidade.',
    '',
    '## Casos de autorização esperados',
    '',
    '| Caso | Ator | Recurso | Ação | Relação | Decisão esperada | Origem |',
    '|---|---|---|---|---|---|---|',
  ];

  for (const testCase of matrix.cases) {
    lines.push(`| ${testCase.id} | ${testCase.actor.id} (${testCase.actor.role}) | ${testCase.resource.type}/${testCase.resource.id} | ${testCase.action} | ${testCase.ownership} | ${testCase.expectedDecision} | ${testCase.decisionSource} |`);
  }

  lines.push('', '## Pontos para revisão', '');
  lines.push(`- Casos sem regra explícita, usando deny padrão: ${analysis.defaultDenyCases.length}.`);
  lines.push(`- Permissões allow para recursos de non-owner: ${analysis.nonOwnerAllows.length}.`);
  lines.push(`- Bloqueios para recursos do owner: ${analysis.ownerDenies.length}.`);
  for (const note of analysis.reviewNotes) lines.push(`- ${note}`);

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler opções da linha de comando.
 * O que faz: encontra o valor após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda do terminal.
 * O que faz: explica o formato de política local e como exportar a matriz documental em JSON, CSV ou Markdown.
 */
function showHelp() {
  console.log(`\nUso:\n  node idor-matrix.js --input authorization-policy.json [opções]\n\nFormato de entrada:\n  {\n    "actors": [\n      { "id": "alice", "role": "customer" },\n      { "id": "admin", "role": "admin" }\n    ],\n    "resources": [\n      { "id": "order-100", "type": "order", "ownerId": "alice" }\n    ],\n    "actions": ["read", "update", "delete"],\n    "rules": [\n      { "actorRole": "customer", "resourceType": "order", "action": "read", "ownership": "owner", "decision": "allow" },\n      { "actorRole": "customer", "resourceType": "order", "action": "read", "ownership": "non-owner", "decision": "deny" }\n    ]\n  }\n\nOpções:\n  --format FORMATO       json, csv ou markdown. Padrão: json\n  --output ARQUIVO       Salva o resultado em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node idor-matrix.js --input authorization-policy.json --format markdown --output idor-matrix.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const policy = JSON.parse(await readFile(input, 'utf8'));
      const matrix = buildAuthorizationMatrix(policy);
      const analysis = analyzeMatrix(matrix);
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
