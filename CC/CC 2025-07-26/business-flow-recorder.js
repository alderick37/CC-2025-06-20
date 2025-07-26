#!/usr/bin/env node

/**
 * Business Flow Recorder
 *
 * O que é: um utilitário JavaScript para registrar e revisar localmente fluxos de negócio, estados, transições e regras.
 * O que faz: organiza eventos já observados ou definidos em uma linha do tempo, valida transições contra uma máquina de estados
 * declarada, destaca lacunas de regra, mudanças de estado inválidas e ausência de evidência de autorização. Ele não envia
 * requisições, não executa transações, não altera dados e não acessa sistemas externos.
 *
 * Uso como módulo:
 *   import { recordBusinessFlow, analyzeBusinessFlow, formatMarkdownReport } from './business-flow-recorder.js';
 *
 *   const flow = recordBusinessFlow({
 *     name: 'Pedido de compra',
 *     states: ['draft', 'submitted', 'approved', 'cancelled'],
 *     transitions: [{ from: 'draft', action: 'submit', to: 'submitted', roles: ['customer'] }],
 *     events: [{ timestamp: '2026-09-07T20:00:00Z', entityId: 'order-100', from: 'draft', action: 'submit', to: 'submitted', actor: { id: 'user-1', role: 'customer' } }]
 *   });
 *
 * Uso via CLI:
 *   node business-flow-recorder.js --input business-flow.json --format markdown --output business-flow-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';

/**
 * O que é: função para normalizar um identificador textual de estado ou ação.
 * O que faz: remove espaços externos e converte o valor para minúsculas, permitindo comparação previsível em transições.
 */
function normalizeIdentifier(value, field) {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!normalized) throw new TypeError(`${field} não pode ser vazio.`);
  return normalized;
}

/**
 * O que é: função para criar uma chave única de transição.
 * O que faz: combina estado de origem, ação e estado de destino para localizar e validar transições declaradas localmente.
 */
function transitionKey(from, action, to) {
  return `${from}|${action}|${to}`;
}

/**
 * O que é: função para interpretar timestamp de evento.
 * O que faz: converte uma data ISO em objeto Date e rejeita valores inválidos para que a linha do tempo permaneça ordenável.
 */
function parseTimestamp(value, field = 'timestamp') {
  const date = new Date(value ?? new Date());
  if (Number.isNaN(date.getTime())) throw new TypeError(`${field} inválido: ${value}`);
  return date;
}

/**
 * O que é: função para validar e normalizar a definição de estados.
 * O que faz: remove duplicatas, garante ao menos um estado e preserva uma lista canônica usada por transições e eventos.
 */
function normalizeStates(states) {
  if (!Array.isArray(states) || states.length === 0) throw new TypeError('states deve ser um array não vazio.');
  const normalized = [...new Set(states.map((state) => normalizeIdentifier(state, 'state')))];
  if (normalized.length === 0) throw new TypeError('states deve conter ao menos um estado válido.');
  return normalized;
}

/**
 * O que é: função para normalizar transições de negócio declaradas.
 * O que faz: valida origem, ação, destino, papéis permitidos e flags de autorização, criando regras que serão usadas apenas na
 * análise local de eventos, sem executar a mudança de estado em qualquer sistema real.
 */
function normalizeTransitions(transitions, states) {
  if (!Array.isArray(transitions)) throw new TypeError('transitions deve ser um array.');
  const stateSet = new Set(states);
  const map = new Map();

  for (const [index, transition] of transitions.entries()) {
    if (!transition || typeof transition !== 'object' || Array.isArray(transition)) {
      throw new TypeError(`transitions[${index}] deve ser um objeto.`);
    }

    const from = normalizeIdentifier(transition.from, `transitions[${index}].from`);
    const action = normalizeIdentifier(transition.action, `transitions[${index}].action`);
    const to = normalizeIdentifier(transition.to, `transitions[${index}].to`);
    if (!stateSet.has(from) || !stateSet.has(to)) {
      throw new TypeError(`transitions[${index}] referencia estado não declarado: ${from} → ${to}.`);
    }

    const key = transitionKey(from, action, to);
    if (map.has(key)) throw new TypeError(`Transição duplicada: ${key}.`);

    map.set(key, {
      id: transition.id ?? `transition-${index + 1}`,
      from,
      action,
      to,
      roles: [...new Set((transition.roles ?? []).map((role) => String(role).trim()).filter(Boolean))],
      requiresAuthorization: transition.requiresAuthorization !== false,
      requiresApproval: Boolean(transition.requiresApproval),
      requiredEvidence: [...new Set((transition.requiredEvidence ?? []).map((item) => String(item).trim()).filter(Boolean))],
      notes: transition.notes ?? null,
    });
  }

  return map;
}

/**
 * O que é: função para normalizar um ator ligado a evento de negócio.
 * O que faz: preserva identificador, papel e tipo de autenticação declarados, sem validar identidade ou permissões reais.
 */
function normalizeActor(actor = {}) {
  if (!actor || typeof actor !== 'object' || Array.isArray(actor)) return { id: null, role: null, authenticated: null };
  return {
    id: actor.id === undefined || actor.id === null ? null : String(actor.id),
    role: actor.role === undefined || actor.role === null ? null : String(actor.role),
    authenticated: actor.authenticated === undefined ? null : Boolean(actor.authenticated),
  };
}

/**
 * O que é: função para normalizar eventos de um fluxo de negócio.
 * O que faz: padroniza entidade, estado anterior, ação, estado posterior, ator, evidências e timestamp para análise local.
 */
function normalizeEvent(event, index, states) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError(`events[${index}] deve ser um objeto.`);
  const stateSet = new Set(states);
  const from = normalizeIdentifier(event.from, `events[${index}].from`);
  const action = normalizeIdentifier(event.action, `events[${index}].action`);
  const to = normalizeIdentifier(event.to, `events[${index}].to`);
  if (!stateSet.has(from) || !stateSet.has(to)) throw new TypeError(`events[${index}] referencia estado não declarado: ${from} → ${to}.`);

  const entityId = String(event.entityId ?? event.id ?? '').trim();
  if (!entityId) throw new TypeError(`events[${index}] exige entityId.`);

  return {
    id: String(event.id ?? `event-${String(index + 1).padStart(3, '0')}`),
    timestamp: parseTimestamp(event.timestamp).toISOString(),
    entityId,
    entityType: event.entityType ?? null,
    from,
    action,
    to,
    actor: normalizeActor(event.actor),
    authorizationObserved: event.authorizationObserved === undefined ? null : Boolean(event.authorizationObserved),
    approvalObserved: event.approvalObserved === undefined ? null : Boolean(event.approvalObserved),
    evidence: [...new Set((event.evidence ?? []).map((item) => String(item).trim()).filter(Boolean))],
    notes: event.notes ?? null,
  };
}

/**
 * O que é: gravador local de fluxo de negócio.
 * O que faz: valida a máquina de estados declarada, normaliza eventos e os ordena cronologicamente, gerando um registro para
 * documentação, QA e revisão. Ele não executa workflows, pagamentos, aprovações ou alterações de estado reais.
 *
 * @param {object} definition Definição local de estados, transições e eventos.
 * @returns {object} Fluxo de negócio normalizado.
 */
export function recordBusinessFlow(definition = {}) {
  if (!definition || typeof definition !== 'object' || Array.isArray(definition)) throw new TypeError('definition deve ser um objeto.');
  const states = normalizeStates(definition.states);
  const transitions = normalizeTransitions(definition.transitions ?? [], states);
  const events = (definition.events ?? []).map((event, index) => normalizeEvent(event, index, states))
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  return {
    recordedAt: new Date().toISOString(),
    metadata: {
      name: definition.name ?? null,
      version: definition.version ?? null,
      owner: definition.owner ?? null,
      description: definition.description ?? null,
      notes: definition.notes ?? null,
    },
    states,
    transitions: [...transitions.values()],
    events,
  };
}

/**
 * O que é: função para criar achados padronizados de revisão de fluxo.
 * O que faz: registra severidade, código, evento e recomendação para ajudar a priorizar lacunas de processo e autorização.
 */
function finding(severity, code, eventId, message, recommendation) {
  return { severity, code, eventId, message, recommendation };
}

/**
 * O que é: função para localizar transição exata declarada para um evento.
 * O que faz: usa a combinação from, action e to para encontrar regra na máquina de estados local; não infere transições parecidas.
 */
function findTransition(transitions, event) {
  return transitions.find((transition) => transition.from === event.from && transition.action === event.action && transition.to === event.to) ?? null;
}

/**
 * O que é: analisador local de coerência de um fluxo de negócio.
 * O que faz: compara eventos com transições, verifica continuidade por entidade, papéis permitidos, evidências e sinais de
 * autorização/aprovação declarados. A análise não comprova que controles foram executados no backend real.
 *
 * @param {object} flow Fluxo retornado por recordBusinessFlow.
 * @returns {object} Resultado da análise local.
 */
export function analyzeBusinessFlow(flow) {
  if (!flow || !Array.isArray(flow.states) || !Array.isArray(flow.transitions) || !Array.isArray(flow.events)) {
    throw new TypeError('Forneça um fluxo retornado por recordBusinessFlow.');
  }

  const findings = [];
  const entityStates = new Map();
  const transitionsByKey = new Map(flow.transitions.map((transition) => [transitionKey(transition.from, transition.action, transition.to), transition]));
  const eventResults = [];

  for (const event of flow.events) {
    const transition = transitionsByKey.get(transitionKey(event.from, event.action, event.to)) ?? null;
    const previousState = entityStates.get(event.entityId) ?? null;
    const eventFindings = [];

    if (!transition) {
      eventFindings.push(finding('high', 'undeclared-transition', event.id, `Transição não declarada: ${event.from} --${event.action}--> ${event.to}.`, 'Defina explicitamente a transição ou bloqueie a mudança de estado no servidor.'));
    } else {
      if (previousState !== null && previousState !== event.from) {
        eventFindings.push(finding('high', 'state-continuity-mismatch', event.id, `Estado anterior da entidade é ${previousState}, mas o evento informa origem ${event.from}.`, 'Garanta controle transacional e validação de estado atual antes de aplicar transições.'));
      }

      if (transition.roles.length > 0 && (!event.actor.role || !transition.roles.includes(event.actor.role))) {
        eventFindings.push(finding('high', 'role-not-allowed', event.id, `Papel ${event.actor.role ?? 'não informado'} não consta nos papéis permitidos para esta transição.`, 'Aplique autorização server-side por ação, estado e recurso antes de efetivar a transição.'));
      }

      if (transition.requiresAuthorization && event.authorizationObserved !== true) {
        eventFindings.push(finding('medium', 'authorization-not-observed', event.id, 'A transição exige autorização, mas a evidência não confirma checagem de autorização.', 'Registre ou teste controles de autorização no servidor para esta ação e objeto específico.'));
      }

      if (transition.requiresApproval && event.approvalObserved !== true) {
        eventFindings.push(finding('medium', 'approval-not-observed', event.id, 'A transição exige aprovação, mas a evidência não confirma a aprovação.', 'Exija aprovação verificável e mantenha trilha de auditoria antes da mudança de estado.'));
      }

      const missingEvidence = transition.requiredEvidence.filter((item) => !event.evidence.includes(item));
      if (missingEvidence.length > 0) {
        eventFindings.push(finding('medium', 'required-evidence-missing', event.id, `Evidências obrigatórias ausentes: ${missingEvidence.join(', ')}.`, 'Valide documentos, confirmações ou registros exigidos antes de permitir a transição.'));
      }

      if (event.actor.authenticated === false && transition.requiresAuthorization) {
        eventFindings.push(finding('high', 'unauthenticated-actor', event.id, 'Evento associado a ator explicitamente não autenticado em transição que requer autorização.', 'Exija autenticação e autorização antes de processar qualquer mudança de estado protegida.'));
      }
    }

    if (previousState === null && event.from !== flow.states[0]) {
      eventFindings.push(finding('info', 'initial-state-not-observed', event.id, `Primeiro evento conhecido para a entidade parte de ${event.from}.`, 'Registre criação ou estado inicial se for necessário auditar continuidade completa.'));
    }

    entityStates.set(event.entityId, event.to);
    findings.push(...eventFindings);
    eventResults.push({ event, transition, findings: eventFindings });
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    flow,
    eventResults,
    analysis: {
      events: flow.events.length,
      entities: new Set(flow.events.map((event) => event.entityId)).size,
      declaredTransitions: flow.transitions.length,
      findings,
      summary: {
        counts,
        highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
      },
      limitation: 'A análise avalia uma definição e eventos locais. Ela não executa transições, valida identidades, consulta banco de dados, verifica logs de auditoria reais nem confirma controles em produção.',
    },
  };
}

/**
 * O que é: gerador de relatório Markdown de fluxo de negócio.
 * O que faz: apresenta estados, transições, linha do tempo e achados de revisão em formato legível para produto, QA e segurança.
 */
export function formatMarkdownReport(result) {
  const flow = result?.flow ?? result;
  const analysis = result?.analysis ?? analyzeBusinessFlow(flow).analysis;
  if (!flow || !Array.isArray(flow.events)) throw new TypeError('Forneça um fluxo ou resultado de analyzeBusinessFlow.');

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Business Flow Record',
    '',
    `- **Fluxo:** ${flow.metadata?.name ?? 'Não informado'}`,
    `- **Versão:** ${flow.metadata?.version ?? 'Não informada'}`,
    `- **Estados:** ${flow.states.join(', ')}`,
    `- **Eventos:** ${analysis.events}`,
    `- **Maior severidade:** ${analysis.summary.highestSeverity}`,
    `- **Limitação:** ${analysis.limitation}`,
    '',
    '## Transições declaradas',
    '',
    '| Origem | Ação | Destino | Papéis permitidos | Autorização | Aprovação |',
    '|---|---|---|---|---|---|',
  ];

  for (const transition of flow.transitions) {
    lines.push(`| ${transition.from} | ${transition.action} | ${transition.to} | ${clean(transition.roles.join(', ') || 'Qualquer')} | ${transition.requiresAuthorization ? 'Sim' : 'Não'} | ${transition.requiresApproval ? 'Sim' : 'Não'} |`);
  }

  lines.push('', '## Linha do tempo', '', '| Horário | Entidade | Origem | Ação | Destino | Ator | Resultado |', '|---|---|---|---|---|---|---|');
  for (const resultItem of result?.eventResults ?? flow.events.map((event) => ({ event, findings: [] }))) {
    const event = resultItem.event;
    const outcome = resultItem.findings.length ? resultItem.findings.map((item) => item.code).join(', ') : 'Sem achados';
    lines.push(`| ${event.timestamp} | ${clean(event.entityId)} | ${event.from} | ${event.action} | ${event.to} | ${clean(`${event.actor.id ?? '—'} (${event.actor.role ?? '—'})`)} | ${clean(outcome)} |`);
  }

  lines.push('', '## Achados', '');
  if (analysis.findings.length === 0) lines.push('- Nenhum achado produzido pelas verificações locais.');
  else {
    lines.push('| Severidade | Evento | Código | Observação | Recomendação |', '|---|---|---|---|---|');
    for (const item of analysis.findings) {
      lines.push(`| ${item.severity} | ${clean(item.eventId)} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos de terminal.
 * O que faz: retorna o valor logo após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: descreve como registrar e analisar definição e eventos locais de negócio sem executar mudanças reais de estado.
 */
function showHelp() {
  console.log(`\nUso:\n  node business-flow-recorder.js --input business-flow.json [opções]\n\nFormato de entrada:\n  {\n    "name": "Pedido de compra",\n    "states": ["draft", "submitted", "approved", "cancelled"],\n    "transitions": [\n      { "from": "draft", "action": "submit", "to": "submitted", "roles": ["customer"], "requiresAuthorization": true }\n    ],\n    "events": [\n      {\n        "timestamp": "2026-09-07T20:00:00Z",\n        "entityId": "order-100",\n        "from": "draft",\n        "action": "submit",\n        "to": "submitted",\n        "actor": { "id": "user-1", "role": "customer", "authenticated": true },\n        "authorizationObserved": true\n      }\n    ]\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node business-flow-recorder.js --input business-flow.json --format markdown --output business-flow-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const definition = JSON.parse(await readFile(input, 'utf8'));
      const flow = recordBusinessFlow(definition);
      const report = analyzeBusinessFlow(flow);
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
