#!/usr/bin/env node

/**
 * Mass Assignment Field Reviewer
 *
 * O que é: um utilitário JavaScript para revisar localmente campos de entrada de APIs e modelos de dados quanto a riscos de
 * atribuição em massa (mass assignment / auto-binding).
 * O que faz: compara campos aceitos por endpoint com allowlists, campos somente leitura e campos sensíveis conhecidos; destaca
 * propriedades que exigem revisão e gera relatórios JSON, CSV ou Markdown. Ele não envia payloads, não altera registros, não
 * chama APIs e não testa sistemas externos.
 *
 * Uso como módulo:
 *   import { reviewMassAssignment, formatMarkdownReport } from './mass-assignment-field-reviewer.js';
 *
 *   const report = reviewMassAssignment({
 *     resource: 'User',
 *     acceptedFields: ['name', 'email', 'role', 'isAdmin'],
 *     allowedFields: ['name', 'email'],
 *     readOnlyFields: ['id', 'role', 'isAdmin']
 *   });
 *   console.log(formatMarkdownReport(report));
 *
 * Uso via CLI:
 *   node mass-assignment-field-reviewer.js --input field-review.json --format markdown --output field-review.md
 *   node mass-assignment-field-reviewer.js --input endpoints.json --format csv --output field-review.csv
 */

import { readFile, writeFile } from 'node:fs/promises';

const SENSITIVE_FIELD_PATTERNS = [
  { pattern: /^(?:is_?)?admin(?:istrator)?$/i, category: 'Privilégio administrativo' },
  { pattern: /^(?:is_?)?(?:superuser|staff|moderator)$/i, category: 'Privilégio elevado' },
  { pattern: /^(?:role|roles|permission|permissions|scope|scopes)$/i, category: 'Autorização / função' },
  { pattern: /^(?:owner|owner_?id|user_?id|account_?id|tenant_?id|organization_?id|org_?id)$/i, category: 'Propriedade / tenancy' },
  { pattern: /^(?:balance|credit|wallet|amount|price|discount|paid|payment_?status)$/i, category: 'Financeiro / estado comercial' },
  { pattern: /^(?:status|state|approved|verified|enabled|active|suspended|deleted)$/i, category: 'Estado de negócio' },
  { pattern: /^(?:password|password_?hash|secret|api_?key|token|refresh_?token)$/i, category: 'Credencial / segredo' },
  { pattern: /^(?:created_?at|updated_?at|deleted_?at|id|uuid)$/i, category: 'Campo gerenciado pelo sistema' },
];

/**
 * O que é: função para padronizar nomes de campos.
 * O que faz: remove espaços, converte separadores comuns para underscore e usa minúsculas, permitindo comparação consistente
 * entre camelCase, snake_case e nomes fornecidos por fontes diferentes.
 */
function normalizeFieldName(value) {
  return String(value ?? '')
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[.\-\s]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

/**
 * O que é: função para transformar listas de campos em valores únicos.
 * O que faz: aceita arrays ou valores isolados, descarta itens vazios e preserva nome original junto da chave normalizada.
 */
function normalizeFieldList(values = []) {
  const source = Array.isArray(values) ? values : [values];
  const result = [];
  const seen = new Set();

  for (const value of source) {
    const original = String(value ?? '').trim();
    const normalized = normalizeFieldName(original);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push({ original, normalized });
  }

  return result;
}

/**
 * O que é: função para classificar um campo por padrões sensíveis conhecidos.
 * O que faz: associa um campo a categorias como privilégio, ownership, estado, financeiro ou segredo; a classificação é uma
 * heurística de revisão e não prova que o campo seja vulnerável ou modificável no backend.
 */
function classifySensitiveField(normalizedField) {
  return SENSITIVE_FIELD_PATTERNS.find(({ pattern }) => pattern.test(normalizedField))?.category ?? null;
}

/**
 * O que é: função para criar um achado padronizado de revisão.
 * O que faz: registra severidade, código, campo, mensagem e recomendação para relatórios consistentes e filtráveis.
 */
function finding(severity, code, field, message, recommendation) {
  return { severity, code, field, message, recommendation };
}

/**
 * O que é: função para validar uma entrada de revisão de campos.
 * O que faz: aceita um recurso isolado ou endpoint documentado e padroniza campos aceitos, permitidos, somente leitura e
 * bloqueados sem consultar schemas ou rotas externas.
 */
function normalizeReviewInput(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('A entrada deve ser um objeto de revisão de campos.');
  }

  const acceptedFields = normalizeFieldList(input.acceptedFields ?? input.inputFields ?? input.fields ?? []);
  if (acceptedFields.length === 0) throw new TypeError('Informe ao menos um campo em acceptedFields, inputFields ou fields.');

  return {
    resource: input.resource ?? input.model ?? null,
    endpoint: input.endpoint ?? input.path ?? null,
    method: input.method ? String(input.method).toUpperCase() : null,
    operation: input.operation ?? input.operationId ?? null,
    acceptedFields,
    allowedFields: normalizeFieldList(input.allowedFields ?? input.allowlist ?? []),
    readOnlyFields: normalizeFieldList(input.readOnlyFields ?? input.readonlyFields ?? []),
    blockedFields: normalizeFieldList(input.blockedFields ?? input.denylist ?? []),
    notes: input.notes ?? null,
  };
}

/**
 * O que é: revisor local de risco de mass assignment.
 * O que faz: compara campos aceitos por uma operação com allowlist e campos restritos, sinalizando propriedades sensíveis,
 * campos fora da allowlist e conflitos documentais. A análise não envia valores e não demonstra se a API os persiste.
 *
 * @param {object} input Definição local de campos de entrada e política esperada.
 * @returns {object} Relatório estruturado de revisão.
 */
export function reviewMassAssignment(input = {}) {
  const data = normalizeReviewInput(input);
  const allowed = new Set(data.allowedFields.map((item) => item.normalized));
  const readOnly = new Set(data.readOnlyFields.map((item) => item.normalized));
  const blocked = new Set(data.blockedFields.map((item) => item.normalized));
  const hasAllowlist = allowed.size > 0;
  const fields = [];
  const findings = [];

  for (const field of data.acceptedFields) {
    const category = classifySensitiveField(field.normalized);
    const inAllowlist = allowed.has(field.normalized);
    const isReadOnly = readOnly.has(field.normalized);
    const isBlocked = blocked.has(field.normalized);
    const flags = [];

    if (category) flags.push(category);
    if (hasAllowlist && !inAllowlist) flags.push('Fora da allowlist');
    if (isReadOnly) flags.push('Marcado como somente leitura');
    if (isBlocked) flags.push('Marcado como bloqueado');

    fields.push({
      name: field.original,
      normalizedName: field.normalized,
      sensitiveCategory: category,
      inAllowlist,
      readOnly: isReadOnly,
      blocked: isBlocked,
      flags,
      reviewStatus: flags.length ? 'review-required' : 'documented-allowed',
    });

    if (isReadOnly) {
      findings.push(finding('high', 'read-only-accepted', field.original, `Campo somente leitura aparece entre os campos aceitos: ${field.original}.`, 'Remova o campo do binding de entrada ou aplique uma allowlist explícita de atributos mutáveis no servidor.'));
    }
    if (isBlocked) {
      findings.push(finding('high', 'blocked-field-accepted', field.original, `Campo bloqueado aparece entre os campos aceitos: ${field.original}.`, 'Garanta que o campo seja descartado antes da atualização e cubra a regra com testes de contrato.'));
    }
    if (hasAllowlist && !inAllowlist) {
      findings.push(finding(category ? 'high' : 'medium', 'field-outside-allowlist', field.original, `Campo aceito não consta na allowlist: ${field.original}.`, 'Use DTOs ou schemas de entrada específicos por operação e permita somente campos necessários.'));
    }
    if (category && !isReadOnly && !isBlocked && (!hasAllowlist || inAllowlist)) {
      findings.push(finding('medium', 'sensitive-field-review', field.original, `Campo potencialmente sensível aceito: ${field.original} (${category}).`, 'Confirme necessidade de negócio, autorização no servidor e se o campo deve ser calculado ou controlado internamente.'));
    }
  }

  for (const restricted of [...readOnly, ...blocked]) {
    if (!data.acceptedFields.some((field) => field.normalized === restricted)) continue;
  }

  if (!hasAllowlist) {
    findings.push(finding('medium', 'missing-allowlist', null, 'Nenhuma allowlist de campos foi informada para a operação.', 'Prefira DTOs, serializers ou schemas de entrada por endpoint em vez de binding direto do modelo de persistência.'));
  }

  const severities = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(severities.map((severity) => [severity, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    target: {
      resource: data.resource,
      endpoint: data.endpoint,
      method: data.method,
      operation: data.operation,
    },
    fields,
    findings,
    summary: {
      acceptedFields: fields.length,
      fieldsRequiringReview: fields.filter((field) => field.reviewStatus === 'review-required').length,
      allowlistConfigured: hasAllowlist,
      counts,
      highestSeverity: [...severities].reverse().find((severity) => counts[severity] > 0) ?? 'info',
    },
    limitation: 'O relatório compara documentação e listas locais. Ele não envia payloads nem confirma se campos são realmente aceitos, persistidos, autorizados ou vulneráveis no backend.',
  };
}

/**
 * O que é: revisor em lote para várias operações ou recursos.
 * O que faz: executa a análise local para cada entrada e consolida contagens de achados, sem acessar endpoints ou bancos de dados.
 */
export function reviewMassAssignmentBatch(inputs) {
  if (!Array.isArray(inputs)) throw new TypeError('inputs deve ser um array de objetos de revisão.');
  const results = inputs.map((input) => reviewMassAssignment(input));
  const allFindings = results.flatMap((result) => result.findings);
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const item of allFindings) counts[item.severity] += 1;

  return {
    results,
    summary: {
      reviews: results.length,
      totalFindings: allFindings.length,
      counts,
      highPriorityReviews: results.filter((result) => result.findings.some((item) => ['high', 'critical'].includes(item.severity))).length,
    },
  };
}

/**
 * O que é: função para proteger valores ao exportar CSV.
 * O que faz: escapa aspas e delimitadores para permitir a abertura segura do relatório em planilhas.
 */
function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * O que é: exportador CSV da revisão de campos.
 * O que faz: cria uma tabela plana por campo com status de allowlist, bloqueio, sensibilidade e flags de revisão.
 */
export function formatCsv(report) {
  const reports = Array.isArray(report?.results) ? report.results : [report];
  if (!reports.every((item) => item && Array.isArray(item.fields))) throw new TypeError('Forneça um relatório individual ou em lote.');

  const header = ['resource', 'endpoint', 'method', 'field', 'normalized_field', 'sensitive_category', 'in_allowlist', 'read_only', 'blocked', 'review_status', 'flags'];
  const rows = reports.flatMap((item) => item.fields.map((field) => [
    item.target.resource ?? '',
    item.target.endpoint ?? '',
    item.target.method ?? '',
    field.name,
    field.normalizedName,
    field.sensitiveCategory ?? '',
    field.inAllowlist,
    field.readOnly,
    field.blocked,
    field.reviewStatus,
    field.flags.join('; '),
  ].map(csvCell).join(',')));

  return [header.join(','), ...rows].join('\n');
}

/**
 * O que é: gerador de relatório Markdown de revisão de mass assignment.
 * O que faz: apresenta uma matriz de campos e uma tabela de achados para facilitar revisão de DTOs, serializers e modelos.
 */
export function formatMarkdownReport(report) {
  const reports = Array.isArray(report?.results) ? report.results : [report];
  if (!reports.every((item) => item && Array.isArray(item.fields))) throw new TypeError('Forneça um relatório individual ou em lote.');

  const lines = [
    '# Mass Assignment Field Review',
    '',
    `- **Operações revisadas:** ${reports.length}`,
    '- **Escopo:** análise documental local; o resultado não confirma persistência de campo ou vulnerabilidade no backend.',
  ];

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  for (const reportItem of reports) {
    lines.push('', `## ${reportItem.target.method ?? 'OPERAÇÃO'} ${reportItem.target.endpoint ?? reportItem.target.resource ?? 'Recurso não informado'}`, '');
    lines.push(`- Recurso: ${reportItem.target.resource ?? 'Não informado'}`);
    lines.push(`- Allowlist configurada: ${reportItem.summary.allowlistConfigured ? 'sim' : 'não'}`);
    lines.push(`- Campos aceitos: ${reportItem.summary.acceptedFields}`);
    lines.push('', '| Campo | Categoria sensível | Allowlist | Somente leitura | Bloqueado | Status | Flags |', '|---|---|---|---|---|---|---|');
    for (const field of reportItem.fields) {
      lines.push(`| ${clean(field.name)} | ${clean(field.sensitiveCategory)} | ${field.inAllowlist ? 'Sim' : 'Não'} | ${field.readOnly ? 'Sim' : 'Não'} | ${field.blocked ? 'Sim' : 'Não'} | ${field.reviewStatus} | ${clean(field.flags.join('; '))} |`);
    }

    lines.push('', '### Achados', '');
    if (reportItem.findings.length === 0) lines.push('- Nenhum achado gerado pelas regras locais.');
    else {
      lines.push('| Severidade | Código | Campo | Observação | Recomendação |', '|---|---|---|---|---|');
      for (const item of reportItem.findings) {
        lines.push(`| ${item.severity} | ${item.code} | ${clean(item.field)} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
      }
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para extrair valores de flags do terminal.
 * O que faz: devolve o valor imediatamente após opções como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica o formato de revisão local e como exportar relatórios JSON, CSV ou Markdown sem enviar qualquer payload.
 */
function showHelp() {
  console.log(`\nUso:\n  node mass-assignment-field-reviewer.js --input field-review.json [opções]\n\nFormato de entrada:\n  Um objeto ou array de objetos:\n  {\n    "resource": "User",\n    "endpoint": "/users/{id}",\n    "method": "PATCH",\n    "acceptedFields": ["name", "email", "role", "isAdmin"],\n    "allowedFields": ["name", "email"],\n    "readOnlyFields": ["id", "role", "isAdmin"],\n    "blockedFields": ["passwordHash"]\n  }\n\nOpções:\n  --format FORMATO       json, csv ou markdown. Padrão: json\n  --output ARQUIVO       Salva o relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node mass-assignment-field-reviewer.js --input field-review.json --format markdown --output field-review.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const report = Array.isArray(data) ? reviewMassAssignmentBatch(data) : reviewMassAssignment(data);
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
