#!/usr/bin/env node

/**
 * Webhook Request Recorder
 *
 * O que é: um utilitário JavaScript para registrar e revisar localmente requisições de webhook previamente capturadas.
 * O que faz: normaliza método, URL, headers e payload, redige segredos, calcula hashes, verifica presença de assinatura,
 * timestamp, idempotência e padrões de retry; gera relatórios para auditoria e depuração. Ele não recebe tráfego de rede,
 * não expõe uma porta HTTP, não reenvia webhooks e não acessa ou modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { recordWebhookRequest, analyzeWebhookRecords, formatMarkdownReport } from './webhook-request-recorder.js';
 *
 *   const record = recordWebhookRequest({
 *     receivedAt: '2026-09-07T20:37:00Z', method: 'POST', url: 'https://app.exemplo.com/webhooks/payment',
 *     headers: { 'x-signature': 'valor-secreto', 'idempotency-key': 'evt_123' }, body: '{"type":"payment.succeeded"}'
 *   });
 *   console.log(formatMarkdownReport(analyzeWebhookRecords([record])));
 *
 * Uso via CLI:
 *   node webhook-request-recorder.js --input webhook-evidence.json --format markdown --output webhook-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const SENSITIVE_HEADER_PATTERN = /(?:authorization|signature|secret|token|api[-_]?key|cookie)/i;
const SIGNATURE_HEADER_PATTERN = /(?:signature|webhook[-_]?signature|hmac|x-hub-signature|stripe-signature)/i;
const IDEMPOTENCY_HEADER_NAMES = new Set(['idempotency-key', 'x-idempotency-key', 'x-event-id', 'event-id', 'x-webhook-id', 'webhook-id']);
const TIMESTAMP_HEADER_PATTERN = /(?:timestamp|webhook[-_]?timestamp|x-request-timestamp|stripe-signature)/i;

/**
 * O que é: função para criar hash curto de um valor local.
 * O que faz: retorna uma impressão SHA-256 truncada para correlacionar corpo, chave ou assinatura sem expor o valor original.
 */
function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 16);
}

/**
 * O que é: função para normalizar headers HTTP de webhook.
 * O que faz: converte nomes para minúsculas, concatena valores repetidos e preserva apenas texto para análise local consistente.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) throw new TypeError('headers deve ser um objeto simples.');
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value ?? '')]));
}

/**
 * O que é: função para redigir valor de header sensível.
 * O que faz: substitui valores de assinatura, token, cookie e segredo por tamanho e hash curto antes de gerar registros ou relatórios.
 */
function redactHeaderValue(name, value) {
  if (!SENSITIVE_HEADER_PATTERN.test(name)) return value;
  const text = String(value ?? '');
  return `[REDACTED length=${text.length} sha256=${fingerprint(text)}]`;
}

/**
 * O que é: função para validar URL de destino de webhook em evidência local.
 * O que faz: aceita somente URLs HTTP(S) absolutas e normaliza host, sem contatar o destino ou verificar propriedade do domínio.
 */
function normalizeUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(String(value));
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.hostname = url.hostname.toLowerCase();
    if ((url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80')) url.port = '';
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * O que é: função para encontrar headers associados a assinatura, idempotência e timestamp.
 * O que faz: devolve apenas metadados e impressões digitais, permitindo revisão de controles sem salvar valores em claro.
 */
function extractSecuritySignals(headers) {
  const signatureHeaders = [];
  const timestampHeaders = [];
  let idempotency = null;

  for (const [name, value] of Object.entries(headers)) {
    if (SIGNATURE_HEADER_PATTERN.test(name)) signatureHeaders.push({ name, fingerprint: fingerprint(value), length: value.length });
    if (TIMESTAMP_HEADER_PATTERN.test(name)) timestampHeaders.push({ name, value: redactHeaderValue(name, value) });
    if (IDEMPOTENCY_HEADER_NAMES.has(name) && !idempotency) idempotency = { name, fingerprint: fingerprint(value), length: value.length };
  }

  return { signatureHeaders, timestampHeaders, idempotency };
}

/**
 * O que é: função para inferir metadados não sensíveis de payload JSON.
 * O que faz: tenta interpretar JSON e registra somente chaves de primeiro nível, tipo de evento e identificador comum, sem salvar
 * o corpo completo no registro de auditoria.
 */
function summarizeBody(body) {
  const text = String(body ?? '');
  const summary = { characters: text.length, sha256: fingerprint(text), isJson: false, topLevelKeys: [], eventType: null, eventId: null };
  if (!text.trim()) return summary;

  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      summary.isJson = true;
      summary.topLevelKeys = Object.keys(parsed).slice(0, 50);
      summary.eventType = parsed.type ?? parsed.event ?? parsed.event_type ?? null;
      summary.eventId = parsed.id ?? parsed.eventId ?? parsed.event_id ?? null;
    }
  } catch {
    // O corpo pode ser texto, XML ou formato assinado que não deve ser interpretado por esta ferramenta.
  }
  return summary;
}

/**
 * O que é: função para criar achados padronizados de webhook.
 * O que faz: registra severidade, código, mensagem e recomendação para relatórios de segurança, confiabilidade e integração.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: gravador local de uma requisição de webhook.
 * O que faz: normaliza e redige evidências recebidas, retém metadados úteis e calcula fingerprints para correlação; não expõe
 * endpoint HTTP, não valida assinatura criptográfica e não persiste tokens, assinaturas ou corpos em claro.
 *
 * @param {object} evidence Requisição de webhook previamente capturada.
 * @returns {object} Registro local redigido.
 */
export function recordWebhookRequest(evidence = {}) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) throw new TypeError('evidence deve ser um objeto.');
  const receivedAt = new Date(evidence.receivedAt ?? evidence.timestamp ?? new Date());
  if (Number.isNaN(receivedAt.getTime())) throw new TypeError(`receivedAt inválido: ${evidence.receivedAt ?? evidence.timestamp}`);
  const method = String(evidence.method ?? 'POST').toUpperCase();
  const headers = normalizeHeaders(evidence.headers ?? {});
  const url = normalizeUrl(evidence.url ?? evidence.endpoint);
  const body = String(evidence.body ?? evidence.payload ?? '');
  const signals = extractSecuritySignals(headers);

  return {
    id: String(evidence.id ?? `webhook-${fingerprint(`${receivedAt.toISOString()}|${url}|${body}`)}`),
    receivedAt: receivedAt.toISOString(),
    method,
    url,
    status: Number.isInteger(evidence.status) ? evidence.status : null,
    headers: Object.fromEntries(Object.entries(headers).map(([name, value]) => [name, redactHeaderValue(name, value)])),
    body: summarizeBody(body),
    securitySignals: signals,
    source: evidence.source ?? null,
    notes: evidence.notes ?? null,
  };
}

/**
 * O que é: analisador local de registros de webhook.
 * O que faz: verifica método, HTTPS, sinais de assinatura, timestamp, idempotência, duplicatas e respostas registradas; aponta
 * lacunas para revisão. Ele não valida HMAC, não reenvia eventos e não comprova processamento ou segurança do receptor real.
 *
 * @param {object[]} records Registros retornados por recordWebhookRequest ou evidências compatíveis.
 * @returns {object} Análise consolidada de webhooks.
 */
export function analyzeWebhookRecords(records) {
  if (!Array.isArray(records) || records.length === 0) throw new TypeError('records deve ser um array não vazio.');
  const normalized = records.map((record) => record?.securitySignals ? record : recordWebhookRequest(record))
    .sort((a, b) => new Date(a.receivedAt) - new Date(b.receivedAt));
  const findings = [];
  const idempotencyGroups = new Map();
  const eventIdGroups = new Map();

  for (const record of normalized) {
    if (record.method !== 'POST') {
      findings.push(finding('medium', 'unexpected-webhook-method', `Registro ${record.id} usa método ${record.method}.`, 'Aceite somente métodos esperados pelo provedor, normalmente POST, e rejeite métodos não necessários.'));
    }
    if (record.url?.startsWith('http://')) {
      findings.push(finding('high', 'insecure-webhook-url', `Registro ${record.id} usa URL HTTP.`, 'Use HTTPS para endpoints de webhook em ambientes não locais e valide certificados corretamente.'));
    }
    if (!record.url) {
      findings.push(finding('medium', 'missing-or-invalid-webhook-url', `Registro ${record.id} não possui URL HTTP(S) válida.`, 'Registre a URL de destino de forma segura para permitir auditoria de configuração.'));
    }
    if (record.securitySignals.signatureHeaders.length === 0) {
      findings.push(finding('high', 'signature-not-observed', `Nenhum header de assinatura foi observado no registro ${record.id}.`, 'Configure e valide assinatura criptográfica do provedor sobre o corpo bruto, com comparação em tempo constante.'));
    }
    if (record.securitySignals.timestampHeaders.length === 0) {
      findings.push(finding('medium', 'timestamp-not-observed', `Nenhum timestamp de webhook foi observado no registro ${record.id}.`, 'Quando suportado, valide timestamp e uma janela de tolerância para reduzir replay de eventos antigos.'));
    }
    if (!record.securitySignals.idempotency && !record.body.eventId) {
      findings.push(finding('medium', 'idempotency-key-not-observed', `Nenhuma chave de idempotência ou ID de evento foi observado no registro ${record.id}.`, 'Use ID único do evento ou idempotency key persistida para impedir processamento duplicado.'));
    }
    if (record.status !== null && (record.status < 200 || record.status >= 300)) {
      findings.push(finding('info', 'non-success-webhook-response', `Registro ${record.id} possui status de resposta ${record.status}.`, 'Confirme política de retries do provedor e garanta que falhas transitórias sejam tratadas de forma idempotente.'));
    }

    if (record.securitySignals.idempotency) {
      const key = record.securitySignals.idempotency.fingerprint;
      const group = idempotencyGroups.get(key) ?? [];
      group.push(record);
      idempotencyGroups.set(key, group);
    }
    if (record.body.eventId) {
      const key = String(record.body.eventId);
      const group = eventIdGroups.get(key) ?? [];
      group.push(record);
      eventIdGroups.set(key, group);
    }
  }

  for (const [key, group] of idempotencyGroups) {
    if (group.length > 1) {
      findings.push(finding('info', 'repeated-idempotency-key-observed', `${group.length} registros compartilham a mesma impressão de idempotency key (${key}).`, 'Confirme que o receptor retorna resultado consistente e não reaplica efeitos para entregas repetidas.'));
    }
  }
  for (const [eventId, group] of eventIdGroups) {
    if (group.length > 1) {
      findings.push(finding('info', 'repeated-event-id-observed', `${group.length} registros compartilham event ID ${eventId}.`, 'Deduplicate por ID de evento com armazenamento transacional e retenção compatível com a janela de retry do provedor.'));
    }
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    records: normalized,
    findings,
    summary: {
      webhooks: normalized.length,
      signedWebhookRecords: normalized.filter((record) => record.securitySignals.signatureHeaders.length > 0).length,
      recordsWithIdempotencySignal: normalized.filter((record) => record.securitySignals.idempotency || record.body.eventId).length,
      duplicateIdempotencyGroups: [...idempotencyGroups.values()].filter((group) => group.length > 1).length,
      duplicateEventIdGroups: [...eventIdGroups.values()].filter((group) => group.length > 1).length,
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
    },
    limitation: 'A análise usa registros locais redigidos. Ela não valida assinatura criptográfica, integridade do corpo bruto, timestamp real, origem da rede, processamento transacional ou configuração atual do receptor.',
  };
}

/**
 * O que é: gerador de relatório Markdown de webhooks.
 * O que faz: apresenta registros redigidos, sinais observados e achados de revisão sem incluir assinatura, segredo ou payload original.
 */
export function formatMarkdownReport(report) {
  if (!report || !Array.isArray(report.records) || !Array.isArray(report.findings)) {
    throw new TypeError('Forneça um resultado retornado por analyzeWebhookRecords.');
  }

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Webhook Request Record',
    '',
    `- **Webhooks registrados:** ${report.summary.webhooks}`,
    `- **Com sinal de assinatura:** ${report.summary.signedWebhookRecords}`,
    `- **Com sinal de idempotência/event ID:** ${report.summary.recordsWithIdempotencySignal}`,
    `- **Maior severidade:** ${report.summary.highestSeverity}`,
    `- **Limitação:** ${report.limitation}`,
    '',
    '## Registros',
    '',
    '| Horário | ID | Método | URL | Status | Evento | Assinatura | Idempotência |',
    '|---|---|---|---|---:|---|---|---|',
  ];

  for (const record of report.records) {
    lines.push(`| ${record.receivedAt} | ${clean(record.id)} | ${record.method} | ${clean(record.url)} | ${record.status ?? '—'} | ${clean(record.body.eventType)} | ${record.securitySignals.signatureHeaders.length ? 'Observada' : 'Não observada'} | ${record.securitySignals.idempotency || record.body.eventId ? 'Observada' : 'Não observada'} |`);
  }

  lines.push('', '## Achados', '', '| Severidade | Código | Observação | Recomendação |', '|---|---|---|---|');
  if (report.findings.length === 0) {
    lines.push('| — | — | Nenhum achado produzido pelas regras locais. | Revise validação de assinatura, replay e idempotência no receptor. |');
  } else {
    for (const item of report.findings) {
      lines.push(`| ${item.severity} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter argumentos de terminal.
 * O que faz: retorna o valor após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como registrar evidências locais de webhook e gerar relatórios sem abrir listener HTTP ou reenviar eventos.
 */
function showHelp() {
  console.log(`\nUso:\n  node webhook-request-recorder.js --input webhook-evidence.json [opções]\n\nFormato de entrada:\n  Um objeto ou array de objetos:\n  {\n    "receivedAt": "2026-09-07T20:37:00Z",\n    "method": "POST",\n    "url": "https://app.exemplo.com/webhooks/payment",\n    "status": 200,\n    "headers": {\n      "x-signature": "valor-sensivel",\n      "idempotency-key": "evt_123"\n    },\n    "body": "{\\"type\\":\\"payment.succeeded\\",\\"id\\":\\"evt_123\\"}"\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node webhook-request-recorder.js --input webhook-evidence.json --format markdown --output webhook-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const evidences = Array.isArray(data) ? data : [data];
      const records = evidences.map((evidence) => recordWebhookRequest(evidence));
      const report = analyzeWebhookRecords(records);
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
