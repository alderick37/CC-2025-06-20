#!/usr/bin/env node

/**
 * OAuth Flow Recorder
 *
 * O que é: um utilitário JavaScript para registrar e revisar localmente eventos de fluxos OAuth 2.0 e OpenID Connect.
 * O que faz: recebe eventos já observados ou informados pelo usuário, redige valores sensíveis, organiza a sequência do
 * fluxo, verifica coerência básica de state, PKCE, redirect_uri e tokens e exporta relatórios. Ele não inicia login, não
 * abre navegador, não envia requisições, não troca códigos por tokens e não acessa provedores de identidade externos.
 *
 * Uso como módulo:
 *   import { recordOAuthFlow, analyzeOAuthFlow, formatMarkdownReport } from './oauth-flow-recorder.js';
 *
 *   const flow = recordOAuthFlow([
 *     { type: 'authorization_request', timestamp: '2026-09-07T20:00:00Z', clientId: 'web-app', redirectUri: 'https://app.exemplo.com/callback', responseType: 'code', state: 'state-123', codeChallenge: '...' },
 *     { type: 'authorization_response', timestamp: '2026-09-07T20:00:05Z', redirectUri: 'https://app.exemplo.com/callback', state: 'state-123', code: 'authorization-code' }
 *   ]);
 *   console.log(formatMarkdownReport(analyzeOAuthFlow(flow)));
 *
 * Uso via CLI:
 *   node oauth-flow-recorder.js --input oauth-events.json --format markdown --output oauth-flow.md
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const EVENT_TYPES = new Set([
  'authorization_request',
  'authorization_response',
  'token_request',
  'token_response',
  'refresh_request',
  'refresh_response',
  'error',
  'logout',
]);

const SENSITIVE_FIELDS = new Set([
  'authorization',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'idToken',
  'id_token',
  'code',
  'codeVerifier',
  'code_verifier',
  'clientSecret',
  'client_secret',
]);

/**
 * O que é: função para converter timestamp de evento em data válida.
 * O que faz: interpreta uma data ISO 8601 ou usa o instante atual quando o timestamp não é informado; rejeita datas inválidas.
 */
function parseTimestamp(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) throw new TypeError(`Timestamp inválido: ${value}`);
  return date;
}

/**
 * O que é: função para criar uma impressão curta de valor sensível.
 * O que faz: usa SHA-256 truncado para correlacionar valores entre eventos sem preservá-los em claro no registro.
 */
function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

/**
 * O que é: função para redigir um valor sensível mantendo rastreabilidade mínima.
 * O que faz: exibe tamanho e impressão curta do valor, sem salvar código, token, segredo ou verifier original no relatório.
 */
function redactValue(value) {
  if (value === undefined || value === null || value === '') return null;
  const text = String(value);
  return `[REDACTED length=${text.length} sha256=${fingerprint(text)}]`;
}

/**
 * O que é: função para validar uma URL de redirecionamento OAuth localmente.
 * O que faz: aceita URLs HTTP(S) absolutas e retorna sua forma normalizada; não verifica posse, registro prévio ou domínio real.
 */
function normalizeRedirectUri(value) {
  if (!value) return null;
  try {
    const url = new URL(String(value));
    if (!['https:', 'http:'].includes(url.protocol)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * O que é: função para redigir campos de um evento OAuth.
 * O que faz: copia somente campos conhecidos e substitui segredos por metadados redigidos, evitando persistência acidental de tokens.
 */
function sanitizeEvent(event, index) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new TypeError(`Evento ${index + 1} deve ser um objeto.`);
  }

  const type = String(event.type ?? '').trim();
  if (!EVENT_TYPES.has(type)) {
    throw new TypeError(`Evento ${index + 1} possui type inválido: ${type || '(vazio)'}.`);
  }

  const timestamp = parseTimestamp(event.timestamp);
  const sanitized = {
    id: String(event.id ?? `event-${String(index + 1).padStart(3, '0')}`),
    type,
    timestamp: timestamp.toISOString(),
    clientId: event.clientId ?? event.client_id ?? null,
    redirectUri: normalizeRedirectUri(event.redirectUri ?? event.redirect_uri),
    responseType: event.responseType ?? event.response_type ?? null,
    grantType: event.grantType ?? event.grant_type ?? null,
    scope: event.scope ?? null,
    state: event.state ? redactValue(event.state) : null,
    nonce: event.nonce ? redactValue(event.nonce) : null,
    codeChallenge: event.codeChallenge ?? event.code_challenge ? redactValue(event.codeChallenge ?? event.code_challenge) : null,
    codeChallengeMethod: event.codeChallengeMethod ?? event.code_challenge_method ?? null,
    code: event.code ? redactValue(event.code) : null,
    codeVerifier: event.codeVerifier ?? event.code_verifier ? redactValue(event.codeVerifier ?? event.code_verifier) : null,
    accessToken: event.accessToken ?? event.access_token ? redactValue(event.accessToken ?? event.access_token) : null,
    refreshToken: event.refreshToken ?? event.refresh_token ? redactValue(event.refreshToken ?? event.refresh_token) : null,
    idToken: event.idToken ?? event.id_token ? redactValue(event.idToken ?? event.id_token) : null,
    tokenType: event.tokenType ?? event.token_type ?? null,
    expiresIn: Number.isFinite(Number(event.expiresIn ?? event.expires_in)) ? Number(event.expiresIn ?? event.expires_in) : null,
    error: event.error ?? null,
    errorDescription: event.errorDescription ?? event.error_description ?? null,
    notes: event.notes ?? null,
  };

  for (const key of SENSITIVE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(event, key) && sanitized[key] === undefined) sanitized[key] = redactValue(event[key]);
  }

  return sanitized;
}

/**
 * O que é: função para extrair impressão de um valor já redigido.
 * O que faz: obtém a parte sha256 usada na correlação de state, código e token sem recuperar o segredo original.
 */
function redactedFingerprint(value) {
  const match = String(value ?? '').match(/sha256=([a-f0-9]{12})/i);
  return match?.[1] ?? null;
}

/**
 * O que é: gravador local de eventos OAuth/OIDC.
 * O que faz: normaliza, redige e ordena eventos por tempo, preservando uma linha do tempo segura para auditoria, depuração e
 * documentação. Ele não captura tráfego diretamente e não contém os valores secretos originais após o processamento.
 *
 * @param {object[]} events Eventos OAuth/OIDC observados ou informados localmente.
 * @param {object} [metadata={}] Metadados livres, como ambiente ou nome do fluxo.
 * @returns {{recordedAt: string, metadata: object, events: object[]}}
 */
export function recordOAuthFlow(events, metadata = {}) {
  if (!Array.isArray(events) || events.length === 0) {
    throw new TypeError('events deve ser um array não vazio.');
  }

  const sanitizedEvents = events.map(sanitizeEvent).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  return {
    recordedAt: new Date().toISOString(),
    metadata: {
      name: metadata.name ?? null,
      environment: metadata.environment ?? null,
      issuer: metadata.issuer ?? null,
      notes: metadata.notes ?? null,
    },
    events: sanitizedEvents,
  };
}

/**
 * O que é: função que cria achados de fluxo em formato padronizado.
 * O que faz: registra severidade, código, mensagem e recomendação para manter a análise de OAuth legível e acionável.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: analisador de coerência de eventos OAuth/OIDC gravados.
 * O que faz: revisa sequência Authorization Code, state, PKCE, redirect_uri, grant type, tokens e erros reportados; a análise
 * é documental e não confirma configurações do provedor, validade criptográfica ou segurança real da implementação.
 */
export function analyzeOAuthFlow(flow) {
  if (!flow || !Array.isArray(flow.events)) throw new TypeError('Forneça um fluxo retornado por recordOAuthFlow.');

  const findings = [];
  const requests = flow.events.filter((event) => event.type === 'authorization_request');
  const responses = flow.events.filter((event) => event.type === 'authorization_response');
  const tokenRequests = flow.events.filter((event) => event.type === 'token_request');
  const tokenResponses = flow.events.filter((event) => event.type === 'token_response');
  const errors = flow.events.filter((event) => event.type === 'error' || event.error);

  if (requests.length === 0) {
    findings.push(finding('medium', 'missing-authorization-request', 'Nenhum authorization_request foi registrado.', 'Registre a solicitação de autorização para revisar response_type, state, PKCE e redirect_uri.'));
  }

  for (const request of requests) {
    const responseType = String(request.responseType ?? '').toLowerCase();
    if (!responseType) {
      findings.push(finding('medium', 'missing-response-type', `Evento ${request.id} não declara response_type.`, 'Use Authorization Code Flow com response_type=code quando aplicável.'));
    } else if (responseType !== 'code') {
      findings.push(finding('medium', 'non-code-flow', `Evento ${request.id} usa response_type=${request.responseType}.`, 'Avalie se o fluxo é apropriado; Authorization Code com PKCE é a opção usual para clientes modernos.'));
    }

    if (!request.state) {
      findings.push(finding('high', 'missing-state', `Evento ${request.id} não contém state.`, 'Envie state imprevisível e valide a correspondência no callback para reduzir risco de CSRF no fluxo OAuth.'));
    }

    if (responseType === 'code' && !request.codeChallenge) {
      findings.push(finding('medium', 'missing-pkce', `Evento ${request.id} usa Authorization Code sem code_challenge registrado.`, 'Use PKCE, preferencialmente S256, especialmente em clientes públicos e aplicações web.'));
    }

    if (request.codeChallenge && String(request.codeChallengeMethod ?? '').toUpperCase() !== 'S256') {
      findings.push(finding('low', 'pkce-method-review', `Evento ${request.id} usa code_challenge_method=${request.codeChallengeMethod ?? 'não informado'}.`, 'Prefira code_challenge_method=S256 e evite plain salvo compatibilidade excepcional.'));
    }

    if (!request.redirectUri) {
      findings.push(finding('high', 'missing-redirect-uri', `Evento ${request.id} não contém redirect_uri válida.`, 'Use redirect URIs exatas e previamente registradas no provedor de identidade.'));
    } else if (request.redirectUri.startsWith('http://')) {
      findings.push(finding('medium', 'insecure-redirect-uri', `Evento ${request.id} usa redirect_uri HTTP: ${request.redirectUri}`, 'Use HTTPS em redirect URIs, exceto em cenários locais controlados e explicitamente suportados.'));
    }
  }

  for (const response of responses) {
    const relatedRequest = requests.find((request) => {
      const requestState = redactedFingerprint(request.state);
      const responseState = redactedFingerprint(response.state);
      return requestState && responseState && requestState === responseState;
    });

    if (!response.state) {
      findings.push(finding('high', 'callback-missing-state', `Evento ${response.id} não contém state no retorno de autorização.`, 'Rejeite callbacks sem state válido e compare-o com o valor associado à sessão original.'));
    } else if (!relatedRequest) {
      findings.push(finding('high', 'state-mismatch', `Evento ${response.id} não corresponde a nenhum state registrado.`, 'Rejeite callbacks cujo state não corresponda a uma solicitação pendente da mesma sessão.'));
    }

    if (!response.code && !response.error) {
      findings.push(finding('medium', 'callback-missing-code', `Evento ${response.id} não contém code nem erro OAuth.`, 'Registre e trate callbacks incompletos como falha do fluxo.'));
    }

    if (relatedRequest?.redirectUri && response.redirectUri && relatedRequest.redirectUri !== response.redirectUri) {
      findings.push(finding('high', 'redirect-uri-mismatch', `Evento ${response.id} possui redirect_uri diferente da solicitação associada.`, 'Exija correspondência exata da redirect_uri durante todo o fluxo e no token endpoint quando for exigido.'));
    }
  }

  for (const tokenRequest of tokenRequests) {
    if (String(tokenRequest.grantType ?? '').toLowerCase() !== 'authorization_code') {
      findings.push(finding('info', 'non-authorization-code-grant', `Evento ${tokenRequest.id} usa grant_type=${tokenRequest.grantType ?? 'não informado'}.`, 'Confirme que o grant type é compatível com o fluxo e as políticas do cliente.'));
    }

    if (String(tokenRequest.grantType ?? '').toLowerCase() === 'authorization_code' && !tokenRequest.code) {
      findings.push(finding('medium', 'token-request-missing-code', `Evento ${tokenRequest.id} usa authorization_code sem código registrado.`, 'Garanta que o token request use o código recebido no callback, sem registrar o valor em claro.'));
    }

    if (tokenRequest.codeVerifier && !requests.some((request) => request.codeChallenge)) {
      findings.push(finding('medium', 'orphan-code-verifier', `Evento ${tokenRequest.id} possui code_verifier sem code_challenge registrado.`, 'Confirme que o verifier corresponde a uma solicitação inicial com PKCE.'));
    }
  }

  for (const tokenResponse of tokenResponses) {
    if (!tokenResponse.accessToken && !tokenResponse.error) {
      findings.push(finding('medium', 'token-response-missing-access-token', `Evento ${tokenResponse.id} não contém access_token nem erro.`, 'Revise o registro de resposta e o tratamento de falhas do token endpoint.'));
    }

    if (tokenResponse.tokenType && String(tokenResponse.tokenType).toLowerCase() !== 'bearer') {
      findings.push(finding('info', 'unusual-token-type', `Evento ${tokenResponse.id} declara token_type=${tokenResponse.tokenType}.`, 'Confirme o tipo de token e o comportamento esperado pelo resource server.'));
    }

    if (tokenResponse.expiresIn !== null && tokenResponse.expiresIn <= 0) {
      findings.push(finding('medium', 'invalid-expires-in', `Evento ${tokenResponse.id} declara expires_in=${tokenResponse.expiresIn}.`, 'Use uma duração positiva e compatível com a política de sessão e renovação.'));
    }
  }

  for (const event of errors) {
    findings.push(finding('info', 'oauth-error-observed', `Evento ${event.id} registrou erro OAuth: ${event.error ?? 'não especificado'}.`, 'Revise o tratamento do erro e evite exibir detalhes sensíveis ao usuário final.'));
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    flow,
    analysis: {
      events: flow.events.length,
      authorizationRequests: requests.length,
      authorizationResponses: responses.length,
      tokenRequests: tokenRequests.length,
      tokenResponses: tokenResponses.length,
      findings,
      summary: {
        counts,
        highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
      },
      limitation: 'A análise avalia somente eventos locais redigidos. Ela não valida assinaturas OIDC, registros do cliente, redirect URIs no provedor, chaves, tokens ou controles efetivos de produção.',
    },
  };
}

/**
 * O que é: gerador de relatório OAuth/OIDC em Markdown.
 * O que faz: transforma um fluxo e sua análise em linha do tempo e tabela de achados, omitindo valores secretos originais.
 */
export function formatMarkdownReport(result) {
  const flow = result?.flow ?? result;
  const analysis = result?.analysis ?? analyzeOAuthFlow(flow).analysis;
  if (!flow || !Array.isArray(flow.events)) throw new TypeError('Forneça um fluxo ou resultado de analyzeOAuthFlow.');

  const lines = [
    '# OAuth / OIDC Flow Record',
    '',
    `- **Nome:** ${flow.metadata?.name ?? 'Não informado'}`,
    `- **Ambiente:** ${flow.metadata?.environment ?? 'Não informado'}`,
    `- **Eventos:** ${analysis.events}`,
    `- **Maior severidade:** ${analysis.summary.highestSeverity}`,
    `- **Limitação:** ${analysis.limitation}`,
    '',
    '## Linha do tempo',
    '',
    '| Horário | Tipo | Cliente | Redirect URI | Observação |',
    '|---|---|---|---|---|',
  ];

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  for (const event of flow.events) {
    const note = event.error ? `Erro: ${event.error}` : event.notes ?? '—';
    lines.push(`| ${event.timestamp} | ${event.type} | ${clean(event.clientId)} | ${clean(event.redirectUri)} | ${clean(note)} |`);
  }

  lines.push('', '## Achados', '', '| Severidade | Código | Observação | Recomendação |', '|---|---|---|---|');
  if (analysis.findings.length === 0) {
    lines.push('| — | — | Nenhum achado produzido pelas verificações locais. | Revise configurações e registros do provedor conforme necessário. |');
  } else {
    for (const item of analysis.findings) {
      lines.push(`| ${item.severity} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler opções de terminal.
 * O que faz: encontra o valor após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: demonstra o formato de eventos locais aceitos e os comandos para gerar relatórios sem coletar credenciais ou tráfego.
 */
function showHelp() {
  console.log(`\nUso:\n  node oauth-flow-recorder.js --input oauth-events.json [opções]\n\nFormato de entrada:\n  Um array de eventos ou um objeto { metadata, events }. Valores de code, token, secret e verifier são redigidos automaticamente.\n\nExemplo de evento:\n  {\n    "type": "authorization_request",\n    "timestamp": "2026-09-07T20:00:00Z",\n    "clientId": "web-app",\n    "redirectUri": "https://app.exemplo.com/callback",\n    "responseType": "code",\n    "state": "valor-aleatorio",\n    "codeChallenge": "valor-pkce",\n    "codeChallengeMethod": "S256"\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva o relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node oauth-flow-recorder.js --input oauth-events.json --format markdown --output oauth-flow.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const events = Array.isArray(data) ? data : data.events;
      const metadata = Array.isArray(data) ? {} : data.metadata ?? {};
      const flow = recordOAuthFlow(events, metadata);
      const analysis = analyzeOAuthFlow(flow);
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(analysis)
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
