#!/usr/bin/env node

/**
 * Open Redirect Checker
 *
 * O que é: um utilitário JavaScript para revisar localmente regras de redirecionamento e cadeias HTTP já coletadas.
 * O que faz: avalia valores de destino contra allowlists, esquemas, hosts, caminhos e parâmetros de URL; também analisa
 * evidências de Location previamente registradas para destacar desvios de escopo. Ele não envia requisições, não cria URLs
 * de teste, não segue redirecionamentos e não acessa ou altera sistemas externos.
 *
 * Uso como módulo:
 *   import { checkRedirectTarget, analyzeRedirectEvidence } from './open-redirect-checker.js';
 *
 *   const result = checkRedirectTarget('/dashboard', {
 *     baseUrl: 'https://app.exemplo.com',
 *     allowedHosts: ['app.exemplo.com'],
 *     allowedPathPrefixes: ['/dashboard', '/account']
 *   });
 *
 * Uso via CLI:
 *   node open-redirect-checker.js --config redirect-policy.json --targets redirect-targets.txt --format markdown --output redirect-review.md
 *   node open-redirect-checker.js --config redirect-policy.json --evidence redirect-evidence.json --format json --pretty
 */

import { readFile, writeFile } from 'node:fs/promises';

const DEFAULT_PARAMETER_NAMES = ['next', 'return', 'returnto', 'return_url', 'redirect', 'redirect_uri', 'redirect_url', 'continue', 'continue_url', 'callback', 'url', 'destination'];

/**
 * O que é: função para normalizar nomes de hosts.
 * O que faz: converte hosts para minúsculas e remove pontos externos para comparação consistente com allowlists.
 */
function normalizeHost(value) {
  return String(value ?? '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}

/**
 * O que é: função para normalizar prefixos de caminho.
 * O que faz: garante uma barra inicial e remove a barra final dispensável, preservando a raiz como /.
 */
function normalizePathPrefix(value) {
  let path = String(value ?? '').trim();
  if (!path || path === '/') return '/';
  if (!path.startsWith('/')) path = `/${path}`;
  path = path.replace(/\/{2,}/g, '/');
  return path.length > 1 ? path.replace(/\/+$/, '') : path;
}

/**
 * O que é: função para verificar host exato ou wildcard permitido.
 * O que faz: aceita regras como app.exemplo.com e *.exemplo.com, mas não considera o domínio raiz compatível com wildcard.
 */
function hostMatches(host, rule) {
  const normalizedHost = normalizeHost(host);
  const normalizedRule = normalizeHost(rule);
  if (!normalizedRule) return false;
  if (normalizedRule.startsWith('*.')) return normalizedHost.endsWith(`.${normalizedRule.slice(2)}`);
  return normalizedHost === normalizedRule;
}

/**
 * O que é: função para verificar se um caminho pertence a um prefixo permitido.
 * O que faz: exige correspondência de segmento, para que /account não aceite indevidamente /accounting.
 */
function pathMatches(pathname, prefix) {
  const normalized = normalizePathPrefix(prefix);
  return normalized === '/' || pathname === normalized || pathname.startsWith(`${normalized}/`);
}

/**
 * O que é: função para normalizar a política local de destinos de redirecionamento.
 * O que faz: valida URL base, esquemas, hosts, caminhos e parâmetros observados, sem ler configuração de servidor ou acessar rede.
 */
export function normalizeRedirectPolicy(policy = {}) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new TypeError('policy deve ser um objeto.');

  let baseUrl = null;
  if (policy.baseUrl) {
    try {
      baseUrl = new URL(String(policy.baseUrl));
      if (!['http:', 'https:'].includes(baseUrl.protocol)) throw new TypeError('baseUrl deve usar HTTP(S).');
    } catch (error) {
      throw new TypeError(`baseUrl inválida: ${error.message}`);
    }
  }

  const allowedSchemes = [...new Set((policy.allowedSchemes ?? ['https:']).map((scheme) => {
    const value = String(scheme).trim().toLowerCase();
    return value.endsWith(':') ? value : `${value}:`;
  }))];
  const allowedHosts = [...new Set((policy.allowedHosts ?? (baseUrl ? [baseUrl.hostname] : [])).map(normalizeHost).filter(Boolean))];
  const allowedPathPrefixes = [...new Set((policy.allowedPathPrefixes ?? ['/']).map(normalizePathPrefix))];

  if (!baseUrl && allowedHosts.length === 0) {
    throw new TypeError('Informe baseUrl ou ao menos um host em allowedHosts.');
  }

  return {
    baseUrl: baseUrl?.toString() ?? null,
    allowedSchemes,
    allowedHosts,
    allowedPathPrefixes,
    allowRelativePaths: policy.allowRelativePaths !== false,
    allowQuery: policy.allowQuery !== false,
    allowFragments: Boolean(policy.allowFragments),
    parameterNames: [...new Set((policy.parameterNames ?? DEFAULT_PARAMETER_NAMES).map((name) => String(name).trim().toLowerCase()).filter(Boolean))],
  };
}

/**
 * O que é: função para interpretar uma referência de destino sem acessá-la.
 * O que faz: classifica caminho relativo, URL absoluta, URL protocol-relative e valores inválidos, resolvendo relativos apenas
 * contra a base local declarada na política.
 */
function parseTarget(value, policy) {
  const raw = String(value ?? '').trim();
  if (!raw) return { raw, type: 'empty', url: null, error: 'Destino vazio.' };

  if (raw.startsWith('//')) {
    return { raw, type: 'protocol-relative', url: null, error: 'URLs protocol-relative não são aceitas.' };
  }

  const looksAbsolute = /^[a-z][a-z0-9+.-]*:/i.test(raw);
  if (!looksAbsolute && !raw.startsWith('/')) {
    return { raw, type: 'relative-without-leading-slash', url: null, error: 'Destino deve ser URL absoluta ou caminho iniciado por /.' };
  }

  try {
    const url = looksAbsolute ? new URL(raw) : new URL(raw, policy.baseUrl ?? `https://${policy.allowedHosts[0]}`);
    return { raw, type: looksAbsolute ? 'absolute-url' : 'relative-path', url, error: null };
  } catch {
    return { raw, type: 'invalid', url: null, error: 'Destino não é uma URL ou caminho válido.' };
  }
}

/**
 * O que é: função para criar achados de revisão de redirect de forma padronizada.
 * O que faz: registra severidade, código, mensagem e recomendação para o destino local avaliado.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: verificador local de destino de redirecionamento.
 * O que faz: avalia uma URL ou caminho contra uma política allowlist e informa se seria aceito; não emite Location, não segue
 * URLs e não demonstra se um endpoint real contém open redirect. O resultado apoia revisão de código e testes autorizados.
 *
 * @param {string} target Destino recebido por um fluxo de redirecionamento.
 * @param {object} policy Política local de destinos permitidos.
 * @returns {object} Resultado da validação local.
 */
export function checkRedirectTarget(target, policy) {
  const settings = normalizeRedirectPolicy(policy);
  const parsed = parseTarget(target, settings);
  const findings = [];

  if (!parsed.url) {
    findings.push(finding('high', 'invalid-target', parsed.error, 'Rejeite destinos vazios, ambíguos ou inválidos; aceite somente caminhos relativos seguros ou URLs em allowlist.'));
    return { target: parsed.raw, allowed: false, normalizedTarget: null, findings, policy: settings };
  }

  const url = parsed.url;
  url.hostname = normalizeHost(url.hostname);
  if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) url.port = '';

  if (parsed.type === 'relative-path' && !settings.allowRelativePaths) {
    findings.push(finding('medium', 'relative-path-not-allowed', 'A política não permite caminhos relativos.', 'Defina explicitamente se o fluxo deve aceitar somente URLs absolutas em allowlist.'));
  }

  if (!settings.allowedSchemes.includes(url.protocol)) {
    findings.push(finding('high', 'scheme-not-allowed', `Esquema não permitido: ${url.protocol}`, 'Aceite apenas esquemas explicitamente aprovados, normalmente HTTPS.'));
  }

  const matchingHost = settings.allowedHosts.find((rule) => hostMatches(url.hostname, rule));
  if (!matchingHost) {
    findings.push(finding('high', 'host-not-allowed', `Host fora da allowlist: ${url.hostname}`, 'Valide o host após parsing da URL e compare com allowlist exata; não use correspondência por substring.'));
  }

  const matchingPath = settings.allowedPathPrefixes.find((prefix) => pathMatches(url.pathname, prefix));
  if (!matchingPath) {
    findings.push(finding('medium', 'path-not-allowed', `Caminho fora dos prefixos permitidos: ${url.pathname}`, 'Restrinja destinos a caminhos necessários para o fluxo e normalize a URL antes da comparação.'));
  }

  if (!settings.allowQuery && url.search) {
    findings.push(finding('medium', 'query-not-allowed', 'O destino contém query string, mas a política não a permite.', 'Rejeite ou reconstrua a query usando parâmetros explicitamente necessários.'));
  }

  if (url.hash && !settings.allowFragments) {
    findings.push(finding('low', 'fragment-not-allowed', 'O destino contém fragmento, mas a política não o permite.', 'Remova fragmentos quando não forem necessários e nunca use fragmentos para transportar dados sensíveis.'));
  }

  return {
    target: parsed.raw,
    allowed: findings.length === 0,
    normalizedTarget: url.toString(),
    type: parsed.type,
    matched: { host: matchingHost ?? null, pathPrefix: matchingPath ?? null },
    findings,
    policy: settings,
  };
}

/**
 * O que é: analisador local de evidências de redirecionamento coletadas previamente.
 * O que faz: recebe registros com endpoint, nome de parâmetro e Location observada, avalia o destino contra a política e aponta
 * inconsistências documentais. Ele não cria entradas de teste, não chama endpoints e não segue o Location fornecido.
 */
export function analyzeRedirectEvidence(evidences, policy) {
  if (!Array.isArray(evidences)) throw new TypeError('evidences deve ser um array.');
  const settings = normalizeRedirectPolicy(policy);
  const results = evidences.map((evidence, index) => {
    if (!evidence || typeof evidence !== 'object') throw new TypeError(`evidences[${index}] deve ser um objeto.`);
    const parameter = String(evidence.parameter ?? evidence.parameterName ?? '').trim().toLowerCase() || null;
    const result = checkRedirectTarget(evidence.location ?? evidence.target, settings);
    const findings = [...result.findings];

    if (parameter && !settings.parameterNames.includes(parameter)) {
      findings.push(finding('info', 'unrecognized-redirect-parameter', `O parâmetro ${parameter} não está na lista local de parâmetros esperados.`, 'Confirme se este parâmetro controla redirecionamento e inclua-o na política somente quando necessário.'));
    }

    return {
      evidenceId: evidence.id ?? `evidence-${index + 1}`,
      endpoint: evidence.endpoint ?? null,
      parameter,
      observedStatus: Number.isInteger(evidence.status) ? evidence.status : null,
      observedLocation: evidence.location ?? evidence.target ?? null,
      ...result,
      findings,
    };
  });

  const allFindings = results.flatMap((result) => result.findings);
  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of allFindings) counts[item.severity] += 1;

  return {
    policy: settings,
    results,
    summary: {
      evidences: results.length,
      allowedByPolicy: results.filter((result) => result.allowed).length,
      rejectedByPolicy: results.filter((result) => !result.allowed).length,
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
    },
    limitation: 'A análise compara valores locais com uma política declarada. Um destino fora da política é um ponto de revisão, não prova de open redirect em um endpoint real.',
  };
}

/**
 * O que é: função para criar relatório Markdown de destinos ou evidências analisadas.
 * O que faz: transforma resultados individuais ou em lote em tabelas com decisão, destino normalizado e recomendações de revisão.
 */
export function formatMarkdownReport(report) {
  const results = Array.isArray(report?.results) ? report.results : [report];
  if (!results.every((result) => result && Array.isArray(result.findings))) throw new TypeError('Forneça um resultado de checkRedirectTarget ou analyzeRedirectEvidence.');

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Redirect Target Policy Review',
    '',
    `- **Destinos analisados:** ${results.length}`,
    '- **Escopo:** análise local de política e evidências; a ferramenta não segue redirects ou testa endpoints.',
    '',
    '## Destinos',
    '',
    '| Origem/Endpoint | Parâmetro | Destino observado | Decisão pela política | Destino normalizado |',
    '|---|---|---|---|---|',
  ];

  for (const result of results) {
    lines.push(`| ${clean(result.endpoint)} | ${clean(result.parameter)} | ${clean(result.observedLocation ?? result.target)} | ${result.allowed ? 'Permitido' : 'Rejeitado'} | ${clean(result.normalizedTarget)} |`);
  }

  lines.push('', '## Achados', '', '| Destino | Severidade | Código | Observação | Recomendação |', '|---|---|---|---|---|');
  const rows = results.flatMap((result) => result.findings.map((item) => ({ result, item })));
  if (rows.length === 0) {
    lines.push('| — | — | — | Nenhum achado produzido pela política local. | Mantenha validação server-side e testes de contrato. |');
  } else {
    for (const { result, item } of rows) {
      lines.push(`| ${clean(result.observedLocation ?? result.target)} | ${item.severity} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos da linha de comando.
 * O que faz: retorna o valor logo após flags como --config, --targets, --evidence, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para ler destinos explícitos de um arquivo local de texto.
 * O que faz: separa linhas, remove espaços, ignora linhas vazias e comentários iniciados por #, sem gerar novos destinos.
 */
function parseTargets(text) {
  return String(text).replace(/\r\n?/g, '\n').split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como comparar destinos e evidências já coletadas contra uma política local sem enviar requisições.
 */
function showHelp() {
  console.log(`\nUso:\n  node open-redirect-checker.js --config redirect-policy.json --targets destinos.txt [opções]\n  node open-redirect-checker.js --config redirect-policy.json --evidence redirect-evidence.json [opções]\n\nPolítica exemplo:\n  {\n    "baseUrl": "https://app.exemplo.com",\n    "allowedSchemes": ["https:"],\n    "allowedHosts": ["app.exemplo.com"],\n    "allowedPathPrefixes": ["/dashboard", "/account"],\n    "allowRelativePaths": true,\n    "allowQuery": false\n  }\n\nOpções:\n  --targets ARQUIVO       Arquivo local com um destino por linha\n  --evidence ARQUIVO      Array local de { endpoint, parameter, status, location }\n  --format FORMATO        json ou markdown. Padrão: json\n  --output ARQUIVO        Salva o relatório em arquivo local\n  --pretty                Formata JSON com indentação\n\nExemplo:\n  node open-redirect-checker.js --config redirect-policy.json --targets destinos.txt --format markdown --output redirect-review.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const configFile = getCliOption('config');
  const targetsFile = getCliOption('targets');
  const evidenceFile = getCliOption('evidence');

  if (process.argv.includes('--help') || !configFile || (Boolean(targetsFile) === Boolean(evidenceFile))) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const policy = JSON.parse(await readFile(configFile, 'utf8'));
      const report = targetsFile
        ? {
            policy: normalizeRedirectPolicy(policy),
            results: parseTargets(await readFile(targetsFile, 'utf8')).map((target) => checkRedirectTarget(target, policy)),
            limitation: 'A análise compara destinos locais com uma política declarada; não segue redirects nem testa endpoints.',
          }
        : analyzeRedirectEvidence(JSON.parse(await readFile(evidenceFile, 'utf8')), policy);
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
