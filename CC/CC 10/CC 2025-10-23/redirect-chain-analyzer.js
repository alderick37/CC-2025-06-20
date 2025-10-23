#!/usr/bin/env node

/**
 * Redirect Chain Analyzer
 *
 * O que é: um utilitário JavaScript para analisar localmente cadeias de redirecionamento HTTP previamente coletadas.
 * O que faz: valida sequência de status 3xx, URLs de origem e destino, protocolos, hosts, query strings, fragmentos e
 * parâmetros potencialmente sensíveis; identifica loops, downgrades HTTPS, desvios de domínio e inconsistências. Ele não
 * segue redirecionamentos, não faz requisições, não abre URLs e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { analyzeRedirectChain, formatMarkdownReport } from './redirect-chain-analyzer.js';
 *
 *   const report = analyzeRedirectChain([
 *     { url: 'http://exemplo.com', status: 301, location: 'https://www.exemplo.com/' },
 *     { url: 'https://www.exemplo.com/', status: 200 }
 *   ]);
 *   console.log(formatMarkdownReport(report));
 *
 * Uso via CLI:
 *   node redirect-chain-analyzer.js --input redirects.json --format markdown --output redirects-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const REDIRECT_STATUS_CODES = new Set([300, 301, 302, 303, 307, 308]);
const SENSITIVE_QUERY_KEYS = /(?:^|[_-])(token|access[_-]?token|id[_-]?token|code|state|session|sid|auth|authorization|password|secret|api[_-]?key)(?:$|[_-])/i;

/**
 * O que é: função para normalizar uma URL HTTP(S) localmente.
 * O que faz: valida URLs absolutas, aplica minúsculas ao host, remove porta padrão e devolve URL padronizada sem acessar rede.
 */
function normalizeHttpUrl(value, field) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${field} deve ser uma URL HTTP(S) não vazia.`);
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new TypeError(`${field} não é uma URL absoluta válida: ${value}`);
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new TypeError(`${field} deve usar HTTP ou HTTPS: ${value}`);
  url.hostname = url.hostname.toLowerCase();
  if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) url.port = '';
  return url;
}

/**
 * O que é: função para tornar valores de query string seguros para relatório.
 * O que faz: mascara valores de chaves que aparentam carregar tokens, códigos, sessões ou segredos, preservando somente a chave.
 */
function redactQuery(url) {
  const result = new URL(url.toString());
  for (const [key] of result.searchParams) {
    if (SENSITIVE_QUERY_KEYS.test(key)) result.searchParams.set(key, '[REDACTED]');
  }
  return result.toString();
}

/**
 * O que é: função para construir uma identidade de URL sem fragmento.
 * O que faz: gera uma chave comparável para detectar loops e repetição de destinos, pois fragmentos não são enviados ao servidor.
 */
function urlIdentity(url) {
  const copy = new URL(url.toString());
  copy.hash = '';
  return copy.toString();
}

/**
 * O que é: função para validar e normalizar saltos de uma cadeia de redirecionamento.
 * O que faz: recebe URL de origem, status e Location já coletados e devolve uma estrutura padronizada, sem seguir ou resolver links.
 */
function normalizeHop(hop, index) {
  if (!hop || typeof hop !== 'object' || Array.isArray(hop)) throw new TypeError(`Hop ${index + 1} deve ser um objeto.`);
  const url = normalizeHttpUrl(hop.url, `hop ${index + 1}.url`);
  const status = Number(hop.status);
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new TypeError(`hop ${index + 1}.status deve ser um status HTTP válido.`);

  let location = null;
  if (hop.location !== undefined && hop.location !== null && String(hop.location).trim()) {
    try {
      location = new URL(String(hop.location).trim(), url);
      if (!['http:', 'https:'].includes(location.protocol)) throw new TypeError('Location não usa HTTP(S).');
      location.hostname = location.hostname.toLowerCase();
      if ((location.protocol === 'http:' && location.port === '80') || (location.protocol === 'https:' && location.port === '443')) location.port = '';
    } catch (error) {
      throw new TypeError(`hop ${index + 1}.location inválida: ${error.message}`);
    }
  }

  return {
    index: index + 1,
    url,
    status,
    location,
    method: hop.method ? String(hop.method).toUpperCase() : null,
    source: hop.source ?? null,
  };
}

/**
 * O que é: função para criar achados padronizados de redirecionamento.
 * O que faz: registra severidade, código, hop, mensagem e recomendação para facilitar relatórios e priorização.
 */
function finding(severity, code, hop, message, recommendation) {
  return { severity, code, hop, message, recommendation };
}

/**
 * O que é: analisador local de uma cadeia HTTP de redirecionamentos.
 * O que faz: revisa saltos já registrados, verifica coerência entre hops, segurança de protocolo, mudanças de host, loops,
 * parâmetros sensíveis e uso de fragmentos. O relatório é documental e não confirma comportamento atual do servidor.
 *
 * @param {object[]} chain Lista ordenada de hops coletados previamente.
 * @param {object} [options] Regras de análise.
 * @param {string[]} [options.allowedHosts=[]] Hosts considerados permitidos; vazio apenas registra mudanças de host.
 * @param {boolean} [options.requireHttps=false] Sinaliza URLs HTTP em qualquer ponto da cadeia.
 * @param {number} [options.maxRecommendedHops=3] Quantidade recomendada máxima de redirecionamentos.
 * @returns {object} Relatório estruturado de análise.
 */
export function analyzeRedirectChain(chain, options = {}) {
  if (!Array.isArray(chain) || chain.length === 0) throw new TypeError('chain deve ser um array não vazio de hops.');

  const settings = { allowedHosts: [], requireHttps: false, maxRecommendedHops: 3, ...options };
  const allowedHosts = new Set(settings.allowedHosts.map((host) => String(host).toLowerCase().trim()).filter(Boolean));
  const hops = chain.map(normalizeHop);
  const findings = [];
  const identities = new Map();

  if (hops.length - 1 > settings.maxRecommendedHops) {
    findings.push(finding('low', 'long-chain', null, `A cadeia possui ${hops.length - 1} redirecionamento(s), acima do recomendado (${settings.maxRecommendedHops}).`, 'Reduza saltos intermediários para melhorar desempenho, rastreabilidade e consistência.'));
  }

  for (const hop of hops) {
    const identity = urlIdentity(hop.url);
    if (identities.has(identity)) {
      findings.push(finding('high', 'redirect-loop', hop.index, `A URL do hop ${hop.index} repete o hop ${identities.get(identity)}.`, 'Corrija regras de redirecionamento concorrentes para impedir loops.'));
    } else {
      identities.set(identity, hop.index);
    }

    if (settings.requireHttps && hop.url.protocol !== 'https:') {
      findings.push(finding('medium', 'http-when-https-required', hop.index, `O hop usa HTTP: ${redactQuery(hop.url)}`, 'Redirecione para HTTPS no primeiro ponto possível e aplique HSTS quando apropriado.'));
    }

    if (hop.url.hash) {
      findings.push(finding('info', 'fragment-present', hop.index, `A URL contém fragmento: ${hop.url.hash}`, 'Não use fragmentos para transportar segredos; eles não são enviados ao servidor, mas podem aparecer no navegador, histórico ou scripts.'));
    }

    for (const [key] of hop.url.searchParams) {
      if (SENSITIVE_QUERY_KEYS.test(key)) {
        findings.push(finding('medium', 'sensitive-query-parameter', hop.index, `A URL contém parâmetro potencialmente sensível: ${key}.`, 'Evite transportar tokens, códigos, senhas ou segredos em query strings; redija logs e use mecanismos de transporte apropriados.'));
      }
    }

    const isRedirect = REDIRECT_STATUS_CODES.has(hop.status);
    if (isRedirect && !hop.location) {
      findings.push(finding('high', 'redirect-without-location', hop.index, `Status ${hop.status} indica redirecionamento, mas Location está ausente.`, 'Inclua um header Location válido ou use um status de resposta que represente o resultado real.'));
    }
    if (!isRedirect && hop.location) {
      findings.push(finding('low', 'location-on-non-redirect', hop.index, `Hop possui Location, mas status ${hop.status} não é de redirecionamento.`, 'Confirme se o uso de Location é intencional e documente o comportamento para clientes.'));
    }
  }

  for (let index = 0; index < hops.length - 1; index += 1) {
    const current = hops[index];
    const next = hops[index + 1];

    if (!current.location) continue;
    const expected = urlIdentity(current.location);
    const actual = urlIdentity(next.url);
    if (expected !== actual) {
      findings.push(finding('medium', 'chain-discontinuity', current.index, `Location do hop ${current.index} não corresponde à URL registrada no hop seguinte.`, 'Verifique se a coleta preservou todos os saltos ou se houve reescrita por proxy, cache ou cliente.'));
    }

    if (current.url.protocol === 'https:' && current.location.protocol === 'http:') {
      findings.push(finding('high', 'https-downgrade', current.index, `Redirecionamento reduz HTTPS para HTTP: ${redactQuery(current.url)} → ${redactQuery(current.location)}`, 'Evite downgrade de protocolo; mantenha HTTPS em toda a cadeia.'));
    }

    if (current.url.hostname !== current.location.hostname) {
      const severity = allowedHosts.size > 0 && !allowedHosts.has(current.location.hostname) ? 'high' : 'info';
      findings.push(finding(severity, 'host-change', current.index, `O redirecionamento muda de host: ${current.url.hostname} → ${current.location.hostname}.`, allowedHosts.size > 0 ? 'Mantenha uma allowlist explícita de destinos confiáveis e valide redirecionamentos controlados por usuário.' : 'Confirme se a mudança de domínio é esperada e documentada.'));
    }

    if (allowedHosts.size > 0 && !allowedHosts.has(current.location.hostname)) {
      findings.push(finding('high', 'destination-outside-allowlist', current.index, `Destino ${current.location.hostname} não pertence à allowlist declarada.`, 'Restrinja destinos de redirect a hosts confiáveis e valide URLs no servidor antes de emitir Location.'));
    }
  }

  const finalHop = hops.at(-1);
  if (REDIRECT_STATUS_CODES.has(finalHop.status)) {
    findings.push(finding('medium', 'chain-ends-in-redirect', finalHop.index, `A cadeia termina em status ${finalHop.status}.`, 'Colete o próximo salto ou confirme se a resposta é intencionalmente intermediária.'));
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const item of findings) counts[item.severity] += 1;

  return {
    chain: hops.map((hop) => ({
      index: hop.index,
      url: redactQuery(hop.url),
      status: hop.status,
      location: hop.location ? redactQuery(hop.location) : null,
      method: hop.method,
      source: hop.source,
    })),
    summary: {
      hops: hops.length,
      redirects: hops.filter((hop) => REDIRECT_STATUS_CODES.has(hop.status)).length,
      finalStatus: finalHop.status,
      finalUrl: redactQuery(finalHop.url),
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
    },
    findings,
    limitation: 'A análise usa somente uma cadeia previamente coletada. Ela não segue URLs, não verifica configuração atual, não confirma cache, autenticação, allowlists do servidor ou explorabilidade de redirecionamentos.',
  };
}

/**
 * O que é: gerador de relatório Markdown para cadeias de redirecionamento.
 * O que faz: converte os hops e achados em tabelas legíveis, mantendo valores sensíveis de query redigidos.
 */
export function formatMarkdownReport(report) {
  if (!report || !Array.isArray(report.chain) || !Array.isArray(report.findings)) {
    throw new TypeError('Forneça um relatório retornado por analyzeRedirectChain.');
  }

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# Redirect Chain Analysis Report',
    '',
    `- **Hops registrados:** ${report.summary.hops}`,
    `- **Redirecionamentos:** ${report.summary.redirects}`,
    `- **Status final:** ${report.summary.finalStatus}`,
    `- **URL final:** ${report.summary.finalUrl}`,
    `- **Maior severidade:** ${report.summary.highestSeverity}`,
    `- **Limitação:** ${report.limitation}`,
    '',
    '## Cadeia observada',
    '',
    '| Hop | Status | URL | Location |',
    '|---:|---:|---|---|',
  ];

  for (const hop of report.chain) lines.push(`| ${hop.index} | ${hop.status} | ${clean(hop.url)} | ${clean(hop.location)} |`);

  lines.push('', '## Achados', '', '| Severidade | Hop | Código | Observação | Recomendação |', '|---|---:|---|---|---|');
  if (report.findings.length === 0) {
    lines.push('| — | — | — | Nenhum achado foi produzido pelas regras locais. | Revise o comportamento e requisitos do fluxo conforme necessário. |');
  } else {
    for (const item of report.findings) {
      lines.push(`| ${item.severity} | ${item.hop ?? '—'} | ${item.code} | ${clean(item.message)} | ${clean(item.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para extrair valores de flags do terminal.
 * O que faz: obtém o argumento após opções como --input, --allowed-hosts, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para converter uma lista de hosts separados por vírgula.
 * O que faz: remove espaços e entradas vazias para montar uma allowlist local de destinos de redirecionamento.
 */
function splitHosts(value) {
  return value ? value.split(',').map((host) => host.trim()).filter(Boolean) : [];
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: descreve o formato de cadeia coletada e como gerar relatórios locais sem seguir redirecionamentos pela rede.
 */
function showHelp() {
  console.log(`\nUso:\n  node redirect-chain-analyzer.js --input redirects.json [opções]\n\nFormato de entrada:\n  [\n    { "url": "http://exemplo.com", "status": 301, "location": "https://www.exemplo.com/" },\n    { "url": "https://www.exemplo.com/", "status": 200 }\n  ]\n\nOpções:\n  --allowed-hosts LISTA    Hosts permitidos separados por vírgula\n  --require-https          Sinaliza qualquer hop HTTP\n  --max-hops N             Máximo recomendado de redirects. Padrão: 3\n  --format FORMATO         json ou markdown. Padrão: json\n  --output ARQUIVO         Salva o relatório em arquivo local\n  --pretty                 Formata JSON com indentação\n\nExemplo:\n  node redirect-chain-analyzer.js --input redirects.json --allowed-hosts 'exemplo.com,www.exemplo.com' --require-https --format markdown --output redirects-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const chain = JSON.parse(await readFile(input, 'utf8'));
      const report = analyzeRedirectChain(chain, {
        allowedHosts: splitHosts(getCliOption('allowed-hosts')),
        requireHttps: process.argv.includes('--require-https'),
        maxRecommendedHops: Number(getCliOption('max-hops') ?? 3),
      });
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
