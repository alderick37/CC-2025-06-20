#!/usr/bin/env node

/**
 * Scope Checker
 *
 * O que é: um utilitário JavaScript para validar se uma URL pertence a um escopo permitido.
 * O que faz: recebe uma URL e uma lista de regras de escopo, verifica protocolo, host, porta
 * e caminho; retorna uma decisão estruturada de permitido ou bloqueado, sem realizar requisições.
 *
 * Uso como módulo:
 *   import { checkScope, createScopeChecker } from './scope-checker.js';
 *
 *   const result = checkScope('https://api.exemplo.com/v1/users', {
 *     allowedHosts: ['exemplo.com', '*.exemplo.com'],
 *     allowedProtocols: ['https:'],
 *     allowedPathPrefixes: ['/v1'],
 *   });
 *
 * Uso via CLI:
 *   node scope-checker.js 'https://api.exemplo.com/v1/users' \
 *     --hosts 'exemplo.com,*.exemplo.com' --protocols https: --paths /v1
 */

function normalizeProtocol(protocol) {
  const value = String(protocol).trim().toLowerCase();
  return value.endsWith(':') ? value : `${value}:`;
}

function normalizeHost(host) {
  return String(host).trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}

function normalizePathPrefix(prefix) {
  const value = String(prefix).trim();
  if (!value || value === '/') return '/';
  const path = value.startsWith('/') ? value : `/${value}`;
  return path.replace(/\/+$/, '');
}

function parseUrl(input, defaultProtocol = 'https:') {
  if (input instanceof URL) return new URL(input.toString());
  if (typeof input !== 'string' || !input.trim()) {
    throw new TypeError('Informe uma URL não vazia.');
  }

  let value = input.trim();
  if (!/^[a-z][a-z\d+.-]*:/i.test(value)) value = `${defaultProtocol}//${value}`;
  return new URL(value);
}

function hostMatches(host, rule) {
  const normalizedHost = normalizeHost(host);
  const normalizedRule = normalizeHost(rule);

  if (!normalizedRule) return false;
  if (normalizedRule.startsWith('*.')) {
    const baseDomain = normalizedRule.slice(2);
    return normalizedHost.endsWith(`.${baseDomain}`);
  }

  return normalizedHost === normalizedRule;
}

function pathMatches(pathname, prefix) {
  const normalizedPrefix = normalizePathPrefix(prefix);
  if (normalizedPrefix === '/') return true;
  return pathname === normalizedPrefix || pathname.startsWith(`${normalizedPrefix}/`);
}

/**
 * O que é: função de validação de escopo para URLs.
 * O que faz: compara uma URL com regras permitidas e retorna uma decisão detalhada;
 * não faz chamadas HTTP, DNS, redirecionamentos nem qualquer alteração externa.
 *
 * @param {string|URL} input URL a ser avaliada.
 * @param {object} policy Política de escopo.
 * @param {string[]} [policy.allowedHosts=[]] Hosts exatos ou curingas como *.exemplo.com.
 * @param {string[]} [policy.allowedProtocols=['https:']] Protocolos autorizados.
 * @param {number[]} [policy.allowedPorts=[]] Portas autorizadas; vazio aceita portas padrão.
 * @param {string[]} [policy.allowedPathPrefixes=['/']] Prefixos de caminho autorizados.
 * @param {boolean} [policy.allowSubdomains=false] Aceita subdomínios dos hosts exatos.
 * @param {string} [policy.defaultProtocol='https:'] Protocolo para URLs sem esquema.
 * @returns {{allowed: boolean, reasons: string[], url: string, matched: object}}
 */
export function checkScope(input, policy = {}) {
  const settings = {
    allowedHosts: [],
    allowedProtocols: ['https:'],
    allowedPorts: [],
    allowedPathPrefixes: ['/'],
    allowSubdomains: false,
    defaultProtocol: 'https:',
    ...policy,
  };

  const url = parseUrl(input, normalizeProtocol(settings.defaultProtocol));
  const reasons = [];
  const protocol = normalizeProtocol(url.protocol);
  const hostname = normalizeHost(url.hostname);
  const port = url.port ? Number(url.port) : null;

  const protocols = settings.allowedProtocols.map(normalizeProtocol);
  if (!protocols.includes(protocol)) {
    reasons.push(`Protocolo não permitido: ${protocol}`);
  }

  const hostRules = settings.allowedHosts.map(normalizeHost).filter(Boolean);
  let matchedHost = null;

  if (hostRules.length === 0) {
    reasons.push('Nenhum host permitido foi configurado.');
  } else {
    matchedHost = hostRules.find((rule) => hostMatches(hostname, rule));

    if (!matchedHost && settings.allowSubdomains) {
      matchedHost = hostRules.find(
        (rule) => hostname.endsWith(`.${rule}`) && !rule.startsWith('*.')
      );
    }

    if (!matchedHost) reasons.push(`Host fora do escopo: ${hostname}`);
  }

  const ports = settings.allowedPorts.map(Number).filter(Number.isInteger);
  if (ports.length > 0 && !ports.includes(port ?? (protocol === 'https:' ? 443 : 80))) {
    reasons.push(`Porta não permitida: ${port ?? (protocol === 'https:' ? 443 : 80)}`);
  }

  const prefixes = settings.allowedPathPrefixes.map(normalizePathPrefix);
  const matchedPathPrefix = prefixes.find((prefix) => pathMatches(url.pathname, prefix));
  if (!matchedPathPrefix) {
    reasons.push(`Caminho fora do escopo: ${url.pathname}`);
  }

  return {
    allowed: reasons.length === 0,
    reasons,
    url: url.toString(),
    matched: {
      hostRule: matchedHost,
      pathPrefix: matchedPathPrefix ?? null,
      protocol: protocols.includes(protocol) ? protocol : null,
    },
  };
}

/**
 * O que é: fábrica de verificadores de escopo reutilizáveis.
 * O que faz: recebe uma política uma única vez e devolve uma função para validar diversas URLs
 * contra exatamente as mesmas regras.
 */
export function createScopeChecker(policy) {
  return (input) => checkScope(input, policy);
}

function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = process.argv[2];
  const hosts = splitList(getCliOption('hosts'));
  const protocols = splitList(getCliOption('protocols'));
  const paths = splitList(getCliOption('paths'));
  const ports = splitList(getCliOption('ports')).map(Number).filter(Number.isInteger);

  try {
    const result = checkScope(input, {
      allowedHosts: hosts,
      allowedProtocols: protocols.length ? protocols : ['https:'],
      allowedPathPrefixes: paths.length ? paths : ['/'],
      allowedPorts: ports,
      allowSubdomains: process.argv.includes('--allow-subdomains'),
    });

    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.allowed ? 0 : 2;
  } catch (error) {
    console.error(`Erro: ${error.message}`);
    process.exitCode = 1;
  }
}
