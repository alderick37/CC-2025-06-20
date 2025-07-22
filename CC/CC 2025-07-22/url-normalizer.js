#!/usr/bin/env node

/**
 * Normaliza URLs para comparação, deduplicação e armazenamento.
 * Uso como módulo:
 *   import { normalizeUrl } from './url-normalizer.js';
 *   normalizeUrl('HTTPS://Exemplo.com:443/a/../produto/?utm_source=x#secao');
 *
 * Uso via CLI:
 *   node url-normalizer.js 'HTTPS://Exemplo.com:443/a/../produto/?utm_source=x#secao'
 */

const DEFAULT_TRACKING_PARAMS = [
  /^utm_/i,
  /^fbclid$/i,
  /^gclid$/i,
  /^dclid$/i,
  /^msclkid$/i,
  /^mc_(cid|eid)$/i,
  /^ref$/i,
  /^_ga$/i,
];

function isTrackingParameter(name, extraPatterns = []) {
  return [...DEFAULT_TRACKING_PARAMS, ...extraPatterns].some((pattern) => {
    if (pattern instanceof RegExp) return pattern.test(name);
    return String(pattern).toLowerCase() === name.toLowerCase();
  });
}

function normalizePathname(pathname, { collapseSlashes = true, removeTrailingSlash = true } = {}) {
  let path = pathname || '/';

  if (collapseSlashes) path = path.replace(/\/{2,}/g, '/');

  const parts = [];
  for (const part of path.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      parts.pop();
      continue;
    }
    parts.push(part);
  }

  path = `/${parts.join('/')}`;
  if (removeTrailingSlash && path.length > 1) path = path.replace(/\/+$/, '');
  return path || '/';
}

/**
 * @param {string} input URL absoluta ou domínio/caminho sem protocolo.
 * @param {object} options
 * @param {string} [options.defaultProtocol='https:'] Protocolo aplicado quando não informado.
 * @param {boolean} [options.stripHash=true] Remove fragmentos (#...).
 * @param {boolean} [options.stripTracking=true] Remove UTMs e identificadores comuns de campanha.
 * @param {boolean} [options.sortQuery=true] Ordena parâmetros de query alfabeticamente.
 * @param {boolean} [options.removeTrailingSlash=true] Remove barra final, exceto na raiz.
 * @param {boolean} [options.removeWww=false] Remove o prefixo www.
 * @param {boolean} [options.forceHttps=false] Converte http para https.
 * @param {string[]} [options.removeQueryParams=[]] Parâmetros exatos a remover.
 * @param {(string|RegExp)[]} [options.extraTrackingParams=[]] Padrões adicionais para remover.
 * @returns {string}
 */
export function normalizeUrl(input, options = {}) {
  if (typeof input !== 'string' || !input.trim()) {
    throw new TypeError('Informe uma URL não vazia.');
  }

  const settings = {
    defaultProtocol: 'https:',
    stripHash: true,
    stripTracking: true,
    sortQuery: true,
    removeTrailingSlash: true,
    removeWww: false,
    forceHttps: false,
    removeQueryParams: [],
    extraTrackingParams: [],
    ...options,
  };

  let value = input.trim();
  if (!/^[a-z][a-z\d+.-]*:/i.test(value)) {
    value = `${settings.defaultProtocol}//${value}`;
  }

  const url = new URL(value);
  const protocol = url.protocol.toLowerCase();

  if (!['http:', 'https:'].includes(protocol)) {
    throw new TypeError('Somente URLs HTTP e HTTPS são aceitas.');
  }

  url.protocol = settings.forceHttps ? 'https:' : protocol;
  url.hostname = url.hostname.toLowerCase();

  if (settings.removeWww && url.hostname.startsWith('www.')) {
    url.hostname = url.hostname.slice(4);
  }

  const isDefaultPort =
    (url.protocol === 'http:' && url.port === '80') ||
    (url.protocol === 'https:' && url.port === '443');
  if (isDefaultPort) url.port = '';

  url.pathname = normalizePathname(url.pathname, settings);

  const removeExact = new Set(settings.removeQueryParams.map((name) => String(name).toLowerCase()));
  const query = [];

  for (const [key, value] of url.searchParams.entries()) {
    const shouldRemove =
      removeExact.has(key.toLowerCase()) ||
      (settings.stripTracking && isTrackingParameter(key, settings.extraTrackingParams));

    if (!shouldRemove) query.push([key, value]);
  }

  if (settings.sortQuery) {
    query.sort(([aKey, aValue], [bKey, bValue]) =>
      aKey.localeCompare(bKey) || aValue.localeCompare(bValue)
    );
  }

  url.search = '';
  for (const [key, value] of query) url.searchParams.append(key, value);

  if (settings.stripHash) url.hash = '';

  return url.toString();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = process.argv[2];

  try {
    console.log(normalizeUrl(input));
  } catch (error) {
    console.error(`Erro: ${error.message}`);
    process.exitCode = 1;
  }
}
