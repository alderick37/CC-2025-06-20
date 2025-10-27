#!/usr/bin/env node

/**
 * Robots & Sitemap Parser
 *
 * O que é: um utilitário JavaScript para interpretar conteúdos locais de robots.txt e sitemap XML.
 * O que faz: extrai regras por user-agent, diretivas Allow/Disallow, Crawl-delay e referências a sitemaps;
 * também lê sitemaps XML comuns e sitemap indexes para listar URLs, datas de modificação e prioridades.
 * Ele não faz requisições de rede: processa somente texto fornecido diretamente ou arquivos locais autorizados.
 *
 * Uso como módulo:
 *   import { parseRobotsTxt, parseSitemapXml } from './robots-sitemap-parser.js';
 *
 *   const robots = parseRobotsTxt('User-agent: *\nDisallow: /admin\nSitemap: https://exemplo.com/sitemap.xml');
 *   const sitemap = parseSitemapXml('<urlset>...</urlset>');
 *
 * Uso via CLI:
 *   node robots-sitemap-parser.js --robots robots.txt --json
 *   node robots-sitemap-parser.js --sitemap sitemap.xml --json
 *   node robots-sitemap-parser.js --robots robots.txt --sitemap sitemap.xml --json
 */

import { readFile } from 'node:fs/promises';

/**
 * O que é: função para remover comentários de uma linha de robots.txt.
 * O que faz: elimina o trecho iniciado por # e remove espaços extras, preservando apenas a diretiva relevante.
 */
function stripRobotsComment(line) {
  return line.split('#', 1)[0].trim();
}

/**
 * O que é: função para criar um grupo de regras de robots.txt.
 * O que faz: inicializa uma estrutura previsível para armazenar user-agents, permissões, bloqueios e crawl-delay.
 */
function createRobotsGroup() {
  return {
    userAgents: [],
    allow: [],
    disallow: [],
    crawlDelay: null,
  };
}

/**
 * O que é: parser local de robots.txt.
 * O que faz: interpreta grupos de User-agent e diretivas Allow, Disallow, Crawl-delay e Sitemap; devolve uma
 * representação estruturada sem buscar URLs nem presumir autorização de crawling ou testes externos.
 *
 * @param {string} text Conteúdo do robots.txt.
 * @returns {{groups: object[], sitemaps: string[], warnings: string[]}}
 */
export function parseRobotsTxt(text) {
  if (typeof text !== 'string') throw new TypeError('robots.txt deve ser um texto.');

  const groups = [];
  const sitemaps = [];
  const warnings = [];
  let currentGroup = null;
  let lastDirectiveWasUserAgent = false;

  for (const [index, rawLine] of text.replace(/\r\n?/g, '\n').split('\n').entries()) {
    const line = stripRobotsComment(rawLine);
    if (!line) {
      lastDirectiveWasUserAgent = false;
      continue;
    }

    const separator = line.indexOf(':');
    if (separator < 1) {
      warnings.push(`Linha ${index + 1}: diretiva inválida ignorada.`);
      lastDirectiveWasUserAgent = false;
      continue;
    }

    const field = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();

    if (field === 'sitemap') {
      if (value) sitemaps.push(value);
      else warnings.push(`Linha ${index + 1}: Sitemap sem URL.`);
      lastDirectiveWasUserAgent = false;
      continue;
    }

    if (field === 'user-agent') {
      if (!value) {
        warnings.push(`Linha ${index + 1}: User-agent vazio.`);
        lastDirectiveWasUserAgent = false;
        continue;
      }

      if (!currentGroup || !lastDirectiveWasUserAgent) {
        currentGroup = createRobotsGroup();
        groups.push(currentGroup);
      }

      currentGroup.userAgents.push(value.toLowerCase());
      lastDirectiveWasUserAgent = true;
      continue;
    }

    lastDirectiveWasUserAgent = false;
    if (!currentGroup) {
      warnings.push(`Linha ${index + 1}: ${field} fora de um grupo User-agent.`);
      continue;
    }

    if (field === 'allow') {
      currentGroup.allow.push(value || '/');
    } else if (field === 'disallow') {
      if (value) currentGroup.disallow.push(value);
    } else if (field === 'crawl-delay') {
      const delay = Number(value);
      if (Number.isFinite(delay) && delay >= 0) currentGroup.crawlDelay = delay;
      else warnings.push(`Linha ${index + 1}: Crawl-delay inválido.`);
    }
  }

  return {
    groups,
    sitemaps: [...new Set(sitemaps)],
    warnings,
  };
}

/**
 * O que é: função de decodificação básica de entidades XML.
 * O que faz: converte entidades comuns, como &amp; e &lt;, para seus caracteres equivalentes antes de devolver valores.
 */
function decodeXmlEntities(value) {
  return value
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, '&');
}

/**
 * O que é: função auxiliar para retirar tags XML de um bloco.
 * O que faz: remove marcações e espaços redundantes para obter conteúdo textual de campos simples de sitemap.
 */
function stripXmlTags(value) {
  return decodeXmlEntities(value.replace(/<[^>]*>/g, '').trim());
}

/**
 * O que é: função para extrair o conteúdo de uma tag XML simples.
 * O que faz: encontra a primeira ocorrência de uma tag dentro de um bloco e devolve seu texto normalizado ou null.
 */
function xmlTagValue(block, tagName) {
  const expression = new RegExp(`<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tagName}>`, 'i');
  const match = block.match(expression);
  return match ? stripXmlTags(match[1]) : null;
}

/**
 * O que é: parser local e tolerante para sitemaps XML.
 * O que faz: reconhece documentos urlset e sitemapindex, extrai URLs e metadados usuais; não baixa sitemaps filhos,
 * não visita as URLs listadas e não interpreta XML como código.
 *
 * @param {string} xml Conteúdo XML do sitemap.
 * @returns {{type: 'urlset'|'sitemapindex'|'unknown', entries: object[], warnings: string[]}}
 */
export function parseSitemapXml(xml) {
  if (typeof xml !== 'string') throw new TypeError('Sitemap deve ser um texto XML.');

  const content = xml.replace(/^\uFEFF/, '').trim();
  const warnings = [];
  const rootMatch = content.match(/<\s*(urlset|sitemapindex)(?:\s[^>]*)?>/i);

  if (!rootMatch) {
    return {
      type: 'unknown',
      entries: [],
      warnings: ['Não foi encontrado um elemento raiz urlset ou sitemapindex.'],
    };
  }

  const root = rootMatch[1].toLowerCase();
  const isUrlset = root === 'urlset';
  const elementName = isUrlset ? 'url' : 'sitemap';
  const expression = new RegExp(`<${elementName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${elementName}>`, 'gi');
  const entries = [];

  for (const match of content.matchAll(expression)) {
    const block = match[1];
    const loc = xmlTagValue(block, 'loc');

    if (!loc) {
      warnings.push(`Elemento <${elementName}> sem <loc> foi ignorado.`);
      continue;
    }

    try {
      const parsed = new URL(loc);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        warnings.push(`URL ignorada por protocolo não HTTP(S): ${loc}`);
        continue;
      }
    } catch {
      warnings.push(`URL inválida ignorada: ${loc}`);
      continue;
    }

    if (isUrlset) {
      entries.push({
        loc,
        lastmod: xmlTagValue(block, 'lastmod'),
        changefreq: xmlTagValue(block, 'changefreq'),
        priority: xmlTagValue(block, 'priority'),
      });
    } else {
      entries.push({
        loc,
        lastmod: xmlTagValue(block, 'lastmod'),
      });
    }
  }

  return {
    type: isUrlset ? 'urlset' : 'sitemapindex',
    entries,
    warnings,
  };
}

/**
 * O que é: função para avaliar uma regra simples de robots.txt contra um caminho.
 * O que faz: transforma curingas * e o marcador final $ em uma expressão regular de correspondência de caminho.
 */
function robotsRuleMatches(pathname, rule) {
  const escaped = rule.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  const pattern = escaped.endsWith('$') ? escaped : `${escaped}.*`;
  return new RegExp(`^${pattern}`).test(pathname);
}

/**
 * O que é: verificador local de regras de robots.txt para um user-agent.
 * O que faz: avalia Allow e Disallow do grupo mais específico aplicável, priorizando a regra de maior correspondência;
 * retorna uma orientação de rastreamento, mas não substitui autorização formal para qualquer atividade sobre o site.
 */
export function canCrawlPath(robots, pathname, userAgent = '*') {
  if (!robots || !Array.isArray(robots.groups)) {
    throw new TypeError('Forneça o resultado de parseRobotsTxt.');
  }

  const agent = String(userAgent).toLowerCase();
  const normalizedPath = pathname.startsWith('/') ? pathname : `/${pathname}`;
  const applicable = robots.groups.filter((group) =>
    group.userAgents.some((candidate) => candidate === '*' || agent.includes(candidate))
  );

  if (applicable.length === 0) {
    return { allowed: true, matchedRule: null, reason: 'Nenhum grupo aplicável encontrado.' };
  }

  const bestAgentLength = Math.max(
    ...applicable.flatMap((group) => group.userAgents
      .filter((candidate) => candidate === '*' || agent.includes(candidate))
      .map((candidate) => candidate === '*' ? 0 : candidate.length))
  );

  const selectedGroups = applicable.filter((group) => group.userAgents.some((candidate) =>
    (candidate === '*' ? 0 : candidate.length) === bestAgentLength &&
    (candidate === '*' || agent.includes(candidate))
  ));

  const rules = selectedGroups.flatMap((group) => [
    ...group.allow.map((path) => ({ type: 'allow', path })),
    ...group.disallow.map((path) => ({ type: 'disallow', path })),
  ]).filter((rule) => robotsRuleMatches(normalizedPath, rule.path));

  if (rules.length === 0) {
    return { allowed: true, matchedRule: null, reason: 'Nenhuma regra de caminho correspondente.' };
  }

  rules.sort((a, b) => b.path.length - a.path.length || (a.type === 'allow' ? -1 : 1));
  const matchedRule = rules[0];

  return {
    allowed: matchedRule.type === 'allow',
    matchedRule,
    reason: matchedRule.type === 'allow' ? 'Permitido por uma regra Allow.' : 'Bloqueado por uma regra Disallow.',
  };
}

/**
 * O que é: função auxiliar para leitura de opções do terminal.
 * O que faz: encontra o valor logo após uma flag, como --robots arquivo.txt, sem usar bibliotecas externas.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: mostra comandos para interpretar arquivos locais de robots.txt e sitemap XML ou testar um caminho localmente.
 */
function showHelp() {
  console.log(`\nUso:\n  node robots-sitemap-parser.js --robots robots.txt [--path /admin --user-agent meu-bot] [--json]\n  node robots-sitemap-parser.js --sitemap sitemap.xml [--json]\n  node robots-sitemap-parser.js --robots robots.txt --sitemap sitemap.xml --json\n\nOpções:\n  --robots ARQUIVO       Caminho para um robots.txt local\n  --sitemap ARQUIVO      Caminho para um sitemap XML local\n  --path CAMINHO         Avalia um caminho usando as regras de robots.txt\n  --user-agent NOME      User-agent a considerar com --path. Padrão: *\n  --json                 Imprime o resultado completo em JSON\n\nExemplo:\n  node robots-sitemap-parser.js --robots robots.txt --path /admin --user-agent MeuCrawler --json\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const robotsFile = getCliOption('robots');
  const sitemapFile = getCliOption('sitemap');

  if (process.argv.includes('--help') || (!robotsFile && !sitemapFile)) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const output = {};

      if (robotsFile) {
        output.robots = parseRobotsTxt(await readFile(robotsFile, 'utf8'));
        const path = getCliOption('path');
        if (path) output.crawlCheck = canCrawlPath(output.robots, path, getCliOption('user-agent') ?? '*');
      }

      if (sitemapFile) {
        output.sitemap = parseSitemapXml(await readFile(sitemapFile, 'utf8'));
      }

      if (process.argv.includes('--json')) {
        console.log(JSON.stringify(output, null, 2));
      } else {
        if (output.robots) {
          console.log(`robots.txt: ${output.robots.groups.length} grupo(s), ${output.robots.sitemaps.length} sitemap(s).`);
          if (output.crawlCheck) {
            console.log(`Caminho: ${output.crawlCheck.allowed ? 'permitido' : 'bloqueado'} — ${output.crawlCheck.reason}`);
          }
        }
        if (output.sitemap) {
          console.log(`sitemap: tipo ${output.sitemap.type}, ${output.sitemap.entries.length} entrada(s).`);
        }
      }
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
