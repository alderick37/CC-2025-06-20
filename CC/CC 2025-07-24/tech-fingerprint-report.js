#!/usr/bin/env node

/**
 * Technology Fingerprint Report
 *
 * O que é: um utilitário JavaScript para gerar um relatório de tecnologias a partir de evidências HTTP e HTML
 * coletadas previamente e fornecidas em arquivos locais.
 * O que faz: analisa headers, cookies, HTML, meta tags, scripts, links e padrões públicos para sugerir tecnologias,
 * frameworks, CDN, servidores web, CMS e bibliotecas. Ele não faz requisições, não escaneia hosts e não tenta explorar
 * vulnerabilidades; todas as conclusões são hipóteses baseadas nas evidências fornecidas e incluem nível de confiança.
 *
 * Uso como módulo:
 *   import { fingerprintTechnology, formatMarkdownReport } from './tech-fingerprint-report.js';
 *
 *   const report = fingerprintTechnology({
 *     url: 'https://app.exemplo.com',
 *     headers: { server: 'nginx', 'x-powered-by': 'Express' },
 *     html: '<meta name="generator" content="WordPress 6.6">',
 *   });
 *   console.log(formatMarkdownReport(report));
 *
 * Uso via CLI:
 *   node tech-fingerprint-report.js --input evidence.json --format markdown --output report.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const RULES = [
  {
    name: 'Cloudflare',
    category: 'CDN / WAF',
    confidence: 'high',
    evidence: [
      { source: 'header', name: 'server', pattern: /cloudflare/i },
      { source: 'header', name: 'cf-ray', pattern: /.+/ },
      { source: 'header', name: 'cf-cache-status', pattern: /.+/ },
      { source: 'cookie', pattern: /^__cf_bm=|^cf_clearance=/i },
    ],
  },
  {
    name: 'nginx',
    category: 'Web server',
    confidence: 'high',
    evidence: [{ source: 'header', name: 'server', pattern: /nginx/i }],
  },
  {
    name: 'Apache HTTP Server',
    category: 'Web server',
    confidence: 'high',
    evidence: [{ source: 'header', name: 'server', pattern: /apache/i }],
  },
  {
    name: 'Microsoft IIS',
    category: 'Web server',
    confidence: 'high',
    evidence: [{ source: 'header', name: 'server', pattern: /microsoft-iis/i }],
  },
  {
    name: 'LiteSpeed',
    category: 'Web server',
    confidence: 'high',
    evidence: [{ source: 'header', name: 'server', pattern: /litespeed/i }],
  },
  {
    name: 'Express',
    category: 'Web framework',
    confidence: 'high',
    evidence: [
      { source: 'header', name: 'x-powered-by', pattern: /express/i },
      { source: 'html', pattern: /express(?:\.js)?/i },
    ],
  },
  {
    name: 'ASP.NET',
    category: 'Web framework',
    confidence: 'high',
    evidence: [
      { source: 'header', name: 'x-powered-by', pattern: /asp\.net/i },
      { source: 'header', name: 'x-aspnet-version', pattern: /.+/ },
      { source: 'cookie', pattern: /^ASP\.NET_SessionId=/i },
      { source: 'html', pattern: /__VIEWSTATE|__EVENTVALIDATION/i },
    ],
  },
  {
    name: 'PHP',
    category: 'Runtime',
    confidence: 'medium',
    evidence: [
      { source: 'header', name: 'x-powered-by', pattern: /php/i },
      { source: 'cookie', pattern: /^PHPSESSID=/i },
    ],
  },
  {
    name: 'WordPress',
    category: 'CMS',
    confidence: 'high',
    evidence: [
      { source: 'meta-generator', pattern: /wordpress/i },
      { source: 'html', pattern: /\/wp-content\/|\/wp-includes\//i },
      { source: 'html', pattern: /wp-json\/|wp-emoji-release/i },
    ],
  },
  {
    name: 'Drupal',
    category: 'CMS',
    confidence: 'high',
    evidence: [
      { source: 'meta-generator', pattern: /drupal/i },
      { source: 'header', name: 'x-generator', pattern: /drupal/i },
      { source: 'html', pattern: /\/sites\/default\/files\//i },
    ],
  },
  {
    name: 'Joomla',
    category: 'CMS',
    confidence: 'high',
    evidence: [
      { source: 'meta-generator', pattern: /joomla/i },
      { source: 'html', pattern: /\/media\/system\/js\/|option=com_/i },
    ],
  },
  {
    name: 'Shopify',
    category: 'E-commerce platform',
    confidence: 'high',
    evidence: [
      { source: 'header', name: 'x-shopify-stage', pattern: /.+/ },
      { source: 'header', name: 'x-shopify-shop-api-call-limit', pattern: /.+/ },
      { source: 'html', pattern: /cdn\.shopify\.com|shopify-section/i },
    ],
  },
  {
    name: 'Next.js',
    category: 'Web framework',
    confidence: 'high',
    evidence: [
      { source: 'html', pattern: /\/_next\//i },
      { source: 'html', pattern: /<script[^>]+id=["']__NEXT_DATA__["']/i },
      { source: 'header', name: 'x-powered-by', pattern: /next\.js/i },
    ],
  },
  {
    name: 'Nuxt',
    category: 'Web framework',
    confidence: 'high',
    evidence: [
      { source: 'html', pattern: /\/_nuxt\//i },
      { source: 'html', pattern: /__NUXT__/i },
    ],
  },
  {
    name: 'React',
    category: 'JavaScript library',
    confidence: 'medium',
    evidence: [
      { source: 'html', pattern: /data-reactroot|data-reactid/i },
      { source: 'html', pattern: /react(?:\.production\.min)?\.js/i },
    ],
  },
  {
    name: 'Vue.js',
    category: 'JavaScript framework',
    confidence: 'medium',
    evidence: [
      { source: 'html', pattern: /data-v-[a-f0-9]+|vue(?:\.global)?(?:\.prod)?\.js/i },
    ],
  },
  {
    name: 'jQuery',
    category: 'JavaScript library',
    confidence: 'medium',
    evidence: [{ source: 'html', pattern: /jquery(?:-[\d.]+)?(?:\.min)?\.js/i }],
  },
  {
    name: 'Bootstrap',
    category: 'Frontend framework',
    confidence: 'medium',
    evidence: [{ source: 'html', pattern: /bootstrap(?:\.min)?\.(?:css|js)|\bcontainer-fluid\b/i }],
  },
  {
    name: 'Google Analytics',
    category: 'Analytics',
    confidence: 'high',
    evidence: [
      { source: 'html', pattern: /googletagmanager\.com\/gtag\/js|google-analytics\.com\/analytics\.js/i },
      { source: 'html', pattern: /\bG-[A-Z0-9]{6,}\b|\bUA-\d+-\d+\b/i },
    ],
  },
  {
    name: 'Google Tag Manager',
    category: 'Tag manager',
    confidence: 'high',
    evidence: [{ source: 'html', pattern: /googletagmanager\.com\/gtm\.js|\bGTM-[A-Z0-9]+\b/i }],
  },
  {
    name: 'Sentry',
    category: 'Error monitoring',
    confidence: 'medium',
    evidence: [{ source: 'html', pattern: /sentry\.io|Sentry\.init/i }],
  },
  {
    name: 'Vercel',
    category: 'Hosting / deployment',
    confidence: 'high',
    evidence: [
      { source: 'header', name: 'x-vercel-id', pattern: /.+/ },
      { source: 'header', name: 'server', pattern: /vercel/i },
      { source: 'html', pattern: /_vercel\/insights/i },
    ],
  },
  {
    name: 'Netlify',
    category: 'Hosting / deployment',
    confidence: 'high',
    evidence: [
      { source: 'header', name: 'server', pattern: /netlify/i },
      { source: 'header', name: 'x-nf-request-id', pattern: /.+/ },
    ],
  },
];

/**
 * O que é: função para padronizar nomes de headers HTTP.
 * O que faz: converte um objeto de headers para chaves em minúsculas e valores textuais, permitindo comparação consistente.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TypeError('headers deve ser um objeto simples.');
  }

  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value)])
  );
}

/**
 * O que é: função para converter Set-Cookie em nomes e valores legíveis.
 * O que faz: aceita string ou array de cookies e retém somente o primeiro trecho de cada cookie, sem analisar atributos sensíveis.
 */
function normalizeCookies(cookies = []) {
  const values = Array.isArray(cookies) ? cookies : [cookies];
  return values.filter(Boolean).map((cookie) => String(cookie).split(';', 1)[0].trim());
}

/**
 * O que é: função para coletar metatags generator do HTML.
 * O que faz: extrai conteúdos de meta name="generator" para aumentar a precisão de identificação de CMS e frameworks.
 */
function extractMetaGenerators(html) {
  const generators = [];
  const expression = /<meta\b[^>]*\bname\s*=\s*(["'])generator\1[^>]*>/gi;

  for (const match of html.matchAll(expression)) {
    const tag = match[0];
    const contentMatch = tag.match(/\bcontent\s*=\s*(["'])(.*?)\1/i);
    if (contentMatch?.[2]) generators.push(contentMatch[2]);
  }

  return generators;
}

/**
 * O que é: função para testar uma evidência individual contra o conjunto local de dados.
 * O que faz: compara padrões com headers, cookies, HTML ou meta generators e devolve uma descrição curta da evidência quando encontrada.
 */
function matchEvidence(evidence, context) {
  if (evidence.source === 'header') {
    const value = context.headers[evidence.name];
    return value && evidence.pattern.test(value) ? `${evidence.name}: ${value}` : null;
  }

  if (evidence.source === 'cookie') {
    const value = context.cookies.find((cookie) => evidence.pattern.test(cookie));
    return value ? `cookie: ${value.split('=', 1)[0]}` : null;
  }

  if (evidence.source === 'html') {
    return evidence.pattern.test(context.html) ? `HTML corresponde a ${evidence.pattern}` : null;
  }

  if (evidence.source === 'meta-generator') {
    const value = context.generators.find((generator) => evidence.pattern.test(generator));
    return value ? `meta generator: ${value}` : null;
  }

  return null;
}

/**
 * O que é: função que ajusta confiança a partir de várias evidências independentes.
 * O que faz: conserva a confiança da regra como referência e eleva hipóteses de média para alta quando há duas ou mais provas.
 */
function confidenceFor(rule, evidenceCount) {
  if (rule.confidence === 'high' || evidenceCount >= 2) return 'high';
  return rule.confidence;
}

/**
 * O que é: mecanismo local de fingerprinting tecnológico baseado em evidências.
 * O que faz: aplica regras transparentes sobre dados HTTP/HTML já coletados, organiza achados por categoria e preserva as
 * evidências que sustentam cada hipótese. Uma correspondência não prova versão, configuração interna ou vulnerabilidade.
 *
 * @param {object} evidence Evidências previamente coletadas.
 * @param {string|null} [evidence.url=null] URL de referência exibida no relatório.
 * @param {object} [evidence.headers={}] Headers HTTP em objeto.
 * @param {string|string[]} [evidence.cookies=[]] Valores Set-Cookie ou nomes de cookies.
 * @param {string} [evidence.html=''] HTML da resposta.
 * @returns {{target: string|null, generatedAt: string, technologies: object[], summary: object}}
 */
export function fingerprintTechnology(evidence = {}) {
  const context = {
    headers: normalizeHeaders(evidence.headers ?? {}),
    cookies: normalizeCookies(evidence.cookies ?? []),
    html: String(evidence.html ?? ''),
  };
  context.generators = extractMetaGenerators(context.html);

  const technologies = [];

  for (const rule of RULES) {
    const matches = rule.evidence.map((item) => matchEvidence(item, context)).filter(Boolean);
    if (matches.length === 0) continue;

    technologies.push({
      name: rule.name,
      category: rule.category,
      confidence: confidenceFor(rule, matches.length),
      evidence: matches,
    });
  }

  technologies.sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  const byCategory = Object.fromEntries(
    [...new Set(technologies.map((item) => item.category))].map((category) => [
      category,
      technologies.filter((item) => item.category === category).length,
    ])
  );

  return {
    target: evidence.url ?? null,
    generatedAt: new Date().toISOString(),
    technologies,
    summary: {
      technologiesDetected: technologies.length,
      highConfidence: technologies.filter((item) => item.confidence === 'high').length,
      mediumConfidence: technologies.filter((item) => item.confidence === 'medium').length,
      byCategory,
      limitations: 'Detecções são hipóteses baseadas apenas nas evidências fornecidas; ausência de evidência não confirma ausência da tecnologia.',
    },
  };
}

/**
 * O que é: gerador de relatório em Markdown.
 * O que faz: transforma o resultado de fingerprintTechnology em um documento legível, com tabela de achados e evidências resumidas.
 */
export function formatMarkdownReport(report) {
  if (!report || !Array.isArray(report.technologies)) {
    throw new TypeError('Forneça um relatório retornado por fingerprintTechnology.');
  }

  const lines = [
    '# Technology Fingerprint Report',
    '',
    `- **Alvo:** ${report.target ?? 'Não informado'}`,
    `- **Gerado em:** ${report.generatedAt}`,
    `- **Tecnologias detectadas:** ${report.summary.technologiesDetected}`,
    `- **Limitação:** ${report.summary.limitations}`,
    '',
    '## Achados',
    '',
    '| Tecnologia | Categoria | Confiança | Evidências |',
    '|---|---|---|---|',
  ];

  if (report.technologies.length === 0) {
    lines.push('| Nenhuma tecnologia identificada | — | — | As evidências fornecidas não acionaram as regras locais. |');
  } else {
    for (const item of report.technologies) {
      const proof = item.evidence.map((value) => value.replace(/\|/g, '\\|')).join('<br>');
      lines.push(`| ${item.name} | ${item.category} | ${item.confidence} | ${proof} |`);
    }
  }

  lines.push('', '## Resumo por categoria', '');
  for (const [category, count] of Object.entries(report.summary.byCategory)) {
    lines.push(`- ${category}: ${count}`);
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para leitura de argumentos do terminal.
 * O que faz: retorna o valor logo após flags como --input, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: mostra o formato de evidência esperado e como gerar saída JSON ou Markdown a partir de arquivos locais.
 */
function showHelp() {
  console.log(`\nUso:\n  node tech-fingerprint-report.js --input evidence.json [opções]\n\nFormato do JSON de evidência:\n  {\n    "url": "https://app.exemplo.com",\n    "headers": { "server": "nginx", "x-powered-by": "Express" },\n    "cookies": ["PHPSESSID=abc"],\n    "html": "<html>...</html>"\n  }\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva o relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node tech-fingerprint-report.js --input evidence.json --format markdown --output report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const evidence = JSON.parse(await readFile(input, 'utf8'));
      const report = fingerprintTechnology(evidence);
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
