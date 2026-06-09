#!/usr/bin/env node

/**
 * Error Disclosure Scanner
 *
 * O que é: um utilitário JavaScript para analisar respostas HTTP já coletadas de ativos autorizados e identificar
 * possíveis exposições de detalhes técnicos em mensagens de erro.
 * O que faz: inspeciona status, headers e corpo de respostas locais em busca de stack traces, caminhos de sistema,
 * mensagens de banco, versões, segredos aparentes e páginas de debug; atribui severidade e gera um relatório. Ele não
 * envia requisições, não gera payloads, não executa exploração e não acessa URLs ou sistemas externos.
 *
 * Uso como módulo:
 *   import { scanErrorDisclosure, scanResponses } from './error-disclosure-scanner.js';
 *
 *   const result = scanErrorDisclosure({
 *     url: 'https://app.exemplo.com/api',
 *     status: 500,
 *     headers: { 'content-type': 'text/html' },
 *     body: 'Traceback (most recent call last): ...',
 *   });
 *
 * Uso via CLI:
 *   node error-disclosure-scanner.js --input responses.json --format markdown --output error-report.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const DETECTION_RULES = [
  {
    id: 'stacktrace-java',
    title: 'Stack trace Java',
    severity: 'high',
    pattern: /(?:java\.lang\.[A-Za-z]+Exception|at\s+[\w.$]+\([\w.]+:\d+\)|Exception in thread "[^"]+")/i,
    recommendation: 'Desative a exibição de stack traces ao cliente e registre detalhes somente em logs protegidos.',
  },
  {
    id: 'stacktrace-dotnet',
    title: 'Stack trace .NET / ASP.NET',
    severity: 'high',
    pattern: /(?:System\.[\w.]+Exception|at\s+[\w.]+\s+in\s+.+?:line\s+\d+|Yellow Screen of Death)/i,
    recommendation: 'Use páginas de erro genéricas em produção e mantenha customErrors ou configuração equivalente habilitada.',
  },
  {
    id: 'stacktrace-python',
    title: 'Traceback Python',
    severity: 'high',
    pattern: /Traceback \(most recent call last\):[\s\S]{0,1000}(?:File ".+", line \d+|[A-Za-z]+Error:)/i,
    recommendation: 'Desative debug em produção e retorne mensagens genéricas, preservando detalhes apenas nos logs internos.',
  },
  {
    id: 'stacktrace-php',
    title: 'Erro detalhado PHP',
    severity: 'high',
    pattern: /(?:Fatal error|Warning|Notice|Parse error):\s+.+?\s+in\s+.+?\s+on line\s+\d+/i,
    recommendation: 'Desative display_errors em produção e registre erros em arquivo ou observabilidade protegida.',
  },
  {
    id: 'stacktrace-node',
    title: 'Stack trace Node.js',
    severity: 'high',
    pattern: /(?:Error:\s+.+\n\s*at\s+.+\(.+?:\d+:\d+\)|node_modules\/.+?\.(?:js|cjs|mjs):\d+:\d+)/i,
    recommendation: 'Implemente middleware de tratamento de erros e não devolva stack traces ou caminhos internos em produção.',
  },
  {
    id: 'database-sql',
    title: 'Mensagem de erro de banco de dados',
    severity: 'high',
    pattern: /(?:SQLSTATE\[[A-Z0-9]+\]|You have an error in your SQL syntax|ORA-\d{5}|PostgreSQL.*ERROR|pg_query\(|SQLite(?:Exception|3::)|Microsoft OLE DB Provider for SQL Server|Unknown column ['`].+?['`])/i,
    recommendation: 'Retorne erros genéricos ao cliente, use consultas parametrizadas e restrinja detalhes de banco aos logs internos.',
  },
  {
    id: 'filesystem-unix',
    title: 'Caminho interno Unix/Linux',
    severity: 'medium',
    pattern: /(?:\/var\/www\/|\/home\/[\w.-]+\/|\/usr\/src\/|\/opt\/[\w.-]+\/|\/srv\/[\w.-]+\/)/i,
    recommendation: 'Evite expor caminhos absolutos de arquivos em respostas de erro públicas.',
  },
  {
    id: 'filesystem-windows',
    title: 'Caminho interno Windows',
    severity: 'medium',
    pattern: /(?:[A-Z]:\\(?:inetpub|xampp|wamp|Users|Program Files|Windows)\\)/i,
    recommendation: 'Evite expor caminhos absolutos de arquivos em respostas de erro públicas.',
  },
  {
    id: 'debug-mode',
    title: 'Página ou modo de debug exposto',
    severity: 'high',
    pattern: /(?:Django (?:DEBUG|technical 500)|Werkzeug Debugger|Laravel Debugbar|Symfony Profiler|Rails application failed to start|Whoops! There was an error)/i,
    recommendation: 'Desative ferramentas e páginas de debug em produção; limite-as a ambientes autenticados e não públicos.',
  },
  {
    id: 'version-disclosure',
    title: 'Versão de tecnologia exposta em erro',
    severity: 'low',
    pattern: /(?:Apache\/\d+\.\d+(?:\.\d+)?|nginx\/\d+\.\d+(?:\.\d+)?|PHP\/\d+\.\d+(?:\.\d+)?|ASP\.NET Version:\s*\d+(?:\.\d+)+)/i,
    recommendation: 'Reduza banners de versão expostos publicamente quando possível; não trate essa medida isolada como controle de segurança.',
  },
  {
    id: 'secret-apparent',
    title: 'Possível segredo ou credencial em resposta',
    severity: 'critical',
    pattern: /(?:api[_-]?key|secret|password|passwd|token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{12,}/i,
    recommendation: 'Revogue e rotacione imediatamente o segredo exposto, remova-o da resposta e implemente gestão segura de segredos.',
  },
  {
    id: 'framework-error-page',
    title: 'Página padrão de erro de framework',
    severity: 'medium',
    pattern: /(?:Whitelabel Error Page|Server Error \(500\)|Application Error|Internal Server Error\s*<\/title>)/i,
    recommendation: 'Personalize páginas de erro para não revelar detalhes de framework ou ambiente e inclua um identificador de suporte.',
  },
];

/**
 * O que é: função para normalizar headers de uma resposta HTTP coletada.
 * O que faz: converte os nomes para minúsculas e os valores para texto, tornando a análise independente da capitalização.
 */
function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return {};
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]));
}

/**
 * O que é: função para gerar um trecho seguro de evidência.
 * O que faz: reduz a evidência ao redor do padrão encontrado, colapsa espaços e limita o tamanho para evitar que relatórios
 * repliquem desnecessariamente conteúdo sensível inteiro.
 */
function excerptAroundMatch(text, matchIndex, matchLength, radius = 110) {
  const start = Math.max(0, matchIndex - radius);
  const end = Math.min(text.length, matchIndex + matchLength + radius);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return `${prefix}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${suffix}`;
}

/**
 * O que é: função para ocultar parcialmente valores parecidos com segredos em uma evidência.
 * O que faz: mascara tokens e valores associados a chaves comuns antes de incluí-los no relatório para reduzir nova exposição.
 */
function redactApparentSecrets(text) {
  return text.replace(
    /\b(api[_-]?key|secret|password|passwd|token)\s*([=:])\s*(['"]?)([A-Za-z0-9_\-]{8,})\3/gi,
    (_, key, operator, quote, value) => `${key}${operator}${quote}${value.slice(0, 4)}…[redigido]${quote}`
  );
}

/**
 * O que é: função para verificar um conjunto de padrões em um campo de resposta.
 * O que faz: registra no máximo uma ocorrência por regra e campo, associando severidade, recomendação e trecho redigido.
 */
function scanText(text, field, rules = DETECTION_RULES) {
  const findings = [];
  const value = String(text ?? '');

  for (const rule of rules) {
    const match = value.match(rule.pattern);
    if (!match || match.index === undefined) continue;

    findings.push({
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      field,
      evidence: redactApparentSecrets(excerptAroundMatch(value, match.index, match[0].length)),
      recommendation: rule.recommendation,
    });
  }

  return findings;
}

/**
 * O que é: função que cria uma pontuação resumida de severidade.
 * O que faz: calcula a maior severidade encontrada e conta resultados por nível para priorização de revisão.
 */
function severitySummary(findings) {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(order.map((severity) => [severity, 0]));
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;

  const highestSeverity = [...order].reverse().find((severity) => counts[severity] > 0) ?? 'info';
  return { highestSeverity, counts };
}

/**
 * O que é: scanner local de divulgação de informações em respostas de erro.
 * O que faz: examina dados já capturados, como URL, status, headers e body, para apontar evidências revisáveis de detalhes
 * técnicos expostos. O resultado é indicativo e requer confirmação humana antes de qualquer registro de vulnerabilidade.
 *
 * @param {object} response Resposta HTTP coletada previamente.
 * @param {string|null} [response.url=null] URL de origem exibida no relatório.
 * @param {number|null} [response.status=null] Código HTTP da resposta.
 * @param {object} [response.headers={}] Headers da resposta.
 * @param {string} [response.body=''] Corpo da resposta.
 * @returns {object} Resultado da análise local.
 */
export function scanErrorDisclosure(response = {}) {
  const headers = normalizeHeaders(response.headers);
  const headerText = Object.entries(headers).map(([name, value]) => `${name}: ${value}`).join('\n');
  const body = String(response.body ?? '');
  const findings = [
    ...scanText(headerText, 'headers'),
    ...scanText(body, 'body'),
  ];

  const uniqueFindings = [];
  const keys = new Set();
  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.field}`;
    if (keys.has(key)) continue;
    keys.add(key);
    uniqueFindings.push(finding);
  }

  return {
    target: response.url ?? null,
    status: Number.isInteger(response.status) ? response.status : null,
    analyzed: {
      headerCount: Object.keys(headers).length,
      bodyCharacters: body.length,
    },
    findings: uniqueFindings,
    summary: severitySummary(uniqueFindings),
    limitation: 'O relatório identifica padrões indicativos em dados fornecidos localmente. Cada achado deve ser confirmado no contexto autorizado antes de ser tratado como vulnerabilidade.',
  };
}

/**
 * O que é: scanner de múltiplas respostas já coletadas.
 * O que faz: analisa uma lista local de respostas, preserva o resultado individual de cada alvo e consolida as contagens.
 */
export function scanResponses(responses) {
  if (!Array.isArray(responses)) throw new TypeError('responses deve ser um array.');

  const results = responses.map((response) => scanErrorDisclosure(response));
  const allFindings = results.flatMap((result) => result.findings);

  return {
    results,
    summary: {
      responsesAnalyzed: results.length,
      responsesWithFindings: results.filter((result) => result.findings.length > 0).length,
      findings: allFindings.length,
      ...severitySummary(allFindings),
    },
  };
}

/**
 * O que é: gerador de relatório em Markdown.
 * O que faz: converte a análise de uma ou várias respostas em uma tabela legível, com evidência redigida e recomendação.
 */
export function formatMarkdownReport(report) {
  const isBatch = Array.isArray(report?.results);
  const results = isBatch ? report.results : [report];

  if (!results.every((result) => result && Array.isArray(result.findings))) {
    throw new TypeError('Forneça um resultado de scanErrorDisclosure ou scanResponses.');
  }

  const lines = [
    '# Error Disclosure Report',
    '',
    `- **Respostas analisadas:** ${results.length}`,
    `- **Achados:** ${results.reduce((total, result) => total + result.findings.length, 0)}`,
    `- **Limitação:** ${isBatch ? 'Achados consolidados de respostas locais previamente coletadas.' : report.limitation}`,
    '',
    '## Achados',
    '',
    '| Alvo | Status | Severidade | Evidência | Recomendação |',
    '|---|---:|---|---|---|',
  ];

  const rows = results.flatMap((result) => result.findings.map((finding) => ({ result, finding })));
  if (rows.length === 0) {
    lines.push('| — | — | — | Nenhum padrão de divulgação encontrado nas evidências fornecidas. | Revisar manualmente quando necessário. |');
  } else {
    for (const { result, finding } of rows) {
      const clean = (value) => String(value).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
      lines.push(`| ${clean(result.target ?? 'Não informado')} | ${result.status ?? '—'} | ${finding.severity} | ${clean(`${finding.title}: ${finding.evidence}`)} | ${clean(finding.recommendation)} |`);
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para leitura de argumentos de terminal.
 * O que faz: retorna o valor após uma flag, como --input responses.json ou --output report.md.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda para a interface de terminal.
 * O que faz: explica o formato local de entrada e como gerar relatórios JSON ou Markdown, sem realizar coleta remota.
 */
function showHelp() {
  console.log(`\nUso:\n  node error-disclosure-scanner.js --input responses.json [opções]\n\nFormato de entrada:\n  Um objeto de resposta ou um array de objetos:\n  {\n    "url": "https://app.exemplo.com/api",\n    "status": 500,\n    "headers": { "content-type": "text/html" },\n    "body": "mensagem de erro coletada previamente"\n  }\n\nOpções:\n  --format FORMATO      json ou markdown. Padrão: json\n  --output ARQUIVO      Salva o relatório localmente\n  --pretty              Formata JSON com indentação\n\nExemplo:\n  node error-disclosure-scanner.js --input responses.json --format markdown --output error-report.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const data = JSON.parse(await readFile(input, 'utf8'));
      const report = Array.isArray(data) ? scanResponses(data) : scanErrorDisclosure(data);
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
