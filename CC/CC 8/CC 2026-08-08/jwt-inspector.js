#!/usr/bin/env node

/**
 * JWT Inspector
 *
 * O que é: um utilitário JavaScript para inspecionar JSON Web Tokens (JWTs) localmente, sem validar assinaturas.
 * O que faz: decodifica header, payload e assinatura em Base64URL, valida campos temporais, identifica algoritmos e
 * configurações potencialmente inseguras e gera relatório com dados sensíveis redigidos. Ele não faz requisições, não
 * tenta quebrar ou falsificar tokens, não busca chaves remotas e não altera sistemas externos.
 *
 * Uso como módulo:
 *   import { inspectJwt, formatMarkdownReport } from './jwt-inspector.js';
 *
 *   const report = inspectJwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.assinatura');
 *   console.log(formatMarkdownReport(report));
 *
 * Uso via CLI:
 *   node jwt-inspector.js --token 'HEADER.PAYLOAD.SIGNATURE' --format markdown --output jwt-report.md
 *   node jwt-inspector.js --input token.txt --json
 */

import { readFile, writeFile } from 'node:fs/promises';

const WEAK_OR_UNSAFE_ALGORITHMS = new Set(['none', 'hs256']);
const SENSITIVE_CLAIMS = new Set(['password', 'passwd', 'secret', 'token', 'access_token', 'refresh_token', 'api_key', 'apikey', 'private_key', 'authorization']);

/**
 * O que é: função para decodificar texto Base64URL.
 * O que faz: converte o formato URL-safe em Base64 e decodifica UTF-8 localmente, rejeitando segmentos com caracteres inválidos.
 */
function decodeBase64Url(segment) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]*$/.test(segment)) {
    throw new TypeError('Segmento Base64URL inválido.');
  }

  const padded = segment.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(segment.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}

/**
 * O que é: função para converter um segmento JWT JSON em objeto.
 * O que faz: decodifica Base64URL, interpreta JSON e produz uma mensagem de erro clara quando header ou payload forem inválidos.
 */
function decodeJsonSegment(segment, label) {
  let decoded;
  try {
    decoded = decodeBase64Url(segment);
  } catch (error) {
    throw new TypeError(`${label} não contém Base64URL válido: ${error.message}`);
  }

  try {
    const value = JSON.parse(decoded);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError('deve representar um objeto JSON.');
    }
    return value;
  } catch (error) {
    throw new TypeError(`${label} não contém JSON válido: ${error.message}`);
  }
}

/**
 * O que é: função para converter NumericDate JWT em dados legíveis.
 * O que faz: recebe segundos Unix, valida o valor e devolve ISO 8601 e timestamp; retorna null para claims ausentes ou inválidas.
 */
function parseNumericDate(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  const date = new Date(value * 1000);
  return Number.isNaN(date.getTime()) ? null : { unix: value, iso: date.toISOString() };
}

/**
 * O que é: função para redigir claims potencialmente sensíveis.
 * O que faz: mantém os nomes dos campos e substitui valores de senha, segredo, token e chave por um marcador no relatório.
 */
function redactSensitiveClaims(value, key = '') {
  if (Array.isArray(value)) return value.map((item) => redactSensitiveClaims(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactSensitiveClaims(item, name)]));
  }
  return SENSITIVE_CLAIMS.has(String(key).toLowerCase()) ? '[REDACTED]' : value;
}

/**
 * O que é: função para analisar a validade temporal de um JWT.
 * O que faz: compara exp, nbf e iat com uma data de referência, gerando avisos para expiração, uso prematuro, timestamps
 * inválidos e durações excessivas. A análise não verifica assinatura, revogação, emissor ou audiência.
 */
function analyzeTemporalClaims(payload, now) {
  const findings = [];
  const exp = parseNumericDate(payload.exp);
  const nbf = parseNumericDate(payload.nbf);
  const iat = parseNumericDate(payload.iat);
  const currentUnix = Math.floor(now.getTime() / 1000);

  if (payload.exp === undefined) {
    findings.push({ severity: 'medium', code: 'missing-exp', message: 'Claim exp ausente; o token não declara expiração.' });
  } else if (!exp) {
    findings.push({ severity: 'high', code: 'invalid-exp', message: 'Claim exp existe, mas não é um NumericDate válido.' });
  } else if (exp.unix <= currentUnix) {
    findings.push({ severity: 'high', code: 'expired', message: `Token expirado em ${exp.iso}.` });
  }

  if (payload.nbf !== undefined && !nbf) {
    findings.push({ severity: 'medium', code: 'invalid-nbf', message: 'Claim nbf existe, mas não é um NumericDate válido.' });
  } else if (nbf && nbf.unix > currentUnix) {
    findings.push({ severity: 'medium', code: 'not-active', message: `Token só deve ser aceito após ${nbf.iso}.` });
  }

  if (payload.iat !== undefined && !iat) {
    findings.push({ severity: 'low', code: 'invalid-iat', message: 'Claim iat existe, mas não é um NumericDate válido.' });
  } else if (iat && iat.unix > currentUnix + 300) {
    findings.push({ severity: 'medium', code: 'future-iat', message: `Claim iat está no futuro: ${iat.iso}.` });
  }

  if (iat && exp && exp.unix > iat.unix) {
    const lifetimeSeconds = exp.unix - iat.unix;
    if (lifetimeSeconds > 2_592_000) {
      findings.push({ severity: 'medium', code: 'long-lifetime', message: `Duração declarada de aproximadamente ${Math.round(lifetimeSeconds / 86_400)} dias.` });
    }
  }

  return { exp, nbf, iat, findings };
}

/**
 * O que é: função para analisar escolhas declaradas no header JWT.
 * O que faz: aponta alg ausente, alg none, algoritmos simétricos e campos de chave que merecem revisão, sem tentar verificar
 * assinatura nem determinar se uma configuração é explorável no ambiente real.
 */
function analyzeHeader(header) {
  const findings = [];
  const algorithm = typeof header.alg === 'string' ? header.alg.toLowerCase() : null;

  if (!algorithm) {
    findings.push({ severity: 'high', code: 'missing-alg', message: 'Header JWT não declara o algoritmo alg.' });
  } else if (algorithm === 'none') {
    findings.push({ severity: 'critical', code: 'alg-none', message: 'Header declara alg: none. O servidor deve rejeitar tokens não assinados, salvo protocolo explicitamente projetado para isso.' });
  } else if (WEAK_OR_UNSAFE_ALGORITHMS.has(algorithm)) {
    findings.push({ severity: 'info', code: 'symmetric-algorithm', message: `Header declara ${header.alg}. Algoritmos simétricos exigem proteção rigorosa do segredo e validação explícita de algoritmo no servidor.` });
  }

  if (header.jku || header.x5u) {
    findings.push({ severity: 'medium', code: 'remote-key-reference', message: 'Header inclui referência remota de chave (jku ou x5u); validadores devem aplicar allowlist rígida e validação de origem.' });
  }

  if (header.kid && typeof header.kid !== 'string') {
    findings.push({ severity: 'low', code: 'invalid-kid', message: 'Header kid não é uma string; valide e trate identificadores de chave com segurança.' });
  }

  return { algorithm: header.alg ?? null, tokenType: header.typ ?? null, keyId: header.kid ?? null, findings };
}

/**
 * O que é: função para analisar claims de contexto e boas práticas.
 * O que faz: identifica ausência de iss, aud e sub, além de payload excessivamente grande; a necessidade de cada claim depende
 * do protocolo e da arquitetura de autenticação adotada.
 */
function analyzeContextClaims(payload, payloadLength) {
  const findings = [];

  if (payload.iss === undefined) findings.push({ severity: 'info', code: 'missing-iss', message: 'Claim iss ausente; considere validar o emissor quando houver mais de uma fonte de tokens.' });
  if (payload.aud === undefined) findings.push({ severity: 'info', code: 'missing-aud', message: 'Claim aud ausente; considere validar audiência para reduzir aceitação cruzada de tokens.' });
  if (payload.sub === undefined) findings.push({ severity: 'info', code: 'missing-sub', message: 'Claim sub ausente; avalie se há um identificador de sujeito apropriado.' });
  if (payloadLength > 8192) findings.push({ severity: 'medium', code: 'large-payload', message: `Payload decodificado possui ${payloadLength} bytes; evite incluir dados desnecessários ou sensíveis em JWTs.` });

  return findings;
}

/**
 * O que é: função para gerar resumo por severidade.
 * O que faz: conta achados e identifica o nível mais alto, permitindo priorização rápida de revisões de configuração.
 */
function summarizeFindings(findings) {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(order.map((level) => [level, 0]));
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  return { counts, highestSeverity: [...order].reverse().find((level) => counts[level] > 0) ?? 'info' };
}

/**
 * O que é: inspetor local de JWT.
 * O que faz: decompõe um token compacto de três partes, decodifica header e payload, analisa metadados e boas práticas e
 * devolve dados redigidos. Ele não verifica criptograficamente a assinatura; tokenValidSignature permanece desconhecido.
 *
 * @param {string} token JWT no formato header.payload.signature.
 * @param {object} [options] Opções de inspeção.
 * @param {Date|string} [options.now=new Date()] Data de referência para validar exp, nbf e iat.
 * @returns {object} Relatório de inspeção local.
 */
export function inspectJwt(token, options = {}) {
  if (typeof token !== 'string' || !token.trim()) throw new TypeError('Forneça um JWT não vazio.');

  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new TypeError('JWT compacto deve conter exatamente três segmentos não vazios separados por ponto.');
  }

  const now = new Date(options.now ?? new Date());
  if (Number.isNaN(now.getTime())) throw new TypeError('options.now deve ser uma data válida.');

  const header = decodeJsonSegment(parts[0], 'Header');
  const payload = decodeJsonSegment(parts[1], 'Payload');
  const decodedPayloadText = decodeBase64Url(parts[1]);
  const headerAnalysis = analyzeHeader(header);
  const temporal = analyzeTemporalClaims(payload, now);
  const findings = [
    ...headerAnalysis.findings,
    ...temporal.findings,
    ...analyzeContextClaims(payload, Buffer.byteLength(decodedPayloadText, 'utf8')),
  ];

  return {
    format: 'JWS Compact Serialization',
    segments: {
      headerLength: parts[0].length,
      payloadLength: parts[1].length,
      signatureLength: parts[2].length,
      signaturePresent: parts[2].length > 0,
    },
    tokenValidSignature: 'unknown — assinatura não foi verificada por esta ferramenta',
    inspectedAt: now.toISOString(),
    header: redactSensitiveClaims(header),
    payload: redactSensitiveClaims(payload),
    temporalClaims: { exp: temporal.exp, nbf: temporal.nbf, iat: temporal.iat },
    algorithm: headerAnalysis.algorithm,
    tokenType: headerAnalysis.tokenType,
    keyId: headerAnalysis.keyId,
    findings,
    summary: summarizeFindings(findings),
    limitation: 'A ferramenta apenas decodifica e inspeciona localmente. Não valida assinatura, chave, revogação, issuer, audience, algoritmo aceito pelo servidor ou permissões efetivas.',
  };
}

/**
 * O que é: gerador de relatório Markdown para inspeção JWT.
 * O que faz: apresenta metadados, claims temporais e achados de revisão sem imprimir a assinatura nem valores sensíveis redigidos.
 */
export function formatMarkdownReport(report) {
  if (!report || !report.header || !report.payload || !Array.isArray(report.findings)) {
    throw new TypeError('Forneça um relatório retornado por inspectJwt.');
  }

  const lines = [
    '# JWT Inspection Report',
    '',
    `- **Inspecionado em:** ${report.inspectedAt}`,
    `- **Algoritmo declarado:** ${report.algorithm ?? 'Não informado'}`,
    `- **Tipo declarado:** ${report.tokenType ?? 'Não informado'}`,
    `- **Assinatura:** ${report.tokenValidSignature}`,
    `- **Maior severidade:** ${report.summary.highestSeverity}`,
    `- **Limitação:** ${report.limitation}`,
    '',
    '## Claims temporais',
    '',
    `- exp: ${report.temporalClaims.exp?.iso ?? 'Ausente ou inválido'}`,
    `- nbf: ${report.temporalClaims.nbf?.iso ?? 'Ausente ou inválido'}`,
    `- iat: ${report.temporalClaims.iat?.iso ?? 'Ausente ou inválido'}`,
    '',
    '## Achados',
    '',
  ];

  if (report.findings.length === 0) {
    lines.push('- Nenhum padrão de revisão foi identificado. Isso não valida a segurança do token ou da implementação.');
  } else {
    lines.push('| Severidade | Código | Observação |', '|---|---|---|');
    for (const finding of report.findings) {
      lines.push(`| ${finding.severity} | ${finding.code} | ${finding.message.replace(/\|/g, '\\|')} |`);
    }
  }

  lines.push('', '## Header decodificado', '', '```json', JSON.stringify(report.header, null, 2), '```');
  lines.push('', '## Payload decodificado', '', '```json', JSON.stringify(report.payload, null, 2), '```');

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter argumentos do terminal.
 * O que faz: retorna o valor imediatamente após uma flag, como --token, --input, --format ou --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como inspecionar um token digitado ou armazenado em arquivo local e como exportar JSON ou Markdown.
 */
function showHelp() {
  console.log(`\nUso:\n  node jwt-inspector.js --token 'HEADER.PAYLOAD.SIGNATURE' [opções]\n  node jwt-inspector.js --input token.txt [opções]\n\nOpções:\n  --format FORMATO       json ou markdown. Padrão: json\n  --output ARQUIVO       Salva o relatório em arquivo local\n  --pretty               Formata JSON com indentação\n  --now DATA_ISO         Data de referência para checagem temporal\n\nExemplo:\n  node jwt-inspector.js --input token.txt --format markdown --output jwt-report.md\n\nObservação: o token é somente decodificado. A assinatura não é validada pela ferramenta.\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const rawToken = getCliOption('token');
  const input = getCliOption('input');

  if (process.argv.includes('--help') || (!rawToken && !input)) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const token = rawToken ?? (await readFile(input, 'utf8')).trim();
      const report = inspectJwt(token, { now: getCliOption('now') ?? new Date() });
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
