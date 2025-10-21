#!/usr/bin/env node

/**
 * Redaction Tool
 *
 * O que é: um utilitário JavaScript para detectar e redigir dados potencialmente sensíveis em textos e documentos JSON locais.
 * O que faz: identifica e mascara e-mails, telefones, CPF, CNPJ, cartões, tokens, chaves, senhas, cookies, URLs com query
 * sensível e campos JSON configuráveis; gera contagens e relatório de alterações. Ele não envia dados, não acessa rede, não
 * armazena os valores originais no relatório e não modifica sistemas externos.
 *
 * Uso como módulo:
 *   import { redactText, redactJson, formatMarkdownReport } from './redaction-tool.js';
 *
 *   const result = redactText('Contato: ana@exemplo.com; token=segredo-123');
 *   console.log(result.redacted);
 *
 * Uso via CLI:
 *   node redaction-tool.js --input dados.txt --output dados-redigidos.txt --report redaction-report.md
 *   node redaction-tool.js --input evidence.json --json --output evidence-redigida.json
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const DEFAULT_SENSITIVE_FIELD_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|session|sid|csrf|xsrf|email|phone|telefone|celular|cpf|cnpj|credit[_-]?card|card[_-]?number|cvv|ssn|documento|address|endereco)/i;

const TEXT_RULES = [
  { name: 'email', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { name: 'cpf', pattern: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g },
  { name: 'cnpj', pattern: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g },
  { name: 'credit-card', pattern: /\b(?:\d[ -]*?){13,19}\b/g },
  { name: 'phone', pattern: /(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,3}\)?[\s.-]?)?9?\d{4}[\s.-]?\d{4}(?!\w)/g },
  { name: 'bearer-token', pattern: /\bBearer\s+[A-Za-z0-9._~+\/-]{12,}\b/gi },
  { name: 'key-value-secret', pattern: /\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?token|refresh[_-]?token|authorization)\s*([=:])\s*(["']?)([^\s"'&;,]{8,})\2/gi },
  { name: 'cookie-value', pattern: /\b(?:session(?:id)?|sid|auth(?:token)?|jwt|csrf(?:token)?|xsrf(?:token)?)=([^;\s]{8,})/gi },
];

/**
 * O que é: função para criar impressão curta de um valor original.
 * O que faz: calcula SHA-256 truncado para permitir auditoria de duplicatas sem registrar conteúdo sensível em claro.
 */
function fingerprint(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 12);
}

/**
 * O que é: função para construir um marcador de redação seguro.
 * O que faz: substitui conteúdo potencialmente sensível por tipo, tamanho e hash curto, sem revelar o valor original.
 */
function marker(type, value) {
  const text = String(value ?? '');
  return `[REDACTED:${type} length=${text.length} sha256=${fingerprint(text)}]`;
}

/**
 * O que é: função para normalizar padrões extras definidos pelo usuário.
 * O que faz: aceita RegExp ou textos de expressão regular e cria padrões globais para uso somente no processamento local.
 */
function normalizePatterns(patterns = []) {
  if (!Array.isArray(patterns)) throw new TypeError('patterns deve ser um array.');
  return patterns.map((item) => {
    if (item instanceof RegExp) return new RegExp(item.source, item.flags.includes('g') ? item.flags : `${item.flags}g`);
    return new RegExp(String(item), 'g');
  });
}

/**
 * O que é: função para verificar validade matemática básica de CPF.
 * O que faz: calcula dígitos verificadores para reduzir falsos positivos ao redigir sequências numéricas semelhantes a CPF.
 */
function isValidCpf(value) {
  const digits = String(value).replace(/\D/g, '');
  if (!/^\d{11}$/.test(digits) || /^(\d)\1+$/.test(digits)) return false;
  const calculate = (length) => {
    const sum = digits.slice(0, length).split('').reduce((total, digit, index) => total + Number(digit) * (length + 1 - index), 0);
    const remainder = (sum * 10) % 11;
    return remainder === 10 ? 0 : remainder;
  };
  return calculate(9) === Number(digits[9]) && calculate(10) === Number(digits[10]);
}

/**
 * O que é: função para verificar validade matemática básica de CNPJ.
 * O que faz: calcula dígitos verificadores para reduzir falsos positivos ao redigir sequências numéricas semelhantes a CNPJ.
 */
function isValidCnpj(value) {
  const digits = String(value).replace(/\D/g, '');
  if (!/^\d{14}$/.test(digits) || /^(\d)\1+$/.test(digits)) return false;
  const calculate = (base, weights) => {
    const sum = base.split('').reduce((total, digit, index) => total + Number(digit) * weights[index], 0);
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };
  const first = calculate(digits.slice(0, 12), [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const second = calculate(digits.slice(0, 12) + first, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return first === Number(digits[12]) && second === Number(digits[13]);
}

/**
 * O que é: função para aplicar redação de texto por regras conhecidas.
 * O que faz: percorre padrões de dados pessoais e credenciais, registra somente metadados das substituições e devolve texto redigido.
 */
function redactByRules(text, rules, options, changes) {
  let output = text;

  for (const rule of rules) {
    output = output.replace(rule.pattern, (match) => {
      if (rule.name === 'cpf' && options.validateBrazilianDocuments && !isValidCpf(match)) return match;
      if (rule.name === 'cnpj' && options.validateBrazilianDocuments && !isValidCnpj(match)) return match;
      changes.push({ type: rule.name, length: match.length, fingerprint: fingerprint(match) });
      return marker(rule.name, match);
    });
  }

  return output;
}

/**
 * O que é: função para redigir query strings de URLs encontradas em texto.
 * O que faz: identifica URLs HTTP(S), mascara valores de parâmetros sensíveis por nome e registra mudanças sem alterar hosts ou caminhos.
 */
function redactSensitiveUrlQueries(text, options, changes) {
  const parameterPattern = options.sensitiveFieldPatterns;
  return text.replace(/https?:\/\/[^\s"'<>]+/gi, (rawUrl) => {
    const trailing = rawUrl.match(/[.,;:!?]+$/)?.[0] ?? '';
    const candidate = trailing ? rawUrl.slice(0, -trailing.length) : rawUrl;
    try {
      const url = new URL(candidate);
      let modified = false;
      for (const [key, value] of url.searchParams) {
        if (parameterPattern.some((pattern) => pattern.test(key))) {
          url.searchParams.set(key, marker(`query-${key}`, value));
          changes.push({ type: 'sensitive-url-query', field: key, length: value.length, fingerprint: fingerprint(value) });
          modified = true;
        }
      }
      return `${modified ? url.toString() : candidate}${trailing}`;
    } catch {
      return rawUrl;
    }
  });
}

/**
 * O que é: redator de texto local.
 * O que faz: mascara PII e credenciais por padrões, aplica expressões extras e redige parâmetros sensíveis de URLs; não transmite
 * o texto nem mantém valores originais no relatório retornado.
 *
 * @param {string} input Texto local a sanitizar.
 * @param {object} [options] Opções de redação.
 * @returns {{redacted: string, changes: object[], summary: object}} Texto redigido e metadados das alterações.
 */
export function redactText(input, options = {}) {
  if (typeof input !== 'string') throw new TypeError('input deve ser um texto.');
  const settings = {
    validateBrazilianDocuments: true,
    extraPatterns: [],
    sensitiveFieldPatterns: [DEFAULT_SENSITIVE_FIELD_PATTERN],
    ...options,
  };
  settings.sensitiveFieldPatterns = normalizePatterns(settings.sensitiveFieldPatterns);
  const extraRules = normalizePatterns(settings.extraPatterns).map((pattern, index) => ({ name: `custom-${index + 1}`, pattern }));
  const changes = [];
  let redacted = redactByRules(input, TEXT_RULES, settings, changes);
  redacted = redactByRules(redacted, extraRules, settings, changes);
  redacted = redactSensitiveUrlQueries(redacted, settings, changes);

  const byType = {};
  for (const change of changes) byType[change.type] = (byType[change.type] ?? 0) + 1;
  return {
    redacted,
    changes,
    summary: {
      inputCharacters: input.length,
      outputCharacters: redacted.length,
      replacements: changes.length,
      byType,
      inputFingerprint: fingerprint(input),
      outputFingerprint: fingerprint(redacted),
    },
    limitation: 'A redação é baseada em padrões e nomes de campos. Revise manualmente o resultado, pois dados sensíveis podem aparecer em formatos, idiomas, imagens, anexos ou campos não reconhecidos.',
  };
}

/**
 * O que é: função para decidir se um campo JSON deve ser redigido.
 * O que faz: compara o nome normalizado com lista explícita e padrões sensíveis, sem tentar classificar ou transmitir o valor.
 */
function shouldRedactJsonField(name, options) {
  const normalized = String(name ?? '').toLowerCase();
  return options.redactFields.has(normalized) || options.sensitiveFieldPatterns.some((pattern) => pattern.test(normalized));
}

/**
 * O que é: redator recursivo de documentos JSON locais.
 * O que faz: substitui valores de campos sensíveis por marcadores, aplica redação textual em strings restantes e preserva estrutura
 * JSON; limita profundidade para evitar processamento excessivo ou documentos malformados.
 */
function redactJsonValue(value, options, path, depth, changes) {
  if (depth > options.maxDepth) {
    const serialized = JSON.stringify(value);
    changes.push({ type: 'depth-limit', path, length: serialized.length, fingerprint: fingerprint(serialized) });
    return marker('depth-limit', serialized);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => redactJsonValue(item, options, `${path}[${index}]`, depth + 1, changes));
  }

  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      if (shouldRedactJsonField(key, options)) {
        const serialized = typeof item === 'string' ? item : JSON.stringify(item);
        changes.push({ type: 'sensitive-json-field', field: key, path: childPath, length: serialized.length, fingerprint: fingerprint(serialized) });
        output[key] = marker(`field-${key}`, serialized);
      } else {
        output[key] = redactJsonValue(item, options, childPath, depth + 1, changes);
      }
    }
    return output;
  }

  if (typeof value === 'string') {
    const result = redactText(value, options);
    changes.push(...result.changes.map((change) => ({ ...change, path })));
    return result.redacted;
  }

  return value;
}

/**
 * O que é: redator de documento JSON local.
 * O que faz: aplica redação por campos e por padrões textuais a um objeto JSON, sem modificar o documento de origem e sem salvar
 * os valores originais no resultado de auditoria.
 *
 * @param {unknown} input Objeto JSON já carregado.
 * @param {object} [options] Opções de redação.
 * @returns {{redacted: unknown, changes: object[], summary: object}} Documento redigido e metadados.
 */
export function redactJson(input, options = {}) {
  const settings = {
    redactFields: [],
    sensitiveFieldPatterns: [DEFAULT_SENSITIVE_FIELD_PATTERN],
    validateBrazilianDocuments: true,
    extraPatterns: [],
    maxDepth: 32,
    ...options,
  };
  settings.redactFields = new Set(settings.redactFields.map((field) => String(field).toLowerCase()));
  settings.sensitiveFieldPatterns = normalizePatterns(settings.sensitiveFieldPatterns);
  const changes = [];
  const redacted = redactJsonValue(input, settings, '$', 0, changes);
  const original = JSON.stringify(input);
  const output = JSON.stringify(redacted);
  const byType = {};
  for (const change of changes) byType[change.type] = (byType[change.type] ?? 0) + 1;

  return {
    redacted,
    changes,
    summary: {
      replacements: changes.length,
      byType,
      inputFingerprint: fingerprint(original),
      outputFingerprint: fingerprint(output),
    },
    limitation: 'A redação por JSON usa nomes e padrões locais. Faça revisão humana antes de compartilhar o documento, pois dados sensíveis podem estar em chaves não previstas, conteúdo codificado, arquivos ou imagens.',
  };
}

/**
 * O que é: gerador de relatório Markdown de redação.
 * O que faz: resume substituições por tipo e caminho sem reproduzir os valores originais ou o conteúdo redigido completo.
 */
export function formatMarkdownReport(result) {
  if (!result?.summary || !Array.isArray(result.changes)) throw new TypeError('Forneça um resultado de redactText ou redactJson.');
  const lines = [
    '# Redaction Report',
    '',
    `- **Substituições aplicadas:** ${result.summary.replacements}`,
    `- **Fingerprint de entrada:** ${result.summary.inputFingerprint}`,
    `- **Fingerprint de saída:** ${result.summary.outputFingerprint}`,
    `- **Limitação:** ${result.limitation}`,
    '',
    '## Resumo por tipo',
    '',
  ];

  if (Object.keys(result.summary.byType).length === 0) lines.push('- Nenhuma substituição foi aplicada.');
  else for (const [type, count] of Object.entries(result.summary.byType)) lines.push(`- ${type}: ${count}`);

  lines.push('', '## Alterações', '', '| Tipo | Campo/Caminho | Tamanho | Fingerprint |', '|---|---|---:|---|');
  if (result.changes.length === 0) lines.push('| — | — | — | — |');
  else for (const change of result.changes) {
    lines.push(`| ${change.type} | ${String(change.path ?? change.field ?? 'texto').replace(/\|/g, '\\|')} | ${change.length ?? '—'} | ${change.fingerprint ?? '—'} |`);
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para ler argumentos de terminal.
 * O que faz: retorna o valor logo após flags como --input, --output, --report e --redact-fields.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função para converter lista separada por vírgulas em valores de campo.
 * O que faz: remove espaços e itens vazios para aceitar campos adicionais de redação por meio de uma flag simples.
 */
function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como redigir texto ou JSON local e gerar relatório sem enviar ou compartilhar o conteúdo original.
 */
function showHelp() {
  console.log(`\nUso:\n  node redaction-tool.js --input arquivo.txt --output arquivo-redigido.txt [opções]\n  node redaction-tool.js --input arquivo.json --json --output arquivo-redigido.json [opções]\n\nOpções:\n  --json                     Trata a entrada como JSON\n  --redact-fields LISTA      Campos JSON adicionais a redigir, separados por vírgula\n  --extra-pattern REGEX      Padrão adicional de texto a redigir; pode ser repetido\n  --report ARQUIVO           Salva relatório Markdown sem valores originais\n  --no-document-validation   Redige qualquer sequência compatível com CPF/CNPJ, mesmo sem dígito verificador válido\n\nExemplo:\n  node redaction-tool.js --input evidence.json --json --output evidence-redigida.json --redact-fields 'customerId,documento' --report redaction-report.md\n\nObservação: revise manualmente a saída antes de compartilhar. A ferramenta usa padrões e não reconhece todos os tipos de dado sensível.\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');
  const output = getCliOption('output');

  if (process.argv.includes('--help') || !input || !output) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const extraPatterns = [];
      for (let index = 0; index < process.argv.length; index += 1) {
        if (process.argv[index] === '--extra-pattern' && process.argv[index + 1]) extraPatterns.push(process.argv[index + 1]);
      }
      const options = {
        redactFields: splitList(getCliOption('redact-fields')),
        extraPatterns,
        validateBrazilianDocuments: !process.argv.includes('--no-document-validation'),
      };
      const source = await readFile(input, 'utf8');
      const result = process.argv.includes('--json')
        ? redactJson(JSON.parse(source), options)
        : redactText(source, options);
      const content = process.argv.includes('--json')
        ? JSON.stringify(result.redacted, null, 2)
        : result.redacted;

      await writeFile(output, `${content}\n`, 'utf8');
      const reportFile = getCliOption('report');
      if (reportFile) await writeFile(reportFile, `${formatMarkdownReport(result)}\n`, 'utf8');
      console.log(`Redações aplicadas: ${result.summary.replacements}. Saída criada: ${output}`);
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
