#!/usr/bin/env node

/**
 * security.txt Checker
 *
 * O que é: um utilitário JavaScript para validar localmente o conteúdo de um arquivo security.txt conforme RFC 9116.
 * O que faz: interpreta campos, confere presença e formato de campos importantes, identifica diretivas repetidas,
 * avalia datas de expiração e produz avisos de qualidade. Ele não faz requisições de rede nem busca arquivos remotos.
 *
 * Uso como módulo:
 *   import { parseSecurityTxt, validateSecurityTxt } from './security-txt-checker.js';
 *
 *   const parsed = parseSecurityTxt('Contact: mailto:security@exemplo.com\nExpires: 2027-01-01T00:00:00Z');
 *   const report = validateSecurityTxt(parsed);
 *
 * Uso via CLI:
 *   node security-txt-checker.js --input .well-known/security.txt --json
 */

import { readFile } from 'node:fs/promises';

const SINGLE_VALUE_FIELDS = new Set(['expires', 'canonical', 'preferred-languages', 'policy']);
const KNOWN_FIELDS = new Set([
  'acknowledgments',
  'canonical',
  'contact',
  'csrf',
  'encryption',
  'expires',
  'hiring',
  'policy',
  'preferred-languages',
  'signature',
]);

/**
 * O que é: função para remover comentários de linhas security.txt.
 * O que faz: descarta linhas inteiramente comentadas e remove comentários finais iniciados com #, mantendo a diretiva útil.
 */
function stripComment(line) {
  return line.split('#', 1)[0].trim();
}

/**
 * O que é: função para validar referências URI aceitas em campos de security.txt.
 * O que faz: verifica se o valor contém uma URI absoluta com esquema, incluindo mailto:, https: e openpgp4fpr:.
 */
function isAbsoluteUri(value) {
  try {
    const parsed = new URL(value);
    return Boolean(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * O que é: parser local de security.txt.
 * O que faz: separa campos no formato Nome: valor, preserva número da linha e identifica comentários, linhas malformadas
 * e extensões de campo desconhecidas, sem acessar a URL Canonical ou qualquer contato declarado no arquivo.
 *
 * @param {string} text Conteúdo de um arquivo security.txt.
 * @returns {{fields: Record<string, object[]>, entries: object[], parseWarnings: object[]}}
 */
export function parseSecurityTxt(text) {
  if (typeof text !== 'string') throw new TypeError('security.txt deve ser um texto.');

  const fields = {};
  const entries = [];
  const parseWarnings = [];
  const lines = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n');

  for (const [index, rawLine] of lines.entries()) {
    const line = stripComment(rawLine);
    if (!line) continue;

    const separator = line.indexOf(':');
    if (separator < 1) {
      parseWarnings.push({ line: index + 1, message: 'Linha sem separador Nome: valor.' });
      continue;
    }

    const rawName = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    const name = rawName.toLowerCase();

    if (!/^[a-z][a-z0-9-]*$/i.test(rawName)) {
      parseWarnings.push({ line: index + 1, message: `Nome de campo inválido: ${rawName}` });
      continue;
    }

    if (!value) {
      parseWarnings.push({ line: index + 1, message: `Campo ${rawName} sem valor.` });
      continue;
    }

    const entry = { name, rawName, value, line: index + 1, known: KNOWN_FIELDS.has(name) };
    entries.push(entry);
    fields[name] ??= [];
    fields[name].push(entry);

    if (!entry.known) {
      parseWarnings.push({ line: index + 1, message: `Campo de extensão ou não reconhecido: ${rawName}.` });
    }
  }

  return { fields, entries, parseWarnings };
}

/**
 * O que é: validador de um security.txt já interpretado.
 * O que faz: aplica verificações alinhadas à RFC 9116, como Contact obrigatório, Expires obrigatório e futuro,
 * URIs absolutas, Canonical em HTTPS, unicidade de campos selecionados e formato de Preferred-Languages.
 *
 * @param {ReturnType<typeof parseSecurityTxt>} parsed Resultado de parseSecurityTxt.
 * @param {object} [options] Opções de validação.
 * @param {Date|string} [options.now=new Date()] Data de referência para checar expiração.
 * @param {string|null} [options.expectedCanonical=null] URL esperada do arquivo, para conferir Canonical quando conhecida.
 * @returns {{valid: boolean, errors: object[], warnings: object[], info: object[]}}
 */
export function validateSecurityTxt(parsed, options = {}) {
  if (!parsed || typeof parsed !== 'object' || !parsed.fields) {
    throw new TypeError('Forneça o resultado retornado por parseSecurityTxt.');
  }

  const settings = { now: new Date(), expectedCanonical: null, ...options };
  const now = new Date(settings.now);
  if (Number.isNaN(now.getTime())) throw new TypeError('A opção now deve ser uma data válida.');

  const errors = [];
  const warnings = [...(parsed.parseWarnings ?? []).map((item) => ({ ...item, type: 'parse' }))];
  const info = [];
  const { fields } = parsed;

  for (const field of SINGLE_VALUE_FIELDS) {
    if ((fields[field]?.length ?? 0) > 1) {
      errors.push({ field, message: `O campo ${field} deve aparecer apenas uma vez.` });
    }
  }

  const contacts = fields.contact ?? [];
  if (contacts.length === 0) {
    errors.push({ field: 'contact', message: 'Contact é obrigatório pela RFC 9116.' });
  } else {
    for (const contact of contacts) {
      if (!isAbsoluteUri(contact.value)) {
        errors.push({ line: contact.line, field: 'contact', message: 'Contact deve conter uma URI absoluta.' });
      }
    }
  }

  const expires = fields.expires ?? [];
  if (expires.length === 0) {
    errors.push({ field: 'expires', message: 'Expires é obrigatório pela RFC 9116.' });
  } else if (expires.length === 1) {
    const expiresAt = new Date(expires[0].value);
    if (Number.isNaN(expiresAt.getTime())) {
      errors.push({ line: expires[0].line, field: 'expires', message: 'Expires deve usar uma data/hora ISO 8601 válida.' });
    } else if (expiresAt <= now) {
      errors.push({ line: expires[0].line, field: 'expires', message: 'O security.txt está expirado.' });
    } else {
      const daysUntilExpiration = Math.floor((expiresAt - now) / 86_400_000);
      info.push({ field: 'expires', message: `Expira em aproximadamente ${daysUntilExpiration} dia(s).`, value: expiresAt.toISOString() });
      if (daysUntilExpiration > 366) {
        warnings.push({ line: expires[0].line, field: 'expires', message: 'A expiração está a mais de um ano; recomenda-se renovação mais frequente.' });
      }
    }
  }

  const uriFields = ['acknowledgments', 'canonical', 'encryption', 'hiring', 'policy', 'signature'];
  for (const field of uriFields) {
    for (const entry of fields[field] ?? []) {
      if (!isAbsoluteUri(entry.value)) {
        errors.push({ line: entry.line, field, message: `${entry.rawName} deve conter uma URI absoluta.` });
      }
    }
  }

  for (const canonical of fields.canonical ?? []) {
    try {
      const url = new URL(canonical.value);
      if (url.protocol !== 'https:') {
        warnings.push({ line: canonical.line, field: 'canonical', message: 'Canonical normalmente deve usar HTTPS.' });
      }

      if (settings.expectedCanonical && canonical.value !== settings.expectedCanonical) {
        warnings.push({
          line: canonical.line,
          field: 'canonical',
          message: `Canonical difere da URL esperada: ${settings.expectedCanonical}`,
        });
      }
    } catch {
      // O formato já é reportado acima como erro de URI absoluta.
    }
  }

  for (const languages of fields['preferred-languages'] ?? []) {
    const values = languages.value.split(',').map((value) => value.trim()).filter(Boolean);
    if (values.length === 0 || values.some((value) => !/^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/i.test(value))) {
      warnings.push({ line: languages.line, field: 'preferred-languages', message: 'Preferred-Languages deve usar tags de idioma separadas por vírgulas, como pt-BR, en.' });
    }
  }

  if ((fields.encryption?.length ?? 0) === 0) {
    warnings.push({ field: 'encryption', message: 'Encryption é opcional, mas recomendável quando houver canal PGP ou outra chave pública para relatos.' });
  }

  if ((fields.policy?.length ?? 0) === 0) {
    warnings.push({ field: 'policy', message: 'Policy é opcional, mas recomendável para definir escopo e processo de divulgação responsável.' });
  }

  if ((fields.canonical?.length ?? 0) === 0) {
    warnings.push({ field: 'canonical', message: 'Canonical é opcional, mas ajuda a identificar a localização oficial do arquivo.' });
  }

  return { valid: errors.length === 0, errors, warnings, info };
}

/**
 * O que é: função de conveniência para análise completa de security.txt.
 * O que faz: combina parsing e validação em uma única chamada e devolve campos, erros, avisos e informações úteis.
 */
export function checkSecurityTxt(text, options = {}) {
  const parsed = parseSecurityTxt(text);
  return { parsed, report: validateSecurityTxt(parsed, options) };
}

/**
 * O que é: função auxiliar para leitura de argumentos no terminal.
 * O que faz: encontra o valor após uma flag como --input arquivo.txt ou --expected-canonical URL.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: mostra como validar um arquivo security.txt local e como comparar o campo Canonical com uma URL conhecida.
 */
function showHelp() {
  console.log(`\nUso:\n  node security-txt-checker.js --input security.txt [opções]\n\nOpções:\n  --expected-canonical URL  URL esperada para comparação com o campo Canonical\n  --now DATA_ISO            Data de referência para teste de expiração\n  --json                    Imprime o relatório completo em JSON\n\nExemplo:\n  node security-txt-checker.js --input .well-known/security.txt --expected-canonical 'https://exemplo.com/.well-known/security.txt' --json\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const input = getCliOption('input');

  if (process.argv.includes('--help') || !input) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const result = checkSecurityTxt(await readFile(input, 'utf8'), {
        expectedCanonical: getCliOption('expected-canonical') ?? null,
        now: getCliOption('now') ?? new Date(),
      });

      if (process.argv.includes('--json')) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`Status: ${result.report.valid ? 'válido' : 'inválido'}.`);
        console.log(`Campos encontrados: ${result.parsed.entries.length}.`);
        for (const error of result.report.errors) console.log(`[ERRO] ${error.message}`);
        for (const warning of result.report.warnings) console.log(`[AVISO] ${warning.message}`);
        for (const item of result.report.info) console.log(`[INFO] ${item.message}`);
      }

      process.exitCode = result.report.valid ? 0 : 2;
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
