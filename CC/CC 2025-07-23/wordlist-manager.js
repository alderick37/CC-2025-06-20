#!/usr/bin/env node

/**
 * Wordlist Manager
 *
 * O que é: um utilitário JavaScript para criar, higienizar, combinar e analisar listas de palavras.
 * O que faz: importa palavras de texto, remove entradas vazias e duplicadas, normaliza espaços e
 * maiúsculas/minúsculas, filtra por tamanho ou padrão, une listas e exporta o resultado em texto.
 * Não realiza requisições de rede, não interage com serviços externos e não executa tentativas de login.
 *
 * Uso como módulo:
 *   import { WordlistManager } from './wordlist-manager.js';
 *
 *   const manager = new WordlistManager({ lowercase: true, minLength: 3 });
 *   manager.addText('Admin\n usuário \nadmin\neditor');
 *   console.log(manager.toText());
 *
 * Uso via CLI:
 *   node wordlist-manager.js --input palavras.txt --output limpa.txt --lowercase --min-length 3
 *   node wordlist-manager.js --input lista-a.txt,lista-b.txt --output unificada.txt --sort alpha
 */

import { readFile, writeFile } from 'node:fs/promises';

/**
 * O que é: função para converter uma entrada textual em palavras individuais.
 * O que faz: separa o conteúdo por linhas, preservando frases com espaços internos para posterior
 * normalização; também aceita listas delimitadas por vírgula quando usadas como entrada programática.
 */
function splitEntries(text) {
  return String(text)
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .flatMap((line) => line.includes(',') ? line.split(',') : [line]);
}

/**
 * O que é: função de normalização de uma palavra ou expressão.
 * O que faz: remove espaços nas extremidades, colapsa espaços internos e aplica opções de caixa alta
 * ou baixa, sem alterar o conteúdo semântico restante da entrada.
 */
function normalizeEntry(entry, options) {
  let value = String(entry).trim().replace(/\s+/g, ' ');
  if (!value) return '';
  if (options.lowercase) value = value.toLowerCase();
  if (options.uppercase) value = value.toUpperCase();
  return value;
}

/**
 * O que é: classe para administração segura de wordlists locais.
 * O que faz: armazena entradas únicas, aplica regras de qualidade, oferece filtros e gera uma saída
 * determinística para uso em pesquisa, testes autorizados, dicionários internos ou processamento de texto.
 */
export class WordlistManager {
  constructor(options = {}) {
    this.options = {
      lowercase: false,
      uppercase: false,
      minLength: 1,
      maxLength: Number.POSITIVE_INFINITY,
      allowedPattern: null,
      ...options,
    };

    if (this.options.lowercase && this.options.uppercase) {
      throw new TypeError('Escolha apenas uma opção: lowercase ou uppercase.');
    }

    if (!Number.isInteger(this.options.minLength) || this.options.minLength < 0) {
      throw new TypeError('minLength deve ser um inteiro maior ou igual a zero.');
    }

    if (!Number.isFinite(this.options.maxLength) && this.options.maxLength !== Number.POSITIVE_INFINITY) {
      throw new TypeError('maxLength deve ser um número válido.');
    }

    this.entries = new Map();
  }

  /**
   * O que é: método de inclusão de uma única entrada.
   * O que faz: normaliza, valida tamanho e padrão, remove duplicatas por uma chave sem distinção de caixa
   * e retorna true quando a palavra é adicionada; retorna false quando ela é descartada.
   */
  add(entry) {
    const value = normalizeEntry(entry, this.options);
    if (!value) return false;
    if (value.length < this.options.minLength || value.length > this.options.maxLength) return false;
    if (this.options.allowedPattern && !this.options.allowedPattern.test(value)) return false;

    const key = value.toLocaleLowerCase('pt-BR');
    if (this.entries.has(key)) return false;

    this.entries.set(key, value);
    return true;
  }

  /**
   * O que é: método de importação de texto.
   * O que faz: lê entradas separadas por linhas ou vírgulas, tenta adicionar cada uma e retorna um resumo
   * com quantas foram adicionadas e descartadas.
   */
  addText(text) {
    const candidates = splitEntries(text);
    let added = 0;

    for (const candidate of candidates) {
      if (this.add(candidate)) added += 1;
    }

    return { received: candidates.length, added, discarded: candidates.length - added };
  }

  /**
   * O que é: método de união de wordlists.
   * O que faz: incorpora entradas de outro WordlistManager, array ou texto, mantendo apenas valores únicos
   * que respeitem as regras de normalização e filtragem desta instância.
   */
  merge(source) {
    if (source instanceof WordlistManager) {
      return this.addText(source.toText());
    }

    if (Array.isArray(source)) {
      return this.addText(source.join('\n'));
    }

    return this.addText(source);
  }

  /**
   * O que é: método de filtragem.
   * O que faz: remove entradas que não satisfaçam uma função predicado e retorna o número de itens removidos.
   */
  filter(predicate) {
    if (typeof predicate !== 'function') {
      throw new TypeError('filter exige uma função predicado.');
    }

    let removed = 0;
    for (const [key, value] of this.entries) {
      if (!predicate(value)) {
        this.entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /**
   * O que é: método de ordenação.
   * O que faz: retorna uma cópia das entradas em ordem de inserção, alfabética, por tamanho crescente ou
   * por tamanho decrescente, sem modificar a lista armazenada.
   */
  list(order = 'insertion') {
    const values = [...this.entries.values()];

    if (order === 'alpha') {
      return values.sort((a, b) => a.localeCompare(b, 'pt-BR', { sensitivity: 'base' }));
    }

    if (order === 'length-asc') {
      return values.sort((a, b) => a.length - b.length || a.localeCompare(b, 'pt-BR'));
    }

    if (order === 'length-desc') {
      return values.sort((a, b) => b.length - a.length || a.localeCompare(b, 'pt-BR'));
    }

    if (order !== 'insertion') {
      throw new TypeError('Ordem inválida. Use insertion, alpha, length-asc ou length-desc.');
    }

    return values;
  }

  /**
   * O que é: método de estatísticas da wordlist.
   * O que faz: calcula quantidade total, menor e maior comprimento e comprimento médio das entradas atuais.
   */
  stats() {
    const values = this.list();
    const lengths = values.map((value) => value.length);
    const totalCharacters = lengths.reduce((sum, length) => sum + length, 0);

    return {
      entries: values.length,
      minLength: lengths.length ? Math.min(...lengths) : 0,
      maxLength: lengths.length ? Math.max(...lengths) : 0,
      averageLength: lengths.length ? Number((totalCharacters / lengths.length).toFixed(2)) : 0,
    };
  }

  /**
   * O que é: método de exportação para texto simples.
   * O que faz: transforma a wordlist em uma string com uma entrada por linha, adequada para salvar localmente.
   */
  toText(order = 'insertion') {
    return this.list(order).join('\n');
  }
}

/**
 * O que é: função auxiliar para ler opções simples do terminal.
 * O que faz: encontra o valor que sucede uma flag, como --input arquivo.txt, sem depender de bibliotecas externas.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função auxiliar de uso da CLI.
 * O que faz: imprime instruções de execução quando faltam argumentos obrigatórios ou quando o usuário pede ajuda.
 */
function showHelp() {
  console.log(`\nUso:\n  node wordlist-manager.js --input origem.txt --output destino.txt [opções]\n\nOpções:\n  --lowercase             Converte entradas para minúsculas\n  --uppercase             Converte entradas para maiúsculas\n  --min-length N          Descarta entradas menores que N\n  --max-length N          Descarta entradas maiores que N\n  --pattern REGEX         Mantém apenas entradas compatíveis com a expressão regular\n  --sort ORDEM            insertion, alpha, length-asc ou length-desc\n  --stats                 Exibe estatísticas após processar\n\nPara unir arquivos, separe-os por vírgula:\n  --input lista-a.txt,lista-b.txt\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const inputOption = getCliOption('input');
  const outputOption = getCliOption('output');

  if (process.argv.includes('--help') || !inputOption || !outputOption) {
    showHelp();
    process.exitCode = inputOption && outputOption ? 0 : 1;
  } else {
    try {
      const patternOption = getCliOption('pattern');
      const manager = new WordlistManager({
        lowercase: process.argv.includes('--lowercase'),
        uppercase: process.argv.includes('--uppercase'),
        minLength: Number(getCliOption('min-length') ?? 1),
        maxLength: Number(getCliOption('max-length') ?? Number.POSITIVE_INFINITY),
        allowedPattern: patternOption ? new RegExp(patternOption) : null,
      });

      const inputFiles = inputOption.split(',').map((file) => file.trim()).filter(Boolean);
      let received = 0;
      let added = 0;

      for (const file of inputFiles) {
        const text = await readFile(file, 'utf8');
        const result = manager.addText(text);
        received += result.received;
        added += result.added;
      }

      const order = getCliOption('sort') ?? 'insertion';
      await writeFile(outputOption, `${manager.toText(order)}\n`, 'utf8');

      console.log(`Processadas: ${received}. Mantidas: ${added}. Únicas no resultado: ${manager.stats().entries}.`);
      console.log(`Arquivo criado: ${outputOption}`);
      if (process.argv.includes('--stats')) console.log(JSON.stringify(manager.stats(), null, 2));
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
