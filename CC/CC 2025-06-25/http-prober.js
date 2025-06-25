#!/usr/bin/env node

/**
 * HTTP Prober
 *
 * O que é: um utilitário JavaScript para verificar, de forma controlada, a disponibilidade e os metadados
 * básicos de endpoints HTTP(S) que estejam dentro de um escopo previamente autorizado.
 * O que faz: recebe URLs explícitas ou um arquivo de URLs, valida cada destino com uma política de escopo,
 * realiza uma requisição HEAD (com alternativa GET), registra status, URL final, tempo de resposta, tipo e
 * tamanho de conteúdo. Não descobre hosts, não enumera diretórios e não tenta autenticação ou exploração.
 *
 * Use somente em ativos que você possui ou para os quais tem autorização explícita.
 *
 * Uso como módulo:
 *   import { probeUrl, probeMany } from './http-prober.js';
 *
 *   const result = await probeUrl('https://status.exemplo.com/health', {
 *     scope: { allowedHosts: ['status.exemplo.com'] },
 *   });
 *
 * Uso via CLI:
 *   node http-prober.js --url 'https://app.exemplo.com/health' --hosts 'app.exemplo.com'
 *   node http-prober.js --input urls.txt --hosts 'exemplo.com,*.exemplo.com' --concurrency 3
 */

import { readFile } from 'node:fs/promises';
import { checkScope } from './scope-checker.js';

/**
 * O que é: função auxiliar de espera assíncrona.
 * O que faz: pausa uma execução por uma quantidade definida de milissegundos, permitindo limitar o ritmo
 * entre requisições e reduzir impacto sobre o serviço autorizado.
 */
function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * O que é: função que converte texto em URLs explícitas.
 * O que faz: lê linhas de uma string, remove espaços e comentários iniciados com # e retorna apenas entradas válidas.
 */
function parseUrlList(text) {
  return String(text)
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

/**
 * O que é: função que extrai metadados seguros de uma resposta HTTP.
 * O que faz: retorna somente informações de diagnóstico e inventário, sem registrar corpo, cookies ou headers sensíveis.
 */
function responseMetadata(response, elapsedMs, method) {
  const contentLength = response.headers.get('content-length');

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    method,
    finalUrl: response.url,
    redirected: response.redirected,
    responseTimeMs: Math.round(elapsedMs),
    contentType: response.headers.get('content-type') ?? null,
    contentLength: contentLength && /^\d+$/.test(contentLength) ? Number(contentLength) : null,
    server: response.headers.get('server') ?? null,
  };
}

/**
 * O que é: função de sondagem de um endpoint HTTP(S) autorizado.
 * O que faz: valida a URL contra o escopo fornecido e faz uma requisição HEAD com timeout; se o servidor rejeitar
 * HEAD com 405 ou 501, repete com GET usando Range: bytes=0-0 para evitar baixar o corpo inteiro quando possível.
 *
 * @param {string} input URL explícita a testar.
 * @param {object} options Configurações da sondagem.
 * @param {object} options.scope Política compatível com checkScope do arquivo scope-checker.js.
 * @param {number} [options.timeoutMs=8000] Tempo máximo por requisição.
 * @param {boolean} [options.followRedirects=false] Se true, segue redirecionamentos dentro do escopo.
 * @param {string} [options.userAgent='http-prober/1.0'] Identificação enviada ao servidor.
 * @returns {Promise<object>} Resultado estruturado da validação e da resposta HTTP.
 */
export async function probeUrl(input, options = {}) {
  const settings = {
    scope: { allowedHosts: [] },
    timeoutMs: 8000,
    followRedirects: false,
    userAgent: 'http-prober/1.0 (+authorized-security-testing)',
    ...options,
  };

  const scopeResult = checkScope(input, settings.scope);
  if (!scopeResult.allowed) {
    return {
      input,
      allowed: false,
      error: 'URL fora do escopo autorizado.',
      scope: scopeResult,
    };
  }

  const fetchOptions = {
    redirect: settings.followRedirects ? 'follow' : 'manual',
    headers: {
      'user-agent': settings.userAgent,
      accept: '*/*',
    },
  };

  async function request(method, extraHeaders = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), settings.timeoutMs);
    const startedAt = performance.now();

    try {
      const response = await fetch(scopeResult.url, {
        ...fetchOptions,
        method,
        headers: { ...fetchOptions.headers, ...extraHeaders },
        signal: controller.signal,
      });

      const elapsedMs = performance.now() - startedAt;
      return { response, elapsedMs };
    } finally {
      clearTimeout(timeout);
    }
  }

  try {
    let { response, elapsedMs } = await request('HEAD');
    let method = 'HEAD';

    if (response.status === 405 || response.status === 501) {
      ({ response, elapsedMs } = await request('GET', { range: 'bytes=0-0' }));
      method = 'GET';
    }

    const finalScope = checkScope(response.url, settings.scope);
    if (!finalScope.allowed) {
      return {
        input,
        allowed: false,
        error: 'A resposta apontou para uma URL fora do escopo autorizado.',
        scope: finalScope,
        response: responseMetadata(response, elapsedMs, method),
      };
    }

    return {
      input,
      allowed: true,
      scope: scopeResult,
      response: responseMetadata(response, elapsedMs, method),
    };
  } catch (error) {
    const isTimeout = error?.name === 'AbortError';
    return {
      input,
      allowed: true,
      scope: scopeResult,
      error: isTimeout ? `Timeout após ${settings.timeoutMs} ms.` : error.message,
      errorType: isTimeout ? 'timeout' : error?.name ?? 'request_error',
    };
  }
}

/**
 * O que é: função para sondar várias URLs explícitas com limite de concorrência.
 * O que faz: processa uma lista já fornecida pelo usuário sem gerar novos destinos, respeita intervalo entre tarefas
 * e devolve os resultados na mesma ordem da entrada para facilitar relatórios e automações.
 */
export async function probeMany(urls, options = {}) {
  if (!Array.isArray(urls)) throw new TypeError('urls deve ser um array.');

  const concurrency = Math.max(1, Math.min(Number(options.concurrency ?? 2), 10));
  const delayMs = Math.max(0, Number(options.delayMs ?? 250));
  const results = new Array(urls.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      if (currentIndex >= urls.length) return;

      results[currentIndex] = await probeUrl(urls[currentIndex], options);
      if (delayMs > 0 && currentIndex < urls.length - 1) await sleep(delayMs);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, worker));
  return results;
}

/**
 * O que é: função auxiliar para leitura de flags no terminal.
 * O que faz: obtém o valor que sucede uma opção como --input ou --timeout, sem usar dependências externas.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função auxiliar para transformar valores separados por vírgula em listas.
 * O que faz: remove espaços extras e entradas vazias para montar regras de hosts, portas, protocolos e caminhos.
 */
function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: mostra os argumentos disponíveis, incluindo a exigência de declarar hosts autorizados explicitamente.
 */
function showHelp() {
  console.log(`\nUso:\n  node http-prober.js --url URL --hosts HOSTS [opções]\n  node http-prober.js --input urls.txt --hosts HOSTS [opções]\n\nObrigatório:\n  --hosts LISTA             Hosts autorizados, separados por vírgula. Ex.: app.exemplo.com,*.exemplo.com\n\nEntrada:\n  --url URL                 Uma URL explícita para verificar\n  --input ARQUIVO           Arquivo texto, com uma URL explícita por linha\n\nOpções:\n  --protocols LISTA         Protocolos permitidos. Padrão: https:\n  --paths LISTA             Prefixos permitidos. Padrão: /\n  --ports LISTA             Portas permitidas. Padrão: portas HTTP(S) padrão\n  --allow-subdomains        Permite subdomínios de hosts exatos\n  --timeout MS              Timeout por URL. Padrão: 8000\n  --concurrency N           Máximo de requisições simultâneas, de 1 a 10. Padrão: 2\n  --delay MS                Pausa entre tarefas. Padrão: 250\n  --follow-redirects        Segue redirecionamentos; o destino final também precisa estar no escopo\n  --json                    Emite resultados completos em JSON\n\nExemplo:\n  node http-prober.js --input urls.txt --hosts 'app.exemplo.com' --paths '/,/health' --concurrency 2 --delay 500\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const inputUrl = getCliOption('url');
  const inputFile = getCliOption('input');
  const hosts = splitList(getCliOption('hosts'));

  if (process.argv.includes('--help') || (!inputUrl && !inputFile) || hosts.length === 0) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const urls = inputUrl ? [inputUrl] : parseUrlList(await readFile(inputFile, 'utf8'));
      const results = await probeMany(urls, {
        scope: {
          allowedHosts: hosts,
          allowedProtocols: splitList(getCliOption('protocols')).length
            ? splitList(getCliOption('protocols'))
            : ['https:'],
          allowedPathPrefixes: splitList(getCliOption('paths')).length
            ? splitList(getCliOption('paths'))
            : ['/'],
          allowedPorts: splitList(getCliOption('ports')).map(Number).filter(Number.isInteger),
          allowSubdomains: process.argv.includes('--allow-subdomains'),
        },
        timeoutMs: Number(getCliOption('timeout') ?? 8000),
        concurrency: Number(getCliOption('concurrency') ?? 2),
        delayMs: Number(getCliOption('delay') ?? 250),
        followRedirects: process.argv.includes('--follow-redirects'),
      });

      if (process.argv.includes('--json')) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        for (const result of results) {
          if (!result.allowed) {
            console.log(`[FORA DO ESCOPO] ${result.input} — ${result.error}`);
          } else if (result.error) {
            console.log(`[ERRO] ${result.input} — ${result.error}`);
          } else {
            console.log(`[${result.response.status}] ${result.input} — ${result.response.responseTimeMs} ms — ${result.response.contentType ?? 'tipo desconhecido'}`);
          }
        }
      }

      process.exitCode = results.some((result) => !result.allowed || result.error) ? 2 : 0;
    } catch (error) {
      console.error(`Erro: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
