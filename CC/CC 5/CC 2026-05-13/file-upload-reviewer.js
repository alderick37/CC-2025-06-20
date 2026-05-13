#!/usr/bin/env node

/**
 * File Upload Reviewer
 *
 * O que é: um utilitário JavaScript para revisar localmente políticas e evidências de upload de arquivos.
 * O que faz: compara metadados de arquivos previamente coletados com uma política de tipos, extensões, tamanho, nome,
 * armazenamento e exposição; destaca divergências e controles que exigem revisão. Ele não envia arquivos, não acessa
 * diretórios, não executa conteúdo enviado e não interage com qualquer sistema externo.
 *
 * Uso como módulo:
 *   import { reviewUpload, reviewUploadBatch, formatMarkdownReport } from './file-upload-reviewer.js';
 *
 *   const report = reviewUpload({ name: 'foto.jpg', mimeType: 'image/jpeg', sizeBytes: 240000 }, {
 *     allowedExtensions: ['jpg', 'png'],
 *     allowedMimeTypes: ['image/jpeg', 'image/png'],
 *     maxBytes: 5000000,
 *     storage: { public: false, outsideWebRoot: true }
 *   });
 *
 * Uso via CLI:
 *   node file-upload-reviewer.js --policy upload-policy.json --files upload-evidence.json --format markdown --output upload-review.md
 */

import { readFile, writeFile } from 'node:fs/promises';

const EXECUTABLE_OR_SERVER_SIDE_EXTENSIONS = new Set([
  'php', 'phtml', 'php3', 'php4', 'php5', 'phar', 'asp', 'aspx', 'ashx', 'jsp', 'jspx',
  'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'zsh', 'ps1', 'exe', 'dll', 'msi', 'bat', 'cmd',
]);

const DANGEROUS_CONTAINER_EXTENSIONS = new Set(['svg', 'html', 'htm', 'xml', 'pdf', 'zip', 'tar', 'gz', '7z', 'rar', 'docm', 'xlsm']);
const MIME_BY_EXTENSION = {
  jpg: ['image/jpeg'],
  jpeg: ['image/jpeg'],
  png: ['image/png'],
  gif: ['image/gif'],
  webp: ['image/webp'],
  pdf: ['application/pdf'],
  txt: ['text/plain'],
  csv: ['text/csv', 'application/csv'],
  json: ['application/json', 'text/json'],
  mp3: ['audio/mpeg'],
  mp4: ['video/mp4'],
};

/**
 * O que é: função para normalizar extensões de arquivo.
 * O que faz: remove ponto inicial, converte para minúsculas e aceita somente caracteres seguros para comparação com allowlists.
 */
function normalizeExtension(value) {
  const extension = String(value ?? '').trim().replace(/^\.+/, '').toLowerCase();
  return /^[a-z0-9]{1,12}$/.test(extension) ? extension : '';
}

/**
 * O que é: função para extrair extensões compostas e extensão final de um nome de arquivo.
 * O que faz: identifica a extensão final e todas as extensões visíveis, ajudando a revisar nomes como relatorio.pdf.php ou foto.jpg.exe.
 */
function extractExtensions(name) {
  const filename = String(name ?? '').trim().split(/[\\/]/).at(-1) ?? '';
  const parts = filename.split('.').filter(Boolean);
  const extensions = parts.length > 1 ? parts.slice(1).map(normalizeExtension).filter(Boolean) : [];
  return { filename, extensions, finalExtension: extensions.at(-1) ?? '' };
}

/**
 * O que é: função para normalizar MIME types.
 * O que faz: remove parâmetros como charset e converte valores para minúsculas antes de comparar com uma allowlist local.
 */
function normalizeMimeType(value) {
  return String(value ?? '').split(';', 1)[0].trim().toLowerCase();
}

/**
 * O que é: função para construir achados de revisão de upload.
 * O que faz: padroniza severidade, código, mensagem e recomendação para relatórios consistentes e priorizáveis.
 */
function finding(severity, code, message, recommendation) {
  return { severity, code, message, recommendation };
}

/**
 * O que é: normalizador de uma política local de upload.
 * O que faz: valida allowlists de extensão e MIME, limites de tamanho e controles de armazenamento e entrega, sem consultar o
 * filesystem, bucket, CDN ou configuração real do servidor.
 */
export function normalizeUploadPolicy(policy = {}) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new TypeError('policy deve ser um objeto.');

  const allowedExtensions = [...new Set((policy.allowedExtensions ?? []).map(normalizeExtension).filter(Boolean))];
  const allowedMimeTypes = [...new Set((policy.allowedMimeTypes ?? []).map(normalizeMimeType).filter(Boolean))];
  const maxBytes = Number(policy.maxBytes ?? policy.maxSizeBytes ?? 0);
  if (!Number.isInteger(maxBytes) || maxBytes < 0) throw new TypeError('maxBytes deve ser um inteiro maior ou igual a zero.');

  return {
    allowedExtensions,
    allowedMimeTypes,
    maxBytes,
    requireExtensionMimeMatch: policy.requireExtensionMimeMatch !== false,
    rejectDoubleExtensions: policy.rejectDoubleExtensions !== false,
    sanitizeOriginalFilename: policy.sanitizeOriginalFilename !== false,
    generateServerFilename: policy.generateServerFilename !== false,
    inspectFileSignature: Boolean(policy.inspectFileSignature),
    malwareScan: Boolean(policy.malwareScan),
    storage: {
      outsideWebRoot: Boolean(policy.storage?.outsideWebRoot),
      public: Boolean(policy.storage?.public),
      randomObjectKeys: Boolean(policy.storage?.randomObjectKeys),
      contentDispositionAttachment: Boolean(policy.storage?.contentDispositionAttachment),
      separateUploadDomain: Boolean(policy.storage?.separateUploadDomain),
    },
  };
}

/**
 * O que é: normalizador de metadados de um arquivo de upload já coletado.
 * O que faz: organiza nome, MIME declarado, MIME detectado opcional, tamanho e destino informado sem abrir, executar ou ler o arquivo.
 */
function normalizeFileEvidence(file = {}) {
  if (!file || typeof file !== 'object' || Array.isArray(file)) throw new TypeError('Cada arquivo deve ser um objeto.');
  const name = String(file.name ?? file.filename ?? file.originalName ?? '').trim();
  if (!name) throw new TypeError('Cada arquivo exige name, filename ou originalName.');
  const sizeBytes = Number(file.sizeBytes ?? file.size ?? 0);
  if (!Number.isFinite(sizeBytes) || sizeBytes < 0) throw new TypeError(`Tamanho inválido para ${name}.`);

  const extensionInfo = extractExtensions(name);
  return {
    name,
    filename: extensionInfo.filename,
    extensions: extensionInfo.extensions,
    extension: extensionInfo.finalExtension,
    mimeType: normalizeMimeType(file.mimeType ?? file.contentType ?? file.declaredMimeType),
    detectedMimeType: normalizeMimeType(file.detectedMimeType ?? file.magicMimeType),
    sizeBytes,
    destination: file.destination ?? file.url ?? null,
    notes: file.notes ?? null,
  };
}

/**
 * O que é: revisor local de uma evidência de upload.
 * O que faz: compara metadados fornecidos com a política de upload e identifica extensões, MIME types, tamanhos e controles de
 * armazenamento que exigem revisão. A análise não confirma o conteúdo binário ou o comportamento do sistema real.
 *
 * @param {object} file Metadados locais de um arquivo.
 * @param {object} policy Política local de upload.
 * @returns {object} Relatório de revisão por arquivo.
 */
export function reviewUpload(file, policy) {
  const settings = normalizeUploadPolicy(policy);
  const item = normalizeFileEvidence(file);
  const findings = [];

  if (!item.extension) {
    findings.push(finding('medium', 'missing-extension', 'O arquivo não possui extensão final reconhecível.', 'Exija tipos aceitos por allowlist e não dependa apenas do nome original para determinar o formato.'));
  }

  if (EXECUTABLE_OR_SERVER_SIDE_EXTENSIONS.has(item.extension)) {
    findings.push(finding('high', 'executable-extension', `Extensão potencialmente executável ou server-side: .${item.extension}`, 'Rejeite arquivos executáveis ou interpretáveis e impeça execução no armazenamento de uploads.'));
  }

  const dangerousEmbedded = item.extensions.slice(0, -1).find((extension) => EXECUTABLE_OR_SERVER_SIDE_EXTENSIONS.has(extension));
  if (dangerousEmbedded) {
    findings.push(finding('high', 'dangerous-double-extension', `Nome contém extensão executável intermediária: .${dangerousEmbedded}`, 'Rejeite nomes com extensões duplas suspeitas e gere nome de arquivo no servidor.'));
  }

  if (settings.rejectDoubleExtensions && item.extensions.length > 1) {
    findings.push(finding('medium', 'double-extension', `Arquivo possui extensões múltiplas: ${item.extensions.map((extension) => `.${extension}`).join('')}`, 'Rejeite ou trate explicitamente extensões múltiplas, conforme o formato permitido.'));
  }

  if (settings.allowedExtensions.length === 0) {
    findings.push(finding('medium', 'missing-extension-allowlist', 'A política não declara extensões permitidas.', 'Defina allowlist estrita por endpoint ou finalidade de upload.'));
  } else if (!settings.allowedExtensions.includes(item.extension)) {
    findings.push(finding('high', 'extension-not-allowed', `Extensão .${item.extension || '(ausente)'} não consta na allowlist.`, 'Aceite somente extensões necessárias para o recurso e valide no servidor.'));
  }

  if (!item.mimeType) {
    findings.push(finding('medium', 'missing-declared-mime', 'O MIME type declarado não foi informado.', 'Registre e valide Content-Type, mas não o use como única fonte de confiança.'));
  } else if (settings.allowedMimeTypes.length === 0) {
    findings.push(finding('medium', 'missing-mime-allowlist', 'A política não declara MIME types permitidos.', 'Defina allowlist de MIME por endpoint e combine-a com inspeção do arquivo.'));
  } else if (!settings.allowedMimeTypes.includes(item.mimeType)) {
    findings.push(finding('high', 'mime-not-allowed', `MIME type declarado não permitido: ${item.mimeType}`, 'Rejeite MIME types fora da allowlist e verifique o tipo real do arquivo quando possível.'));
  }

  if (item.detectedMimeType && item.mimeType && item.detectedMimeType !== item.mimeType) {
    findings.push(finding('high', 'mime-detection-mismatch', `MIME declarado (${item.mimeType}) diverge do MIME detectado (${item.detectedMimeType}).`, 'Rejeite ou coloque em quarentena arquivos cujo tipo real não corresponda ao tipo esperado.'));
  }

  if (settings.requireExtensionMimeMatch && item.extension && item.mimeType && MIME_BY_EXTENSION[item.extension] && !MIME_BY_EXTENSION[item.extension].includes(item.mimeType)) {
    findings.push(finding('medium', 'extension-mime-mismatch', `A extensão .${item.extension} não costuma corresponder ao MIME ${item.mimeType}.`, 'Valide extensão e MIME em conjunto e, idealmente, confirme magic bytes com biblioteca apropriada.'));
  }

  if (settings.maxBytes <= 0) {
    findings.push(finding('medium', 'missing-size-limit', 'A política não declara um limite máximo de tamanho.', 'Defina limite de tamanho por tipo de upload e aplique-o antes de processar o arquivo.'));
  } else if (item.sizeBytes > settings.maxBytes) {
    findings.push(finding('high', 'file-too-large', `Arquivo possui ${item.sizeBytes} bytes e excede o máximo de ${settings.maxBytes}.`, 'Rejeite arquivos acima do limite no proxy e na aplicação; evite carregar o arquivo integralmente em memória.'));
  }

  if (DANGEROUS_CONTAINER_EXTENSIONS.has(item.extension)) {
    findings.push(finding('info', 'active-or-container-format', `Formato .${item.extension} pode carregar conteúdo ativo, links, macros ou estruturas complexas.`, 'Aplique validação específica, sanitização/transcodificação quando apropriado e entrega segura como anexo.'));
  }

  if (!settings.sanitizeOriginalFilename) {
    findings.push(finding('medium', 'filename-not-sanitized', 'A política informa que o nome original não é sanitizado.', 'Normalize e descarte caminhos, caracteres de controle e nomes especiais antes de registrar metadados.'));
  }
  if (!settings.generateServerFilename) {
    findings.push(finding('medium', 'server-filename-not-generated', 'A política não exige nome gerado pelo servidor.', 'Use IDs ou nomes aleatórios gerados pelo servidor; não use o nome original como chave ou caminho de armazenamento.'));
  }
  if (!settings.inspectFileSignature) {
    findings.push(finding('medium', 'signature-inspection-not-configured', 'A política não declara inspeção de assinatura/magic bytes.', 'Valide o tipo real do arquivo com uma biblioteca confiável antes de processar ou publicar.'));
  }
  if (!settings.malwareScan) {
    findings.push(finding('info', 'malware-scan-not-configured', 'A política não declara verificação antimalware.', 'Considere análise antimalware ou quarentena para uploads de usuários, especialmente documentos e arquivos compactados.'));
  }
  if (!settings.storage.outsideWebRoot) {
    findings.push(finding('high', 'storage-inside-web-root-risk', 'A política não confirma armazenamento fora do web root.', 'Armazene uploads fora da raiz pública ou em object storage privado; entregue arquivos por uma camada controlada.'));
  }
  if (settings.storage.public) {
    findings.push(finding('medium', 'public-upload-storage', 'A política marca o armazenamento como público.', 'Restrinja leitura por padrão e use URLs assinadas ou autorização no download quando os arquivos não forem públicos.'));
  }
  if (!settings.storage.randomObjectKeys) {
    findings.push(finding('medium', 'predictable-storage-keys', 'A política não declara chaves aleatórias de armazenamento.', 'Use identificadores aleatórios e não deriváveis do nome original ou de IDs sequenciais.'));
  }
  if (!settings.storage.contentDispositionAttachment && DANGEROUS_CONTAINER_EXTENSIONS.has(item.extension)) {
    findings.push(finding('medium', 'inline-active-content-risk', 'Formato potencialmente ativo pode ser entregue inline sem Content-Disposition: attachment.', 'Para tipos ativos ou não confiáveis, prefira download como anexo e use domínio separado de conteúdo.'));
  }
  if (!settings.storage.separateUploadDomain && DANGEROUS_CONTAINER_EXTENSIONS.has(item.extension)) {
    findings.push(finding('low', 'same-origin-upload-content', 'Conteúdo potencialmente ativo pode compartilhar a origin principal da aplicação.', 'Considere servir uploads em domínio separado, com política de conteúdo restritiva e sem cookies da aplicação.'));
  }

  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const itemFinding of findings) counts[itemFinding.severity] += 1;

  return {
    file: item,
    policy: settings,
    findings,
    summary: {
      counts,
      highestSeverity: [...levels].reverse().find((level) => counts[level] > 0) ?? 'info',
      acceptedByDeclaredAllowlists: settings.allowedExtensions.includes(item.extension) && settings.allowedMimeTypes.includes(item.mimeType),
    },
    limitation: 'A revisão usa somente metadados e política locais. Ela não lê magic bytes, não descompacta arquivos, não executa antivírus e não confirma armazenamento, permissões ou entrega reais.',
  };
}

/**
 * O que é: revisor em lote para evidências locais de upload.
 * O que faz: aplica a mesma política a vários metadados e consolida achados, sem manipular os arquivos correspondentes.
 */
export function reviewUploadBatch(files, policy) {
  if (!Array.isArray(files)) throw new TypeError('files deve ser um array.');
  const results = files.map((file) => reviewUpload(file, policy));
  const allFindings = results.flatMap((result) => result.findings);
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const item of allFindings) counts[item.severity] += 1;

  return {
    policy: normalizeUploadPolicy(policy),
    results,
    summary: {
      filesReviewed: results.length,
      filesWithHighOrCritical: results.filter((result) => result.findings.some((item) => ['high', 'critical'].includes(item.severity))).length,
      totalFindings: allFindings.length,
      counts,
    },
  };
}

/**
 * O que é: função para proteger valores ao exportar CSV.
 * O que faz: escapa aspas e delimitadores, permitindo abrir o relatório em planilhas sem corromper colunas.
 */
function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * O que é: exportador CSV de revisão de uploads.
 * O que faz: gera uma linha por arquivo com tipo, tamanho, decisão por allowlist, severidade e códigos de achados.
 */
export function formatCsv(report) {
  const reports = Array.isArray(report?.results) ? report.results : [report];
  if (!reports.every((item) => item?.file && Array.isArray(item.findings))) throw new TypeError('Forneça um relatório individual ou em lote.');

  const header = ['filename', 'extension', 'declared_mime', 'detected_mime', 'size_bytes', 'accepted_by_allowlists', 'highest_severity', 'finding_codes'];
  const rows = reports.map((item) => [
    item.file.filename,
    item.file.extension,
    item.file.mimeType,
    item.file.detectedMimeType,
    item.file.sizeBytes,
    item.summary.acceptedByDeclaredAllowlists,
    item.summary.highestSeverity,
    item.findings.map((findingItem) => findingItem.code).join('; '),
  ].map(csvCell).join(','));

  return [header.join(','), ...rows].join('\n');
}

/**
 * O que é: gerador de relatório Markdown de revisão de upload.
 * O que faz: apresenta cada arquivo, metadados, decisão local e recomendações sem expor ou processar seu conteúdo.
 */
export function formatMarkdownReport(report) {
  const reports = Array.isArray(report?.results) ? report.results : [report];
  if (!reports.every((item) => item?.file && Array.isArray(item.findings))) throw new TypeError('Forneça um relatório individual ou em lote.');

  const clean = (value) => String(value ?? '—').replace(/\|/g, '\\|');
  const lines = [
    '# File Upload Review',
    '',
    `- **Arquivos revisados:** ${reports.length}`,
    '- **Escopo:** análise local de metadados e política; nenhum arquivo é enviado, aberto, executado ou acessado pela ferramenta.',
  ];

  for (const item of reports) {
    lines.push('', `## ${clean(item.file.filename)}`, '');
    lines.push(`- Extensão final: .${item.file.extension || 'não identificada'}`);
    lines.push(`- MIME declarado: ${item.file.mimeType || 'não informado'}`);
    lines.push(`- MIME detectado: ${item.file.detectedMimeType || 'não informado'}`);
    lines.push(`- Tamanho: ${item.file.sizeBytes} bytes`);
    lines.push(`- Aceito pelas allowlists declaradas: ${item.summary.acceptedByDeclaredAllowlists ? 'sim' : 'não'}`);
    lines.push(`- Maior severidade: ${item.summary.highestSeverity}`);
    lines.push('', '### Achados', '');

    if (item.findings.length === 0) lines.push('- Nenhum achado produzido pelas regras locais.');
    else {
      lines.push('| Severidade | Código | Observação | Recomendação |', '|---|---|---|---|');
      for (const issue of item.findings) {
        lines.push(`| ${issue.severity} | ${issue.code} | ${clean(issue.message)} | ${clean(issue.recommendation)} |`);
      }
    }
  }

  return lines.join('\n');
}

/**
 * O que é: função auxiliar para obter valores de flags da linha de comando.
 * O que faz: retorna o argumento logo após opções como --policy, --files, --format e --output.
 */
function getCliOption(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/**
 * O que é: função de ajuda da interface de terminal.
 * O que faz: explica como revisar metadados de arquivos locais contra uma política de upload sem manipular os arquivos reais.
 */
function showHelp() {
  console.log(`\nUso:\n  node file-upload-reviewer.js --policy upload-policy.json --files upload-evidence.json [opções]\n\nPolítica exemplo:\n  {\n    "allowedExtensions": ["jpg", "png", "pdf"],\n    "allowedMimeTypes": ["image/jpeg", "image/png", "application/pdf"],\n    "maxBytes": 5000000,\n    "inspectFileSignature": true,\n    "malwareScan": true,\n    "storage": {\n      "outsideWebRoot": true,\n      "public": false,\n      "randomObjectKeys": true,\n      "contentDispositionAttachment": true,\n      "separateUploadDomain": true\n    }\n  }\n\nEvidências exemplo:\n  [\n    { "name": "foto.jpg", "mimeType": "image/jpeg", "detectedMimeType": "image/jpeg", "sizeBytes": 240000 }\n  ]\n\nOpções:\n  --format FORMATO       json, csv ou markdown. Padrão: json\n  --output ARQUIVO       Salva relatório em arquivo local\n  --pretty               Formata JSON com indentação\n\nExemplo:\n  node file-upload-reviewer.js --policy upload-policy.json --files upload-evidence.json --format markdown --output upload-review.md\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const policyFile = getCliOption('policy');
  const filesFile = getCliOption('files');

  if (process.argv.includes('--help') || !policyFile || !filesFile) {
    showHelp();
    process.exitCode = process.argv.includes('--help') ? 0 : 1;
  } else {
    try {
      const [policy, data] = await Promise.all([
        readFile(policyFile, 'utf8').then(JSON.parse),
        readFile(filesFile, 'utf8').then(JSON.parse),
      ]);
      const files = Array.isArray(data) ? data : [data];
      const report = reviewUploadBatch(files, policy);
      const format = (getCliOption('format') ?? 'json').toLowerCase();
      const content = format === 'markdown'
        ? formatMarkdownReport(report)
        : format === 'csv'
          ? formatCsv(report)
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
