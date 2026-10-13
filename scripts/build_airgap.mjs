import fs from 'fs';
import path from 'path';

const wasmPath = path.resolve('web/pkg/scafonix_wasm_bg.wasm');
const jsPath = path.resolve('web/pkg/scafonix_wasm.js');
const indexPath = path.resolve('web/index.html');
const outPath = path.resolve('web/scafonix-vault-airgap.html');

console.log('Building standalone airgap HTML...');
const wasmBytes = fs.readFileSync(wasmPath);
const wasmBase64 = wasmBytes.toString('base64');
let wasmJs = fs.readFileSync(jsPath, 'utf8');

// Modify wasmJs so that it doesn't try to fetch or import.meta.url
// Instead, expose initSync with inline base64
const inlineInit = `
const _WASM_B64 = "${wasmBase64}";
function _base64ToUint8Array(base64) {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
}
export async function initAirgap() {
  const wasmModuleBytes = _base64ToUint8Array(_WASM_B64);
  initSync({ module: wasmModuleBytes });
}
`;

wasmJs = wasmJs.replace('export default function __wbg_init', 'function __wbg_init');
wasmJs += inlineInit;

// Read index.html and adapt for standalone airgap
let indexHtml = fs.readFileSync(indexPath, 'utf8');

// Replace the <script type="module"> section to use inline wasm code
const marker = '<script type="module">';
const scriptStartIdx = indexHtml.indexOf(marker);
const scriptEndIdx = indexHtml.lastIndexOf('</script>');

let appScript = indexHtml.substring(scriptStartIdx + marker.length, scriptEndIdx);
// Replace the import with local functions from the inlined wasmJs
appScript = appScript.replace(/import init, \{[\s\S]*?\} from '\.\/pkg\/scafonix_wasm\.js';/, '');
appScript = appScript.replace('await init();', 'await initAirgap();');

// Inline favicon.svg as base64 data URI for 100% self-contained offline usage
const faviconPath = path.resolve('web/favicon.svg');
if (fs.existsSync(faviconPath)) {
  const faviconSvg = fs.readFileSync(faviconPath, 'utf8');
  const faviconB64 = Buffer.from(faviconSvg).toString('base64');
  indexHtml = indexHtml.replaceAll('./favicon.svg', `data:image/svg+xml;base64,${faviconB64}`);
}

// Also update title and badge for clarity
indexHtml = indexHtml.replace(
  'Scafonix Vault — Programmable MPC Vault (pEOA)',
  'Scafonix Vault — Standalone Air-Gap Edition (100% Offline)'
);

const standaloneScript = `
<script type="module">
// --- EMBEDDED SCAFONIX WASM CORE ---
${wasmJs}

// --- AIRGAP APPLICATION LOGIC ---
${appScript}
</script>
`;

const standaloneHtml = indexHtml.substring(0, scriptStartIdx) + standaloneScript + indexHtml.substring(scriptEndIdx + 9);

fs.writeFileSync(outPath, standaloneHtml);
const stats = fs.statSync(outPath);
console.log(`Standalone Air-Gap HTML built successfully: ${outPath} (${(stats.size / 1024).toFixed(1)} KB)`);
