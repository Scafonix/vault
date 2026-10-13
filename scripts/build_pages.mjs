import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

console.log('1. Building standalone airgap HTML...');
execSync('node scripts/build_airgap.mjs', { stdio: 'inherit' });

console.log('2. Syncing to docs/ for GitHub Pages...');
const docsDir = path.resolve('docs');
if (!fs.existsSync(docsDir)) {
  fs.mkdirSync(docsDir, { recursive: true });
}

// Copy web files to docs/
fs.cpSync('web/index.html', 'docs/index.html');
fs.cpSync('web/scafonix-vault-airgap.html', 'docs/scafonix-vault-airgap.html');
fs.cpSync('web/favicon.svg', 'docs/favicon.svg');
fs.cpSync('web/pkg', 'docs/pkg', { recursive: true });

// GitHub Pages configuration files
fs.writeFileSync('docs/.nojekyll', '');
fs.writeFileSync('docs/CNAME', 'vault.scafonix.com\n');

console.log('3. docs/ prepared for GitHub Pages deployment.');
console.log('   - docs/index.html');
console.log('   - docs/scafonix-vault-airgap.html');
console.log('   - docs/pkg/');
console.log('   - docs/.nojekyll');
console.log('   - docs/CNAME (vault.scafonix.com)');
