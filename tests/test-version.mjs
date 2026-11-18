import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = dirname(dirname(fileURLToPath(import.meta.url)));
const exe = process.env.PM_SERVER_CLI
  || join(pkg, 'build', 'dev', process.platform === 'win32' ? 'pm-server.exe' : 'pm-server');

if (!existsSync(exe)) {
  console.error('pm-server is not built. From packages/server.cpp: npm run build:cpp');
  process.exit(1);
}

const run = spawnSync(exe, ['version'], { encoding: 'utf8', cwd: pkg });
let json = null;
try {
  json = JSON.parse((run.stdout || '').trim());
} catch {
  json = null;
}
if (run.status !== 0 || !json?.ok || json.role !== 'server') {
  console.error('FAIL version', run.status, run.stdout, run.stderr);
  process.exit(1);
}
console.log('ok: version');
