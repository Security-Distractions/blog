/* Render icon.html to every size the site needs, then pack the .ico.
 *
 * Playwright is not a dependency of this repo. Run it from a directory that has one installed —
 * on util-debian that is /opt/compromise-canvas:
 *
 *   cp tools/favicon/build.mjs /opt/compromise-canvas/ && (node build.mjs /opt/blog/site)
 *
 * Then: python3 tools/favicon/pack-ico.py static/favicon.ico <16> <32> <48>
 */
import { chromium } from '@playwright/test';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const site = process.argv[2] || '/opt/blog/site';
const tmp = mkdtempSync(join(tmpdir(), 'favicon-'));
const tpl = `file://${site}/tools/favicon/icon.html`;

const b = await chromium.launch();
for (const s of [512, 180, 48, 32, 16]) {
  const p = await b.newPage({ viewport: { width: s, height: s }, deviceScaleFactor: 1 });
  await p.goto(`${tpl}?size=${s}`);
  await p.waitForTimeout(200);
  await p.screenshot({ path: `${tmp}/icon-${s}.png` });
  await p.close();
}
await b.close();
console.log(`rendered into ${tmp}
  cp ${tmp}/icon-16.png  ${site}/static/favicon-16x16.png
  cp ${tmp}/icon-32.png  ${site}/static/favicon-32x32.png
  cp ${tmp}/icon-180.png ${site}/static/apple-touch-icon.png
  cp ${tmp}/icon-512.png ${site}/static/icon-512.png
  python3 ${site}/tools/favicon/pack-ico.py ${site}/static/favicon.ico ${tmp}/icon-{16,32,48}.png`);
