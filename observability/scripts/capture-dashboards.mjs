import { readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';

const password = (await readFile('/run/flare-secrets/analyst.password', 'utf8')).trim();
const authorization = `Basic ${Buffer.from(`flare_analyst:${password}`).toString('base64')}`;
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  extraHTTPHeaders: { authorization },
});
const page = await context.newPage();
page.on('response', response => {
  if (response.status() >= 400) {
    console.error(`HTTP ${response.status()} ${response.url()}`);
  }
});

for (const [id, filename, expectedPanels] of [
  ['flare-overview', 'overview.png', 8],
  ['flare-geoip', 'geoip.png', 4],
  ['flare-security', 'security.png', 6],
]) {
  const url = `http://127.0.0.1:5601/s/flare-lab/app/dashboards#/view/${id}?_g=(refreshInterval:(pause:!t,value:60000),time:(from:now-24h,to:now))`;
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 120_000 });
  try {
    await page.locator([
      '[data-test-subj="dashboardViewport"]',
      '[data-test-subj="dashboardPanel"]',
      '[data-test-subj^="embeddablePanel"]',
    ].join(',')).first().waitFor({ state: 'visible', timeout: 45_000 });
  } catch (error) {
    const body = (await page.locator('body').innerText()).replaceAll(/\s+/g, ' ').slice(0, 500);
    throw new Error(`dashboard ${id} did not render; url=${page.url()}; title=${await page.title()}; body=${body}`, { cause: error });
  }
  await page.waitForTimeout(8_000);
  const panelCount = await page.locator('[data-test-subj="dashboardPanel"]').count();
  if (panelCount < expectedPanels) {
    throw new Error(`dashboard ${id} rendered ${panelCount}/${expectedPanels} panels`);
  }
  const visibleErrors = await page.getByText('Error', { exact: true }).evaluateAll(elements =>
    elements.filter(element => element.checkVisibility()).length
  );
  if (visibleErrors > 0) {
    throw new Error(`dashboard ${id} contains ${visibleErrors} failed panels`);
  }
  if (await page.getByText(/You do not have permission|Forbidden/i).count()) {
    throw new Error(`analyst cannot view dashboard ${id}`);
  }
  await page.screenshot({ path: `/evidence/${filename}`, fullPage: false });
}

await browser.close();
