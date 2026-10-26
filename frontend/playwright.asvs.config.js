import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/asvs', timeout: 100000, workers: 1, fullyParallel: false,
  reporter: [['line']],
  use: { baseURL: 'https://app.soc.test:8443', browserName: 'chromium',
    viewport: { width: 1366, height: 768 }, ignoreHTTPSErrors: false,
    screenshot: 'off', trace: 'off', video: 'off' }
});
