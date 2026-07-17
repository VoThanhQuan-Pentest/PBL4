import { defineConfig } from '@playwright/test';

const chromiumPath = process.env.CHROMIUM_PATH;
const chromiumLaunchOptions = chromiumPath ? { executablePath: chromiumPath } : {};

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 45_000,
  workers: 1,
  fullyParallel: false,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:8088',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    // Video requires Playwright's FFmpeg binary. Keep it opt-in so a normal
    // local/CI run only needs the version-matched Chromium browser.
    video: process.env.PLAYWRIGHT_VIDEO === '1' ? 'retain-on-failure' : 'off'
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: {
        browserName: 'chromium',
        launchOptions: chromiumLaunchOptions,
        viewport: { width: 1440, height: 900 }
      }
    },
    {
      name: 'mobile-chromium',
      use: {
        browserName: 'chromium',
        launchOptions: chromiumLaunchOptions,
        viewport: { width: 390, height: 844 },
        isMobile: true
      }
    }
  ]
});
