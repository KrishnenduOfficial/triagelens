import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:18742', viewport: { width: 1440, height: 900 }, channel: process.env.SMOKE_BROWSER || 'chromium' },
  webServer: [
    { command: `"${process.env.SMOKE_PYTHON || 'python'}" ../scripts/dashboard_smoke_server.py`, url: 'http://127.0.0.1:18741/api/alerts', reuseExistingServer: false, timeout: 30000 },
    { command: 'npm run dev -- --host 127.0.0.1 --port 18742 --strictPort', url: 'http://127.0.0.1:18742', reuseExistingServer: false, timeout: 30000,
      env: { VITE_API_BASE_URL: 'http://127.0.0.1:18741' } },
  ],
});
