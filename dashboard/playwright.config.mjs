import { defineConfig } from '@playwright/test';

function smokePort(variable, fallback) {
  const port = Number(process.env[variable] ?? fallback);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`${variable} must be a port from 1024 to 65535`);
  }
  return port;
}

const apiPort = smokePort('TRIAGELENS_SMOKE_API_PORT', 18741);
const uiPort = smokePort('TRIAGELENS_SMOKE_UI_PORT', 18742);
const apiURL = `http://127.0.0.1:${apiPort}`;
const baseURL = `http://127.0.0.1:${uiPort}`;

export default defineConfig({
  testDir: './e2e',
  workers: 1,
  use: { baseURL, viewport: { width: 1440, height: 900 }, channel: process.env.SMOKE_BROWSER || 'chromium' },
  webServer: [
    { command: `"${process.env.SMOKE_PYTHON || 'python'}" ../scripts/dashboard_smoke_server.py`, url: `${apiURL}/api/alerts`, reuseExistingServer: false, timeout: 30000,
      env: { TRIAGELENS_SMOKE_API_PORT: String(apiPort), TRIAGELENS_SMOKE_UI_PORT: String(uiPort) } },
    { command: `npm run dev -- --host 127.0.0.1 --port ${uiPort} --strictPort`, url: baseURL, reuseExistingServer: false, timeout: 30000,
      env: { VITE_API_BASE_URL: apiURL } },
  ],
});
