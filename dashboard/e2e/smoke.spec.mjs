import { test, expect } from '@playwright/test';

test('synthetic investigation across dashboard views', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('synthetic-incident')).toBeVisible();
  if (process.env.SMOKE_SCREENSHOTS) await page.screenshot({ path: '../docs/images/dashboard-overview.png', fullPage: true });
  await page.getByRole('link', { name: /Investigate/ }).click();
  await expect(page.getByText('AI output needs human review.')).toBeVisible();
  await expect(page.getByText('Synthetic advisory verdict')).toBeVisible();
  if (process.env.SMOKE_SCREENSHOTS) await page.screenshot({ path: '../docs/images/dashboard-timeline.png', fullPage: true });
  await page.getByRole('button', { name: 'Save review' }).click();
  await expect(page.getByText('Decision: confirm')).toBeVisible();
  await page.reload();
  await expect(page.getByText('Decision: confirm')).toBeVisible();

  await page.getByRole('link', { name: 'Alerts', exact: true }).click();
  await page.getByLabel('Dataset', { exact: true }).fill('synthetic-smoke');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByText('1 matching alerts')).toBeVisible();
  await page.getByRole('button', { name: 'View', exact: true }).click();
  await expect(page.getByText('fixture-host')).toBeVisible();

  await page.getByRole('link', { name: 'Threat intelligence' }).click();
  await page.getByLabel('Indicator').fill('example.invalid');
  await page.getByRole('button', { name: 'Find recorded lookups' }).click();
  await expect(page.getByRole('heading', { name: 'fixture-provider' })).toBeVisible();
  await expect(page.getByText(/Unavailable is not clean/)).toBeVisible();

  await page.getByRole('link', { name: 'Threat Hunting' }).click();
  await page.getByLabel('KQL-style hunting filter query').fill('event_type == "ProcessCreate"');
  await page.getByRole('button', { name: 'Run Query' }).click();
  await expect(page.getByRole('button', { name: 'Export returned results as JSON' })).toBeVisible();
  await page.getByLabel('Query name').fill('smoke query');
  await page.getByRole('button', { name: 'Save query' }).click();
  await expect(page.getByText('smoke query', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText('smoke query', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('smoke query', { exact: true })).toHaveCount(0);

  await page.getByRole('link', { name: 'Detections', exact: true }).click();
  await expect(page.getByText('synthetic-rule')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'ATT&CK Enterprise annotation coverage' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'YARA scan results' })).toBeVisible();
  await expect(page.getByText(/fixture:synthetic_yara/)).toBeVisible();
});
