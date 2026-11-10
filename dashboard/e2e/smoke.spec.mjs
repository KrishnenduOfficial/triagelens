import { test, expect } from '@playwright/test';

test('synthetic investigation across dashboard views', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.getByText('synthetic-incident')).toBeVisible();
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) await page.screenshot({ path: testInfo.outputPath('overview.png') });
  if (process.env.SMOKE_SCREENSHOTS) await page.screenshot({ path: '../docs/images/dashboard-overview.png', fullPage: true });
  await page.getByRole('link', { name: /Investigate/ }).click();
  await expect(page.getByText('AI output needs human review.')).toBeVisible();
  await expect(page.getByText('Synthetic advisory verdict')).toBeVisible();
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) await page.screenshot({ path: testInfo.outputPath('investigation.png') });
  if (process.env.SMOKE_SCREENSHOTS) await page.screenshot({ path: '../docs/images/dashboard-timeline.png', fullPage: true });
  await page.getByRole('link', { name: /Jump to source events/ }).click();
  await expect(page.getByRole('region', { name: 'Constituent Alert Sequence' })).toBeFocused();
  await page.getByRole('button', { name: 'Save review' }).click();
  await expect(page.getByText('Decision: confirm')).toBeVisible();
  await page.reload();
  await expect(page.getByText('Decision: confirm')).toBeVisible();

  await page.getByRole('link', { name: 'Alerts', exact: true }).click();
  await page.getByLabel('Dataset', { exact: true }).fill('synthetic-smoke');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByText('1 matching alert', { exact: true })).toBeVisible();
  const alertRow = page.getByRole('row').filter({ has: page.getByRole('button', { name: 'View', exact: true }) });
  await alertRow.getByRole('button').click();
  const expandedRow = page.getByRole('row').filter({ has: page.getByRole('button', { name: 'Hide', exact: true }) });
  await expect(expandedRow.getByRole('button')).toHaveAttribute('aria-expanded', 'true');
  const inlineDetail = expandedRow.locator('xpath=following-sibling::tr[1]').getByRole('region', { name: 'Alert detail' });
  await expect(inlineDetail.getByText(/fixture-host/)).toBeVisible();
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) {
    await page.getByRole('region', { name: 'Alert results' }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath('alert-details.png') });
  }
  await expandedRow.getByRole('button').click();
  await expect(page.getByRole('region', { name: 'Alert detail' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.getByLabel('Dataset', { exact: true })).toBeEmpty();

  await page.getByRole('link', { name: 'Threat intelligence' }).click();
  await page.getByLabel('Indicator').fill('example.invalid');
  await page.getByRole('button', { name: 'Find recorded lookups' }).click();
  await expect(page.getByRole('heading', { name: 'fixture-provider' })).toBeVisible();
  await expect(page.getByText(/Unavailable is not clean/)).toBeVisible();

  await page.getByRole('link', { name: 'Threat Hunting' }).click();
  await page.getByLabel('KQL-style hunting filter query').fill('event_type == "ProcessCreate"');
  await page.getByRole('button', { name: 'Run Query' }).click();
  await expect(page.getByRole('button', { name: 'Export returned results as JSON' })).toBeVisible();
  await page.getByRole('button', { name: 'Inspect', exact: true }).click();
  await expect(page.getByText(/Alert ID: [0-9a-f-]{36}/)).toBeVisible();
  await page.getByText('Saved queries', { exact: true }).click();
  await page.getByLabel('Query name').fill('smoke query');
  await page.getByRole('button', { name: 'Save query' }).click();
  await expect(page.getByText('smoke query', { exact: true })).toBeVisible();
  await page.reload();
  await page.locator('summary').filter({ hasText: 'Saved queries' }).click();
  await expect(page.getByText('smoke query', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('smoke query', { exact: true })).toHaveCount(0);

  await page.getByRole('link', { name: 'Detections', exact: true }).click();
  await expect(page.getByText('synthetic-rule')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'ATT&CK Enterprise annotation coverage' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'YARA scan results' })).toBeVisible();
  await expect(page.getByText(/fixture:synthetic_yara/)).toBeVisible();
  await page.getByRole('link', { name: /Jump to ATT&CK coverage/ }).click();
  await expect(page.getByRole('region', { name: 'ATT&CK Enterprise annotation coverage' })).toBeFocused();
  const matrix = page.getByRole('region', { name: 'ATT&CK technique matrix' });
  await expect(matrix.getByRole('heading').first()).toHaveText('Reconnaissance');
  await expect(matrix.getByRole('heading').last()).toHaveText('Impact');
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) await page.screenshot({ path: testInfo.outputPath('attack-matrix.png') });
  const commandInterpreter = matrix.getByLabel(/Command and Scripting Interpreter: .* sub-techniques/);
  const powershell = matrix.getByText('T1059.001', { exact: true });
  await expect(powershell).toBeHidden();
  await commandInterpreter.click();
  await expect(powershell).toBeVisible();
  const techniqueSearch = page.getByRole('searchbox', { name: 'Find a technique' });
  await techniqueSearch.fill('T1059.001');
  await expect(powershell).toBeVisible();
  await expect(matrix.getByText('T1059', { exact: true })).toBeVisible();
  await techniqueSearch.clear();
  await page.getByRole('checkbox', { name: 'Recorded hits only' }).check();
  const systemDiscovery = matrix.getByRole('region', { name: 'Discovery', exact: true });
  await expect(systemDiscovery.getByText('T1082', { exact: true })).toBeVisible();
  await expect(systemDiscovery.getByText('Sigma: recorded', { exact: true })).toBeVisible();
  await expect(systemDiscovery.getByText('YARA: none', { exact: true })).toBeVisible();
  await expect(powershell).toHaveCount(0);
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) {
    await page.getByRole('region', { name: 'ATT&CK Enterprise annotation coverage' }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath('attack-coverage.png') });
  }
});

test('workspace navigation and tables fit a phone viewport', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('main')).toBeFocused();
  const menu = page.getByRole('button', { name: 'Menu' });
  const navigation = page.getByRole('navigation', { name: 'Main Navigation' });
  const fitsViewport = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
  await expect(page.getByText('synthetic-incident')).toBeAttached();
  await expect(page.getByRole('link', { name: /Investigate/ })).toBeInViewport();
  expect(await fitsViewport()).toBe(true);
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) await page.screenshot({ path: testInfo.outputPath('phone.png') });

  await menu.focus();
  await page.keyboard.press('Enter');
  await expect(menu).toHaveAttribute('aria-expanded', 'true');
  await navigation.getByRole('link', { name: 'Alerts', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Alerts', exact: true })).toBeVisible();
  await expect(page.getByRole('main')).toBeFocused();
  await expect(menu).toHaveAttribute('aria-expanded', 'false');
  await expect(navigation).toBeHidden();
  await expect(page.getByText('1 matching alert', { exact: true })).toBeVisible();
  const view = page.getByRole('button', { name: 'View', exact: true });
  await view.scrollIntoViewIfNeeded();
  await expect(view).toBeInViewport();
  await view.press('Enter');
  await expect(page.getByRole('region', { name: 'Alert detail' })).toBeVisible();
  expect(await fitsViewport()).toBe(true);

  const open = async (name) => {
    await menu.click();
    await navigation.getByRole('link', { name, exact: true }).click();
  };
  await open('Threat Hunting');
  await page.getByRole('button', { name: 'Process Creation' }).click();
  await page.getByRole('button', { name: 'Inspect', exact: true }).click();
  await expect(page.getByText(/Alert ID: [0-9a-f-]{36}/)).toBeVisible();
  expect(await fitsViewport()).toBe(true);

  await open('Threat intelligence');
  await page.getByLabel('Indicator').fill('example.invalid');
  await page.getByRole('button', { name: 'Find recorded lookups' }).click();
  await expect(page.getByRole('heading', { name: 'fixture-provider' })).toBeVisible();
  expect(await fitsViewport()).toBe(true);

  await open('Detections');
  await expect(page.getByRole('region', { name: 'ATT&CK technique matrix' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Tactic', exact: true }).selectOption('discovery');
  const mobileMatrix = page.getByRole('region', { name: 'ATT&CK technique matrix' });
  await expect(mobileMatrix.getByRole('heading')).toHaveText('Discovery');
  await page.getByRole('searchbox', { name: 'Find a technique' }).fill('T1082');
  await expect(mobileMatrix.getByText('System Information Discovery', { exact: true })).toBeVisible();
  expect(await fitsViewport()).toBe(true);
  if (process.env.SMOKE_LAYOUT_SCREENSHOTS) {
    await mobileMatrix.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath('attack-phone.png') });
  }

  await open('Overview Dashboard');
  await page.getByRole('link', { name: /Investigate/ }).click();
  await expect(page.getByRole('heading', { name: 'synthetic-incident' })).toBeVisible();
  expect(await fitsViewport()).toBe(true);
});
