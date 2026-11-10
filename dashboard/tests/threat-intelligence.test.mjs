import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { IntelligenceResults } from '../src/pages/ThreatIntelligence.tsx';

test('recorded provider statuses, timestamps and summaries render safely', () => {
  const records = ['ok', 'not_found', 'rate_limited', 'unavailable'].map((status, id) => ({
    id, status, recorded_status: status === 'unavailable' ? 'error' : status,
    provider: '<provider>', lookup_timestamp: '2026-01-01T00:00:00Z', summary: { signal: '<script>' },
  }));
  const html = renderToStaticMarkup(React.createElement(IntelligenceResults, { records }));
  for (const status of ['ok', 'not_found', 'rate_limited', 'unavailable', 'error']) assert.ok(html.includes(status));
  assert.match(html, /2026-01-01/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(renderToStaticMarkup(React.createElement(IntelligenceResults, { records: [] })), /does not mean it is clean/);
});
