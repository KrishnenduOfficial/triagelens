import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AnalystReviewSummary, HumanReviewNotice } from '../src/pages/TimelineView.tsx';

test('analyst review displays the recorded decision and escapes rationale', () => {
  const html = renderToStaticMarkup(React.createElement(AnalystReviewSummary, { review: {
    verdict_id: 'v1', decision: 'override', override_disposition: 'BENIGN',
    rationale: '<script>bad</script>', created_at: '2026-11-10T00:00:00Z',
  } }));
  assert.match(html, /override/);
  assert.match(html, /BENIGN/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
});

test('AI assessment notice states analyst authority', () => {
  const html = renderToStaticMarkup(React.createElement(HumanReviewNotice));
  assert.match(html, /AI output needs human review/);
  assert.match(html, /never the final authority/);
});
