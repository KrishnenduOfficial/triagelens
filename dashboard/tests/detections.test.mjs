import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { DetectionResults, DetectionState } from '../src/pages/Detections.tsx';

test('recorded results retain source, uncertainty and safe text', () => {
  const props = { rules: [], issues: [{source:'<rule>', status:'unsupported', reason:'field'}],
    hits: [{id:'1', rule_id:'<script>', source:'sigma', detected_at:'now', event_ids:['event'], technique_ids:null}],
    scans: [{scan_id:'s', status:'timeout', sha256:null, ended_at:'now', engine:'yara-x', version:null, matches:[], diagnostics:[{category:'timeout'}]}],
    rows: [{tactic:'execution', technique_id:'T1082', name:'example', parent:null, sources:{sigma:true,yara:false}}] };
  const html = renderToStaticMarkup(React.createElement(DetectionResults, props));
  assert.match(html, /&lt;script&gt;/); assert.doesNotMatch(html, /<script>/);
  for (const text of ['unsupported', 'timeout', 'unavailable', 'Sigma: recorded', 'YARA: none', 'not detection effectiveness']) assert.ok(html.includes(text));
  const empty = renderToStaticMarkup(React.createElement(DetectionResults, {rules:[], issues:[], hits:[], scans:[], rows:[]}));
  assert.match(empty, /No recorded scans/); assert.match(empty, /does not establish that rules were evaluated/);
  assert.match(empty, /No coverage annotations available/);
});

test('detection loading and error states are distinguishable and offer retry', () => {
  const render = props => renderToStaticMarkup(React.createElement(DetectionState, { retry: () => {}, ...props }));
  assert.match(render({loading:true, error:''}), /role="status"/);
  const failed = render({loading:false, error:'Unable to load <results>'});
  assert.match(failed, /role="alert"/); assert.match(failed, /&lt;results&gt;/); assert.match(failed, /Retry/);
  assert.equal(render({loading:false, error:''}), '');
});
