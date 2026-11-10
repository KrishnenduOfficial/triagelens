import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { DetectionResults } from '../src/pages/Detections.tsx';

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
});
