import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { apiClient, fetchMetrics } from '../src/api/apiService.ts';
import { buildMetricQuery, formatPercent, validateMetricQuery, validateMetricResponse } from '../src/metrics/presentation.ts';
import { createMetricsLoader } from '../src/metrics/request.ts';
import { MetricRequestView, MetricResults, MetricsOverview } from '../src/components/MetricsOverview.tsx';
import { DashboardHome } from '../src/pages/DashboardHome.tsx';

const run = '11111111-1111-4111-8111-111111111111';
const cohort = 'a'.repeat(64);
const text = element => renderToStaticMarkup(element).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
const fixture = (scope = 'history', overrides = {}) => ({
  accuracy: .5, precision: 1, recall: .5, f1_score: 2 / 3,
  false_positive_rate: 0, false_negative_rate: .5, fpr_valid: false, fnr_valid: true,
  tp: 1, tn: 0, fp: 0, fn: 1, true_positives: 1, true_negatives: 0, false_positives: 0, false_negatives: 1,
  total: 2, unknown: 1, unavailable: 2, availability_rate: .6,
  severity_evaluated: 3, severity_matches: 2, severity_accuracy: 2 / 3,
  accuracy_ci95: [.1, .9], precision_ci95: [.2, 1], recall_ci95: [.1, .9],
  brier_score: .25, expected_calibration_error: .1,
  selection: {
    scope, source: 'database', unit: {history:'evaluation_row',run:'run_evaluation_row',quality:'verdict_context',attempts:'completed_fresh_attempt'}[scope],
    run_id: scope === 'run' || scope === 'attempts' ? run : null, run_status: 'completed',
    cohort_id: scope === 'quality' ? cohort : null, cohort_kind: scope === 'quality' ? 'declared' : null,
    availability_status: scope === 'quality' ? 'not_applicable_to_quality' : scope === 'attempts' ? 'fresh_result_availability' : 'result_availability',
    coverage: {evaluation_rows: 5, selected_units: 5, fresh: 2, cache: 3, skipped: 4, pending: 1, interrupted: 1,
      unknown_origin: 0, legacy_unknown: 1, excluded_legacy_unknown: 0, unique_evidence: 2, repeated_evidence: 3,
      excluded_unverifiable: 0, excluded_no_verdict: 0, deduplicated: 0, missing_outcomes: 0},
    denominators: {binary: 2, severity: 3, calibration: 3, availability: scope === 'quality' ? null : 5},
  }, ...overrides,
});

test('history is the initial dashboard selection', () => {
  const html = renderToStaticMarkup(React.createElement(MetricsOverview));
  assert.match(html, /value="history" selected/);
  assert.doesNotMatch(html, /value="quality" selected/);
});

for (const [scope, selector, value, expected] of [
  ['history', 'run', '', {scope:'history'}],
  ['run', 'run', run, {scope:'run',run_id:run}],
  ['quality', 'cohort', cohort, {scope:'quality',cohort_id:cohort}],
  ['attempts', 'run', run, {scope:'attempts',run_id:run}],
  ['attempts', 'cohort', cohort, {scope:'attempts',cohort_id:cohort}],
]) test(`selector: ${scope}/${selector}`, () => assert.deepEqual(buildMetricQuery(scope, selector, value), expected));

for (const [scope, selector, value] of [['run','run',''],['quality','cohort','bad'],['attempts','run','bad'],['bad','run',run]]) {
  test(`invalid selector: ${scope}/${value}`, () => assert.throws(() => buildMetricQuery(scope,selector,value)));
}

test('null, absent, nonfinite, and zero percentages remain distinct', () => {
  for (const value of [null, undefined, NaN, Infinity]) assert.equal(formatPercent(value), 'N/A');
  assert.equal(formatPercent(0), '0.0%');
});

test('history discloses replay counting, source, and separate lifecycle counts', () => {
  const html = text(React.createElement(MetricResults, {metrics: fixture()}));
  for (const label of ['History', 'evaluation rows', 'Database', 'Unknown binary labels', 'Unavailable outcomes', 'Skipped', 'Cache', 'Legacy', 'Repeated evidence']) assert.ok(html.includes(label), label);
  assert.doesNotMatch(html, /Unlabeled \/ Skipped/);
  assert.match(html, /Unknown binary labels 1/);
  assert.match(html, /Unavailable outcomes 2/);
  assert.match(html, /Skipped 4/);
  assert.match(html, /Result availability 60.0%/);
  assert.match(html, /5 completed results/);
});

test('empty binary data and undefined FPR render N/A without changing payload', () => {
  const metrics = fixture('history', {accuracy:0,total:0,tp:0,tn:0,fp:0,fn:0});
  const html = text(React.createElement(MetricResults, {metrics}));
  assert.match(html, /Model accuracy N\/A/);
  assert.match(html, /False positive rate N\/A/);
  assert.equal(metrics.accuracy, 0);
});

test('quality has no availability percentage and shows cohort membership coverage', () => {
  const metrics = fixture('quality', {availability_rate:null});
  metrics.selection.coverage.manifest_cases = 4;
  metrics.selection.coverage.missing_cases = 1;
  const html = text(React.createElement(MetricResults, {metrics}));
  assert.match(html, /Quality/);
  assert.match(html, /Availability Not applicable/);
  assert.match(html, /Manifest cases 4/);
  assert.ok(html.includes(cohort));
});

test('replay-only attempts explain null availability and logical counting', () => {
  const metrics = fixture('attempts', {total:0,unknown:0,unavailable:0,availability_rate:null});
  metrics.selection.denominators.availability = 0;
  metrics.selection.availability_status = 'no_completed_fresh_attempts';
  const html = text(React.createElement(MetricResults, {metrics}));
  assert.match(html, /Fresh result availability N\/A/);
  assert.match(html, /No completed fresh attempts/);
  assert.match(html, /logical/);
  assert.doesNotMatch(html, /Fresh result availability 0.0%/);
});

test('severity, calibration, intervals and sample caveat have denominator context', () => {
  const html = text(React.createElement(MetricResults, {metrics:fixture()}));
  for (const label of ['Severity accuracy', '3 severity', 'Brier', '3 calibration', '95%', '10.0%', '90.0%', 'independent', 'provider uptime']) assert.ok(html.includes(label),label);
});

test('legacy history remains usable with provenance explicitly unavailable', () => {
  const metrics = fixture();
  delete metrics.selection;
  delete metrics.unavailable;
  delete metrics.availability_rate;
  const html = text(React.createElement(MetricResults, {metrics}));
  assert.match(html, /History/);
  assert.match(html, /Scope metadata unavailable/);
  assert.match(html, /Unavailable outcomes N\/A/);
  assert.match(html, /Result availability N\/A/);
  assert.doesNotMatch(html, /Result availability 100.0%/);
});

test('default and explicit selectors are sent without inventing a latest run', async () => {
  const calls=[];
  const old=apiClient.defaults.adapter;
  apiClient.defaults.adapter=async config=>{calls.push(config);return {data:fixture(config.params?.scope),status:200,statusText:'OK',headers:{},config};};
  try {
    await fetchMetrics();
    assert.equal(calls[0].url,'/api/metrics');
    assert.equal(calls[0].params,undefined);
    await fetchMetrics({scope:'run',run_id:run});
    assert.deepEqual(calls[1].params,{scope:'run',run_id:run});
  } finally {apiClient.defaults.adapter=old;}
});

test('explicit scope rejects metadata mismatch instead of using history', async () => {
  const old=apiClient.defaults.adapter;
  apiClient.defaults.adapter=async config=>({data:fixture(),status:200,statusText:'OK',headers:{},config});
  try {await assert.rejects(fetchMetrics({scope:'quality',cohort_id:cohort}), /scope|selection/i);}
  finally {apiClient.defaults.adapter=old;}
});

test('latest request wins even when an older request ignores cancellation', async () => {
  const pending=[], updates=[];
  const loader=createMetricsLoader((query,signal)=>new Promise(resolve=>pending.push({query,signal,resolve})));
  loader.load({scope:'history'},state=>updates.push(state));
  loader.load({scope:'quality',cohort_id:cohort},state=>updates.push(state));
  assert.equal(pending[0].signal.aborted,true);
  pending[1].resolve(fixture('quality',{availability_rate:null}));
  await new Promise(resolve=>setImmediate(resolve));
  pending[0].resolve(fixture());
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(updates.at(-1).metrics.selection.scope,'quality');
  assert.equal(updates.filter(s=>s.status==='ready').length,1);
});

test('failed new scope clears results and keeps error attached to its selection', async () => {
  const updates=[];
  const loader=createMetricsLoader(async()=>{throw new Error('[API 409] Conflicting canonical quality snapshots');});
  loader.load({scope:'quality',cohort_id:cohort},state=>updates.push(state));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(updates.at(-1).status,'error');
  assert.equal(updates.at(-1).metrics,null);
  assert.equal(updates.at(-1).query.cohort_id,cohort);
  assert.match(updates.at(-1).error,/409/);
});

test('cleanup suppresses completion after unmount or StrictMode cleanup', async () => {
  let resolve;
  const updates=[];
  const loader=createMetricsLoader(()=>new Promise(done=>{resolve=done;}));
  const cancel=loader.load({scope:'history'},state=>updates.push(state));
  cancel();resolve(fixture());
  await new Promise(done=>setImmediate(done));
  assert.equal(updates.filter(s=>s.status==='ready').length,0);
});

test('dashboard makes no unconditional live-provider claim', () => {
  const html=text(React.createElement(DashboardHome));
  assert.doesNotMatch(html,/Cloud LLM Active|Pipeline Online/);
  assert.match(html,/Live provider status not checked/);
});

test('draft input trims and normalizes identifiers without adding hidden selectors', () => {
  assert.deepEqual(buildMetricQuery('quality','run',`  ${cohort.toUpperCase()} `),{scope:'quality',cohort_id:cohort});
  assert.deepEqual(buildMetricQuery('history','cohort',cohort),{scope:'history'});
});

for (const query of [
  {scope:'history',run_id:run}, {scope:'run',run_id:run,cohort_id:cohort},
  {scope:'attempts'}, {scope:'attempts',run_id:run,cohort_id:cohort}, {scope:'history',latest:true},
]) test(`ambiguous programmatic selectors are rejected: ${JSON.stringify(query)}`, () => {
  assert.throws(()=>validateMetricQuery(query));
});

test('old history API is accepted but cannot satisfy explicit run selection', () => {
  const metrics=fixture();delete metrics.selection;
  assert.doesNotThrow(()=>validateMetricResponse(metrics,{scope:'history'}));
  assert.throws(()=>validateMetricResponse(metrics,{scope:'run',run_id:run}),/selection/);
});

for (const mutation of ['source','cohort','denominator','count','rate','missing_core']) {
  test(`malformed response rejected: ${mutation}`, () => {
    const metrics=fixture('quality',{availability_rate:null});
    if(mutation==='source') metrics.selection.source='memory';
    if(mutation==='cohort') metrics.selection.cohort_id='b'.repeat(64);
    if(mutation==='denominator') metrics.selection.denominators.binary=999;
    if(mutation==='count') metrics.selection.coverage.cache=-1;
    if(mutation==='rate') metrics.accuracy=NaN;
    if(mutation==='missing_core') delete metrics.total;
    assert.throws(()=>validateMetricResponse(metrics,{scope:'quality',cohort_id:cohort}));
  });
}

test('in-memory history fallback is visible without claiming persisted results', () => {
  const metrics=fixture();metrics.selection.source='memory';
  const html=text(React.createElement(MetricResults,{metrics}));
  assert.match(html,/In-memory tracker/);
  assert.match(html,/stored history is empty/i);
  assert.doesNotMatch(html,/Persisted evaluation rows/);
});

for(const status of [404,409,422]) test(`API ${status} remains an error without a history retry`, async()=>{
  let calls=0;
  const old=apiClient.defaults.adapter;
  apiClient.defaults.adapter=async config=>{
    calls++;
    throw {isAxiosError:true,response:{status,data:{detail:'Selected scope rejected'}},config,message:'Rejected'};
  };
  try {await assert.rejects(fetchMetrics({scope:'quality',cohort_id:cohort}),new RegExp(`API ${status}`));assert.equal(calls,1);}
  finally {apiClient.defaults.adapter=old;}
});

test('all five wire selector combinations pass the API response contract', async()=>{
  const old=apiClient.defaults.adapter;
  const calls=[];
  apiClient.defaults.adapter=async config=>{
    calls.push(config);
    const query=config.params??{scope:'history'};
    const data=fixture(query.scope,{availability_rate:query.scope==='quality'?null:.6});
    data.selection.run_id=query.run_id??null;
    data.selection.run_status=query.run_id?'completed':null;
    data.selection.cohort_id=query.cohort_id??null;
    data.selection.cohort_kind=query.cohort_id?'declared':null;
    return {data,status:200,statusText:'OK',headers:{},config};
  };
  const controller=new AbortController();
  try{
    for(const query of [{scope:'history'},{scope:'run',run_id:run},{scope:'quality',cohort_id:cohort},
      {scope:'attempts',run_id:run},{scope:'attempts',cohort_id:cohort}]){
      const data=await fetchMetrics(query,controller.signal);
      assert.equal(data.selection.scope,query.scope);
      assert.deepEqual(calls.at(-1).params,query.scope==='history'?undefined:query);
      assert.equal(calls.at(-1).signal,controller.signal);
    }
  }finally{apiClient.defaults.adapter=old;}
});

test('zero-attempt contract rejects a fabricated availability percentage', ()=>{
  const metrics=fixture('attempts',{availability_rate:null});
  metrics.selection.denominators.availability=0;
  metrics.selection.availability_status='no_completed_fresh_attempts';
  assert.doesNotThrow(()=>validateMetricResponse(metrics,{scope:'attempts',run_id:run}));
  metrics.availability_rate=1;
  assert.throws(()=>validateMetricResponse(metrics,{scope:'attempts',run_id:run}),/availability/);
});

test('cleanup from an older effect does not cancel the newer request',async()=>{
  const pending=[], updates=[];
  const loader=createMetricsLoader((query,signal)=>new Promise(resolve=>pending.push({query,signal,resolve})));
  const oldCleanup=loader.load({scope:'history'},state=>updates.push(state));
  loader.load({scope:'run',run_id:run},state=>updates.push(state));
  oldCleanup();
  assert.equal(pending[1].signal.aborted,false);
  pending[1].resolve(fixture('run'));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(updates.at(-1).status,'ready');
  assert.equal(updates.at(-1).query.run_id,run);
});

test('frontend tests block real network requests',()=>{
  assert.throws(()=>fetch('https://example.invalid'),/External network disabled/);
});

for (const status of ['loading','error']) test(`${status} screen never renders prior results under a new scope`,()=>{
  const state={query:{scope:'quality',cohort_id:cohort},status,metrics:fixture(),error:status==='error'?'[API 409] Cohort conflict':null};
  const html=text(React.createElement(MetricRequestView,{state,onRetry:()=>{}}));
  assert.match(html,/Applied selection: Quality/);
  assert.ok(html.includes(cohort));
  assert.doesNotMatch(html,/Model accuracy|50.0%|Confusion matrix/);
  if(status==='error')assert.match(html,/409/);
  else assert.match(html,/Loading metrics/);
});

test('an outdated failure cannot replace newer successful results',async()=>{
  const pending=[],updates=[];
  const loader=createMetricsLoader(()=>new Promise((resolve,reject)=>pending.push({resolve,reject})));
  loader.load({scope:'history'},state=>updates.push(state));
  loader.load({scope:'run',run_id:run},state=>updates.push(state));
  pending[1].resolve(fixture('run'));
  await new Promise(resolve=>setImmediate(resolve));
  pending[0].reject(new Error('Old failure'));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(updates.at(-1).status,'ready');
  assert.equal(updates.at(-1).query.run_id,run);
});

test('failed parent runs keep completed metrics and disclose incomplete work',()=>{
  const metrics=fixture('run');metrics.selection.run_status='failed';
  metrics.selection.coverage.interrupted=2;
  const html=text(React.createElement(MetricResults,{metrics}));
  assert.match(html,/Run status: failed/);
  assert.match(html,/Interrupted 2/);
  assert.match(html,/Model accuracy 50.0%/);
});
