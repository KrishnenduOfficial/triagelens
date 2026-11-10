import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {ThreatHunt, huntExport} from '../src/pages/ThreatHunt.tsx';
import {apiClient, listSavedHunts, saveHunt, deleteHunt} from '../src/api/apiService.ts';

test('hunting presents grammar and saved query controls', () => {
  const html = renderToStaticMarkup(React.createElement(ThreatHunt));
  assert.match(html, /Filter grammar help/);
  assert.match(html, /Saved queries/);
  assert.match(html, /Save query/);
  assert.match(html, /not full KQL/);
});

test('export preserves returned records as JSON, including hostile text', () => {
  const records = [{id: '1', original_record: {message: '<script>alert(1)</script>'}}];
  assert.deepEqual(JSON.parse(huntExport(records)), records);
  assert.deepEqual(JSON.parse(huntExport([])), []);
});

test('saved query client uses bounded API operations', async () => {
  const calls = [];
  const original = apiClient.defaults.adapter;
  apiClient.defaults.adapter = async config => {
    calls.push([config.method, config.url, config.data && JSON.parse(config.data)]);
    return {data: config.method === 'get' ? [] : {}, status: 200, statusText: 'OK', headers: {}, config};
  };
  try {
    assert.deepEqual(await listSavedHunts(), []);
    await saveHunt('test', 'a == 1');
    await deleteHunt('test');
    assert.deepEqual(calls, [
      ['get', '/api/hunt/saved', undefined],
      ['put', '/api/hunt/saved', {name: 'test', query: 'a == 1'}],
      ['post', '/api/hunt/saved/delete', {name: 'test'}],
    ]);
  } finally { apiClient.defaults.adapter = original; }
});
