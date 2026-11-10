import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {AlertDetail} from '../src/pages/Alerts.tsx';

test('alert detail renders raw telemetry as escaped text', () => {
  const html = renderToStaticMarkup(React.createElement(AlertDetail, {alert: {
    id: '1', source_dataset: 'sample', source_file: 'sample.evtx', event_type: 'test',
    original_record: {message: '<img src=x onerror=alert(1)>'}, extracted_indicators: []
  }}));
  assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /Raw telemetry/);
});
