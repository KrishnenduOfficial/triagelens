import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {VerdictQualifications} from '../src/components/VerdictQualifications.tsx';

const ref={evidence_id:'E1',field_path:['details','Protocol']};
const fixture=()=>({
  id:'offline',timeline_id:'offline',severity:'LOW',confidence_score:.5,
  disposition:'UNDETERMINED',policy_version:'triage-v2',summary:'Review required',
  reasoning:['Observed TCP only'],recommended_actions:['Preserve and review'],
  uncertainty_level:'HIGH',missing_information:['Protocol and intent unknown'],missing_information_recorded:true,
  evidence_contract_version:'evidence-basis-v1',
  evidence_context:{E1:{evidence_id:'E1',details:{Protocol:'tcp',values:[0,false,null,'']}}},
  evidence_basis:{kind:'insufficient_evidence',decision_refs:[ref],
    observations:[{statement:'Recorded transport is TCP',refs:[ref]}],
    hypotheses:[{statement:'TLS is unverified',refs:[]}],
    gaps:[{category:'protocol',description:'Protocol and intent unknown',required_evidence:'Handshake and process context',blocks_disposition:true}]},
});
const render=verdict=>renderToStaticMarkup(React.createElement(VerdictQualifications,{verdict}));
const text=verdict=>render(verdict).replace(/<[^>]*>/g,' ').replace(/\s+/g,' ');

test('actual qualification component renders observations, hypotheses, blocking gaps and saved values',()=>{
  const html=text(fixture());
  for(const value of ['Uncertainty: HIGH','Protocol and intent unknown','Declared basis: insufficient_evidence',
    'model-authored analysis','Observations','Recorded transport is TCP','Hypotheses','TLS is unverified',
    'Blocking gap (protocol)','Required evidence: Handshake and process context','E1 / details / Protocol','tcp',
    'do not certify conclusions or action safety']) assert.ok(html.includes(value),value);
});

for(const level of ['LOW','MEDIUM','HIGH']) test(`uncertainty ${level} is explicit`,()=>{
  const verdict=fixture();verdict.uncertainty_level=level;
  assert.match(text(verdict),new RegExp(`Uncertainty: ${level}`));
});

for(const level of [null,undefined]) test(`absent uncertainty ${level} is not LOW`,()=>{
  const verdict=fixture();verdict.uncertainty_level=level;
  assert.match(text(verdict),/Uncertainty not recorded/);
  assert.doesNotMatch(text(verdict),/Uncertainty: LOW/);
});

test('recorded empty list is reported without claiming completeness',()=>{
  const verdict=fixture();verdict.missing_information=[];
  assert.match(text(verdict),/No gaps reported by the model. This is not proof of completeness/);
});

for(const flag of [false,undefined]) test(`legacy empty gaps with presence ${flag} remain unrecorded`,()=>{
  const verdict=fixture();verdict.policy_version='triage-v1';verdict.evidence_basis=null;
  verdict.missing_information=[];verdict.missing_information_recorded=flag;
  assert.match(text(verdict),/Missing-information assessment not recorded/);
  assert.match(text(verdict),/Evidence basis not recorded for this policy/);
  assert.doesNotMatch(text(verdict),/No gaps reported/);
});

test('older API nonempty gaps are still shown without a presence flag',()=>{
  const verdict=fixture();delete verdict.missing_information_recorded;
  assert.match(text(verdict),/Protocol and intent unknown/);
  assert.doesNotMatch(text(verdict),/Missing-information assessment not recorded/);
});

for(const [value,flag] of [['invalid',false],[null,true],[[], 'true'],[['context'],false],[[42],true]]) {
  test(`malformed gap metadata ${JSON.stringify([value,flag])} warns rather than claiming no gaps`,()=>{
    const verdict=fixture();verdict.missing_information=value;verdict.missing_information_recorded=flag;
    assert.match(text(verdict),/Data-quality warning/);
    assert.doesNotMatch(text(verdict),/No gaps reported by the model/);
    if(Array.isArray(value)&&typeof value[0]==='string') assert.ok(text(verdict).includes(value[0]));
  });
}

for(const [id,path] of [['E9',['details','Protocol']],['E1',['evidence_id']],
  ['E1',['details','TLSVersion']],['E1',['details','values','01']],['E1',['details','values','2']],
  ['E1',['details','values','3']],['E1',['details','values','-1']],['E1',['toString']]]) {
  test(`invalid saved citation ${id}/${path.join('/')} never resolves from current/global data`,()=>{
    const verdict=fixture();verdict.evidence_basis.decision_refs=[{evidence_id:id,field_path:path}];
    assert.match(text(verdict),/Evidence reference unavailable or invalid in saved snapshot/);
  });
}

for(const [index,value] of [[0,'0'],[1,'false']]) test(`saved scalar ${value} is valid support data`,()=>{
  const verdict=fixture();verdict.evidence_basis.decision_refs=[{evidence_id:'E1',field_path:['details','values',String(index)]}];
  assert.match(text(verdict),new RegExp(`E1 / details / values / ${index}\\s*:\\s*${value}`));
});

test('nonblocking gaps remain visibly distinct',()=>{
  const verdict=fixture();verdict.evidence_basis.gaps[0].blocks_disposition=false;
  assert.match(text(verdict),/Nonblocking gap \(protocol\)/);
});

test('new policy with missing/invalid basis is a warning rather than legacy absence',()=>{
  for(const value of [null,{},'invalid']){
    const verdict=fixture();verdict.evidence_basis=value;
    assert.match(text(verdict),/Data-quality warning: evidence basis/);
  }
  const verdict=fixture();verdict.evidence_contract_version='unknown';
  assert.match(text(verdict),/Data-quality warning: evidence basis/);
});

test('saved evidence and model text are escaped without executing markup',()=>{
  const verdict=fixture();verdict.evidence_context.E1.details.Protocol='<script>private()</script>';
  verdict.evidence_basis.observations[0].statement='<img src=x onerror=private()>';
  const html=render(verdict);
  assert.doesNotMatch(html,/<script>|<img /);
  assert.match(html,/&lt;script&gt;/);
  assert.match(html,/&lt;img/);
});

test('qualification rendering does not mutate the saved evidence or assessment',()=>{
  const verdict=fixture(),before=JSON.stringify(verdict);
  render(verdict);
  assert.equal(JSON.stringify(verdict),before);
});
