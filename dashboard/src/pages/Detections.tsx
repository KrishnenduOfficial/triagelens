import React, { useEffect, useState } from 'react';
import { fetchDetectionRules, fetchDetectionHits, fetchDetectionCoverage, fetchYaraScans,
  type SigmaRule, type RuleIssue, type DetectionHit, type CoverageRow, type YaraRecord, type PageResult } from '../api/apiService';

export function CoverageMatrix({ rows }: { rows: CoverageRow[] }) {
  const tactics = [...new Set(rows.map(row => row.tactic))];
  return <div className="attack-matrix">{tactics.map(tactic => <section key={tactic}>
    <h3>{tactic}</h3>{rows.filter(row => row.tactic === tactic).map(row => <div key={row.technique_id}
      className={`attack-cell ${row.sources.sigma || row.sources.yara ? 'attack-covered' : ''}`}>
      <strong>{row.technique_id}</strong> {row.name}<br />
      <small>Sigma: {row.sources.sigma ? 'recorded' : 'none'} · YARA: {row.sources.yara ? 'recorded' : 'none'}</small>
    </div>)}
  </section>)}</div>;
}

export function DetectionResults({ rules, issues, hits, scans, rows }: { rules: SigmaRule[]; issues: RuleIssue[]; hits: DetectionHit[]; scans: YaraRecord[]; rows: CoverageRow[] }) {
  return <>
    <section className="dashboard-card"><h2>Curated Sigma rules</h2>
      {!rules.length && <p>No supported rules available.</p>}
      {rules.map(rule => <div key={rule.id}><h3>{rule.title}</h3><p>{rule.id} · {rule.author} · {rule.license} · {rule.level || 'level unavailable'}</p><p>{rule.source}</p><p>{rule.tags.join(', ')}</p></div>)}
      {issues.map((issue, i) => <p key={i}>Rule {issue.status}: {issue.source} — {issue.reason}</p>)}
    </section>
    <section className="dashboard-card"><h2>Recorded rule hits</h2>
      {!hits.length && <p>No recorded hits on this page. This does not establish that rules were evaluated.</p>}
      {hits.map(hit => <div key={hit.id}><p><strong>{hit.source}</strong> · {hit.rule_id} · {hit.detected_at}</p><p>Detection {hit.id} · Alerts: {hit.event_ids.join(', ')}</p><p>Technique mappings: {hit.technique_ids === null ? 'unavailable' : hit.technique_ids.join(', ') || 'none recorded'}</p></div>)}
    </section>
    <section className="dashboard-card"><h2>YARA scan results</h2>
      {!scans.length && <p>No recorded scans on this page.</p>}
      {scans.map(scan => <div key={scan.scan_id}><h3>{scan.status} · {scan.scan_id}</h3><p>Ended: {scan.ended_at} · {scan.engine} {scan.version || 'version unavailable'} · SHA-256: {scan.sha256 || 'unavailable'}</p>
        {scan.matches.map(match => <div key={`${match.namespace}:${match.rule}`}><p>{match.namespace}:{match.rule} · Techniques: {match.technique_ids.join(', ') || 'none recorded'}{match.invalid_technique_ids.length > 0 && ` · Unknown: ${match.invalid_technique_ids.join(', ')}`}</p><pre>{JSON.stringify(match.metadata, null, 2)}</pre></div>)}
        {scan.diagnostics.map((diagnostic, i) => <p key={i}>Diagnostic: {diagnostic.category}</p>)}
      </div>)}
    </section>
    <section className="dashboard-card"><h2>ATT&amp;CK Enterprise annotation coverage</h2>
      <p>Version 17.1. Highlighting means a persisted Sigma or YARA hit has an explicit technique mapping; it is not detection effectiveness. No highlight does not establish that a technique was tested. AI predictions and dataset labels are not included.</p>
      <CoverageMatrix rows={rows} />
    </section>
  </>;
}

export const Detections: React.FC = () => {
  const [rules, setRules] = useState<SigmaRule[]>([]); const [issues, setIssues] = useState<RuleIssue[]>([]);
  const [hits, setHits] = useState<PageResult<DetectionHit> | null>(null); const [scans, setScans] = useState<PageResult<YaraRecord> | null>(null);
  const [rows, setRows] = useState<CoverageRow[] | null>(null); const [hitPage, setHitPage] = useState(0); const [scanPage, setScanPage] = useState(0);
  const [error, setError] = useState('');
  useEffect(() => { let active = true; Promise.all([fetchDetectionRules(), fetchDetectionCoverage()]).then(([r, c]) => {
    if (active) { setRules(r.rules); setIssues(r.issues); setRows(c.rows); }
  }).catch(() => { if (active) setError('Unable to load rules or coverage.'); }); return () => { active = false; }; }, []);
  useEffect(() => { let active = true; setHits(null); fetchDetectionHits(hitPage * 50).then(value => { if (active) setHits(value); }).catch(() => { if (active) setError('Unable to load rule hits.'); }); return () => { active = false; }; }, [hitPage]);
  useEffect(() => { let active = true; setScans(null); fetchYaraScans(scanPage * 50).then(value => { if (active) setScans(value); }).catch(() => { if (active) setError('Unable to load YARA scans.'); }); return () => { active = false; }; }, [scanPage]);
  return <div><h1>Detections and coverage</h1><p>Recorded rule results are separate from AI output, ground truth and analyst decisions.</p>
    {error && <p role="alert">{error}</p>}
    {(!hits || !scans || !rows) && !error && <p>Loading recorded results…</p>}
    {hits && scans && rows && <><div className="dashboard-card"><p>Rule hits: {hits.total} · YARA scans: {scans.total}</p>
      <button disabled={hitPage === 0} onClick={() => setHitPage(hitPage - 1)}>Previous hits</button> <span>Page {hitPage + 1}</span> <button disabled={(hitPage + 1) * 50 >= hits.total} onClick={() => setHitPage(hitPage + 1)}>Next hits</button>{' '}
      <button disabled={scanPage === 0} onClick={() => setScanPage(scanPage - 1)}>Previous scans</button> <span>Page {scanPage + 1}</span> <button disabled={(scanPage + 1) * 50 >= scans.total} onClick={() => setScanPage(scanPage + 1)}>Next scans</button></div>
      <DetectionResults rules={rules} issues={issues} hits={hits.items} scans={scans.items} rows={rows} /></>}
  </div>;
};
