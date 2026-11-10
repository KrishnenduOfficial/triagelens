import React, { useEffect, useId, useState } from 'react';
import { fetchDetectionRules, fetchDetectionHits, fetchDetectionCoverage, fetchYaraScans,
  type SigmaRule, type RuleIssue, type DetectionHit, type CoverageRow, type YaraRecord, type PageResult } from '../api/apiService';

// Canonical column order for the pinned Enterprise 17.1 snapshot.
const tacticOrder = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact',
];
const tacticName = (tactic: string) => tactic.replaceAll('-', ' ').replace(/\b(?!and\b)\w/g, c => c.toUpperCase());
const hasHit = (row: CoverageRow) => row.sources.sigma === true || row.sources.yara === true;
const sourceStatus = (recorded: boolean | null) => recorded === null ? 'unavailable' : recorded ? 'recorded' : 'none';

function TechniqueCard({ row }: { row: CoverageRow }) {
  return <div className={`attack-cell${hasHit(row) ? ' attack-covered' : ''}`}>
    <span className="attack-technique-id mono">{row.technique_id}</span>
    <strong>{row.name}</strong>
    <div className="attack-sources">
      <small className={row.sources.sigma === true ? 'attack-source-sigma' : ''}>Sigma: {sourceStatus(row.sources.sigma)}</small>
      <small className={row.sources.yara === true ? 'attack-source-yara' : ''}>YARA: {sourceStatus(row.sources.yara)}</small>
    </div>
  </div>;
}

export function CoverageMatrix({ rows }: { rows: CoverageRow[] }) {
  const tacticLabel = useId();
  const [tacticFilter, setTacticFilter] = useState('');
  const [search, setSearch] = useState('');
  const [recordedOnly, setRecordedOnly] = useState(false);
  const query = search.trim().toLowerCase();
  const filtering = Boolean(query || recordedOnly);
  const grouped = new Map<string, CoverageRow[]>();
  for (const row of rows) {
    const column = grouped.get(row.tactic);
    if (column) column.push(row);
    else grouped.set(row.tactic, [row]);
  }
  const tactics = [...tacticOrder.filter(tactic => grouped.has(tactic)),
    ...[...grouped.keys()].filter(tactic => !tacticOrder.includes(tactic)).sort()];
  const columns = tactics.filter(tactic => !tacticFilter || tactic === tacticFilter).flatMap(tactic => {
    const all = grouped.get(tactic) ?? [];
    const matching = all.filter(row => (!recordedOnly || hasHit(row))
      && (!query || `${row.technique_id} ${row.name}`.toLowerCase().includes(query)));
    if (!matching.length) return [];
    const matches = new Set(matching.map(row => row.technique_id));
    const ids = new Set(all.map(row => row.technique_id));
    const children = new Map<string, CoverageRow[]>();
    for (const row of matching) {
      if (!row.parent || !ids.has(row.parent)) continue;
      const siblings = children.get(row.parent);
      if (siblings) siblings.push(row);
      else children.set(row.parent, [row]);
    }
    const parents = all.filter(row => (!row.parent || !ids.has(row.parent))
      && (matches.has(row.technique_id) || children.has(row.technique_id)));
    return [{ tactic, parents, children }];
  });

  if (!rows.length) return <p>No coverage annotations available.</p>;
  return <>
    <div className="attack-controls">
      <label>Find a technique<input type="search" placeholder="e.g. T1082 or Discovery" value={search}
        onChange={event => setSearch(event.target.value)} /></label>
      <label><span id={tacticLabel}>Tactic</span><select aria-labelledby={tacticLabel} value={tacticFilter} onChange={event => setTacticFilter(event.target.value)}>
        <option value="">All tactics</option>
        {tactics.map(tactic => <option key={tactic} value={tactic}>{tacticName(tactic)}</option>)}
      </select></label>
      <label className="attack-toggle"><input type="checkbox" checked={recordedOnly}
        onChange={event => setRecordedOnly(event.target.checked)} /> Recorded hits only</label>
    </div>
    <div className="attack-key" aria-label="Coverage legend">
      <span className="attack-source-sigma">Sigma hit recorded</span>
      <span className="attack-source-yara">YARA hit recorded</span>
      <span>No highlight · no recorded hit</span>
    </div>
    <p className="attack-matrix-caption" role="status">
      {columns.length ? `${columns.length} of ${tactics.length} tactics shown.` : 'No techniques match these filters.'}
      {columns.length > 1 && ' Scroll within the matrix or choose a tactic above.'}
    </p>
    {columns.length > 0 && <div className="attack-matrix" tabIndex={0} role="region" aria-label="ATT&CK technique matrix">
      {columns.map(({ tactic, parents, children }) => <section className="attack-column" key={tactic} aria-label={tacticName(tactic)}>
        <header className="attack-column-heading">
          <h3>{tacticName(tactic)}</h3>
          <p>{parents.length} {parents.length === 1 ? 'technique' : 'techniques'}</p>
        </header>
        <ul className="attack-techniques">
          {parents.map(row => {
            const nested = children.get(row.technique_id) ?? [];
            return <li key={row.technique_id}>
              <TechniqueCard row={row} />
              {nested.length > 0 && <details className="attack-family" open={filtering || undefined}>
                <summary aria-label={`${row.name}: ${nested.length} sub-techniques${!filtering && nested.some(hasHit) ? ' with recorded hits' : ''}`}>
                  {nested.length} {nested.length === 1 ? 'sub-technique' : 'sub-techniques'}
                  {!filtering && nested.some(hasHit) && <span> · recorded hits</span>}
                </summary>
                <ul>{nested.map(child => <li key={child.technique_id}><TechniqueCard row={child} /></li>)}</ul>
              </details>}
            </li>;
          })}
        </ul>
      </section>)}
    </div>}
  </>;
}

export function DetectionResults({ rules, issues, hits, scans, rows }: { rules: SigmaRule[]; issues: RuleIssue[]; hits: DetectionHit[]; scans: YaraRecord[]; rows: CoverageRow[] }) {
  return <>
    <section className="dashboard-card data-panel attack-panel" id="attack-coverage" tabIndex={-1} aria-labelledby="attack-coverage-heading">
      <div className="attack-panel-heading">
        <div><p className="workspace-eyebrow">Enterprise matrix</p><h2 className="card-title" id="attack-coverage-heading">ATT&amp;CK Enterprise annotation coverage</h2></div>
        <span className="badge badge-neutral">ATT&amp;CK 17.1</span>
      </div>
      <p>Highlights mark explicit technique mappings on stored Sigma or YARA hits, not detection effectiveness. Unmarked techniques may not have been tested. AI predictions and dataset labels are excluded.</p>
      <CoverageMatrix rows={rows} />
    </section>
    <section className="dashboard-card data-panel"><h2 className="card-title">Curated Sigma rules</h2>
      {!rules.length && <p>No supported rules available.</p>}
      {rules.map(rule => <div className="record-item" key={rule.id}><h3>{rule.title}</h3><p>{rule.id} · {rule.author} · {rule.license} · {rule.level || 'level unavailable'}</p><p>{rule.source}</p><p>{rule.tags.join(', ')}</p></div>)}
      {issues.map((issue, i) => <p key={i}>Rule {issue.status}: {issue.source} — {issue.reason}</p>)}
    </section>
    <section className="dashboard-card data-panel"><h2 className="card-title">Recorded rule hits</h2>
      {!hits.length && <p>No recorded hits on this page. This does not establish that rules were evaluated.</p>}
      {hits.map(hit => <div className="record-item" key={hit.id}><p><span className="badge badge-accent">{hit.source}</span> <strong>{hit.rule_id}</strong> · {hit.detected_at}</p><p>Detection {hit.id} · Alerts: {hit.event_ids.join(', ')}</p><p>Technique mappings: {hit.technique_ids === null ? 'unavailable' : hit.technique_ids.join(', ') || 'none recorded'}</p></div>)}
    </section>
    <section className="dashboard-card data-panel"><h2 className="card-title">YARA scan results</h2>
      {!scans.length && <p>No recorded scans on this page.</p>}
      {scans.map(scan => <div className="record-item" key={scan.scan_id}><h3><span className="badge badge-neutral">{scan.status}</span> <span className="mono">{scan.scan_id}</span></h3><p>Ended: {scan.ended_at} · {scan.engine} {scan.version || 'version unavailable'} · SHA-256: {scan.sha256 || 'unavailable'}</p>
        {scan.matches.map(match => <div key={`${match.namespace}:${match.rule}`}><p>{match.namespace}:{match.rule} · Techniques: {match.technique_ids.join(', ') || 'none recorded'}{match.invalid_technique_ids.length > 0 && ` · Unknown: ${match.invalid_technique_ids.join(', ')}`}</p><pre>{JSON.stringify(match.metadata, null, 2)}</pre></div>)}
        {scan.diagnostics.map((diagnostic, i) => <p key={i}>Diagnostic: {diagnostic.category}</p>)}
      </div>)}
    </section>
  </>;
}

export function DetectionState({ loading, error, retry }: { loading: boolean; error: string; retry: () => void }) {
  if (loading) return <p className="state-container" role="status">Loading recorded results…</p>;
  if (error) return <p className="state-container error-state" role="alert">{error} <button className="btn btn-secondary" type="button" onClick={retry}>Retry</button></p>;
  return null;
}

export const Detections: React.FC = () => {
  const [rules, setRules] = useState<SigmaRule[]>([]); const [issues, setIssues] = useState<RuleIssue[]>([]);
  const [hits, setHits] = useState<PageResult<DetectionHit> | null>(null); const [scans, setScans] = useState<PageResult<YaraRecord> | null>(null);
  const [rows, setRows] = useState<CoverageRow[] | null>(null); const [hitPage, setHitPage] = useState(0); const [scanPage, setScanPage] = useState(0);
  const [error, setError] = useState(''); const [loading, setLoading] = useState(true); const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    setLoading(true); setError(''); setHits(null); setScans(null); setRows(null);
    Promise.all([fetchDetectionRules(), fetchDetectionCoverage(), fetchDetectionHits(hitPage * 50), fetchYaraScans(scanPage * 50)])
      .then(([r, c, h, s]) => { if (active) { setRules(r.rules); setIssues(r.issues); setRows(c.rows); setHits(h); setScans(s); } })
      .catch(() => { if (active) setError('Unable to load recorded detection results.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [hitPage, scanPage, revision]);
  return <div className="detections-page"><header className="console-banner"><div className="console-info">
    <p className="workspace-eyebrow">Detection engineering</p>
    <h1 className="console-title">Detections and coverage</h1>
    <p className="console-description">Recorded rule results are separate from AI output, ground truth and analyst decisions.</p>
  </div></header>
    <DetectionState loading={loading} error={error} retry={() => setRevision(value => value + 1)} />
    {!loading && !error && hits && scans && rows && <><div className="dashboard-card detection-toolbar">
      <div><p className="workspace-eyebrow">Recorded rule hits</p><strong>{hits.total}</strong>
        <div className="pagination-controls"><button className="btn btn-secondary btn-sm" disabled={hitPage === 0} onClick={() => setHitPage(hitPage - 1)}>Previous hits</button><span>Page {hitPage + 1}</span><button className="btn btn-secondary btn-sm" disabled={(hitPage + 1) * 50 >= hits.total} onClick={() => setHitPage(hitPage + 1)}>Next hits</button></div>
      </div>
      <div><p className="workspace-eyebrow">YARA scans</p><strong>{scans.total}</strong>
        <div className="pagination-controls"><button className="btn btn-secondary btn-sm" disabled={scanPage === 0} onClick={() => setScanPage(scanPage - 1)}>Previous scans</button><span>Page {scanPage + 1}</span><button className="btn btn-secondary btn-sm" disabled={(scanPage + 1) * 50 >= scans.total} onClick={() => setScanPage(scanPage + 1)}>Next scans</button></div>
      </div>
      <a className="btn btn-secondary" href="#attack-coverage">Jump to ATT&amp;CK coverage ↓</a>
    </div>
      <DetectionResults rules={rules} issues={issues} hits={hits.items} scans={scans.items} rows={rows} /></>}
  </div>;
};
