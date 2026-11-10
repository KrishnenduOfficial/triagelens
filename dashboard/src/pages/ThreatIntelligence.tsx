import React, { useRef, useState } from 'react';
import { fetchThreatIntelligence, type IntelligenceLookup } from '../api/apiService';

export function IntelligenceResults({ records }: { records: IntelligenceLookup[] }) {
  if (!records.length) return <p className="state-container">No recorded lookups for this indicator. This does not mean it is clean.</p>;
  return <div className="intelligence-grid">{records.map(record => <section className="dashboard-card data-panel" key={record.id}>
    <h2 className="card-title">{record.provider}</h2>
    <p><strong>Status:</strong> {record.status}{record.status === 'unavailable' && record.recorded_status !== 'unavailable' ? ` (${record.recorded_status})` : ''}</p>
    <p><strong>Lookup time:</strong> {record.lookup_timestamp || 'Unavailable'}</p>
    <h3>Compact summary</h3>
    {Object.keys(record.summary).length ? <pre>{JSON.stringify(record.summary, null, 2)}</pre> : <p>No summary available.</p>}
  </section>)}</div>;
}

export function ThreatIntelligence() {
  const [indicator, setIndicator] = useState('');
  const [searched, setSearched] = useState('');
  const [records, setRecords] = useState<IntelligenceLookup[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const request = useRef(0);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const value = indicator.trim();
    if (!value) return;
    const current = ++request.current;
    setSearched(value); setLoading(true); setRecords(null); setError('');
    try { const result = await fetchThreatIntelligence(value); if (request.current === current) setRecords(result); }
    catch (err) { if (request.current === current) setError(err instanceof Error ? err.message : 'Lookup failed.'); }
    finally { if (request.current === current) setLoading(false); }
  }
  return <div>
    <header className="console-banner"><div className="console-info">
      <p className="workspace-eyebrow">Indicator enrichment</p>
      <h1 className="console-title">Threat intelligence</h1>
      <p className="console-description">Recorded lookups only. Unavailable is not clean; a provider finding is not a final analyst decision.</p>
    </div></header>
    <form className="dashboard-card alert-filters" onSubmit={submit}>
      <label>Indicator <input value={indicator} maxLength={2048} onChange={event => setIndicator(event.target.value)} required /></label>
      <button className="btn btn-primary" type="submit">Find recorded lookups</button>
    </form>
    {loading && <p className="state-container" role="status">Loading recorded lookups…</p>}{error && <p className="state-container error-state" role="alert">{error}</p>}
    {records && <><p className="results-caption">Results for <code>{searched}</code></p><IntelligenceResults records={records} /></>}
  </div>;
}
