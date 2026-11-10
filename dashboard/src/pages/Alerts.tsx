import React, { useEffect, useState } from 'react';
import { fetchAlerts, type AlertQuery, type AlertPage, type NormalizedAlert } from '../api/apiService';

const initial: AlertQuery = { skip: 0, limit: 50, sort: 'timestamp', direction: 'desc' };
const fields = [ ['search', 'Search ID, dataset, event type or source file'], ['dataset', 'Dataset'],
  ['event_type', 'Event type'], ['host', 'Host'], ['user', 'User'], ['start', 'From (local time)'], ['end', 'To (local time)'] ] as const;

export function AlertDetail({ alert }: { alert: NormalizedAlert }) {
  return <section className="dashboard-card alert-detail" aria-label="Alert detail">
    <h2>Alert detail</h2><p><strong>ID:</strong> {alert.id}</p>
    <p><strong>Dataset:</strong> {alert.source_dataset} · <strong>Event:</strong> {alert.event_type}</p>
    <p><strong>Source:</strong> {alert.source_file}</p><p><strong>Time:</strong> {alert.timestamp ?? 'Unavailable'}</p>
    <h3>Raw telemetry</h3><pre>{JSON.stringify(alert.original_record, null, 2)}</pre>
    <h3>Extracted indicators</h3><pre>{JSON.stringify(alert.extracted_indicators, null, 2)}</pre>
  </section>;
}

export function Alerts() {
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [query, setQuery] = useState<AlertQuery>(initial);
  const [page, setPage] = useState<AlertPage | null>(null);
  const [selected, setSelected] = useState<NormalizedAlert | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    setLoading(true); setError(''); setSelected(null);
    fetchAlerts(query).then(result => { if (active) setPage(result); })
      .catch(err => { if (active) { setPage(null); setError(err.message); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [query]);
  function submit(event: React.FormEvent) {
    event.preventDefault();
    const values: Record<string, string> = {};
    for (const [key] of fields) {
      const value = (draft[key] ?? '').trim();
      if (value) values[key] = key === 'start' || key === 'end' ? new Date(value).toISOString() : value;
    }
    setQuery({ ...initial, sort: query.sort, direction: query.direction, ...values });
  }
  return <div className="alerts-page">
    <h1>Alerts</h1>
    <form className="dashboard-card alert-filters" onSubmit={submit}>
      {fields.map(([key, label]) => <label key={key}>{label}<input type={key === 'start' || key === 'end' ? 'datetime-local' : 'text'} maxLength={200} value={draft[key] ?? ''} onChange={e => setDraft({ ...draft, [key]: e.target.value })} /></label>)}
      <button type="submit">Apply filters</button>
    </form>
    <div className="alert-controls">
      <label>Sort by <select value={query.sort} onChange={e => setQuery({ ...query, sort: e.target.value, skip: 0 })}>
        <option value="timestamp">Time</option><option value="dataset">Dataset</option><option value="event_type">Event type</option><option value="source_file">Source file</option>
      </select></label>
      <label>Order <select value={query.direction} onChange={e => setQuery({ ...query, direction: e.target.value, skip: 0 })}><option value="desc">Descending</option><option value="asc">Ascending</option></select></label>
    </div>
    {loading && <p>Loading alerts…</p>}{error && <p role="alert">{error}</p>}
    {!loading && !error && page && <>
      <p>{page.total} matching alerts</p>
      {page.items.length === 0 ? <p>No matching alerts found.</p> : <div className="alert-table-wrap"><table><thead><tr><th>Time</th><th>Dataset</th><th>Event type</th><th>Source file</th><th>Detail</th></tr></thead><tbody>
        {page.items.map(alert => <tr key={alert.id}><td>{alert.timestamp ?? 'Unavailable'}</td><td>{alert.source_dataset}</td><td>{alert.event_type}</td><td>{alert.source_file}</td><td><button type="button" onClick={() => setSelected(alert)}>View</button></td></tr>)}
      </tbody></table></div>}
      <div className="alert-controls"><button disabled={query.skip === 0} onClick={() => setQuery({ ...query, skip: Math.max(0, query.skip - query.limit) })}>Previous</button><span>Offset {query.skip}</span><button disabled={query.skip + query.limit >= page.total} onClick={() => setQuery({ ...query, skip: query.skip + query.limit })}>Next</button></div>
    </>}
    {selected && <AlertDetail alert={selected} />}
  </div>;
}
