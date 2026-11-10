import React, { useEffect, useState } from 'react';
import { fetchAlerts, type AlertQuery, type AlertPage, type NormalizedAlert } from '../api/apiService';

const initial: AlertQuery = { skip: 0, limit: 50, sort: 'timestamp', direction: 'desc' };
const fields = [ ['search', 'Search ID, dataset, event type or source file'], ['dataset', 'Dataset'],
  ['event_type', 'Event type'], ['host', 'Host'], ['user', 'User'], ['start', 'From (local time)'], ['end', 'To (local time)'] ] as const;

export function AlertDetail({ alert, id }: { alert: NormalizedAlert; id?: string }) {
  return <section id={id} className="alert-detail" aria-label="Alert detail">
    <h2>Alert detail</h2>
    <dl className="alert-detail-facts">
      <div><dt>Event type</dt><dd>{alert.event_type}</dd></div>
      <div><dt>Dataset</dt><dd>{alert.source_dataset}</dd></div>
      <div><dt>Source file</dt><dd>{alert.source_file}</dd></div>
      <div><dt>Time</dt><dd>{alert.timestamp ?? 'Unavailable'}</dd></div>
      <div><dt>Alert ID</dt><dd className="mono">{alert.id}</dd></div>
    </dl>
    <h3>Raw telemetry</h3>
    <pre tabIndex={0} aria-label="Raw telemetry JSON">{JSON.stringify(alert.original_record, null, 2)}</pre>
    <h3>Extracted indicators</h3>
    {alert.extracted_indicators.length > 0
      ? <pre tabIndex={0} aria-label="Extracted indicators JSON">{JSON.stringify(alert.extracted_indicators, null, 2)}</pre>
      : <p>No indicators extracted.</p>}
  </section>;
}

export function Alerts() {
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [query, setQuery] = useState<AlertQuery>(initial);
  const [page, setPage] = useState<AlertPage | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    setLoading(true); setError(''); setExpandedId(null);
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
  function clearFilters() {
    setDraft({});
    setQuery({ ...initial, sort: query.sort, direction: query.direction });
  }
  return <div className="alerts-page">
    <header className="console-banner"><div className="console-info">
      <p className="workspace-eyebrow">Event inventory</p>
      <h1 className="console-title">Alerts</h1>
      <p className="console-description">Filter ingested events and inspect the original telemetry.</p>
    </div></header>
    <form className="dashboard-card alert-filters" aria-label="Alert filters" onSubmit={submit}>
      {fields.map(([key, label]) => <label key={key}>{label}<input type={key === 'start' || key === 'end' ? 'datetime-local' : 'text'} maxLength={200} value={draft[key] ?? ''} onChange={e => setDraft({ ...draft, [key]: e.target.value })} /></label>)}
      <div className="workspace-controls">
        <button className="btn btn-primary" type="submit">Apply filters</button>
        <button className="btn btn-secondary" type="button" onClick={clearFilters}>Clear filters</button>
      </div>
    </form>
    <div className="alert-controls">
      <label>Sort by <select value={query.sort} onChange={e => setQuery({ ...query, sort: e.target.value, skip: 0 })}>
        <option value="timestamp">Time</option><option value="dataset">Dataset</option><option value="event_type">Event type</option><option value="source_file">Source file</option>
      </select></label>
      <label>Order <select value={query.direction} onChange={e => setQuery({ ...query, direction: e.target.value, skip: 0 })}><option value="desc">Descending</option><option value="asc">Ascending</option></select></label>
    </div>
    {loading && <p className="state-container" role="status">Loading alerts…</p>}{error && <p className="state-container error-state" role="alert">{error}</p>}
    {!loading && !error && page && <section className="dashboard-card data-panel" aria-label="Alert results">
      <p role="status">{page.total} {page.total === 1 ? 'matching alert' : 'matching alerts'}</p>
      {page.items.length === 0 ? <p className="state-container">No matching alerts found. Try clearing a filter.</p> : (
        <div className="alert-table-wrap" tabIndex={0} role="region" aria-label="Alert table">
          <table>
            <thead><tr>
              <th scope="col">Time</th>
              <th scope="col" className="alert-secondary-column">Dataset</th>
              <th scope="col">Event type</th>
              <th scope="col" className="alert-secondary-column">Source file</th>
              <th scope="col">Details</th>
            </tr></thead>
            <tbody>{page.items.map(alert => {
              const expanded = expandedId === alert.id;
              const detailId = `alert-detail-${alert.id}`;
              return <React.Fragment key={alert.id}>
                <tr className={expanded ? 'alert-row-expanded' : undefined}>
                  <td className="mono">{alert.timestamp ?? 'Unavailable'}</td>
                  <td className="alert-secondary-column">{alert.source_dataset}</td>
                  <td><span className="event-type-badge">{alert.event_type}</span></td>
                  <td className="alert-secondary-column">{alert.source_file}</td>
                  <td><button className="btn btn-secondary btn-sm" type="button" aria-expanded={expanded}
                    aria-controls={expanded ? detailId : undefined}
                    onClick={() => setExpandedId(expanded ? null : alert.id)}>
                    {expanded ? 'Hide' : 'View'}
                  </button></td>
                </tr>
                {expanded && <tr className="alert-detail-row">
                  <td colSpan={5}><AlertDetail alert={alert} id={detailId} /></td>
                </tr>}
              </React.Fragment>;
            })}</tbody>
          </table>
        </div>
      )}
      {page.total > query.limit && <div className="alert-controls"><button disabled={query.skip === 0} onClick={() => setQuery({ ...query, skip: Math.max(0, query.skip - query.limit) })}>Previous</button><span>Showing {query.skip + 1}–{query.skip + page.items.length} of {page.total}</span><button disabled={query.skip + query.limit >= page.total} onClick={() => setQuery({ ...query, skip: query.skip + query.limit })}>Next</button></div>}
    </section>}
  </div>;
}
