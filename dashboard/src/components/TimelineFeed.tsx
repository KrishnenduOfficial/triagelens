import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchTimelines, type TimelineSummary } from "../api/apiService";

export const TimelineFeed: React.FC = () => {
  const [timelines, setTimelines] = useState<TimelineSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [skip, setSkip] = useState<number>(0);
  const limit = 20;

  const loadTimelines = async (currentSkip: number) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchTimelines(currentSkip, limit);
      setTimelines(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to retrieve threat timelines from API."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTimelines(skip);
  }, [skip]);

  const formatDate = (isoString: string | null | undefined): string => {
    if (!isoString) return "N/A";
    try {
      const d = new Date(isoString);
      return isNaN(d.getTime()) ? isoString : d.toLocaleString();
    } catch {
      return isoString;
    }
  };

  return (
    <section className="dashboard-card timeline-feed-section" aria-label="Correlated Threat Timelines">
      <div className="card-header">
        <div>
          <div className="badge-row">
            <span className="badge badge-accent">Stage 3 Correlation</span>
            <span className="badge badge-neutral">Chronological Events</span>
          </div>
          <h2 className="card-title">Correlated Threat Timelines</h2>
          <p className="card-subtitle">
            Sequenced security events grouped by attack source, dataset, or victim endpoint.
          </p>
        </div>
        <div className="pagination-controls">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setSkip((prev) => Math.max(0, prev - limit))}
            disabled={skip === 0 || loading}
            aria-label="Previous page"
          >
            ← Previous
          </button>
          <span className="page-indicator mono">
            Offset: {skip}
          </span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setSkip((prev) => prev + limit)}
            disabled={timelines.length < limit || loading}
            aria-label="Next page"
          >
            Next →
          </button>
        </div>
      </div>

      {loading && (
        <div className="state-container loading-state">
          <div className="spinner" />
          <p>Querying SQLite store for correlated incident timelines...</p>
        </div>
      )}

      {error && (
        <div className="state-container error-state">
          <div className="error-icon">⚠️</div>
          <div>
            <h4>Failed to Load Timelines</h4>
            <p className="error-text">{error}</p>
            <button
              className="btn btn-primary btn-sm"
              onClick={() => loadTimelines(skip)}
            >
              Retry
            </button>
          </div>
        </div>
      )}

      {!loading && !error && timelines.length === 0 && (
        <div className="state-container empty-state">
          <div className="empty-icon">📁</div>
          <h4>No Timelines Ingested Yet</h4>
          <p className="empty-text">
            Start the ingestion engine or load security datasets to populate incident timelines.
          </p>
        </div>
      )}

      {!loading && !error && timelines.length > 0 && (
        <div className="timeline-table-wrapper">
          <table className="data-table" aria-label="Timelines List">
            <thead>
              <tr>
                <th scope="col">Grouping Key</th>
                <th scope="col">Events</th>
                <th scope="col">Earliest Event</th>
                <th scope="col">Latest Event</th>
                <th scope="col">Created</th>
                <th scope="col" className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {timelines.map((tl) => (
                <tr key={tl.id} className="table-row-hover">
                  <td>
                    <div className="grouping-cell">
                      <span className="mono key-text">{tl.grouping_key}</span>
                      <span className="timeline-id-sub mono">ID: {tl.id.substring(0, 8)}...</span>
                    </div>
                  </td>
                  <td>
                    <span className="badge badge-events mono">
                      {tl.total_events} {tl.total_events === 1 ? "event" : "events"}
                    </span>
                  </td>
                  <td className="mono text-muted text-sm">
                    {formatDate(tl.start_time)}
                  </td>
                  <td className="mono text-muted text-sm">
                    {formatDate(tl.end_time)}
                  </td>
                  <td className="mono text-muted text-sm">
                    {formatDate(tl.created_at)}
                  </td>
                  <td className="text-right">
                    <Link
                      to={`/timeline/${encodeURIComponent(tl.id)}`}
                      className="btn btn-primary btn-sm"
                    >
                      Investigate →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};

