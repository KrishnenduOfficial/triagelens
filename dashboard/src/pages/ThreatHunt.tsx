import React, { useState } from "react";
import { huntAlerts, type NormalizedAlert } from "../api/apiService";

export const ThreatHunt: React.FC = () => {
  const [query, setQuery] = useState<string>('CommandLine contains "mimikatz"');
  const [alerts, setAlerts] = useState<NormalizedAlert[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const sampleQueries = [
    { label: "Mimikatz Activity", query: 'CommandLine contains "mimikatz"' },
    { label: "PowerShell Invocations", query: 'CommandLine contains "powershell"' },
    { label: "Malicious Alerts", query: 'ground_truth_label == "malicious"' },
    { label: "Process Creation", query: 'event_type == "ProcessCreate"' },
    { label: "HTTPS / C2 Ports", query: "Network.DestinationPort == 443" },
    { label: "SYSTEM User Actions", query: 'User == "SYSTEM" AND event_type == "ProcessCreate"' },
  ];

  const handleSearch = async (queryToRun?: string) => {
    const activeQuery = queryToRun !== undefined ? queryToRun : query;
    if (!activeQuery.trim()) return;

    setLoading(true);
    setError(null);
    setHasExecuted(true);

    try {
      const results = await huntAlerts(activeQuery.trim());
      setAlerts(results);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred while executing the hunt query.");
      }
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSearch();
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const formatTimestamp = (ts?: string | null): string => {
    if (!ts) return "—";
    try {
      const d = new Date(ts);
      return isNaN(d.getTime()) ? ts : d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    } catch {
      return ts;
    }
  };

  return (
    <div className="threat-hunt-page">
      {/* Console Header Banner */}
      <div className="console-banner">
        <div className="console-info">
          <h1 className="console-title">Telemetry Threat Hunting Console</h1>
          <p className="console-description">
            Search ingested endpoint, network, and cloud telemetry with a parameterized KQL-style hunting filter.
          </p>
        </div>
        <div className="pipeline-status-badge">
          <span className="status-dot pulsing" />
          <span>KQL-style filter to SQL translator active</span>
        </div>
      </div>

      {/* Query Bar Section */}
      <div className="hunt-search-card">
        <div className="hunt-input-wrapper">
          <span className="hunt-icon">🔎</span>
          <input
            type="text"
            className="hunt-query-input mono"
            placeholder='e.g. event_type == "ProcessCreate" AND CommandLine contains "powershell"'
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            aria-label="KQL-style hunting filter query"
          />
          <button
            type="button"
            className="btn btn-primary hunt-submit-btn"
            onClick={() => handleSearch()}
            disabled={loading || !query.trim()}
          >
            {loading ? (
              <>
                <span className="spinner-sm" />
                <span>Searching...</span>
              </>
            ) : (
              <span>Run Query</span>
            )}
          </button>
        </div>

        {/* Quick Query Suggestions */}
        <div className="hunt-quick-queries">
          <span className="quick-queries-label">Preset Hunts:</span>
          <div className="quick-query-pills">
            {sampleQueries.map((item, idx) => (
              <button
                key={idx}
                type="button"
                className="quick-query-pill mono text-xs"
                onClick={() => {
                  setQuery(item.query);
                  handleSearch(item.query);
                }}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Syntax / Query Error Banner */}
      {error && (
        <div className="hunt-error-banner" role="alert">
          <div className="hunt-error-header">
            <span className="hunt-error-icon">⚠️</span>
            <strong>KQL-style hunting filter error</strong>
          </div>
          <div className="hunt-error-message mono">{error}</div>
          <p className="hunt-error-hint">
            Ensure string literals are enclosed in quotes (e.g. <code>event_type == &quot;ProcessCreate&quot;</code>) and operators are valid (<code>==</code>, <code>!=</code>, <code>contains</code>, <code>&gt;=</code>, <code>&lt;=</code>).
          </p>
        </div>
      )}

      {/* Results Header */}
      {hasExecuted && !error && (
        <div className="hunt-results-header">
          <div className="results-count-badge">
            <span className="text-secondary">Matches:</span>
            <strong className="text-accent mono">{alerts.length}</strong>
            <span className="text-muted">records found</span>
          </div>
          {alerts.length > 0 && (
            <span className="text-xs text-muted mono">
              Queried against alerts table with parameterized SQLite JSON extraction
            </span>
          )}
        </div>
      )}

      {/* Results Table following modern responsive table guidance */}
      {alerts.length > 0 && (
        <div
          tabIndex={0}
          role="region"
          aria-label="Threat hunting search results"
          className="table-wrapper hunt-table-wrapper"
        >
          <table className="hunt-table">
            <thead>
              <tr>
                <th scope="col" style={{ width: "170px" }}>Timestamp</th>
                <th scope="col" style={{ width: "140px" }}>Event Type</th>
                <th scope="col" style={{ width: "200px" }}>Source / Dataset</th>
                <th scope="col" style={{ width: "120px" }}>Ground Truth</th>
                <th scope="col">Extracted Indicators</th>
                <th scope="col" style={{ width: "90px" }} className="text-right">Payload</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => {
                const isExpanded = expandedId === alert.id;
                const isMalicious = alert.ground_truth_label?.toLowerCase() === "malicious";
                const isBenign = alert.ground_truth_label?.toLowerCase() === "benign";

                return (
                  <React.Fragment key={alert.id}>
                    <tr className={`hunt-row ${isExpanded ? "row-expanded" : ""}`}>
                      <td className="mono text-xs text-secondary">
                        {formatTimestamp(alert.timestamp)}
                      </td>
                      <td>
                        <span className="event-badge mono">{alert.event_type}</span>
                      </td>
                      <td>
                        <div className="source-info">
                          <span className="source-dataset text-sm">{alert.source_dataset}</span>
                          <span className="source-file mono text-xs text-muted">{alert.source_file}</span>
                        </div>
                      </td>
                      <td>
                        {isMalicious ? (
                          <span className="badge badge-malicious">MALICIOUS</span>
                        ) : isBenign ? (
                          <span className="badge badge-benign">BENIGN</span>
                        ) : (
                          <span className="badge badge-unknown">
                            {alert.ground_truth_label || "UNLABELED"}
                          </span>
                        )}
                      </td>
                      <td>
                        <div className="indicator-pill-list">
                          {alert.extracted_indicators && alert.extracted_indicators.length > 0 ? (
                            alert.extracted_indicators.map((ioc, i) => (
                              <span key={i} className="ioc-pill mono text-xs">
                                {ioc}
                              </span>
                            ))
                          ) : (
                            <span className="text-muted text-xs">—</span>
                          )}
                        </div>
                      </td>
                      <td className="text-right">
                        <button
                          type="button"
                          className="btn-inspect mono text-xs"
                          onClick={() => toggleExpand(alert.id)}
                          aria-expanded={isExpanded}
                        >
                          {isExpanded ? "Hide" : "Inspect"}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="detail-expanded-row">
                        <td colSpan={6}>
                          <div className="record-details-card">
                            <div className="record-details-header">
                              <span className="text-xs text-muted mono">Alert ID: {alert.id}</span>
                              <button
                                type="button"
                                className="btn-copy text-xs mono"
                                onClick={() => {
                                  navigator.clipboard.writeText(
                                    JSON.stringify(alert.original_record, null, 2)
                                  );
                                }}
                              >
                                📋 Copy Raw JSON
                              </button>
                            </div>
                            <pre className="record-json mono">
                              {JSON.stringify(alert.original_record, null, 2)}
                            </pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty State */}
      {hasExecuted && alerts.length === 0 && !error && !loading && (
        <div className="state-container empty-state hunt-empty-state">
          <div className="empty-icon">🛡️</div>
          <h3>No matching alerts found</h3>
          <p className="empty-text">
            No telemetry records matched the query. Try broadening your criteria or search across different attributes.
          </p>
        </div>
      )}
    </div>
  );
};

