import React from "react";
import { MetricsOverview } from "../components/MetricsOverview";
import { TimelineFeed } from "../components/TimelineFeed";

export const DashboardHome: React.FC = () => {
  return (
    <div className="dashboard-home">
      <div className="console-banner overview-banner">
        <div className="console-info">
          <p className="workspace-eyebrow">Triage workspace</p>
          <h1 className="console-title">Security operations</h1>
          <p className="console-description">
            Investigate correlated alerts and measure AI triage against independent ground truth.
          </p>
        </div>
        <div className="pipeline-status-badge">
          <span>Live provider status not checked</span>
        </div>
      </div>

      <div className="dashboard-grid">
        <TimelineFeed />
        <MetricsOverview />
      </div>
    </div>
  );
};

