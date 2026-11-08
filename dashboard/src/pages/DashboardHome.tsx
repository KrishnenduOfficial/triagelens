import React from "react";
import { MetricsOverview } from "../components/MetricsOverview";
import { TimelineFeed } from "../components/TimelineFeed";

export const DashboardHome: React.FC = () => {
  return (
    <div className="dashboard-home">
      <div className="console-banner">
        <div className="console-info">
          <h1 className="console-title">Security Operations Triage Console</h1>
          <p className="console-description">
            Automated SOC timeline correlation, AI-assisted threat triage, and continuous reliability validation.
          </p>
        </div>
        <div className="pipeline-status-badge">
          <span>Live provider status not checked</span>
        </div>
      </div>

      <div className="dashboard-grid">
        <MetricsOverview />
        <TimelineFeed />
      </div>
    </div>
  );
};

