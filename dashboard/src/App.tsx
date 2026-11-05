import React from "react";
import { BrowserRouter, Link, NavLink, Route, Routes } from "react-router-dom";
import { DashboardHome } from "./pages/DashboardHome";
import { TimelineView } from "./pages/TimelineView";
import { ThreatHunt } from "./pages/ThreatHunt";

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="app-shell">
        {/* Top Operations Header */}
        <header className="app-header">
          <div className="header-container">
            <div className="brand-group">
              <Link to="/" className="brand-logo-link">
                <div className="brand-logo-icon">🔍</div>
                <div className="brand-text-block">
                  <span className="brand-name">TriageLens</span>
                  <span className="brand-tagline">AI SOC Alert Triage · Reliability Engine</span>
                </div>
              </Link>
            </div>

            <nav className="header-nav" aria-label="Main Navigation">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
              >
                Overview Dashboard
              </NavLink>
              <NavLink
                to="/hunt"
                className={({ isActive }) =>
                  `nav-link ${isActive ? "active" : ""}`
                }
              >
                Threat Hunting
              </NavLink>
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noreferrer"
                className="nav-link nav-link-external"
              >
                API Docs ↗
              </a>
              <div className="header-status-indicator">
                <span className="status-ping" />
                <span className="status-text mono">SOC Engine Online</span>
              </div>
            </nav>
          </div>
        </header>

        {/* Main Content Area */}
        <main className="app-main-content">
          <Routes>
            <Route path="/" element={<DashboardHome />} />
            <Route path="/timeline/:id" element={<TimelineView />} />
            <Route path="/hunt" element={<ThreatHunt />} />
          </Routes>
        </main>

        {/* Analyst Footer */}
        <footer className="app-footer">
          <div className="footer-container">
            <p className="footer-tagline">
              <strong>TriageLens:</strong> An alert triage pipeline that measures how often its AI is wrong.
            </p>
            <p className="footer-subtext">
              Human-in-the-loop mandated · AI verdicts are non-authoritative recommendations · v0.1.0
            </p>
          </div>
        </footer>
      </div>
    </BrowserRouter>
  );
};

export default App;
