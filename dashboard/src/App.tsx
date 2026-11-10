import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { DashboardHome } from "./pages/DashboardHome";
import { TimelineView } from "./pages/TimelineView";
import { ThreatHunt } from "./pages/ThreatHunt";
import { Alerts } from "./pages/Alerts";
import { ThreatIntelligence } from "./pages/ThreatIntelligence";
import { Detections } from "./pages/Detections";

const navigation = [
  { to: "/", label: "Overview Dashboard", icon: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z" },
  { to: "/alerts", label: "Alerts", icon: "M3 5h18v14H3z M7 9h10 M7 13h7" },
  { to: "/intelligence", label: "Threat intelligence", icon: "M12 2l8 4v6c0 5-8 10-8 10S4 17 4 12V6z M9 12l2 2 4-4" },
  { to: "/hunt", label: "Threat Hunting", icon: "M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13z M16 16l5 5" },
  { to: "/detections", label: "Detections", icon: "M3 12h4l3-7 4 14 3-7h4" },
];

function Workspace() {
  const [menuOpen, setMenuOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const { pathname } = useLocation();
  const section = navigation.find(item => item.to === pathname)?.label ?? "Investigation";

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  const closeMenu = () => {
    if (menuOpen) mainRef.current?.focus({ preventScroll: true });
    setMenuOpen(false);
  };

  return (
      <div className="app-shell">
        <a className="skip-link" href="#workspace-main">Skip to content</a>
        <header className="app-header">
          <div className="header-container">
              <Link to="/" className="brand-logo-link" onClick={closeMenu}>
                <span className="brand-logo-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                    <path d="M12 3l9 9-9 9-9-9z M3 12h5l2-4 3 8 2-4h6" />
                  </svg>
                </span>
                <span className="brand-text-block">
                  <span className="brand-name">TriageLens</span>
                  <span className="brand-tagline">Analyst workspace</span>
                </span>
              </Link>
              <button className="menu-toggle btn btn-secondary" type="button" aria-expanded={menuOpen}
                aria-controls="workspace-nav" onClick={() => setMenuOpen(open => !open)}>Menu</button>
          </div>

            <nav id="workspace-nav" className={`header-nav${menuOpen ? " is-open" : ""}`} aria-label="Main Navigation">
              <p className="workspace-eyebrow">Operations</p>
              {navigation.map(({ to, label, icon }) => (
                <NavLink key={to} to={to} end className="nav-link" onClick={closeMenu}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d={icon} /></svg>
                  {label}
                </NavLink>
              ))}
              <p className="workspace-eyebrow nav-resources">Resources</p>
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noreferrer"
                className="nav-link nav-link-external"
              >
                API Docs <span aria-hidden="true">↗</span>
              </a>
            </nav>
            <div className="workspace-sidebar-note"><strong>Human review required</strong><span>AI assessments are advisory</span></div>
        </header>

        <div className="workspace-body">
        <div className="workspace-bar"><span>Workspace <span aria-hidden="true">/</span> <strong>{section}</strong></span><span className="workspace-local">Local instance</span></div>
        <main id="workspace-main" ref={mainRef} tabIndex={-1} className="app-main-content">
          <Routes>
            <Route path="/" element={<DashboardHome />} />
            <Route path="/timeline/:id" element={<TimelineView />} />
            <Route path="/hunt" element={<ThreatHunt />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/intelligence" element={<ThreatIntelligence />} />
            <Route path="/detections" element={<Detections />} />
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
      </div>
  );
}

export const App = () => <BrowserRouter><Workspace /></BrowserRouter>;
export default App;
