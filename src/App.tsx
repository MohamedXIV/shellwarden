import { useState } from "react";
import { APP_VERSION } from "./version";

type Section = "Dashboard" | "Activity" | "Approvals" | "Permissions" | "Audit" | "Settings";

const sections: Array<{ label: Section; glyph: string }> = [
  { label: "Dashboard", glyph: "◫" },
  { label: "Activity", glyph: "⌁" },
  { label: "Approvals", glyph: "◇" },
  { label: "Permissions", glyph: "⌾" },
  { label: "Audit", glyph: "≡" },
  { label: "Settings", glyph: "⚙" },
];

const health = [
  { label: "Desktop shell", value: "Ready", tone: "good" },
  { label: "Execution broker", value: "Not connected", tone: "idle" },
  { label: "Remote access", value: "Not configured", tone: "idle" },
] as const;

function Placeholder({ section }: { section: Section }) {
  if (section === "Dashboard") {
    return (
      <>
        <section className="hero-panel">
          <div>
            <p className="eyebrow">LOCAL CONTROL CENTER</p>
            <h1>Your shell stays yours.</h1>
            <p className="hero-copy">
              ShellWarden will place scoped human approval between AI agents and local execution.
              This foundation build exposes no shell access yet.
            </p>
          </div>
          <div className="access-state" aria-label="Remote access status">
            <span className="status-dot offline" />
            <div>
              <strong>Remote access offline</strong>
              <span>Execution features arrive in Phase 2.</span>
            </div>
          </div>
        </section>

        <section className="health-grid" aria-label="Development health">
          {health.map((item) => (
            <article className="health-card" key={item.label}>
              <div className={"health-icon " + item.tone} />
              <div>
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            </article>
          ))}
        </section>

        <section className="workspace-grid">
          <article className="panel activity-preview">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">ACTIVITY</span>
                <h2>Nothing is executing</h2>
              </div>
              <span className="quiet-badge">0 running</span>
            </div>
            <div className="empty-state">
              <div className="empty-mark">›_</div>
              <p>Execution requests will appear here as structured, inspectable activity.</p>
            </div>
          </article>

          <article className="panel next-step">
            <span className="section-kicker">FOUNDATION STATUS</span>
            <h2>Desktop shell online</h2>
            <p>
              Navigation, application version, health state, and the Windows desktop foundation are
              now in place.
            </p>
            <div className="milestone-row">
              <span>Current build</span>
              <code>{APP_VERSION}</code>
            </div>
          </article>
        </section>
      </>
    );
  }

  return (
    <section className="panel section-placeholder">
      <span className="section-kicker">{section.toUpperCase()}</span>
      <h1>{section}</h1>
      <p>
        This surface is intentionally reserved for its roadmap slice. The foundation only
        establishes the application shell and navigation contract.
      </p>
    </section>
  );
}

export function App() {
  const [section, setSection] = useState<Section>("Dashboard");

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">SW</div>
          <div>
            <strong>ShellWarden</strong>
            <span>Control Center</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Primary navigation">
          {sections.map((item) => (
            <button
              className={section === item.label ? "nav-item active" : "nav-item"}
              key={item.label}
              onClick={() => setSection(item.label)}
              type="button"
            >
              <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
              {item.label}
              {item.label === "Approvals" && <span className="nav-count">0</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="local-only">
            <span className="status-dot local" />
            <div>
              <strong>Local only</strong>
              <span>No remote transport</span>
            </div>
          </div>
          <span className="version">v{APP_VERSION}</span>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <span className="crumb">ShellWarden /</span>
            <strong>{section}</strong>
          </div>
          <div className="topbar-actions">
            <span className="phase-chip">Foundation</span>
            <button
              className="pause-button"
              disabled
              type="button"
              title="Remote access is not configured yet"
            >
              Pause Remote Access
            </button>
          </div>
        </header>

        <div className="content">
          <Placeholder section={section} />
        </div>
      </main>
    </div>
  );
}
