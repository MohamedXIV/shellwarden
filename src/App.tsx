import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { APP_VERSION } from "./version";

type Section = "Dashboard" | "Activity" | "Approvals" | "Permissions" | "Audit" | "Settings";

type ExecutionCoreStatus = {
  running: boolean;
  expectedVersion: string;
  detectedVersion: string | null;
  error: string | null;
};

const sections: Array<{ label: Section; glyph: string }> = [
  { label: "Dashboard", glyph: "◫" },
  { label: "Activity", glyph: "⌁" },
  { label: "Approvals", glyph: "◇" },
  { label: "Permissions", glyph: "⌾" },
  { label: "Audit", glyph: "≡" },
  { label: "Settings", glyph: "⚙" },
];

function Placeholder({
  section,
  executionCore,
}: {
  section: Section;
  executionCore: ExecutionCoreStatus;
}) {
  if (section === "Dashboard") {
    const health = [
      { label: "Desktop shell", value: "Ready", tone: "good", detail: "Tauri desktop runtime" },
      {
        label: "Execution core",
        value: executionCore.running
          ? `Ready · v${executionCore.detectedVersion}`
          : "Unavailable",
        tone: executionCore.running ? "good" : "idle",
        detail: executionCore.error ?? `Pinned mcp-shell-server v${executionCore.expectedVersion}`,
      },
      {
        label: "Remote access",
        value: "Not configured",
        tone: "idle",
        detail: "No MCP transport is exposed yet",
      },
    ] as const;

    return (
      <>
        <section className="hero-panel">
          <div>
            <p className="eyebrow">LOCAL CONTROL CENTER</p>
            <h1>Your shell stays yours.</h1>
            <p className="hero-copy">
              ShellWarden now supervises a pinned local execution core behind its broker boundary.
              No remote MCP client can invoke it yet.
            </p>
          </div>
          <section className="access-state" aria-label="Remote access status">
            <span className="status-dot offline" />
            <div>
              <strong>Remote access offline</strong>
              <span>The execution core remains local-only until the remote transport phase.</span>
            </div>
          </section>
        </section>

        <section className="health-grid" aria-label="Development health">
          {health.map((item) => (
            <article className="health-card" key={item.label} title={item.detail}>
              <div className={`health-icon ${item.tone}`} />
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
            <span className="section-kicker">EXECUTION CORE</span>
            <h2>{executionCore.running ? "Pinned core supervised" : "Core needs attention"}</h2>
            <p>
              {executionCore.running
                ? "mcp-shell-server is running behind ShellWarden's bootstrap broker. Only the internal git probe is admitted in this slice."
                : executionCore.error ??
                  "Install the pinned Python execution dependency to enable the local core."}
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
        This surface is intentionally reserved for its roadmap slice. The current build keeps the
        execution core local-only and exposes status, not arbitrary execution, to the frontend.
      </p>
    </section>
  );
}

const initialCoreStatus: ExecutionCoreStatus = {
  running: false,
  expectedVersion: "1.1.12",
  detectedVersion: null,
  error: "Checking execution core…",
};

export function App() {
  const [section, setSection] = useState<Section>("Dashboard");
  const [executionCore, setExecutionCore] = useState<ExecutionCoreStatus>(initialCoreStatus);

  useEffect(() => {
    let cancelled = false;

    invoke<ExecutionCoreStatus>("execution_core_status")
      .then((status) => {
        if (!cancelled) {
          setExecutionCore(status);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setExecutionCore({
            ...initialCoreStatus,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            SW
          </div>
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
              <span className="nav-glyph" aria-hidden="true">
                {item.glyph}
              </span>
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
            <span className="phase-chip">Execution core</span>
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
          <Placeholder section={section} executionCore={executionCore} />
        </div>
      </main>
    </div>
  );
}
