import { useMemo, useState } from "react";

export type PolicyEffect = "allow" | "deny";
export type ApprovalScope =
  | "once"
  | "session"
  | "exact_request"
  | "exact_directory"
  | "directory_tree"
  | "always"
  | "deny";

export type PolicyRuleView = {
  id: string;
  effect: PolicyEffect;
  scope: ApprovalScope;
  persistence: string;
  source: string;
  sessionId: string | null;
  executable: string;
  operationClass: string;
  directory: string;
  scopeRoot: string | null;
  environmentKeyCount: number;
  createdAtMs: number;
};

export type AuditEntry = {
  id: number;
  kind: "decision" | "execution";
  timestampMs: number;
  executionId: string | null;
  source: string;
  commandSummary: string;
  operationClass: string;
  directory: string;
  outcome: string | null;
  status: string | null;
  durationMs: number | null;
  riskClass: string | null;
  ruleId: string | null;
  reason: string | null;
};

const scopeLabels: Record<ApprovalScope, string> = {
  once: "Once",
  session: "Session",
  exact_request: "Exact request",
  exact_directory: "Exact directory",
  directory_tree: "Directory tree",
  always: "Always",
  deny: "Deny",
};

function formatTimestamp(timestampMs: number) {
  return new Date(timestampMs).toLocaleString();
}

function formatDuration(milliseconds: number | null) {
  if (milliseconds == null) return "—";
  if (milliseconds < 1000) return String(milliseconds) + " ms";
  const seconds = Math.round(milliseconds / 100) / 10;
  if (seconds < 60) return String(seconds) + "s";
  const minutes = Math.floor(seconds / 60);
  return String(minutes) + "m " + String(Math.round(seconds % 60)) + "s";
}

function shortDirectory(directory: string) {
  const normalized = directory.replaceAll("\\", "/").replace(/\/$/, "");
  const parts = normalized.split("/");
  if (parts.length <= 4) return directory;
  return ["…", ...parts.slice(-4)].join("/");
}

function ruleSearchText(rule: PolicyRuleView) {
  return [
    rule.id,
    rule.effect,
    rule.scope,
    rule.persistence,
    rule.source,
    rule.executable,
    rule.operationClass,
    rule.directory,
    rule.scopeRoot ?? "",
    rule.sessionId ?? "",
  ]
    .join(" ")
    .toLowerCase();
}

export function PermissionsView({
  rules,
  error,
  busy,
  onRevoke,
  onResetSessions,
  onResetDirectoryScopes,
  onResetPersistent,
}: {
  rules: PolicyRuleView[];
  error: string | null;
  busy: string | null;
  onRevoke: (ruleId: string) => void;
  onResetSessions: () => void;
  onResetDirectoryScopes: () => void;
  onResetPersistent: () => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "persistent" | "ephemeral">("all");
  const [confirmReset, setConfirmReset] = useState(false);

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (filter !== "all" && rule.persistence !== filter) return false;
      return normalizedQuery.length === 0 || ruleSearchText(rule).includes(normalizedQuery);
    });
  }, [filter, query, rules]);

  const persistentCount = rules.filter((rule) => rule.persistence === "persistent").length;
  const sessionCount = rules.filter((rule) => rule.persistence === "ephemeral").length;

  return (
    <section className="management-page">
      <div className="page-heading">
        <div>
          <span className="section-kicker">ACCUMULATED AUTHORITY</span>
          <h1>Permissions</h1>
          <p>Every remembered grant is visible, searchable, and reversible from here.</p>
        </div>
        <div className="management-metrics">
          <span><strong>{persistentCount}</strong> persistent</span>
          <span><strong>{sessionCount}</strong> session</span>
        </div>
      </div>

      {error && (
        <div className="panel inline-error large">
          <strong>Could not read permissions</strong>
          <span>{error}</span>
        </div>
      )}

      <section className="management-toolbar panel">
        <input
          aria-label="Search permissions"
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search executable, directory, source, rule ID…"
          type="search"
          value={query}
        />
        <fieldset className="segmented-control">
          <legend className="visually-hidden">Permission persistence filter</legend>
          {(["all", "persistent", "ephemeral"] as const).map((value) => (
            <button
              className={filter === value ? "active" : ""}
              key={value}
              onClick={() => setFilter(value)}
              type="button"
            >
              {value}
            </button>
          ))}
        </fieldset>
      </section>

      <section className="permission-reset-strip">
        <button disabled={busy !== null || sessionCount === 0} onClick={onResetSessions} type="button">
          Clear session rules
        </button>
        <button disabled={busy !== null} onClick={onResetDirectoryScopes} type="button">
          Clear directory scopes
        </button>
        {!confirmReset ? (
          <button
            className="danger-outline"
            disabled={busy !== null || persistentCount === 0}
            onClick={() => setConfirmReset(true)}
            type="button"
          >
            Reset all persistent
          </button>
        ) : (
          <div className="inline-confirm">
            <span>Remove every persistent grant/deny?</span>
            <button
              className="danger-solid"
              disabled={busy !== null}
              onClick={() => {
                setConfirmReset(false);
                onResetPersistent();
              }}
              type="button"
            >
              Confirm reset
            </button>
            <button disabled={busy !== null} onClick={() => setConfirmReset(false)} type="button">
              Cancel
            </button>
          </div>
        )}
      </section>

      {filtered.length === 0 ? (
        <section className="panel management-empty">
          <div className="empty-mark">⌾</div>
          <strong>{rules.length === 0 ? "No permissions stored" : "No matching permissions"}</strong>
          <p>
            Persistent approvals created from the Approvals screen appear here. Session-only rules
            disappear when ShellWarden exits.
          </p>
        </section>
      ) : (
        <div className="permission-list">
          {filtered.map((rule) => (
            <article className={"permission-card effect-" + rule.effect} key={rule.id}>
              <div className="permission-card-head">
                <div>
                  <div className="permission-badges">
                    <span className={"effect-badge effect-" + rule.effect}>{rule.effect}</span>
                    <span>{scopeLabels[rule.scope]}</span>
                    <span>{rule.persistence}</span>
                  </div>
                  <strong>{rule.executable}</strong>
                  <code>{rule.id}</code>
                </div>
                <button
                  className="danger-outline compact"
                  disabled={busy !== null}
                  onClick={() => onRevoke(rule.id)}
                  type="button"
                >
                  {busy === "revoke:" + rule.id ? "Revoking…" : "Revoke"}
                </button>
              </div>

              <div className="permission-details">
                <div>
                  <span>Operation</span>
                  <strong>{rule.operationClass}</strong>
                </div>
                <div>
                  <span>Authority</span>
                  <strong title={rule.scopeRoot ?? rule.directory}>
                    {shortDirectory(rule.scopeRoot ?? rule.directory)}
                  </strong>
                </div>
                <div>
                  <span>Requester</span>
                  <strong>{rule.source}</strong>
                </div>
                <div>
                  <span>Created</span>
                  <strong>{formatTimestamp(rule.createdAtMs)}</strong>
                </div>
              </div>

              {rule.sessionId && <p className="permission-session">Session: {rule.sessionId}</p>}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function auditSearchText(entry: AuditEntry) {
  return [
    entry.id,
    entry.kind,
    entry.executionId ?? "",
    entry.source,
    entry.commandSummary,
    entry.operationClass,
    entry.directory,
    entry.outcome ?? "",
    entry.status ?? "",
    entry.riskClass ?? "",
    entry.ruleId ?? "",
    entry.reason ?? "",
  ]
    .join(" ")
    .toLowerCase();
}

export function AuditView({
  entries,
  error,
}: {
  entries: AuditEntry[];
  error: string | null;
}) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | "decision" | "execution">("all");

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return entries.filter((entry) => {
      if (kind !== "all" && entry.kind !== kind) return false;
      return normalizedQuery.length === 0 || auditSearchText(entry).includes(normalizedQuery);
    });
  }, [entries, kind, query]);

  return (
    <section className="management-page">
      <div className="page-heading">
        <div>
          <span className="section-kicker">DURABLE HISTORY</span>
          <h1>Audit</h1>
          <p>
            Decision and terminal execution history survives restart. Arguments and process output
            are deliberately not stored here.
          </p>
        </div>
        <div className="management-metrics">
          <span><strong>{entries.length}</strong> retained</span>
        </div>
      </div>

      {error && (
        <div className="panel inline-error large">
          <strong>Could not read audit history</strong>
          <span>{error}</span>
        </div>
      )}

      <section className="management-toolbar panel">
        <input
          aria-label="Search audit history"
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search rule, executable, directory, status…"
          type="search"
          value={query}
        />
        <fieldset className="segmented-control">
          <legend className="visually-hidden">Audit event filter</legend>
          {(["all", "decision", "execution"] as const).map((value) => (
            <button
              className={kind === value ? "active" : ""}
              key={value}
              onClick={() => setKind(value)}
              type="button"
            >
              {value}
            </button>
          ))}
        </fieldset>
      </section>

      {filtered.length === 0 ? (
        <section className="panel management-empty">
          <div className="empty-mark">≡</div>
          <strong>{entries.length === 0 ? "Audit history is empty" : "No matching audit events"}</strong>
          <p>ShellWarden records decisions and terminal executions after this audit store is enabled.</p>
        </section>
      ) : (
        <div className="audit-list">
          {filtered.map((entry) => (
            <article className={"audit-card kind-" + entry.kind} key={entry.id}>
              <div className="audit-card-head">
                <div className="audit-title">
                  <span className={"audit-kind kind-" + entry.kind}>{entry.kind}</span>
                  <strong>{entry.commandSummary}</strong>
                  {entry.riskClass && (
                    <span className={"risk-badge risk-" + entry.riskClass}>{entry.riskClass}</span>
                  )}
                </div>
                <time>{formatTimestamp(entry.timestampMs)}</time>
              </div>

              <div className="audit-details">
                <span>{entry.source}</span>
                <span>{entry.operationClass}</span>
                <span title={entry.directory}>{shortDirectory(entry.directory)}</span>
                {entry.outcome && <span className={"audit-result result-" + entry.outcome}>{entry.outcome}</span>}
                {entry.status && <span className={"audit-result result-" + entry.status}>{entry.status}</span>}
                {entry.durationMs != null && <span>{formatDuration(entry.durationMs)}</span>}
              </div>

              {(entry.ruleId || entry.executionId) && (
                <div className="audit-links">
                  {entry.ruleId && (
                    <span>
                      Rule <code>{entry.ruleId}</code>
                    </span>
                  )}
                  {entry.executionId && (
                    <span>
                      Execution <code>{entry.executionId}</code>
                    </span>
                  )}
                </div>
              )}

              {entry.reason && <p className="audit-reason">{entry.reason}</p>}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
