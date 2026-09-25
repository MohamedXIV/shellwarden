import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { AuditView, PermissionsView, type AuditEntry, type PolicyRuleView } from "./ManagementViews";
import { APP_VERSION } from "./version";

type Section = "Dashboard" | "Activity" | "Approvals" | "Permissions" | "Audit" | "Settings";

type ExecutionStatus =
  | "requested"
  | "awaiting_approval"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "denied"
  | "cancelled"
  | "timed_out";

type ExecutionCoreStatus = {
  running: boolean;
  expectedVersion: string;
  detectedVersion: string | null;
  error: string | null;
};

type ExecutionRequest = {
  id: string;
  source: string;
  sessionId: string | null;
  command: string[];
  operationClass: string;
  directory: string;
  timeoutSeconds: number | null;
  environmentKeys: string[];
};

type ExecutionSnapshot = {
  request: ExecutionRequest;
  state: ExecutionStatus;
  stdoutTail: string;
  stderrTail: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  policyRuleId: string | null;
  createdAtMs: number;
  updatedAtMs: number;
};

type RiskClass = "low" | "medium" | "high" | "critical";

type RiskAssessment = {
  class: RiskClass;
  reason: string;
  rule: string;
  allowedScopes: string[];
};

type PolicyOutcome = "allow" | "ask" | "deny";

type ApprovalScope =
  | "once"
  | "session"
  | "exact_request"
  | "exact_directory"
  | "directory_tree"
  | "always"
  | "deny";

type ApprovalStatus = "pending" | "allowed" | "denied" | "cancelled" | "expired";

type ApprovalView = {
  id: string;
  executionId: string | null;
  source: string;
  sessionId: string | null;
  command: string[];
  operationClass: string;
  directory: string;
  environmentKeys: string[];
  risk: RiskAssessment;
  status: ApprovalStatus;
  requestedAtMs: number;
  expiresAtMs: number | null;
  resolvedAtMs: number | null;
  resolutionScope: ApprovalScope | null;
  decisionRuleId: string | null;
  decisionReason: string | null;
};

type ApprovalResolution = {
  approval: ApprovalView;
  decision: {
    outcome: PolicyOutcome;
    ruleId: string | null;
    reason: string;
  } | null;
};

type PolicyDecisionEvent = {
  sequence: number;
  timestampMs: number;
  source: string;
  executable: string;
  argumentCount: number;
  operationClass: string;
  directory: string;
  outcome: PolicyOutcome;
  ruleId: string | null;
  reason: string;
};

type RemoteAccessPhase = "unconfigured" | "paused" | "starting" | "connected" | "error";

type RemoteAccessStatus = {
  phase: RemoteAccessPhase;
  configured: boolean;
  tunnelId: string | null;
  mcpServerUrl: string | null;
  healthUrl: string | null;
  error: string | null;
};

const initialRemoteAccess: RemoteAccessStatus = {
  phase: "unconfigured",
  configured: false,
  tunnelId: null,
  mcpServerUrl: null,
  healthUrl: null,
  error: null,
};

const sections: Array<{ label: Section; glyph: string }> = [
  { label: "Dashboard", glyph: "◫" },
  { label: "Activity", glyph: "⌁" },
  { label: "Approvals", glyph: "◇" },
  { label: "Permissions", glyph: "⌾" },
  { label: "Audit", glyph: "≡" },
  { label: "Settings", glyph: "⚙" },
];

const initialCoreStatus: ExecutionCoreStatus = {
  running: false,
  expectedVersion: "1.1.12",
  detectedVersion: null,
  error: "Checking execution core…",
};

const activeStates = new Set<ExecutionStatus>([
  "requested",
  "awaiting_approval",
  "queued",
  "running",
]);

function statusLabel(status: ExecutionStatus) {
  switch (status) {
    case "awaiting_approval":
      return "Awaiting approval";
    case "timed_out":
      return "Timed out";
    default:
      return status.charAt(0).toUpperCase() + status.slice(1);
  }
}

function formatDuration(milliseconds: number) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainder.toString().padStart(2, "0")}s`;

  const hours = Math.floor(minutes / 60);
  return `${hours}h ${(minutes % 60).toString().padStart(2, "0")}m`;
}

function commandText(command: string[]) {
  return command
    .map((part) => (/\s/.test(part) ? JSON.stringify(part) : part))
    .join(" ");
}

function shortDirectory(directory: string) {
  const normalized = directory.replaceAll("\\", "/").replace(/\/$/, "");
  const pieces = normalized.split("/");
  if (pieces.length <= 3) return directory;
  return ["…", ...pieces.slice(-3)].join("/");
}

function executionDuration(execution: ExecutionSnapshot, now: number) {
  const end = activeStates.has(execution.state) ? now : execution.updatedAtMs;
  return Math.max(0, end - execution.createdAtMs);
}

function riskLabel(risk?: RiskAssessment) {
  return risk ? risk.class.toUpperCase() : "ASSESSING";
}

const approvalScopeCopy: Record<
  ApprovalScope,
  { title: string; detail: string; tone?: "danger" }
> = {
  once: {
    title: "Allow once",
    detail: "Authorize this exact request one time.",
  },
  session: {
    title: "Allow this session",
    detail: "Authorize this exact request until ShellWarden exits.",
  },
  exact_request: {
    title: "Remember exact request",
    detail: "Persist only this exact command and canonical working directory.",
  },
  exact_directory: {
    title: "Allow in this directory",
    detail: "Persist this operation for this canonical directory only.",
  },
  directory_tree: {
    title: "Allow in this directory tree",
    detail: "Persist this operation for this canonical directory and descendants.",
  },
  always: {
    title: "Always allow",
    detail: "Persist this operation regardless of working directory.",
  },
  deny: {
    title: "Deny",
    detail: "Reject this request without creating a persistent deny rule.",
    tone: "danger",
  },
};

function approvalStatusLabel(status: ApprovalStatus) {
  switch (status) {
    case "allowed":
      return "Allowed";
    case "denied":
      return "Denied";
    case "cancelled":
      return "Cancelled";
    case "expired":
      return "Expired";
    default:
      return "Waiting";
  }
}

function approvalAge(approval: ApprovalView, now: number) {
  const end = approval.resolvedAtMs ?? now;
  return formatDuration(Math.max(0, end - approval.requestedAtMs));
}

function ApprovalCard({
  approval,
  now,
  resolving,
  onResolve,
}: {
  approval: ApprovalView;
  now: number;
  resolving: string | null;
  onResolve: (approvalId: string, scope: ApprovalScope) => void;
}) {
  const pending = approval.status === "pending";
  const critical = approval.risk.class === "critical";
  const expiryRemaining =
    approval.expiresAtMs == null ? null : Math.max(0, approval.expiresAtMs - now);

  return (
    <article
      className={critical ? "approval-card critical" : "approval-card"}
      id={`approval-${encodeURIComponent(approval.id)}`}
    >
      <div className="approval-card-header">
        <div>
          <div className="approval-title-row">
            <span className={`approval-risk risk-${approval.risk.class}`}>
              {approval.risk.class.toUpperCase()}
            </span>
            <span className={`approval-status approval-status-${approval.status}`}>
              {approvalStatusLabel(approval.status)}
            </span>
          </div>
          <code className="approval-command" title={commandText(approval.command)}>
            {commandText(approval.command)}
          </code>
        </div>
        <div className="approval-age">
          <strong>{approvalAge(approval, now)}</strong>
          <span>{pending ? "waiting" : "resolved"}</span>
        </div>
      </div>

      <div className="approval-meta">
        <span>Requester: {approval.source}</span>
        <span title={approval.directory}>cwd: {shortDirectory(approval.directory)}</span>
        {approval.sessionId && <span>session: {approval.sessionId}</span>}
        {expiryRemaining != null && pending && (
          <span className="approval-expiry">
            expires in {formatDuration(expiryRemaining)}
          </span>
        )}
      </div>

      <div className={critical ? "approval-warning critical" : "approval-warning"}>
        <strong>{critical ? "Critical request" : "Why ShellWarden is asking"}</strong>
        <p>{approval.risk.reason}</p>
        {critical && (
          <p>
            Persistent approval is intentionally unavailable. Only temporary scopes exposed by the
            risk policy can be selected.
          </p>
        )}
      </div>

      {pending ? (
        <div className="scope-grid">
          {(approval.risk.allowedScopes as ApprovalScope[]).map((scope) => {
            const copy = approvalScopeCopy[scope];
            const busy = resolving === `${approval.id}:${scope}`;
            return (
              <button
                className={copy.tone === "danger" ? "scope-option danger" : "scope-option"}
                disabled={resolving !== null}
                key={scope}
                onClick={() => onResolve(approval.id, scope)}
                type="button"
              >
                <span className="scope-title">{busy ? "Applying…" : copy.title}</span>
                <span className="scope-detail">{copy.detail}</span>
              </button>
            );
          })}
        </div>
      ) : (
        <div className="approval-terminal">
          <span>
            {approval.resolutionScope
              ? approvalScopeCopy[approval.resolutionScope].title
              : approvalStatusLabel(approval.status)}
          </span>
          <p>{approval.decisionReason ?? "This request no longer needs a decision."}</p>
        </div>
      )}
    </article>
  );
}

function ApprovalsView({
  approvals,
  error,
  now,
  resolving,
  onResolve,
}: {
  approvals: ApprovalView[];
  error: string | null;
  now: number;
  resolving: string | null;
  onResolve: (approvalId: string, scope: ApprovalScope) => void;
}) {
  const pending = approvals.filter((approval) => approval.status === "pending");
  const recent = approvals.filter((approval) => approval.status !== "pending").slice(0, 10);

  return (
    <section className="approvals-page">
      <div className="page-heading">
        <div>
          <span className="section-kicker">HUMAN AUTHORITY</span>
          <h1>Approvals</h1>
          <p>
            ShellWarden only offers scopes allowed by the deterministic risk policy for each
            request.
          </p>
        </div>
        <div className={pending.length > 0 ? "approval-count attention" : "approval-count"}>
          <strong>{pending.length}</strong>
          <span>waiting</span>
        </div>
      </div>

      {error && (
        <div className="panel inline-error large">
          <strong>Could not read approvals</strong>
          <span>{error}</span>
        </div>
      )}

      {pending.length === 0 ? (
        <section className="panel approval-empty">
          <div className="empty-mark">◇</div>
          <strong>No approvals waiting</strong>
          <p>
            When an MCP requester needs authority that policy cannot grant automatically, the
            request appears here and the tray calls for attention.
          </p>
        </section>
      ) : (
        <div className="approval-list">
          {pending.map((approval) => (
            <ApprovalCard
              approval={approval}
              key={approval.id}
              now={now}
              onResolve={onResolve}
              resolving={resolving}
            />
          ))}
        </div>
      )}

      {recent.length > 0 && (
        <section className="approval-recent">
          <div className="approval-section-heading">
            <span className="section-kicker">RECENTLY RESOLVED</span>
            <span>{recent.length} retained this session</span>
          </div>
          <div className="approval-list compact">
            {recent.map((approval) => (
              <ApprovalCard
                approval={approval}
                key={approval.id}
                now={now}
                onResolve={onResolve}
                resolving={resolving}
              />
            ))}
          </div>
        </section>
      )}
    </section>
  );
}

function ActivityCard({
  execution,
  risk,
  now,
}: {
  execution: ExecutionSnapshot;
  risk?: RiskAssessment;
  now: number;
}) {
  const outputExists = Boolean(execution.stdoutTail || execution.stderrTail);

  return (
    <article className={`execution-card status-${execution.state}`}>
      <div className="execution-card-header">
        <div className="execution-identity">
          <span className={`execution-state-dot state-${execution.state}`} />
          <div>
            <div className="execution-title-row">
              <strong>{execution.request.command[0] ?? "Unknown command"}</strong>
              <span className={`status-badge status-${execution.state}`}>
                {statusLabel(execution.state)}
              </span>
            </div>
            <code className="command-line" title={commandText(execution.request.command)}>
              {commandText(execution.request.command)}
            </code>
          </div>
        </div>

        <div className="execution-time">
          <strong>{formatDuration(executionDuration(execution, now))}</strong>
          <span>elapsed</span>
        </div>
      </div>

      <div className="execution-meta">
        <span title={execution.request.source}>by {execution.request.source}</span>
        <span title={execution.request.directory}>cwd {shortDirectory(execution.request.directory)}</span>
        <span className={`risk-badge risk-${risk?.class ?? "pending"}`}>{riskLabel(risk)}</span>
        <span className="execution-id">{execution.request.id}</span>
      </div>

      {risk && (
        <div className="risk-reason">
          <span>{risk.rule}</span>
          <p>{risk.reason}</p>
        </div>
      )}

      {outputExists ? (
        <details className="execution-output" open={execution.state === "running"}>
          <summary>
            <span>Output</span>
            <span>
              {execution.stdoutTruncated || execution.stderrTruncated ? "tail · truncated" : "bounded tail"}
            </span>
          </summary>
          {execution.stdoutTail && (
            <div className="stream-block">
              <span>stdout</span>
              <pre>{execution.stdoutTail}</pre>
            </div>
          )}
          {execution.stderrTail && (
            <div className="stream-block stderr">
              <span>stderr</span>
              <pre>{execution.stderrTail}</pre>
            </div>
          )}
        </details>
      ) : (
        <div className="no-output">
          {execution.state === "awaiting_approval"
            ? "Execution is blocked until an approval decision is made."
            : "No output captured for this execution."}
        </div>
      )}
    </article>
  );
}

function EmptyActivity() {
  return (
    <div className="empty-state activity-empty">
      <div className="empty-mark">›_</div>
      <strong>No execution activity yet</strong>
      <p>
        Requests will appear here as separate blocks with state, authority context, risk, duration,
        and bounded output.
      </p>
    </div>
  );
}

function RecentDecisions({ decisions }: { decisions: PolicyDecisionEvent[] }) {
  return (
    <article className="panel decisions-panel">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">RECENT DECISIONS</span>
          <h2>Policy outcomes</h2>
        </div>
        <span className="quiet-badge">{decisions.length} recent</span>
      </div>

      {decisions.length === 0 ? (
        <div className="compact-empty">
          <span>◇</span>
          <p>No policy decisions have been evaluated in this app session.</p>
        </div>
      ) : (
        <div className="decision-list">
          {decisions.slice(0, 5).map((decision) => (
            <div className="decision-row" key={decision.sequence}>
              <span className={`decision-outcome outcome-${decision.outcome}`}>
                {decision.outcome}
              </span>
              <div>
                <strong>{decision.executable}</strong>
                <span title={decision.directory}>
                  {decision.source} · {shortDirectory(decision.directory)}
                </span>
              </div>
              <span className="decision-rule">{decision.ruleId ?? "no rule"}</span>
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

function Dashboard({
  executionCore,
  executions,
  risks,
  decisions,
  activityError,
  now,
  onOpenActivity,
  pendingApprovalCount,
}: {
  executionCore: ExecutionCoreStatus;
  executions: ExecutionSnapshot[];
  risks: Record<string, RiskAssessment>;
  decisions: PolicyDecisionEvent[];
  activityError: string | null;
  now: number;
  onOpenActivity: () => void;
  pendingApprovalCount: number;
}) {
  const active = executions.filter((execution) => activeStates.has(execution.state));
  const running = executions.filter((execution) => execution.state === "running");
  const recent = [...executions].sort((a, b) => b.updatedAtMs - a.updatedAtMs).slice(0, 3);

  const health = [
    { label: "Desktop shell", value: "Ready", tone: "good", detail: "Tauri desktop runtime" },
    {
      label: "Execution core",
      value: executionCore.running
        ? `Ready · v${executionCore.detectedVersion}`
        : "Unavailable",
      tone: executionCore.running ? "good" : "danger",
      detail: executionCore.error ?? `Pinned mcp-shell-server v${executionCore.expectedVersion}`,
    },
    {
      label: "Remote access",
      value: "Offline",
      tone: "idle",
      detail: "Secure MCP Tunnel is not configured yet",
    },
  ] as const;

  return (
    <>
      <section className="hero-panel control-hero">
        <div>
          <p className="eyebrow">LOCAL CONTROL CENTER</p>
          <h1>See every hand on your shell.</h1>
          <p className="hero-copy">
            ShellWarden keeps execution visible as structured activity: who requested it, where it
            runs, what risk it carries, and how it finished.
          </p>
        </div>
        <section className="access-state" aria-label="Remote access status">
          <span className="status-dot offline" />
          <div>
            <strong>Remote access offline</strong>
            <span>Local control is active. No remote MCP transport is connected yet.</span>
          </div>
        </section>
      </section>

      <section className="health-grid" aria-label="System health">
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

      <section className="metric-strip" aria-label="Current activity summary">
        <article>
          <span>Active</span>
          <strong>{active.length}</strong>
          <small>{running.length} running now</small>
        </article>
        <article className={pendingApprovalCount > 0 ? "attention" : ""}>
          <span>Needs approval</span>
          <strong>{pendingApprovalCount}</strong>
          <small>{pendingApprovalCount > 0 ? "human decision required" : "nothing blocked"}</small>
        </article>
        <article>
          <span>Tracked</span>
          <strong>{executions.length}</strong>
          <small>this app session</small>
        </article>
        <article>
          <span>Policy decisions</span>
          <strong>{decisions.length}</strong>
          <small>recent in memory</small>
        </article>
      </section>

      <section className="dashboard-grid">
        <article className="panel live-preview">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">LIVE ACTIVITY</span>
              <h2>{active.length > 0 ? `${active.length} active execution${active.length === 1 ? "" : "s"}` : "Execution stream"}</h2>
            </div>
            <button className="text-button" type="button" onClick={onOpenActivity}>
              Open Activity →
            </button>
          </div>

          {activityError ? (
            <div className="inline-error">
              <strong>Activity unavailable</strong>
              <span>{activityError}</span>
            </div>
          ) : recent.length === 0 ? (
            <EmptyActivity />
          ) : (
            <div className="activity-list compact">
              {recent.map((execution) => (
                <ActivityCard
                  execution={execution}
                  key={execution.request.id}
                  now={now}
                  risk={risks[execution.request.id]}
                />
              ))}
            </div>
          )}
        </article>

        <div className="dashboard-side">
          <RecentDecisions decisions={decisions} />
          <article className="panel build-panel">
            <span className="section-kicker">BUILD</span>
            <h2>ShellWarden {APP_VERSION}</h2>
            <p>
              Policy and activity are local. Durable audit, approval UX, and remote transport land
              in their dedicated roadmap slices.
            </p>
            <div className="milestone-row">
              <span>Execution core</span>
              <code>
                {executionCore.running
                  ? `mcp-shell ${executionCore.detectedVersion}`
                  : "unavailable"}
              </code>
            </div>
          </article>
        </div>
      </section>
    </>
  );
}

function ActivityView({
  executions,
  risks,
  activityError,
  now,
}: {
  executions: ExecutionSnapshot[];
  risks: Record<string, RiskAssessment>;
  activityError: string | null;
  now: number;
}) {
  const ordered = [...executions].sort((a, b) => b.createdAtMs - a.createdAtMs);
  const running = ordered.filter((execution) => execution.state === "running").length;
  const blocked = ordered.filter((execution) => execution.state === "awaiting_approval").length;

  return (
    <section className="activity-page">
      <div className="page-heading">
        <div>
          <span className="section-kicker">EXECUTION STREAM</span>
          <h1>Activity</h1>
          <p>Structured execution blocks, not a global terminal scroll.</p>
        </div>
        <div className="activity-summary">
          <span><strong>{running}</strong> running</span>
          <span><strong>{blocked}</strong> blocked</span>
          <span><strong>{ordered.length}</strong> tracked</span>
        </div>
      </div>

      {activityError ? (
        <div className="panel inline-error large">
          <strong>Could not read execution activity</strong>
          <span>{activityError}</span>
        </div>
      ) : ordered.length === 0 ? (
        <section className="panel activity-surface">
          <EmptyActivity />
        </section>
      ) : (
        <div className="activity-list">
          {ordered.map((execution) => (
            <ActivityCard
              execution={execution}
              key={execution.request.id}
              now={now}
              risk={risks[execution.request.id]}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function remotePhaseLabel(phase: RemoteAccessPhase) {
  switch (phase) {
    case "connected":
      return "Connected";
    case "starting":
      return "Connecting";
    case "paused":
      return "Paused";
    case "error":
      return "Error";
    default:
      return "Not configured";
  }
}

function SettingsView({
  remote,
  busy,
  error,
  onConnect,
}: {
  remote: RemoteAccessStatus;
  busy: boolean;
  error: string | null;
  onConnect: (tunnelId: string, apiKey: string, binary: string) => Promise<void>;
}) {
  const [tunnelId, setTunnelId] = useState(remote.tunnelId ?? "");
  const [apiKey, setApiKey] = useState("");
  const [binary, setBinary] = useState("tunnel-client");

  useEffect(() => {
    if (remote.tunnelId) setTunnelId(remote.tunnelId);
  }, [remote.tunnelId]);

  return (
    <section className="settings-page">
      <div className="page-heading">
        <div>
          <span className="section-kicker">REMOTE TRANSPORT</span>
          <h1>Settings</h1>
          <p>Connect OpenAI Secure MCP Tunnel to ShellWarden's loopback-only MCP endpoint.</p>
        </div>
        <span className={"remote-phase phase-" + remote.phase}>{remotePhaseLabel(remote.phase)}</span>
      </div>

      {(error || remote.error) && (
        <div className="panel inline-error large">
          <strong>Remote access needs attention</strong>
          <span>{error ?? remote.error}</span>
        </div>
      )}

      <div className="settings-grid">
        <section className="panel settings-card">
          <span className="section-kicker">SECURE MCP TUNNEL</span>
          <h2>Runtime connection</h2>
          <p>
            Use a restricted runtime key with Tunnels Read + Use. ShellWarden keeps the key in
            memory and passes it only to the managed tunnel process.
          </p>

          <label>
            <span>Tunnel ID</span>
            <input
              autoComplete="off"
              onChange={(event) => setTunnelId(event.target.value)}
              placeholder="tunnel_0123456789abcdef0123456789abcdef"
              spellCheck={false}
              value={tunnelId}
            />
          </label>

          <label>
            <span>Runtime API key</span>
            <input
              autoComplete="off"
              onChange={(event) => setApiKey(event.target.value)}
              placeholder={remote.configured ? "Enter a new key to reconnect" : "sk-…"}
              spellCheck={false}
              type="password"
              value={apiKey}
            />
          </label>

          <label>
            <span>tunnel-client binary</span>
            <input
              autoComplete="off"
              onChange={(event) => setBinary(event.target.value)}
              placeholder="tunnel-client"
              spellCheck={false}
              value={binary}
            />
          </label>

          <button
            className="settings-primary"
            disabled={busy || tunnelId.trim().length === 0 || apiKey.trim().length === 0}
            onClick={async () => {
              await onConnect(tunnelId.trim(), apiKey, binary.trim());
              setApiKey("");
            }}
            type="button"
          >
            {busy ? "Connecting…" : remote.configured ? "Reconnect tunnel" : "Connect tunnel"}
          </button>
        </section>

        <section className="panel settings-card status-card">
          <span className="section-kicker">LOCAL BOUNDARY</span>
          <h2>ShellWarden MCP</h2>
          <dl>
            <div>
              <dt>Listener</dt>
              <dd>{remote.mcpServerUrl ?? "Starting…"}</dd>
            </div>
            <div>
              <dt>Exposure</dt>
              <dd>127.0.0.1 only</dd>
            </div>
            <div>
              <dt>Tunnel</dt>
              <dd>{remote.tunnelId ?? "Not configured"}</dd>
            </div>
            <div>
              <dt>Health UI</dt>
              <dd>{remote.healthUrl ? remote.healthUrl + "/ui" : "Available after tunnel startup"}</dd>
            </div>
          </dl>
          <p className="settings-note">
            Pause stops the managed tunnel process. The local MCP listener remains private on
            loopback so local control continues without remote authority.
          </p>
        </section>
      </div>
    </section>
  );
}

export function App() {
  const [section, setSection] = useState<Section>("Dashboard");
  const [executionCore, setExecutionCore] = useState<ExecutionCoreStatus>(initialCoreStatus);
  const [executions, setExecutions] = useState<ExecutionSnapshot[]>([]);
  const [risks, setRisks] = useState<Record<string, RiskAssessment>>({});
  const [decisions, setDecisions] = useState<PolicyDecisionEvent[]>([]);
  const [approvals, setApprovals] = useState<ApprovalView[]>([]);
  const [rules, setRules] = useState<PolicyRuleView[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [managementError, setManagementError] = useState<string | null>(null);
  const [managementBusy, setManagementBusy] = useState<string | null>(null);
  const [remoteAccess, setRemoteAccess] = useState<RemoteAccessStatus>(initialRemoteAccess);
  const [remoteError, setRemoteError] = useState<string | null>(null);
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [resolvingApproval, setResolvingApproval] = useState<string | null>(null);
  const [focusedApprovalId, setFocusedApprovalId] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const pendingApprovals = useMemo(
    () => approvals.filter((approval) => approval.status === "pending").length,
    [approvals],
  );

  const refreshManagement = useCallback(async () => {
    try {
      const [permissionRules, audit] = await Promise.all([
        invoke<PolicyRuleView[]>("policy_rules"),
        invoke<AuditEntry[]>("audit_entries", { limit: 500 }),
      ]);
      setRules(permissionRules);
      setAuditEntries(audit);
      setManagementError(null);
    } catch (error: unknown) {
      setManagementError(error instanceof Error ? error.message : String(error));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    invoke<ExecutionCoreStatus>("execution_core_status")
      .then((status) => {
        if (!cancelled) setExecutionCore(status);
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

  useEffect(() => {
    let disposed = false;
    let unlisten: UnlistenFn | undefined;

    const refresh = async () => {
      try {
        const [activity, recentDecisions] = await Promise.all([
          invoke<ExecutionSnapshot[]>("execution_activity_snapshot"),
          invoke<PolicyDecisionEvent[]>("policy_recent_decisions"),
        ]);
        if (!disposed) {
          setExecutions(activity);
          setDecisions(recentDecisions);
          setActivityError(null);
        }
      } catch (error: unknown) {
        if (!disposed) {
          setActivityError(error instanceof Error ? error.message : String(error));
        }
      }
    };

    void refresh();

    listen("shellwarden://execution-activity", () => {
      void refresh();
    }).then((stop) => {
      if (disposed) {
        stop();
      } else {
        unlisten = stop;
      }
    });

    const refreshTimer = window.setInterval(() => void refresh(), 3000);
    const clockTimer = window.setInterval(() => setNow(Date.now()), 1000);

    return () => {
      disposed = true;
      unlisten?.();
      window.clearInterval(refreshTimer);
      window.clearInterval(clockTimer);
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let stopApproval: UnlistenFn | undefined;
    let stopOpenApprovals: UnlistenFn | undefined;
    let stopOpenApproval: UnlistenFn | undefined;

    const refreshApprovals = async () => {
      try {
        const snapshot = await invoke<ApprovalView[]>("approval_snapshot");
        if (!disposed) {
          setApprovals(snapshot);
          setApprovalError(null);
        }
      } catch (error: unknown) {
        if (!disposed) {
          setApprovalError(error instanceof Error ? error.message : String(error));
        }
      }
    };

    void refreshApprovals();

    listen("shellwarden://approval", () => {
      void refreshApprovals();
    }).then((stop) => {
      if (disposed) stop();
      else stopApproval = stop;
    });

    listen("shellwarden://open-approvals", () => {
      if (!disposed) setSection("Approvals");
      void refreshApprovals();
    }).then((stop) => {
      if (disposed) stop();
      else stopOpenApprovals = stop;
    });

    listen<string>("shellwarden://open-approval", (event) => {
      if (!disposed) {
        setFocusedApprovalId(event.payload);
        setSection("Approvals");
      }
      void refreshApprovals();
    }).then((stop) => {
      if (disposed) stop();
      else stopOpenApproval = stop;
    });

    const approvalTimer = window.setInterval(() => void refreshApprovals(), 2000);

    return () => {
      disposed = true;
      stopApproval?.();
      stopOpenApprovals?.();
      stopOpenApproval?.();
      window.clearInterval(approvalTimer);
    };
  }, []);

  useEffect(() => {
    if (!focusedApprovalId || section !== "Approvals") return;

    const target = document.getElementById(
      `approval-${encodeURIComponent(focusedApprovalId)}`,
    );
    if (target instanceof HTMLElement) {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [approvals, focusedApprovalId, section]);

  useEffect(() => {
    let disposed = false;
    let stopRemote: UnlistenFn | undefined;
    let stopOpenSettings: UnlistenFn | undefined;

    const refreshRemote = async () => {
      try {
        const status = await invoke<RemoteAccessStatus>("remote_access_status");
        if (!disposed) {
          setRemoteAccess(status);
          setRemoteError(null);
        }
      } catch (error: unknown) {
        if (!disposed) setRemoteError(error instanceof Error ? error.message : String(error));
      }
    };

    void refreshRemote();

    listen<RemoteAccessStatus>("shellwarden://remote-access", (event) => {
      if (!disposed) {
        setRemoteAccess(event.payload);
        setRemoteError(null);
      }
    }).then((stop) => {
      if (disposed) stop();
      else stopRemote = stop;
    });

    listen("shellwarden://open-settings", () => {
      if (!disposed) setSection("Settings");
      void refreshRemote();
    }).then((stop) => {
      if (disposed) stop();
      else stopOpenSettings = stop;
    });

    const remoteTimer = window.setInterval(() => void refreshRemote(), 3000);

    return () => {
      disposed = true;
      stopRemote?.();
      stopOpenSettings?.();
      window.clearInterval(remoteTimer);
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let stopAudit: UnlistenFn | undefined;

    void refreshManagement();

    listen("shellwarden://audit", () => {
      if (!disposed) void refreshManagement();
    }).then((stop) => {
      if (disposed) stop();
      else stopAudit = stop;
    });

    const managementTimer = window.setInterval(() => {
      if (!disposed) void refreshManagement();
    }, 5000);

    return () => {
      disposed = true;
      stopAudit?.();
      window.clearInterval(managementTimer);
    };
  }, [refreshManagement]);

  async function revokeRule(ruleId: string) {
    setManagementBusy("revoke:" + ruleId);
    try {
      await invoke<boolean>("policy_revoke", { ruleId });
      await refreshManagement();
    } catch (error: unknown) {
      setManagementError(error instanceof Error ? error.message : String(error));
    } finally {
      setManagementBusy(null);
    }
  }

  async function resetSessionRules() {
    setManagementBusy("reset-session");
    try {
      await invoke<number>("policy_reset_all_sessions");
      await refreshManagement();
    } catch (error: unknown) {
      setManagementError(error instanceof Error ? error.message : String(error));
    } finally {
      setManagementBusy(null);
    }
  }

  async function resetDirectoryScopes() {
    setManagementBusy("reset-directory");
    try {
      await invoke<number>("policy_reset_directory_scoped");
      await refreshManagement();
    } catch (error: unknown) {
      setManagementError(error instanceof Error ? error.message : String(error));
    } finally {
      setManagementBusy(null);
    }
  }

  async function resetPersistentRules() {
    setManagementBusy("reset-persistent");
    try {
      await invoke<number>("policy_reset_persistent");
      await refreshManagement();
    } catch (error: unknown) {
      setManagementError(error instanceof Error ? error.message : String(error));
    } finally {
      setManagementBusy(null);
    }
  }

  async function connectRemote(tunnelId: string, apiKey: string, binary: string) {
    setRemoteBusy(true);
    setRemoteError(null);
    try {
      const status = await invoke<RemoteAccessStatus>("remote_access_connect", {
        tunnelId,
        apiKey,
        binary: binary || null,
      });
      setRemoteAccess(status);
    } catch (error: unknown) {
      setRemoteError(error instanceof Error ? error.message : String(error));
    } finally {
      setRemoteBusy(false);
    }
  }

  async function toggleRemoteAccess() {
    if (!remoteAccess.configured) {
      setSection("Settings");
      return;
    }

    setRemoteBusy(true);
    setRemoteError(null);
    try {
      const command =
        remoteAccess.phase === "connected" || remoteAccess.phase === "starting"
          ? "remote_access_pause"
          : "remote_access_resume";
      const status = await invoke<RemoteAccessStatus>(command);
      setRemoteAccess(status);
    } catch (error: unknown) {
      setRemoteError(error instanceof Error ? error.message : String(error));
      setSection("Settings");
    } finally {
      setRemoteBusy(false);
    }
  }

  async function resolveApproval(approvalId: string, scope: ApprovalScope) {
    setResolvingApproval(`${approvalId}:${scope}`);
    setApprovalError(null);
    try {
      await invoke<ApprovalResolution>("approval_resolve", { approvalId, scope });
      const [approvalSnapshot, activity, recentDecisions] = await Promise.all([
        invoke<ApprovalView[]>("approval_snapshot"),
        invoke<ExecutionSnapshot[]>("execution_activity_snapshot"),
        invoke<PolicyDecisionEvent[]>("policy_recent_decisions"),
      ]);
      setApprovals(approvalSnapshot);
      setExecutions(activity);
      setDecisions(recentDecisions);
      await refreshManagement();
    } catch (error: unknown) {
      setApprovalError(error instanceof Error ? error.message : String(error));
      try {
        setApprovals(await invoke<ApprovalView[]>("approval_snapshot"));
      } catch {
        // Preserve the original resolution error; polling/listeners can recover later.
      }
    } finally {
      setResolvingApproval(null);
    }
  }

  useEffect(() => {
    let cancelled = false;
    const missing = executions.filter((execution) => !risks[execution.request.id]);
    if (missing.length === 0) return;

    Promise.all(
      missing.map(async (execution) => {
        const risk = await invoke<RiskAssessment>("risk_assess", {
          input: {
            command: execution.request.command,
            operationClass: execution.request.operationClass,
          },
        });
        return [execution.request.id, risk] as const;
      }),
    )
      .then((entries) => {
        if (!cancelled) {
          setRisks((current) => ({ ...current, ...Object.fromEntries(entries) }));
        }
      })
      .catch(() => {
        // Activity remains useful if risk hydration fails; the card stays in "assessing" state.
      });

    return () => {
      cancelled = true;
    };
  }, [executions, risks]);

  let content: ReactNode;
  if (section === "Dashboard") {
    content = (
      <Dashboard
        activityError={activityError}
        decisions={decisions}
        executionCore={executionCore}
        executions={executions}
        now={now}
        onOpenActivity={() => setSection("Activity")}
        pendingApprovalCount={pendingApprovals}
        risks={risks}
      />
    );
  } else if (section === "Activity") {
    content = (
      <ActivityView
        activityError={activityError}
        executions={executions}
        now={now}
        risks={risks}
      />
    );
  } else if (section === "Approvals") {
    content = (
      <ApprovalsView
        approvals={approvals}
        error={approvalError}
        now={now}
        onResolve={resolveApproval}
        resolving={resolvingApproval}
      />
    );
  } else if (section === "Permissions") {
    content = (
      <PermissionsView
        busy={managementBusy}
        error={managementError}
        onResetDirectoryScopes={resetDirectoryScopes}
        onResetPersistent={resetPersistentRules}
        onResetSessions={resetSessionRules}
        onRevoke={revokeRule}
        rules={rules}
      />
    );
  } else if (section === "Audit") {
    content = <AuditView entries={auditEntries} error={managementError} />;
  } else {
    content = (
      <SettingsView
        busy={remoteBusy}
        error={remoteError}
        onConnect={connectRemote}
        remote={remoteAccess}
      />
    );
  }

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
              {item.label === "Approvals" && (
                <span className={pendingApprovals > 0 ? "nav-count attention" : "nav-count"}>
                  {pendingApprovals}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="local-only">
            <span className={"status-dot remote-" + remoteAccess.phase} />
            <div>
              <strong>Local control active</strong>
              <span>Remote: {remotePhaseLabel(remoteAccess.phase).toLowerCase()}</span>
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
            <span className={"connection-chip remote-" + remoteAccess.phase}>
              <span className={"status-dot remote-" + remoteAccess.phase} />
              Remote {remotePhaseLabel(remoteAccess.phase).toLowerCase()}
            </span>
            <button
              className="pause-button"
              disabled={remoteBusy}
              onClick={toggleRemoteAccess}
              type="button"
              title={remoteAccess.error ?? undefined}
            >
              {remoteBusy
                ? "Updating…"
                : !remoteAccess.configured
                  ? "Configure Remote"
                  : remoteAccess.phase === "connected" || remoteAccess.phase === "starting"
                    ? "Pause Remote Access"
                    : "Resume Remote Access"}
            </button>
          </div>
        </header>

        <div className="content">{content}</div>
      </main>
    </div>
  );
}
